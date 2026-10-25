#!/usr/bin/env node
/*
 * Anne's Test — AI setup wizard (CLI)
 * Part of the Anne's Office suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Configures which AI provider(s) Anne's Test's optional analysis layer consults,
 * tests each one, and writes quilltest.ai.json (git-ignored).
 *
 * Several providers can be enabled at once. The analysis layer then consults
 * them either one after another ("sequential") or all at once ("concurrent").
 * In both modes the providers analyze Anne's Test's own findings and observed
 * responses; they do not run the scan and never emit attack payloads.
 *
 * No third-party dependencies. Node 18+ (global fetch, readline/promises).
 *
 *   node scripts/ai-setup-wizard.mjs                                   # interactive
 *   node scripts/ai-setup-wizard.mjs --list                            # list providers
 *   node scripts/ai-setup-wizard.mjs --providers openai,anthropic,xai --mode concurrent --yes --test
 *   node scripts/ai-setup-wizard.mjs --provider anthropic --model claude-opus-5-5 --yes --test
 *   node scripts/ai-setup-wizard.mjs --config quilltest.ai.json --test-only
 *
 * See docs/AI-WIZARD.md for the full flag list.
 */

import { createInterface } from 'node:readline/promises';
import { stdin, stdout, env, argv, exit } from 'node:process';
import { writeFileSync, readFileSync, existsSync, chmodSync } from 'node:fs';
import { resolve } from 'node:path';

import {
  PROVIDERS,
  getProvider,
  keyOptional,
  buildTestRequest,
  buildListModelsRequest,
  extractModelIds,
  extractText,
  buildMultiConfig,
  normalizeConfig,
  validateBase,
  scrubSecrets,
  ANALYSIS_MODES,
} from '../src/ai/providers.mjs';

const DEFAULT_OUT = resolve(process.cwd(), 'quilltest.ai.json');
const REQUEST_TIMEOUT_MS = 30_000;

// ----- tiny arg parser -------------------------------------------------------

function parseArgs(args) {
  const out = { _: [] };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = args[i + 1];
      if (next === undefined || next.startsWith('--')) out[key] = true;
      else { out[key] = next; i++; }
    } else {
      out._.push(a);
    }
  }
  return out;
}

// ----- output helpers --------------------------------------------------------

const c = {
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  cyan: (s) => `\x1b[36m${s}\x1b[0m`,
};

function printHelp() {
  console.log(`${c.bold('Anne\'s Test AI setup wizard')}

Usage:
  node scripts/ai-setup-wizard.mjs [options]

Selection:
  --providers <ids>   Comma-separated provider ids to enable (e.g. openai,anthropic,xai).
  --provider <id>     Single provider (alias for --providers with one id).
  --mode <mode>       Analysis mode: ${ANALYSIS_MODES.join(' | ')} (default sequential).
  --model <id>        Model id (applied to the single selected provider).
  --base <url>        Endpoint base override (single selected provider).
  --key <value>       API key (single provider; prefer --key-env to avoid shell history).
  --key-env <VAR>     Name of the env var holding the key (stored as a reference).

Actions:
  --test              Test connectivity for every selected provider before saving.
  --test-only         Test the providers in --config (or default) and exit; no save.
  --config <path>     Config to read for --test-only (default quilltest.ai.json).
  --out <path>        Where to write config (default quilltest.ai.json).
  --save-key          Write literal keys into the config file (NOT recommended).
  --allow-insecure-base  Permit a plaintext http:// endpoint on a non-loopback host
                      (your key would travel in cleartext; only for a trusted LAN gateway).
  --no-save           Run the wizard/test but do not write a file.
  --list              List supported providers and exit.
  --yes               Accept defaults without prompting where possible.
  --dry-run           Show the test request(s) that would be sent, without sending.
  --help              This help.

Providers out of the box: ${PROVIDERS.map((p) => p.id).join(', ')}
Network requests time out after ${REQUEST_TIMEOUT_MS / 1000}s. See docs/AI-WIZARD.md for details.`);
}

function listProviders() {
  console.log(c.bold('\nSupported providers:\n'));
  for (const p of PROVIDERS) {
    console.log(`  ${c.cyan(p.id.padEnd(10))} ${p.label}`);
    console.log(`  ${''.padEnd(10)} ${c.dim(p.defaultBase || '(base required)')}  [${p.apiStyle}]`);
    if (p.models.length) console.log(`  ${''.padEnd(10)} ${c.dim('models: ' + p.models.join(', '))}`);
    console.log(`  ${''.padEnd(10)} ${c.dim('keys:   ' + p.keysUrl)}`);
    console.log('');
  }
}

// ----- interactive flow ------------------------------------------------------

function resolveSelection(input) {
  if (!input) return [];
  if (input.trim().toLowerCase() === 'all') return PROVIDERS.slice();
  const out = [];
  for (const tok of input.split(',').map((s) => s.trim()).filter(Boolean)) {
    const n = Number.parseInt(tok, 10);
    const p = Number.isInteger(n) ? PROVIDERS[n - 1] : getProvider(tok);
    if (p && !out.includes(p)) out.push(p);
  }
  return out;
}

async function runInteractive(rl, preset) {
  // 1. provider multi-select
  let chosen = [];
  if (preset.providerIds.length) {
    chosen = preset.providerIds.map(getProvider).filter(Boolean);
  } else {
    console.log(c.bold('\nSelect AI providers (Anne\'s Test can consult several):\n'));
    PROVIDERS.forEach((p, i) => {
      console.log(`  ${String(i + 1).padStart(2)}. ${p.label} ${c.dim('(' + p.id + ')')}`);
    });
    console.log(c.dim('\n  Enter numbers or ids, comma-separated (e.g. 1,2,4 or openai,anthropic).'));
    console.log(c.dim('  "all" selects every provider.'));
    const ans = (await rl.question('\nProviders: ')).trim();
    chosen = resolveSelection(ans);
    if (!chosen.length) { console.error(c.red('No valid providers selected.')); exit(2); }
  }
  console.log(`\n${c.green('→')} selected: ${chosen.map((p) => p.label).join(', ')}`);

  // 2. per-provider base / key / model
  const selections = [];
  for (const provider of chosen) {
    console.log(c.bold(`\n── ${provider.label} ──`));
    if (provider.notes) console.log(c.dim('  ' + provider.notes));

    let base = provider.defaultBase;
    if (preset.single && preset.base) base = preset.base;
    if (provider.baseEditable && !(preset.single && preset.base)) {
      const def = provider.defaultBase ? ` [${provider.defaultBase}]` : ' (required)';
      // Re-ask until the URL is acceptable, so a typo or plaintext endpoint is caught here.
      for (;;) {
        const a = (await rl.question(`  Endpoint base URL${def}: `)).trim();
        const candidate = a || provider.defaultBase;
        const v = validateBase(candidate, { allowInsecure: preset.allowInsecure });
        if (v.ok) { base = candidate; if (v.warning) console.log(c.yellow('  ' + v.warning)); break; }
        console.log(c.red('  ' + v.error));
      }
    } else {
      const v = validateBase(base, { allowInsecure: preset.allowInsecure });
      if (!v.ok) { console.error(c.red(`  ${provider.label}: ${v.error}`)); exit(2); }
      if (v.warning) console.log(c.yellow('  ' + v.warning));
    }
    base = base.replace(/\/+$/, '');

    const apiKeyEnv = (preset.single && preset.keyEnv) || provider.keyEnv;
    let apiKey = (preset.single && preset.key) || null;
    if (!apiKey) {
      const envHas = apiKeyEnv && env[apiKeyEnv];
      const hint = envHas ? ` [found in $${apiKeyEnv}]` : (apiKeyEnv ? ` [will reference $${apiKeyEnv}]` : '');
      const a = await promptHidden(rl, `  API key${hint} (blank = use env var): `);
      if (a.trim()) apiKey = a.trim();
    }
    if (!apiKey && apiKeyEnv && env[apiKeyEnv]) apiKey = env[apiKeyEnv];
    if (!apiKey && !keyOptional(provider.id)) {
      console.log(c.yellow(`  No key yet — will store a reference to $${apiKeyEnv}; set it before scanning.`));
    }

    let model = (preset.single && preset.model) || null;
    if (!model) {
      if (provider.models.length) console.log('  Suggested models: ' + provider.models.join(', '));
      if (provider.listModelsPath && apiKey) {
        const fetchAns = (await rl.question('  Fetch the live model list? [y/N]: ')).trim().toLowerCase();
        if (fetchAns === 'y' || fetchAns === 'yes') {
          const live = await fetchModels(provider, base, apiKey).catch((e) => {
            console.log(c.yellow('  Could not fetch models: ' + e.message));
            return null;
          });
          if (live && live.length) { console.log('  Live: ' + live.slice(0, 40).join(', ')); }
        }
      }
      const a = (await rl.question(`  Model [${provider.models[0] || 'type an id'}]: `)).trim();
      model = a || provider.models[0];
    }
    if (!model) { console.error(c.red(`  ${provider.label} needs a model id.`)); exit(2); }

    selections.push({ providerId: provider.id, base, apiKey, apiKeyEnv, model });
  }

  // 3. analysis mode (only meaningful with >1 provider)
  let mode = preset.mode || 'sequential';
  if (!preset.mode && selections.length > 1) {
    console.log(c.bold('\nAnalysis mode:'));
    console.log('  1. sequential — consult each provider one after another (default)');
    console.log('  2. concurrent — consult all providers at once (used with staging-mirror mode)');
    const a = (await rl.question('\nMode [1]: ')).trim();
    mode = a === '2' || a.toLowerCase() === 'concurrent' ? 'concurrent' : 'sequential';
  }

  return { selections, mode };
}

// readline has no native hidden input. Mute readline's own echo for the
// duration of the question (the documented approach: override _writeToOutput),
// which avoids racing readline's echo against a clear-line escape.
async function promptHidden(rl, query) {
  const original = rl._writeToOutput;
  let muted = false;
  rl._writeToOutput = function (s) {
    if (!muted) return original.call(this, s);
    // Keep the prompt visible; swallow the typed characters.
    if (s.includes(query)) return original.call(this, query);
  };
  stdout.write(query);
  muted = true;
  try { return await rl.question(''); }
  finally { muted = false; rl._writeToOutput = original; stdout.write('\n'); }
}

// ----- provider calls --------------------------------------------------------

async function fetchModels(provider, base, apiKey) {
  const req = buildListModelsRequest({ providerId: provider.id, base, apiKey });
  if (!req) return [];
  const res = await fetch(req.url, { ...req.init, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return extractModelIds(await res.json());
}

async function runTest(entry, { dryRun } = {}) {
  const provider = getProvider(entry.providerId);
  const effectiveKey = entry.apiKey || (entry.apiKeyEnv ? env[entry.apiKeyEnv] : '') || '';
  const { url, init } = buildTestRequest(
    { providerId: entry.providerId, base: entry.base, apiKey: effectiveKey, model: entry.model },
    'Reply with the single word: OK',
  );

  if (dryRun) {
    const redacted = { ...init, headers: redactHeaders(init.headers) };
    console.log(c.bold(`\n[dry-run] ${provider.label}:`));
    console.log('  ' + c.cyan(init.method) + ' ' + url);
    console.log('  headers: ' + JSON.stringify(redacted.headers));
    console.log('  body:    ' + redacted.body);
    return { ok: true, dryRun: true };
  }
  if (!effectiveKey && !keyOptional(provider.id)) {
    return { ok: false, error: `No API key available (set $${entry.apiKeyEnv} or pass --key).` };
  }

  const t0 = Date.now();
  try {
    const res = await fetch(url, { ...init, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
    const ms = Date.now() - t0;
    const text = await res.text();
    let json; try { json = JSON.parse(text); } catch { json = null; }
    if (!res.ok) {
      const msg = json?.error?.message || json?.message || text.slice(0, 200);
      // Never let a provider error that echoes the request print the key.
      return { ok: false, error: scrubSecrets(`HTTP ${res.status} (${ms}ms): ${msg}`, [effectiveKey]) };
    }
    const reply = json ? extractText(provider.apiStyle, json) : '';
    return { ok: true, ms, reply: scrubSecrets(reply || '(empty)', [effectiveKey]) };
  } catch (e) {
    const msg = e?.name === 'TimeoutError' ? `No response within ${REQUEST_TIMEOUT_MS / 1000}s` : (e?.cause?.message || e.message);
    return { ok: false, error: scrubSecrets(msg, [effectiveKey]) };
  }
}

function redactHeaders(h) {
  const out = {};
  for (const [k, v] of Object.entries(h || {})) out[k] = /authorization|api-key|key/i.test(k) ? 'REDACTED' : v;
  return out;
}

function reportTest(label, r) {
  if (r.dryRun) return;
  if (r.ok) console.log(`${label}: ` + c.green('OK') + c.dim(`  (${r.ms}ms, replied ${JSON.stringify(r.reply)})`));
  else console.log(`${label}: ` + c.red('FAILED') + '\n  ' + c.red(r.error));
}

/** Test every entry. Honors mode: concurrent fires them in parallel. */
async function testAll(entries, { dryRun, mode }) {
  if (dryRun) { for (const e of entries) await runTest(e, { dryRun: true }); return true; }
  const labelOf = (e) => getProvider(e.providerId).label;
  let results;
  if (mode === 'concurrent') {
    console.log(c.dim(`\nTesting ${entries.length} provider(s) concurrently…`));
    results = await Promise.all(entries.map((e) => runTest(e)));
  } else {
    results = [];
    for (const e of entries) { process.stdout.write(`\nTesting ${labelOf(e)}…`); results.push(await runTest(e)); }
  }
  let allOk = true;
  entries.forEach((e, i) => { reportTest(labelOf(e), results[i]); if (!results[i].ok) allOk = false; });
  return allOk;
}

// ----- config io -------------------------------------------------------------

/**
 * Merge a freshly built multi-provider config into an existing file, preserving
 * other providers' stored entries (including keys saved with --save-key).
 */
function mergeIntoExisting(outPath, fresh) {
  if (!existsSync(outPath)) return fresh;
  try {
    const existing = JSON.parse(readFileSync(outPath, 'utf8'));
    const providers = { ...(existing.providers || {}), ...fresh.providers };
    return {
      version: fresh.version,
      analysisMode: fresh.analysisMode,
      activeProviders: fresh.activeProviders,
      active: fresh.active,
      providers,
    };
  } catch {
    return fresh;
  }
}

function writeConfig(outPath, config) {
  writeFileSync(outPath, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
  try { chmodSync(outPath, 0o600); } catch { /* best effort (e.g. Windows) */ }
}

// ----- main ------------------------------------------------------------------

async function main() {
  const args = parseArgs(argv.slice(2));
  if (args.help) { printHelp(); return; }
  if (args.list) { listProviders(); return; }

  if (args['test-only']) {
    const cfgPath = resolve(process.cwd(), args.config || DEFAULT_OUT);
    if (!existsSync(cfgPath)) { console.error(c.red(`No config at ${cfgPath}`)); exit(1); }
    const norm = normalizeConfig(JSON.parse(readFileSync(cfgPath, 'utf8')));
    if (!norm.activeProviders.length) { console.error(c.red('Config has no active providers.')); exit(1); }
    console.log(c.dim(`mode: ${norm.analysisMode}  providers: ${norm.activeProviders.join(', ')}`));
    const entries = norm.activeProviders.map((id) => norm.providers[id]);
    const ok = await testAll(entries, { dryRun: args['dry-run'], mode: norm.analysisMode });
    exit(ok ? 0 : 1);
  }

  const providerIds = typeof args.providers === 'string'
    ? args.providers.split(',').map((s) => s.trim()).filter(Boolean)
    : (typeof args.provider === 'string' ? [args.provider] : []);
  if (args.mode !== undefined && !ANALYSIS_MODES.includes(args.mode)) {
    console.error(c.red(`--mode must be one of: ${ANALYSIS_MODES.join(', ')} (got ${JSON.stringify(args.mode)})`));
    exit(2);
  }
  const preset = {
    providerIds,
    single: providerIds.length === 1,
    base: typeof args.base === 'string' ? args.base : null,
    model: typeof args.model === 'string' ? args.model : null,
    key: typeof args.key === 'string' ? args.key : null,
    keyEnv: typeof args['key-env'] === 'string' ? args['key-env'] : null,
    mode: typeof args.mode === 'string' ? args.mode : null,
    allowInsecure: Boolean(args['allow-insecure-base']),
  };

  let selections, mode;
  const nonInteractive = args.yes && providerIds.length;
  if (nonInteractive) {
    selections = providerIds.map((id) => {
      const provider = getProvider(id);
      if (!provider) { console.error(c.red(`Unknown provider: ${id}`)); exit(2); }
      const apiKeyEnv = (preset.single && preset.keyEnv) || provider.keyEnv;
      const base = ((preset.single && preset.base) ? preset.base : provider.defaultBase || '').replace(/\/+$/, '');
      if (!base) { console.error(c.red(`${provider.label} needs --base.`)); exit(2); }
      const v = validateBase(base, { allowInsecure: preset.allowInsecure });
      if (!v.ok) { console.error(c.red(`${provider.label}: ${v.error}`)); exit(2); }
      if (v.warning) console.log(c.yellow(`${provider.label}: ${v.warning}`));
      const model = (preset.single && preset.model) || provider.models[0];
      if (!model) { console.error(c.red(`${provider.label} needs --model.`)); exit(2); }
      const apiKey = (preset.single && preset.key) || (apiKeyEnv ? env[apiKeyEnv] : null) || null;
      return { providerId: provider.id, base, apiKey, apiKeyEnv, model };
    });
    mode = preset.mode || 'sequential';
  } else {
    const rl = createInterface({ input: stdin, output: stdout });
    try { ({ selections, mode } = await runInteractive(rl, preset)); }
    finally { rl.close(); }
  }

  if (args.test || args['dry-run']) {
    const ok = await testAll(selections, { dryRun: args['dry-run'], mode });
    if (!ok && !args['dry-run'] && !args['no-save']) {
      console.log(c.yellow('\nOne or more tests failed — not saving. Fix and re-run, or use --no-save.'));
      exit(1);
    }
  }

  if (args['no-save']) { console.log(c.dim('\n--no-save set; configuration not written.')); return; }

  const saveKey = Boolean(args['save-key']);
  const outPath = resolve(process.cwd(), typeof args.out === 'string' ? args.out : DEFAULT_OUT);
  const fresh = buildMultiConfig(selections.map((s) => ({ ...s, saveKey })), { mode, allowInsecure: preset.allowInsecure });
  const merged = mergeIntoExisting(outPath, fresh);
  writeConfig(outPath, merged);

  console.log(c.green(`\n✓ Wrote ${outPath}`));
  console.log(`  mode: ${c.bold(merged.analysisMode)}  providers: ${c.bold(merged.activeProviders.join(', '))}`);
  if (!saveKey) console.log(c.dim('  keys stored as env-var references — not written to the file.'));
  else console.log(c.yellow('  WARNING: API keys written into the config file. Keep it out of version control.'));
  console.log(c.dim('  quilltest.ai.json is git-ignored by default.'));
}

main().catch((e) => {
  console.error(c.red('\nWizard error: ' + (e?.stack || e?.message || e)));
  exit(1);
});
