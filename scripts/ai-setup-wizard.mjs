#!/usr/bin/env node
/*
 * QuillTest — AI setup wizard (CLI)
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Configures which AI provider/model QuillTest's optional analysis layer talks
 * to, runs a connectivity test, and writes quilltest.ai.json (git-ignored).
 *
 * No third-party dependencies. Node 18+ (uses global fetch, readline/promises).
 *
 *   node scripts/ai-setup-wizard.mjs                 # interactive
 *   node scripts/ai-setup-wizard.mjs --list          # list providers
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
      if (next === undefined || next.startsWith('--')) {
        out[key] = true;
      } else {
        out[key] = next;
        i++;
      }
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
  console.log(`${c.bold('QuillTest AI setup wizard')}

Usage:
  node scripts/ai-setup-wizard.mjs [options]

Options:
  --provider <id>     Provider id (see --list). Skips the provider prompt.
  --model <id>        Model id. Skips the model prompt.
  --base <url>        Override the endpoint base URL.
  --key <value>       API key value (prefer --key-env to avoid shell history).
  --key-env <VAR>     Name of the env var holding the key (stored as a reference).
  --test              Run a connectivity test before saving.
  --test-only         Test the existing --config (or default) and exit; no save.
  --config <path>     Config file to read for --test-only (default quilltest.ai.json).
  --out <path>        Where to write config (default quilltest.ai.json).
  --save-key          Write the literal key into the config file (NOT recommended).
  --no-save           Run through the wizard/test but do not write a file.
  --list              List supported providers and exit.
  --yes               Accept defaults without prompting where possible.
  --dry-run           Show the test request that would be sent, without sending.
  --help              This help.

Providers out of the box: ${PROVIDERS.map((p) => p.id).join(', ')}
See docs/AI-WIZARD.md for details.`);
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

// ----- interactive prompts ---------------------------------------------------

async function runInteractive(rl, preset) {
  // 1. provider
  let provider = preset.provider ? getProvider(preset.provider) : null;
  if (!provider) {
    console.log(c.bold('\nChoose an AI provider:\n'));
    PROVIDERS.forEach((p, i) => {
      console.log(`  ${String(i + 1).padStart(2)}. ${p.label} ${c.dim('(' + p.id + ')')}`);
    });
    const ans = (await rl.question(`\nProvider [1-${PROVIDERS.length}]: `)).trim();
    const idx = Number.parseInt(ans, 10) - 1;
    provider = PROVIDERS[idx] || getProvider(ans);
    if (!provider) {
      console.error(c.red('Unknown provider.'));
      exit(2);
    }
  }
  console.log(`\n${c.green('→')} ${provider.label}  ${c.dim('[' + provider.apiStyle + ']')}`);
  if (provider.notes) console.log(c.dim('  ' + provider.notes));

  // 2. base
  let base = preset.base || provider.defaultBase;
  if (!preset.base && provider.baseEditable) {
    const def = provider.defaultBase ? ` [${provider.defaultBase}]` : ' (required)';
    const ans = (await rl.question(`\nEndpoint base URL${def}: `)).trim();
    if (ans) base = ans;
  }
  if (!base) {
    console.error(c.red('This provider requires an endpoint base URL.'));
    exit(2);
  }
  base = base.replace(/\/+$/, '');

  // 3. key
  let apiKey = preset.key || null;
  let apiKeyEnv = preset.keyEnv || provider.keyEnv;
  if (!apiKey) {
    const envHas = apiKeyEnv && env[apiKeyEnv];
    const hint = envHas ? ` [found in $${apiKeyEnv}]` : (apiKeyEnv ? ` [will reference $${apiKeyEnv}]` : '');
    const ans = await promptHidden(rl, `\nAPI key${hint} (leave blank to use env var): `);
    if (ans.trim()) apiKey = ans.trim();
  }
  if (!apiKey && apiKeyEnv && env[apiKeyEnv]) apiKey = env[apiKeyEnv];
  if (!apiKey && !keyOptional(provider.id)) {
    console.log(c.yellow(`\nNo key provided. Will store a reference to $${apiKeyEnv}; set it before scanning.`));
  }

  // 4. model
  let model = preset.model || null;
  if (!model) {
    if (provider.models.length) {
      console.log(c.bold('\nSuggested models:'));
      provider.models.forEach((m, i) => console.log(`  ${i + 1}. ${m}`));
      console.log(c.dim('  (or type any model id the provider accepts)'));
    }
    if (provider.listModelsPath && apiKey) {
      const fetchAns = (await rl.question('\nFetch the live model list from the provider? [y/N]: ')).trim().toLowerCase();
      if (fetchAns === 'y' || fetchAns === 'yes') {
        const live = await fetchModels(provider, base, apiKey).catch((e) => {
          console.log(c.yellow('  Could not fetch models: ' + e.message));
          return null;
        });
        if (live && live.length) {
          console.log(c.bold('\nLive models:'));
          live.slice(0, 40).forEach((m) => console.log('  - ' + m));
        }
      }
    }
    const ans = (await rl.question(`\nModel [${provider.models[0] || 'type an id'}]: `)).trim();
    model = ans || provider.models[0];
  }
  if (!model) {
    console.error(c.red('A model id is required.'));
    exit(2);
  }

  return { provider, base, apiKey, apiKeyEnv, model };
}

// readline has no native hidden input; mute stdout echo during the question.
async function promptHidden(rl, query) {
  const onData = () => {
    // Move cursor back and clear, so typed key chars are not shown.
    stdout.write('\x1b[2K\r' + query);
  };
  stdout.write(query);
  stdin.on('data', onData);
  try {
    const answer = await rl.question('');
    return answer;
  } finally {
    stdin.removeListener('data', onData);
    stdout.write('\n');
  }
}

// ----- provider calls --------------------------------------------------------

async function fetchModels(provider, base, apiKey) {
  const req = buildListModelsRequest({ providerId: provider.id, base, apiKey });
  if (!req) return [];
  const res = await fetch(req.url, { ...req.init, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return extractModelIds(await res.json());
}

async function runTest(cfg, { dryRun } = {}) {
  const provider = getProvider(cfg.providerId);
  const effectiveKey = cfg.apiKey || (cfg.apiKeyEnv ? env[cfg.apiKeyEnv] : '') || '';
  const { url, init } = buildTestRequest(
    { providerId: cfg.providerId, base: cfg.base, apiKey: effectiveKey, model: cfg.model },
    'Reply with the single word: OK',
  );

  if (dryRun) {
    const redacted = { ...init, headers: redactHeaders(init.headers) };
    console.log(c.bold('\n[dry-run] Request that would be sent:'));
    console.log('  ' + c.cyan(init.method) + ' ' + url);
    console.log('  headers: ' + JSON.stringify(redacted.headers));
    console.log('  body:    ' + redacted.body);
    return { ok: true, dryRun: true };
  }

  if (!effectiveKey && !keyOptional(provider.id)) {
    return { ok: false, error: `No API key available (set $${cfg.apiKeyEnv} or pass --key).` };
  }

  process.stdout.write('\nTesting connectivity… ');
  const t0 = Date.now();
  try {
    const res = await fetch(url, { ...init, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
    const ms = Date.now() - t0;
    const text = await res.text();
    let json;
    try { json = JSON.parse(text); } catch { json = null; }
    if (!res.ok) {
      const msg = json?.error?.message || json?.message || text.slice(0, 200);
      return { ok: false, error: `HTTP ${res.status} (${ms}ms): ${msg}` };
    }
    const reply = json ? extractText(provider.apiStyle, json) : '';
    return { ok: true, ms, reply: reply || '(empty)' };
  } catch (e) {
    const msg = e?.name === 'TimeoutError' ? `No response within ${REQUEST_TIMEOUT_MS / 1000}s` : (e?.cause?.message || e.message);
    return { ok: false, error: msg };
  }
}

function redactHeaders(h) {
  const out = {};
  for (const [k, v] of Object.entries(h || {})) {
    out[k] = /authorization|api-key|key/i.test(k) ? 'REDACTED' : v;
  }
  return out;
}

// ----- config io -------------------------------------------------------------

function buildConfig(choice, { saveKey }) {
  return {
    version: 1,
    active: choice.provider.id,
    providers: {
      [choice.provider.id]: {
        providerId: choice.provider.id,
        base: choice.base,
        model: choice.model,
        apiKeyEnv: choice.apiKeyEnv || null,
        apiKey: saveKey ? (choice.apiKey || null) : null,
      },
    },
  };
}

function mergeIntoExisting(outPath, newConfig) {
  if (!existsSync(outPath)) return newConfig;
  try {
    const existing = JSON.parse(readFileSync(outPath, 'utf8'));
    existing.version = 1;
    existing.providers = { ...(existing.providers || {}), ...newConfig.providers };
    existing.active = newConfig.active;
    return existing;
  } catch {
    return newConfig;
  }
}

function writeConfig(outPath, config, { saveKey, providerId }) {
  // Guard: never let a literal key be written for the provider just configured
  // unless explicitly opted in. Keys other providers already stored in this file
  // (from an earlier --save-key run) are left as they are.
  if (!saveKey && config.providers?.[providerId]) {
    config.providers[providerId].apiKey = null;
  }
  writeFileSync(outPath, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
  // `mode` only applies when the file is created; tighten an existing file too.
  try { chmodSync(outPath, 0o600); } catch { /* best effort (e.g. Windows) */ }
}

// ----- main ------------------------------------------------------------------

async function main() {
  const args = parseArgs(argv.slice(2));

  if (args.help) { printHelp(); return; }
  if (args.list) { listProviders(); return; }

  // --test-only path: load config, test active provider, exit.
  if (args['test-only']) {
    const cfgPath = resolve(process.cwd(), args.config || DEFAULT_OUT);
    if (!existsSync(cfgPath)) {
      console.error(c.red(`No config at ${cfgPath}`));
      exit(1);
    }
    const cfg = JSON.parse(readFileSync(cfgPath, 'utf8'));
    const active = cfg.providers[cfg.active];
    if (!active) { console.error(c.red('Config has no active provider.')); exit(1); }
    const r = await runTest(active, { dryRun: args['dry-run'] });
    reportTest(r);
    exit(r.ok ? 0 : 1);
  }

  const noPrompt = args.yes && args.provider;
  const preset = {
    provider: typeof args.provider === 'string' ? args.provider : null,
    base: typeof args.base === 'string' ? args.base : null,
    model: typeof args.model === 'string' ? args.model : null,
    key: typeof args.key === 'string' ? args.key : null,
    keyEnv: typeof args['key-env'] === 'string' ? args['key-env'] : null,
  };

  let choice;
  if (noPrompt) {
    const provider = getProvider(preset.provider);
    if (!provider) { console.error(c.red('Unknown --provider.')); exit(2); }
    const apiKeyEnv = preset.keyEnv || provider.keyEnv;
    choice = {
      provider,
      base: (preset.base || provider.defaultBase || '').replace(/\/+$/, ''),
      apiKey: preset.key || (apiKeyEnv ? env[apiKeyEnv] : null) || null,
      apiKeyEnv,
      model: preset.model || provider.models[0],
    };
    if (!choice.base) { console.error(c.red('This provider needs --base.')); exit(2); }
    if (!choice.model) { console.error(c.red('This provider needs --model.')); exit(2); }
  } else {
    const rl = createInterface({ input: stdin, output: stdout });
    try {
      choice = await runInteractive(rl, preset);
    } finally {
      rl.close();
    }
  }

  const cfgForProvider = {
    providerId: choice.provider.id,
    base: choice.base,
    model: choice.model,
    apiKey: choice.apiKey,
    apiKeyEnv: choice.apiKeyEnv,
  };

  if (args.test || args['dry-run']) {
    const r = await runTest(cfgForProvider, { dryRun: args['dry-run'] });
    reportTest(r);
    if (!r.ok && !args['dry-run']) {
      console.log(c.yellow('\nTest failed — not saving. Re-run after fixing, or use --no-save to skip tests.'));
      if (!args['no-save']) exit(1);
    }
  }

  if (args['no-save']) {
    console.log(c.dim('\n--no-save set; configuration not written.'));
    return;
  }

  const saveKey = Boolean(args['save-key']);
  const outPath = resolve(process.cwd(), typeof args.out === 'string' ? args.out : DEFAULT_OUT);
  const built = buildConfig(choice, { saveKey });
  const merged = mergeIntoExisting(outPath, built);
  writeConfig(outPath, merged, { saveKey, providerId: choice.provider.id });

  console.log(c.green(`\n✓ Wrote ${outPath}`));
  console.log(`  active provider: ${c.bold(choice.provider.id)}  model: ${c.bold(choice.model)}`);
  if (!saveKey) {
    console.log(c.dim(`  key stored as a reference to $${choice.apiKeyEnv || '(none)'} — not written to the file.`));
  } else {
    console.log(c.yellow('  WARNING: API key written into the config file. Keep it out of version control.'));
  }
  console.log(c.dim('  quilltest.ai.json is git-ignored by default.'));
}

function reportTest(r) {
  if (r.dryRun) return;
  if (r.ok) {
    console.log(c.green('OK') + c.dim(`  (${r.ms}ms, model replied: ${JSON.stringify(r.reply)})`));
  } else {
    console.log(c.red('FAILED'));
    console.log('  ' + c.red(r.error));
  }
}

main().catch((e) => {
  console.error(c.red('\nWizard error: ' + (e?.stack || e?.message || e)));
  exit(1);
});
