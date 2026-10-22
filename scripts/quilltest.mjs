#!/usr/bin/env node
/*
 * QuillTest — command-line shell over the command registry
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Every QuillTest command is runnable here by id, long before the ribbon UI
 * exists. The same executor (src/commands/exec.mjs) enforces the scan gate.
 *
 *   node scripts/quilltest.mjs <area.name> [positional] [--key value] [--json]
 *   node scripts/quilltest.mjs <area> <name> ...          (same thing, two words)
 *   node scripts/quilltest.mjs commands [query]           list / search commands
 *   node scripts/quilltest.mjs ribbon                     default tab layout
 *
 *   node scripts/quilltest.mjs target add https://example.com --name "Prod site"
 *   node scripts/quilltest.mjs target confirmAuthorization https://example.com --statement "I own this site"
 *   node scripts/quilltest.mjs verify issue https://example.com
 *   node scripts/quilltest.mjs verify check https://example.com
 *   node scripts/quilltest.mjs target status
 *   node scripts/quilltest.mjs scan start                 (refused until verified + authorized)
 *
 * The first positional becomes arg.origin for verify and target commands;
 * --flags become arg fields (comma lists for include/exclude/tags).
 */

import { argv, exit } from 'node:process';
import {
  getCommand, allCommands, searchCommands, createContext, exec,
  UnknownCommandError, NotImplementedError, CommandDisabledError,
} from '../src/commands/index.mjs';
import { DEFAULT_TABS, BACKSTAGE_SECTIONS } from '../src/ui/ribbonLayout.mjs';
import { VerificationRequiredError } from '../src/verify/store.mjs';
import { AuthorizationRequiredError, NoActiveTargetError, UnknownTargetError } from '../src/targets/store.mjs';
import { InvalidOriginError } from '../src/verify/origin.mjs';

const c = {
  bold: (s) => `\x1b[1m${s}\x1b[0m`, dim: (s) => `\x1b[2m${s}\x1b[0m`, green: (s) => `\x1b[32m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`, yellow: (s) => `\x1b[33m${s}\x1b[0m`, cyan: (s) => `\x1b[36m${s}\x1b[0m`,
};

const LIST_FLAGS = new Set(['include', 'exclude', 'tags']);

function parseArgs(args) {
  const out = { _: [], flags: {} };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = args[i + 1];
      if (next === undefined || next.startsWith('--')) out.flags[key] = true;
      else { out.flags[key] = LIST_FLAGS.has(key) ? next.split(',').map((s) => s.trim()).filter(Boolean) : next; i++; }
    } else out._.push(a);
  }
  return out;
}

function printHelp() {
  console.log(`${c.bold('QuillTest')} — run any command by id

Usage:
  node scripts/quilltest.mjs <area.name> [origin|value] [--flag value] [--json]
  node scripts/quilltest.mjs commands [query]      list or search commands
  node scripts/quilltest.mjs ribbon                show the default tabs

Examples:
  node scripts/quilltest.mjs target add https://example.com --name "Prod"
  node scripts/quilltest.mjs target confirmAuthorization --statement "Owner; see engagement letter 2026-10"
  node scripts/quilltest.mjs verify issue
  node scripts/quilltest.mjs verify check [--method dns]
  node scripts/quilltest.mjs target status
  node scripts/quilltest.mjs scan start

Options: --json  machine-readable output   --store-dir <dir>  where quilltest.*.json live (default cwd)`);
}

function showCommands(query, json) {
  const list = query ? searchCommands(query, 200) : allCommands();
  if (json) { console.log(JSON.stringify(list.map(({ run, ...rest }) => ({ ...rest, implemented: typeof run === 'function' })), null, 2)); return; }
  const byTab = new Map();
  for (const cmd of list) { if (!byTab.has(cmd.tab)) byTab.set(cmd.tab, []); byTab.get(cmd.tab).push(cmd); }
  for (const [tab, cmds] of byTab) {
    console.log(c.bold(`\n${tab}`));
    for (const cmd of cmds) {
      const impl = typeof cmd.run === 'function' ? c.green('●') : c.dim('○');
      const gate = cmd.requiresVerification ? c.yellow(' [gated]') : '';
      const keys = cmd.keys?.length ? c.dim(`  ${cmd.keys.join(', ')}`) : '';
      console.log(`  ${impl} ${c.cyan(cmd.id.padEnd(30))} ${cmd.label}${gate}${keys}`);
    }
  }
  const impl = list.filter((x) => typeof x.run === 'function').length;
  console.log(c.dim(`\n${list.length} commands, ${impl} implemented (●), ${list.length - impl} planned (○); [gated] = needs a verified, authorized target\n`));
}

function showRibbon(json) {
  if (json) { console.log(JSON.stringify({ backstage: BACKSTAGE_SECTIONS, tabs: DEFAULT_TABS }, null, 2)); return; }
  console.log(c.bold('\nFile (Backstage): ') + BACKSTAGE_SECTIONS.map((s) => s.label).join(' · '));
  for (const t of DEFAULT_TABS) console.log(c.bold(`${t.label}${t.hidden ? c.dim(' (hidden by default)') : ''}: `) + t.groups.map((g) => g.label).join(' · '));
  console.log('');
}

function buildArg(cmd, positional, flags) {
  const arg = { ...flags };
  delete arg.json; delete arg['store-dir'];
  const area = cmd.id.split('.')[0];
  if (positional.length) {
    if (area === 'verify' || area === 'target') arg.origin = positional[0];
    else if (cmd.id === 'view.cmdSearch') arg.query = positional.join(' ');
    else if (cmd.id === 'dev.runMacro' || cmd.id === 'dev.stopRecording' || cmd.id === 'ai.active' || cmd.id === 'ai.test') arg.providerId = arg.name = positional[0];
    else arg.value = positional.length === 1 ? positional[0] : positional;
  }
  if (cmd.id === 'verify.writeFile' && positional[1]) arg.dir = positional[1];
  if (cmd.id === 'target.inScope' && positional[1]) arg.url = positional[1];
  return Object.keys(arg).length ? arg : undefined;
}

const SEV = ['informational', 'low', 'medium', 'high', 'critical'];
const sevRank = (s) => SEV.indexOf(s);
const sevColor = (s) => ({ critical: c.red, high: c.red, medium: c.yellow, low: (x) => x, informational: c.dim }[s] || ((x) => x))(s.padEnd(13));

function print(result, json) {
  if (json) { console.log(JSON.stringify(result ?? null, null, 2)); return; }
  if (result === undefined) return;
  if (typeof result === 'string') { console.log(result); return; }
  // Friendly renderings for the most common shapes.
  if (result?.challenge && result.file) {
    console.log(c.bold(`\nChallenge issued for ${result.challenge.origin}`) + c.dim(`  (expires ${result.challenge.expires})`));
    console.log(`\nPublish this file at ${c.cyan(result.url)}\n`);
    console.log(result.file.replace(/^/gm, '  ').trimEnd());
    if (result.dns) console.log(`\nOr add a DNS record:\n  ${c.cyan(result.dns.name)}.  TXT  "${result.dns.value}"`);
    console.log('');
    return;
  }
  if (result?.result && 'ok' in result.result) {
    const r = result.result;
    console.log(r.ok ? c.green('VERIFIED') : c.red('NOT VERIFIED'));
    for (const x of r.reasons || []) console.log('  ' + c.red('✗ ' + x));
    for (const x of r.warnings || []) console.log('  ' + c.yellow('! ' + x));
    if (result.record) console.log(c.dim(`  valid until ${result.record.validUntil}`));
    return;
  }
  if (result && typeof result.ready === 'boolean') {
    const o = result.origin || result.target?.origin;
    console.log((result.ready ? c.green('READY TO SCAN') : c.red('NOT READY')) + `  ${o}`);
    console.log(`  verified:   ${result.verified ? c.green('yes') : c.red('no')}${result.record ? c.dim(`  (until ${result.record.validUntil})`) : ''}`);
    console.log(`  authorized: ${result.authorized ? c.green('yes') : c.red('no')}${result.target?.authorization?.statement ? c.dim(`  "${result.target.authorization.statement}"`) : ''}`);
    for (const r of result.reasons || []) console.log('  ' + c.yellow('• ' + r));
    if (result.pending) console.log(c.dim(`  pending challenge expires ${result.pending.expires}`));
    return;
  }
  if (result?.id && result.crawl && result.summary && Array.isArray(result.findings)) {
    const sm = result.summary;
    console.log(c.bold(`\nScan ${result.id}`) + c.dim(`  ${result.origin}  ${result.profile}  ${result.durationMs} ms`));
    console.log(`  crawled ${result.crawl.pages} page(s), ${result.crawl.assets} asset(s), ${result.crawl.probes} probe request(s)${result.crawl.active ? `, ${result.crawl.active} active detection request(s) across ${result.crawl.injectionPoints} injection point(s)` : ''}; ${result.crawl.requests} requests total${result.crawl.stopReason ? c.dim(' (' + result.crawl.stopReason + ')') : ''}`);
    if (result.fingerprint.length) console.log('  stack: ' + result.fingerprint.map((f) => f.name + (f.version ? ' ' + f.version : '')).join(', '));
    console.log(`  findings: ${c.red(sm.critical + ' critical')}, ${c.red(sm.high + ' high')}, ${c.yellow(sm.medium + ' medium')}, ${sm.low} low, ${c.dim(sm.informational + ' informational')}${sm.suppressed ? c.dim(`; ${sm.suppressed} suppressed`) : ''}`);
    for (const f of result.findings.filter((x) => x.status === 'open').sort((a, b) => sevRank(b.severity) - sevRank(a.severity)).slice(0, 40)) console.log(`  ${sevColor(f.severity)} ${c.cyan(f.checkId.padEnd(32))} ${f.title}${f.key ? c.dim(' [' + f.key + ']') : ''}  ${c.dim(f.url)}`);
    if (result.findings.length > 40) console.log(c.dim(`  … ${result.findings.length - 40} more; use findings list --json`));
    if (result.checks.errors.length) console.log(c.yellow(`  ${result.checks.errors.length} check error(s): ` + result.checks.errors.map((e) => e.checkId).join(', ')));
    console.log(c.dim(`  details: node scripts/quilltest.mjs findings details <id>   export: findings export sarif --json`));
    return;
  }
  if (result?.scan && Array.isArray(result.findings) && result.summary) {
    const sm = result.summary;
    console.log(c.bold(`Findings of ${result.scan}`) + c.dim(`  open ${sm.open}, suppressed ${sm.suppressed}`));
    for (const f of result.findings) console.log(`  ${sevColor(f.severity)} ${c.dim(f.id)} ${c.cyan(f.checkId.padEnd(32))} ${f.title}${f.key ? c.dim(' [' + f.key + ']') : ''}${f.status !== 'open' ? c.dim(' (' + f.status + ')') : ''}  ${c.dim(f.url)}`);
    return;
  }
  if (result?.scans && Array.isArray(result.scans)) {
    if (!result.scans.length) { console.log(c.dim('No scans yet.')); return; }
    for (const s of result.scans) console.log(`  ${c.cyan(s.id)}  ${s.profile.padEnd(8)} ${s.startedAt}  ${s.pages} pages  ${c.red(s.summary.high + s.summary.critical + ' high+')} ${c.yellow(s.summary.medium + ' med')} ${s.summary.low} low ${c.dim(s.summary.informational + ' info')}`);
    return;
  }
  if (result?.counts && result.after) {
    console.log(c.bold(`Compared ${result.after} with ${result.before}`) + `  ${c.red('+' + result.counts.added + ' new')}  ${c.green('-' + result.counts.fixed + ' fixed')}  ${result.counts.persisting} persisting`);
    for (const f of result.added) console.log(`  ${c.red('+')} ${sevColor(f.severity)} ${f.checkId} ${f.title}  ${c.dim(f.url)}`);
    for (const f of result.fixed) console.log(`  ${c.green('-')} ${sevColor(f.severity)} ${f.checkId} ${f.title}  ${c.dim(f.url)}`);
    return;
  }
  if (result?.targets && Array.isArray(result.targets)) {
    if (!result.targets.length) { console.log(c.dim('No targets. Add one with: target add <origin>')); return; }
    for (const t of result.targets) {
      const star = t.origin === result.active ? c.green('*') : ' ';
      console.log(`${star} ${c.cyan(t.origin.padEnd(36))} ${t.name}${t.tags.length ? c.dim('  [' + t.tags.join(', ') + ']') : ''}${t.authorization.confirmed ? c.green('  authorized') : c.dim('  not authorized')}`);
    }
    return;
  }
  if (Array.isArray(result) && result.length && result[0]?.id && result[0]?.label) {
    for (const x of result) console.log(`  ${x.implemented === false ? c.dim('○') : c.green('●')} ${c.cyan(x.id.padEnd(30))} ${x.label}${x.keys?.length ? c.dim('  ' + x.keys.join(', ')) : ''}`);
    return;
  }
  console.log(JSON.stringify(result, null, 2));
}

async function main() {
  const { _: pos, flags } = parseArgs(argv.slice(2));
  const json = Boolean(flags.json);
  if (!pos.length || flags.help) { printHelp(); return; }

  if (pos[0] === 'commands') { showCommands(pos.slice(1).join(' '), json); return; }
  if (pos[0] === 'ribbon') { showRibbon(json); return; }

  let id = pos[0];
  let rest = pos.slice(1);
  if (!id.includes('.') && rest.length) { id = `${id}.${rest[0]}`; rest = rest.slice(1); }
  const cmd = getCommand(id);
  if (!cmd) {
    const hits = searchCommands(pos.join(' '), 8).length ? searchCommands(pos.join(' '), 8) : allCommands().filter((x) => x.id.startsWith(pos[0] + '.')).slice(0, 8);
    console.error(c.red(`Unknown command ${id}.`) + (hits.length ? ` Did you mean:\n` + hits.map((h) => `  ${c.cyan(h.id)}  ${h.label}`).join('\n') : ''));
    exit(2);
  }

  const cwd = typeof flags['store-dir'] === 'string' ? flags['store-dir'] : process.cwd();
  const ctx = createContext({ cwd, out: (line) => console.log(line) });
  const result = await exec(ctx, id, buildArg(cmd, rest, flags));
  print(result, json);
  if (result?.result && 'ok' in result.result && !result.result.ok) exit(1);
  if (result && typeof result.ready === 'boolean' && !result.ready) exit(1);
}

main().catch((e) => {
  const expected = e instanceof VerificationRequiredError || e instanceof AuthorizationRequiredError || e instanceof NoActiveTargetError
    || e instanceof UnknownTargetError || e instanceof InvalidOriginError || e instanceof NotImplementedError || e instanceof CommandDisabledError
    || e instanceof UnknownCommandError || e instanceof RangeError;
  if (expected) {
    console.error(c.red(e.message));
    exit(e instanceof NotImplementedError ? 3 : 1);
  }
  console.error(c.red('\nquilltest error: ' + (e?.stack || e?.message || e)));
  exit(1);
});
