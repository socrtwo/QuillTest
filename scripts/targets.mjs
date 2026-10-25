#!/usr/bin/env node
/*
 * Anne's Test — target management CLI
 * Part of the Anne's Office suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 *   node scripts/targets.mjs add https://example.com --label "Prod" --tag prod --tag eu --note "main site"
 *   node scripts/targets.mjs list [--tag prod] [--json]
 *   node scripts/targets.mjs show https://example.com
 *   node scripts/targets.mjs remove https://example.com
 *
 * A target is bookkeeping, not a grant: adding one does not verify ownership.
 * `list` and `show` join each target with its verification status from the
 * same store the scanner's gate reads.
 */
import { argv, exit } from 'node:process';
import { resolve } from 'node:path';
import { createTargetStore, withStatus, byTag } from '../src/targets/store.mjs';
import { createStore } from '../src/verify/store.mjs';

const c = {
  bold: (s) => `\x1b[1m${s}\x1b[0m`, dim: (s) => `\x1b[2m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`, red: (s) => `\x1b[31m${s}\x1b[0m`, yellow: (s) => `\x1b[33m${s}\x1b[0m`,
};
const STATE_COLOR = { verified: c.green, expired: c.yellow, unverified: c.dim };

function parseArgs(args) {
  const out = { _: [], tag: [] };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (!a.startsWith('--')) { out._.push(a); continue; }
    const k = a.slice(2), n = args[i + 1];
    if (n === undefined || n.startsWith('--')) out[k] = true;
    else if (k === 'tag') { out.tag.push(n); i++; }
    else { out[k] = n; i++; }
  }
  return out;
}

function usage(code = 0) {
  console.log(`${c.bold('Anne\'s Test targets')}

  add <origin>     Add (or update) a target.   --label <t>  --tag <t> (repeatable)  --note <t>
  list             List targets with verification + last-scan status.   --tag <t>   --json
  show <origin>    Show one target in detail.
  remove <origin>  Remove a target (does not change verification).
      --store <dir>   Verification store directory (default scans/verify).
      --file <path>   Targets file (default scans/targets.json).`);
  exit(code);
}

const args = parseArgs(argv.slice(2));
if (args.help || !args._.length) usage(args.help ? 0 : 2);
const targets = createTargetStore(typeof args.file === 'string' ? resolve(process.cwd(), args.file) : undefined);
const verify = createStore(typeof args.store === 'string' ? resolve(process.cwd(), args.store) : undefined);

const stateLabel = (v) => (STATE_COLOR[v.state] || ((s) => s))(v.state) + (v.expires ? c.dim(` (until ${v.expires})`) : '');

function printTarget(t) {
  console.log(`${c.bold(t.origin)}${t.label ? '  ' + t.label : ''}`);
  console.log(`  ownership: ${stateLabel(t.verification)}`);
  if (t.tags?.length) console.log(`  tags: ${t.tags.join(', ')}`);
  if (t.note) console.log(`  note: ${t.note}`);
  console.log(c.dim(`  added ${t.addedAt}${t.lastScanAt ? `; last scan ${t.lastScanAt}` : '; never scanned'}`));
  if (t.lastScan?.bySeverity) {
    const b = t.lastScan.bySeverity;
    const parts = ['critical', 'high', 'medium', 'low', 'info'].filter((s) => b[s]).map((s) => `${b[s]} ${s}`);
    console.log(c.dim(`  last findings: ${t.lastScan.total}${parts.length ? ` (${parts.join(', ')})` : ''}`));
  }
}

const cmd = args._[0];
try {
  if (cmd === 'add') {
    const origin = args._[1] || usage(2);
    const { target, created } = targets.add(origin, { label: typeof args.label === 'string' ? args.label : null, tags: args.tag, note: typeof args.note === 'string' ? args.note : null });
    console.log((created ? c.green('added ') : c.yellow('updated ')) + c.bold(target.origin));
    const [withS] = withStatus([target], verify.loadVerified());
    printTarget(withS);
  } else if (cmd === 'list') {
    let list = withStatus(targets.list(), verify.loadVerified());
    if (typeof args.tag?.[0] === 'string' || typeof args.tag === 'string') { const tg = Array.isArray(args.tag) ? args.tag[0] : args.tag; list = byTag(list, tg); }
    if (args.json) { console.log(JSON.stringify(list, null, 2)); exit(0); }
    if (!list.length) { console.log(c.dim('No targets. Add one: node scripts/targets.mjs add <origin>')); exit(0); }
    console.log(c.bold(`${list.length} target(s)`));
    for (const t of list) {
      console.log(`  ${stateLabel(t.verification).padEnd(10)} ${c.bold(t.origin)}${t.label ? c.dim('  ' + t.label) : ''}${t.tags?.length ? c.dim('  [' + t.tags.join(', ') + ']') : ''}`);
    }
  } else if (cmd === 'show') {
    const t = targets.get(args._[1] || usage(2));
    if (!t) { console.error(c.red('No such target.')); exit(1); }
    const [withS] = withStatus([t], verify.loadVerified());
    printTarget(withS);
  } else if (cmd === 'remove') {
    const ok = targets.remove(args._[1] || usage(2));
    console.log(ok ? c.green('removed') : c.yellow('no such target'));
    exit(ok ? 0 : 1);
  } else usage(2);
} catch (e) {
  console.error(c.red('Error: ' + (e?.message || e)));
  exit(1);
}
