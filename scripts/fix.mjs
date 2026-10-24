#!/usr/bin/env node
/*
 * QuillTest — generate fix artifacts from a scan report
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 *   node scripts/fix.mjs --report scans/<host>/<timestamp>.json
 *   node scripts/fix.mjs --report r.json --target apache          # force a server
 *   node scripts/fix.mjs --report r.json --all --out fixes/        # every target
 *
 * Writes ready-to-review config files (headers block for your server, a CSP
 * derived from what the crawler saw, cookie settings for your framework) and
 * lists the findings that still need a manual change. Nothing is applied to
 * any server.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { argv, exit } from 'node:process';
import { generateFixes, TARGETS } from '../src/fix/artifacts.mjs';

function parseArgs(args) {
  const out = {};
  for (let i = 0; i < args.length; i++) { const a = args[i]; if (!a.startsWith('--')) continue; const k = a.slice(2), n = args[i + 1]; if (n === undefined || n.startsWith('--')) out[k] = true; else { out[k] = n; i++; } }
  return out;
}
const args = parseArgs(argv.slice(2));
if (args.help || !args.report) {
  console.log(`Usage: node scripts/fix.mjs --report <scan.json> [--target ${TARGETS.join('|')}] [--all] [--out <dir>] [--print]`);
  exit(args.help ? 0 : 2);
}
if (args.target && !TARGETS.includes(args.target)) { console.error(`--target must be one of: ${TARGETS.join(', ')}`); exit(2); }

const reportPath = resolve(process.cwd(), args.report);
if (!existsSync(reportPath)) { console.error(`No report at ${reportPath}`); exit(1); }
const report = JSON.parse(readFileSync(reportPath, 'utf8'));
const result = generateFixes(report, { target: typeof args.target === 'string' ? args.target : undefined, all: Boolean(args.all) });

export function printFixes(result, { print = false } = {}) {
  console.log(`\nFix artifacts — target: ${result.target}${result.files.length ? '' : ' (nothing to generate: no header/cookie findings)'}`);
  for (const f of result.files) {
    console.log(`  • ${f.filename}  [${f.kind}${f.target !== result.target ? ` · ${f.target}` : ''}]`);
    if (print) console.log(f.contents.split('\n').map((l) => '      ' + l).join('\n'));
  }
  if (result.notes.length) { console.log('\nNotes:'); for (const n of result.notes) console.log('  - ' + n); }
  if (result.coverage.manual.length) {
    console.log('\nStill manual (textual remediation only):');
    for (const m of result.coverage.manual) console.log(`  ${m.id}  ${m.title}\n        → ${m.remediation.split('\n')[0]}`);
  }
}

printFixes(result, { print: Boolean(args.print) });

if (result.files.length) {
  const outDir = resolve(process.cwd(), typeof args.out === 'string' ? args.out : reportPath.replace(/\.json$/, '') + '-fixes');
  mkdirSync(outDir, { recursive: true });
  for (const f of result.files) writeFileSync(join(outDir, f.filename), f.contents, { mode: 0o600 });
  writeFileSync(join(outDir, 'fixes.json'), JSON.stringify(result, null, 2) + '\n', { mode: 0o600 });
  console.log(`\nWrote ${result.files.length} file(s) to ${outDir}`);
}
