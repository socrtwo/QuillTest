#!/usr/bin/env node
/*
 * Anne's Test — run the AI analysis layer over a findings file
 * Part of the Anne's Office suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 *   node scripts/ai-analyze.mjs --findings examples/findings.sample.json --dry-run
 *   node scripts/ai-analyze.mjs --findings scans/last/findings.json --mode concurrent
 *   node scripts/ai-analyze.mjs --findings f.json --config quilltest.ai.json --out analysis.json
 *
 * The findings file is a JSON array of Anne's Test finding records (see
 * examples/findings.sample.json). Providers come from quilltest.ai.json, as
 * written by scripts/ai-setup-wizard.mjs. --dry-run prints the exact, redacted
 * requests that would be sent and sends nothing; it needs no API keys.
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { argv, exit } from 'node:process';
import { analyzeFindings } from '../src/ai/analyze.mjs';
import { ANALYSIS_MODES } from '../src/ai/providers.mjs';

function parseArgs(args) {
  const out = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (!a.startsWith('--')) continue;
    const k = a.slice(2); const n = args[i + 1];
    if (n === undefined || n.startsWith('--')) out[k] = true; else { out[k] = n; i++; }
  }
  return out;
}

const args = parseArgs(argv.slice(2));
if (args.help || !args.findings) {
  console.log(`Usage: node scripts/ai-analyze.mjs --findings <file.json> [--config quilltest.ai.json] [--mode sequential|concurrent] [--dry-run] [--out result.json] [--stack '<json>']`);
  exit(args.help ? 0 : 2);
}
if (args.mode !== undefined && !ANALYSIS_MODES.includes(args.mode)) {
  console.error(`--mode must be one of: ${ANALYSIS_MODES.join(', ')}`);
  exit(2);
}

const findingsPath = resolve(process.cwd(), args.findings);
const configPath = resolve(process.cwd(), typeof args.config === 'string' ? args.config : 'quilltest.ai.json');
if (!existsSync(findingsPath)) { console.error(`No findings file at ${findingsPath}`); exit(1); }
if (!existsSync(configPath)) { console.error(`No config at ${configPath} — run scripts/ai-setup-wizard.mjs first`); exit(1); }

const findings = JSON.parse(readFileSync(findingsPath, 'utf8'));
const config = JSON.parse(readFileSync(configPath, 'utf8'));
let stack; if (typeof args.stack === 'string') { try { stack = JSON.parse(args.stack); } catch { console.error('--stack must be JSON'); exit(2); } }

const result = await analyzeFindings(findings, config, {
  mode: typeof args.mode === 'string' ? args.mode : undefined,
  dryRun: Boolean(args['dry-run']),
  stack,
});

if (result.error) { console.error(result.error); exit(1); }

if (args['dry-run']) {
  console.log(`[dry-run] mode=${result.mode}  findings sent=${result.prepared.count}  dropped=${result.prepared.dropped}  payload≈${result.prepared.chars} chars\n`);
  for (const p of result.providers) {
    console.log(`── ${p.label} (${p.model}) ──`);
    if (!p.ok) { console.log('  ' + p.error); continue; }
    console.log('  POST ' + p.request.url);
    console.log('  headers: ' + JSON.stringify(p.request.init.headers));
    const body = JSON.parse(p.request.init.body);
    const preview = JSON.stringify(body).slice(0, 400);
    console.log('  body:    ' + preview + (preview.length >= 400 ? '…' : ''));
  }
  exit(0);
}

for (const p of result.providers) {
  const status = p.ok ? (p.parsed ? 'OK' : 'OK (unparsed)') : 'FAILED';
  console.log(`── ${p.label} (${p.model}): ${status}${p.ms ? ` ${p.ms}ms` : ''}${p.filtered ? `  [${p.removedLines} payload-like line(s) removed]` : ''}`);
  if (!p.ok) console.log('  ' + p.error);
  else if (p.parsed?.summary) console.log('  ' + p.parsed.summary);
}
console.log('\nConsensus:');
for (const [id, c] of Object.entries(result.consensus)) {
  const pr = c.meanAttackerPriority != null ? `  priority≈${c.meanAttackerPriority.toFixed(1)}` : '';
  console.log(`  ${id}: ${c.verdict} (${c.reviewers} reviewer${c.reviewers === 1 ? '' : 's'})${pr}`);
}

if (typeof args.out === 'string') {
  writeFileSync(resolve(process.cwd(), args.out), JSON.stringify(result, null, 2) + '\n');
  console.log(`\nWrote ${args.out}`);
}
