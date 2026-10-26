#!/usr/bin/env node
/*
 * Anne's Test — render, export, diff and package a scan report
 * Part of the Anne's Office suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 *   node scripts/report.mjs --report scans/<host>/<ts>.json                      # → <ts>.html next to it
 *   node scripts/report.mjs --report r.json --format md --out report.md
 *   node scripts/report.mjs --report r.json --format all --out out/              # html + md + csv
 *   node scripts/report.mjs --report r.json --diff previous.json                 # adds a "changes" section
 *   node scripts/report.mjs --report r.json --diff previous.json --format json   # the diff alone, as JSON
 *   node scripts/report.mjs --report r.json --package review/                    # everything + fixes + manifest
 *   node scripts/report.mjs --verify review/                                     # check a package against its manifest
 *
 * The HTML is self-contained and script-free; open it in a browser and print
 * to PDF. Nothing here contacts the network.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync, statSync, readdirSync } from 'node:fs';
import { resolve, join, dirname, basename, sep } from 'node:path';
import { argv, exit } from 'node:process';
import { renderHtml, renderMarkdown, renderCsv, diffReports, buildReviewPackage, verifyManifest, summarize, isSafePackagePath } from '../src/report/render.mjs';
import { generateFixes } from '../src/fix/artifacts.mjs';

const FORMATS = ['html', 'md', 'csv', 'json', 'all'];
const EXT = { html: '.html', md: '.md', csv: '.csv', json: '.diff.json' };

function parseArgs(args) {
  const out = {};
  for (let i = 0; i < args.length; i++) { const a = args[i]; if (!a.startsWith('--')) continue; const k = a.slice(2), n = args[i + 1]; if (n === undefined || n.startsWith('--')) out[k] = true; else { out[k] = n; i++; } }
  return out;
}
const args = parseArgs(argv.slice(2));
if (args.help || (!args.report && !args.verify)) {
  console.log(`Usage:
  node scripts/report.mjs --report <scan.json> [--format ${FORMATS.join('|')}] [--out <file|dir>] [--diff <previous.json>]
                          [--no-evidence] [--no-fixes] [--no-analysis] [--title "<text>"]
  node scripts/report.mjs --report <scan.json> --package <dir> [--diff <previous.json>] [--regenerate-fixes]
  node scripts/report.mjs --verify <package-dir>

  --format json is only meaningful with --diff: it writes the diff itself.
  --package writes report.{json,html,md}, findings.csv, fixes/, README.txt and manifest.json (SHA-256 per file).`);
  exit(args.help ? 0 : 2);
}

const load = (p, what) => {
  const abs = resolve(process.cwd(), p);
  if (!existsSync(abs)) { console.error(`No ${what} at ${abs}`); exit(1); }
  try { return JSON.parse(readFileSync(abs, 'utf8')); } catch (e) { console.error(`${what} is not valid JSON: ${e.message}`); exit(1); }
};
const write = (p, contents) => { mkdirSync(dirname(p), { recursive: true }); writeFileSync(p, contents, { mode: 0o600 }); console.log(`  wrote ${p}`); };

// ---- --verify ---------------------------------------------------------------
if (args.verify) {
  const dir = resolve(process.cwd(), String(args.verify));
  const manifest = load(join(dir, 'manifest.json'), 'manifest');
  // verifyManifest rejects traversal paths itself; the extra check keeps this reader honest on its own.
  const listFiles = (d = dir, prefix = '') => readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? listFiles(join(d, e.name), prefix + e.name + '/') : [prefix + e.name]));
  const res = verifyManifest(manifest, (rel) => (isSafePackagePath(rel) && existsSync(join(dir, rel)) ? readFileSync(join(dir, rel)) : null), { listFiles });
  for (const r of res.results) console.log(`  ${r.ok ? 'ok     ' : 'FAILED '} ${r.path}${r.reason ? `  (${r.reason})` : ''}`);
  console.log(res.ok ? `\nPackage intact: ${res.results.length} file(s) match the manifest.` : '\nPackage does NOT match its manifest.');
  exit(res.ok ? 0 : 4);
}

// ---- load inputs -------------------------------------------------------------
const reportPath = resolve(process.cwd(), String(args.report));
const report = load(reportPath, 'report');
if (!Array.isArray(report.findings)) { console.error('That file has no findings[]; is it an Anne\'s Test scan report?'); exit(1); }
let diff = null;
if (args.diff) {
  const previous = load(String(args.diff), 'previous report');
  diff = diffReports(previous, report);
  if (!diff.sameOrigin) console.error(`warning: origins differ (${previous.origin} vs ${report.origin}); the diff is still produced.`);
}
const renderOpts = { diff, includeEvidence: !args['no-evidence'], includeFixes: !args['no-fixes'], includeAnalysis: !args['no-analysis'], title: typeof args.title === 'string' ? args.title : undefined };

const s = summarize(report);
console.log(`Anne\'s Test report — ${s.origin || reportPath}: ${s.total} finding(s)${s.total ? ` (${Object.entries(s.bySeverity).filter(([, n]) => n).map(([k, n]) => `${n} ${k}`).join(', ')})` : ''}${diff ? ` · diff: +${diff.summary.new} new, −${diff.summary.resolved} resolved, ${diff.summary.changed} changed` : ''}`);

// ---- --package ---------------------------------------------------------------
if (args.package) {
  const dir = resolve(process.cwd(), String(args.package));
  let fixes = report.fixes || null;
  if (args['regenerate-fixes'] || !fixes) fixes = generateFixes(report);
  const previous = args.diff ? load(String(args.diff), 'previous report') : null;
  const pkg = buildReviewPackage(report, { diff, fixes, previousReport: previous });
  for (const f of pkg.files) {
    const target = resolve(dir, f.filename);
    if (!target.startsWith(dir + sep)) { console.error(`Refusing to write outside the package directory: ${f.filename}`); exit(1); }
    write(target, f.contents);
  }
  console.log(`\nReview package: ${pkg.files.length} file(s) in ${dir}. Verify later with: node scripts/report.mjs --verify ${args.package}`);
  exit(0);
}

// ---- render ------------------------------------------------------------------
const format = typeof args.format === 'string' ? args.format : 'html';
if (!FORMATS.includes(format)) { console.error(`--format must be one of: ${FORMATS.join(', ')}`); exit(2); }
if (format === 'json' && !diff) { console.error('--format json writes the findings diff; pass --diff <previous.json>.'); exit(2); }
const wanted = format === 'all' ? ['html', 'md', 'csv', ...(diff ? ['json'] : [])] : [format];
const stem = basename(reportPath).replace(/\.json$/i, '');
const outArg = typeof args.out === 'string' ? resolve(process.cwd(), args.out) : null;
const outIsDir = outArg && (wanted.length > 1 || /[\\/]$/.test(String(args.out)) || (existsSync(outArg) && statSync(outArg).isDirectory()));

for (const fmt of wanted) {
  const contents = fmt === 'html' ? renderHtml(report, renderOpts)
    : fmt === 'md' ? renderMarkdown(report, renderOpts)
      : fmt === 'csv' ? renderCsv(report)
        : JSON.stringify(diff, null, 2) + '\n';
  const target = outIsDir ? join(outArg, stem + EXT[fmt]) : outArg && wanted.length === 1 ? outArg : join(dirname(reportPath), stem + EXT[fmt]);
  write(target, contents);
}
