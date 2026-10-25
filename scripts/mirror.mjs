#!/usr/bin/env node
/*
 * QuillTest — staging-mirror CLI (capture / serve / scan a copy of your site)
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 *   node scripts/mirror.mjs capture https://example.com [--out dir] [--max-pages 25] [--max-bytes 8388608]
 *   node scripts/mirror.mjs serve   scans/example.com/<ts>/            [--port 0]
 *   node scripts/mirror.mjs scan    https://example.com --dir scans/example.com/<ts>/ [--out report.json] [--analyze]
 *   node scripts/mirror.mjs scan    https://example.com                # capture a fresh snapshot, then scan it
 *
 * Capture and scan refuse any origin without a valid verification record —
 * the same gate as a live scan, and there is no override. The snapshot is a
 * local copy of your own client-delivered surface; it is never re-published,
 * and the mirror is tested with the same non-destructive set as production.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { argv, exit } from 'node:process';
import { isOriginVerified } from '../src/verify/ownership.mjs';
import { createStore } from '../src/verify/store.mjs';
import { captureMirror, serveMirror, loadMirror, scanMirror, MIRROR_MANIFEST } from '../src/scan/mirror.mjs';
import { sortFindings } from '../src/scan/passive.mjs';
import { analyzeFindings } from '../src/ai/analyze.mjs';
import { validateConfig, formatValidation } from '../src/ai/config-schema.mjs';
import { createTargetStore } from '../src/targets/store.mjs';

const c = {
  bold: (s) => `\x1b[1m${s}\x1b[0m`, dim: (s) => `\x1b[2m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`, red: (s) => `\x1b[31m${s}\x1b[0m`, yellow: (s) => `\x1b[33m${s}\x1b[0m`,
};
const SEV_COLOR = { critical: c.red, high: c.red, medium: c.yellow, low: c.dim, info: c.dim };

function parseArgs(args) {
  const out = { _: [] };
  for (let i = 0; i < args.length; i++) { const a = args[i]; if (!a.startsWith('--')) { out._.push(a); continue; } const k = a.slice(2), n = args[i + 1]; if (n === undefined || n.startsWith('--')) out[k] = true; else { out[k] = n; i++; } }
  return out;
}

function usage(code = 0) {
  console.log(`${c.bold('QuillTest staging mirror')}

  capture <origin>   Capture a bounded, same-origin snapshot of a verified site into ./scans/<host>/<ts>/.
      --out <dir>        Snapshot directory (default under scans/).
      --max-pages <n>    Page cap (default 25).  --max-depth <n>  Link depth (default 3).
      --max-bytes <n>    Cap on captured body bytes (default 8388608).  --ignore-robots
  serve <dir>        Replay a captured snapshot on a loopback address until Ctrl-C.
      --port <n>         Port (default 0 = pick a free one). Always binds 127.0.0.1.
  scan <origin>      Scan a snapshot with the passive engine; findings name <origin>.
      --dir <dir>        Snapshot to scan. If omitted, a fresh snapshot is captured first.
      --out <file>       Write the JSON report.   --analyze   Run the configured AI providers.
      --store <dir>      Verification store (default scans/verify).

Capture and scan require a verification record for the origin (docs/OWNERSHIP-VERIFICATION.md). Exit 3 if missing.`);
  exit(code);
}

const args = parseArgs(argv.slice(2));
if (args.help || !args._.length) usage(args.help ? 0 : 2);
const store = createStore(typeof args.store === 'string' ? resolve(process.cwd(), args.store) : undefined);

function gateOrigin(originArg) {
  const gate = isOriginVerified(store.loadVerified(), originArg);
  if (!gate.ok) {
    console.error(c.red('Refusing: ') + gate.error);
    console.error(c.dim('QuillTest only mirrors origins you have proven you control. See docs/OWNERSHIP-VERIFICATION.md.'));
    exit(3);
  }
  return gate.origin;
}

async function cmdCapture() {
  const origin = gateOrigin(args._[1] || usage(2));
  console.log(c.bold(`\nCapturing mirror — ${origin}`));
  const res = await captureMirror(origin, {
    outDir: typeof args.out === 'string' ? args.out : undefined,
    maxPages: args['max-pages'] !== undefined ? Number.parseInt(args['max-pages'], 10) : 25,
    maxDepth: args['max-depth'] !== undefined ? Number.parseInt(args['max-depth'], 10) : 3,
    maxBytes: args['max-bytes'] !== undefined ? Number.parseInt(args['max-bytes'], 10) : undefined,
    respectRobots: !args['ignore-robots'],
  });
  console.log(c.green(`✓ ${res.manifest.pageCount} page(s), ${res.files} body file(s), ${res.manifest.bodyBytes} byte(s)${res.manifest.truncated ? ' (truncated at byte cap)' : ''}`));
  console.log(c.dim(`  ${res.dir}/`));
  console.log(c.dim(`  serve it:  node scripts/mirror.mjs serve ${res.dir}`));
}

async function cmdServe() {
  const dir = args._[1] || usage(2);
  if (!existsSync(resolve(process.cwd(), dir, MIRROR_MANIFEST))) { console.error(c.red(`No ${MIRROR_MANIFEST} in ${dir}`)); exit(1); }
  const manifest = loadMirror(dir);
  const srv = await serveMirror(manifest, { port: args.port !== undefined ? Number.parseInt(args.port, 10) : 0 });
  console.log(c.bold(`\nServing mirror of ${manifest.origin}`));
  console.log(c.green(`  ${srv.url}`) + c.dim(`  (${manifest.pageCount} page(s), loopback only — Ctrl-C to stop)`));
  process.on('SIGINT', async () => { await srv.close(); console.log(c.dim('\nstopped.')); exit(0); });
}

async function cmdScan() {
  const origin = gateOrigin(args._[1] || usage(2));
  let dir = typeof args.dir === 'string' ? args.dir : null;
  if (!dir) {
    console.log(c.bold(`\nCapturing mirror — ${origin}`));
    const cap = await captureMirror(origin, { maxPages: args['max-pages'] !== undefined ? Number.parseInt(args['max-pages'], 10) : 25 });
    dir = cap.dir;
    console.log(c.dim(`  snapshot: ${dir}/ (${cap.manifest.pageCount} page(s))`));
  } else if (!existsSync(resolve(process.cwd(), dir, MIRROR_MANIFEST))) { console.error(c.red(`No ${MIRROR_MANIFEST} in ${dir}`)); exit(1); }

  console.log(c.bold(`\nQuillTest mirror scan — ${origin}`));
  const report = await scanMirror(origin, { dir });
  report.findings = sortFindings(report.findings);
  console.log(c.dim(`stack: ${report.stack.summary}  ·  ${report.findings.length} finding(s) from a snapshot of ${report.mirror.pageCount} page(s)`));
  for (const f of report.findings) {
    const col = SEV_COLOR[f.severity] || ((s) => s);
    console.log(`${col(f.severity.padEnd(8))} ${f.id}  ${f.title}`);
    console.log(c.dim(`         ${f.location}`));
  }

  if (args.analyze) {
    const cfgPath = resolve(process.cwd(), 'quilltest.ai.json');
    if (!existsSync(cfgPath)) console.log(c.yellow('\n--analyze requested but quilltest.ai.json not found; skipping.'));
    else {
      const config = JSON.parse(readFileSync(cfgPath, 'utf8'));
      const chk = validateConfig(config);
      if (!chk.ok) { console.log(c.yellow('\nConfig invalid; skipping analysis:')); console.log(formatValidation(chk)); }
      else {
        const analysis = await analyzeFindings(report.findings, config, { stack: { summary: report.stack.summary, server: report.stack.server, framework: report.stack.framework, cms: report.stack.cms } });
        report.analysis = analysis;
        console.log(c.bold('\nAI analysis') + c.dim(` (${config.analysisMode || 'sequential'} mode)`));
        for (const p of analysis.providers || []) console.log(`  ${p.label}: ${p.ok ? c.green('OK') : c.red('FAILED')}`);
      }
    }
  }

  const outPath = typeof args.out === 'string'
    ? resolve(process.cwd(), args.out)
    : resolve(process.cwd(), dir, 'mirror-scan.json');
  mkdirSync(resolve(outPath, '..'), { recursive: true });
  writeFileSync(outPath, JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
  console.log(c.dim(`\nReport written to ${outPath}`));
  try { createTargetStore().recordScan(origin, { findings: report.findings, reportPath: outPath }); } catch { /* target store is optional */ }
}

try {
  if (args._[0] === 'capture') await cmdCapture();
  else if (args._[0] === 'serve') await cmdServe();
  else if (args._[0] === 'scan') await cmdScan();
  else usage(2);
} catch (e) {
  console.error(c.red('Error: ' + (e?.message || e)));
  exit(1);
}
