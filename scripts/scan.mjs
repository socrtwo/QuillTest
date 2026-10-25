#!/usr/bin/env node
/*
 * QuillTest — scan CLI (ownership gate + passive engine + optional AI analysis)
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 *   node scripts/scan.mjs verify issue https://example.com     # get the file to upload (and DNS alternative)
 *   node scripts/scan.mjs verify check https://example.com     # confirm it is in place; unlocks scanning that origin
 *   node scripts/scan.mjs verify list                          # show verified origins and expiry
 *   node scripts/scan.mjs scan https://example.com [--out findings.json] [--analyze] [--mode concurrent] [--no-file-probes]
 *
 * `scan` refuses any origin without a valid, unexpired verification record.
 * There is no flag to bypass that; it is the point of the tool.
 *
 * Output is a JSON report: { origin, startedAt, finishedAt, requests, verification,
 * findings[], observations, analysis? }. Findings are in the shape
 * src/ai/analyze.mjs consumes, each with a concrete remediation.
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { argv, exit } from 'node:process';
import { issueChallenge, verifyChallenge, isOriginVerified, isHostVerified, normalizeOrigin } from '../src/verify/ownership.mjs';
import { createStore } from '../src/verify/store.mjs';
import { runPassiveScan, sortFindings } from '../src/scan/passive.mjs';
import { runProtocolScan } from '../src/scan/protocols.mjs';
import { runActiveScan, SCAN_PROFILES } from '../src/scan/active.mjs';
import { analyzeFindings } from '../src/ai/analyze.mjs';
import { generateFixes, TARGETS } from '../src/fix/artifacts.mjs';
import { renderHtml, renderMarkdown, renderCsv } from '../src/report/render.mjs';
import { validateConfig, formatValidation } from '../src/ai/config-schema.mjs';
import { createTargetStore } from '../src/targets/store.mjs';
import { ANALYSIS_MODES } from '../src/ai/providers.mjs';

const c = {
  bold: (s) => `\x1b[1m${s}\x1b[0m`, dim: (s) => `\x1b[2m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`, red: (s) => `\x1b[31m${s}\x1b[0m`, yellow: (s) => `\x1b[33m${s}\x1b[0m`, cyan: (s) => `\x1b[36m${s}\x1b[0m`,
};
const SEV_COLOR = { critical: c.red, high: c.red, medium: c.yellow, low: c.cyan, info: c.dim };

function parseArgs(args) {
  const out = { _: [] };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (!a.startsWith('--')) { out._.push(a); continue; }
    const k = a.slice(2); const n = args[i + 1];
    if (n === undefined || n.startsWith('--')) out[k] = true; else { out[k] = n; i++; }
  }
  return out;
}

function usage(code = 0) {
  console.log(`${c.bold('QuillTest scan')}

  verify issue <origin>   Issue an ownership challenge; prints the file to upload and a DNS alternative.
  verify check <origin>   Fetch the file (or TXT record) and, if it matches, record the origin as verified.
  verify list             Show verified origins and when each expires.
  scan <origin>           Run the passive checks against a verified origin.
      --out <file>        Write the JSON report (default scans/<host>/<timestamp>.json).
      --analyze           Also run the configured AI providers over the findings (quilltest.ai.json).
      --mode <m>          Override analysis mode: ${ANALYSIS_MODES.join(' | ')}.
      --no-file-probes    Skip the exposed-file probes (.git/HEAD, .env, …).
      --max-pages <n>     Crawl up to n same-origin pages (default 25; 1 = root page only).
      --max-depth <n>     Crawl link depth (default 3).
      --ignore-robots     Do not honor robots.txt Disallow rules (it is your site; default honors them).
      --delay-ms <n>      Pause between requests (default 0).
      --online-cve        Also query OSV.dev for advisories on fingerprinted libraries (off by default; offline otherwise).
      --fixes             Generate ready-to-review fix files (server header block, derived CSP, cookie settings, dependency bumps).
      --target <t>        Force the fix target: nginx | apache | caddy | iis | express | netlify | generic.
      --export <f>        Also write the report as html | md | csv | all, next to the JSON (scripts/report.mjs does more: diff, package).
      --active            Also run the active checks: benign, non-state-changing probes (HTTP methods,
                          open redirect, input reflection). Detection only; implies --profile safe-active.
      --profile <name>    Scan profile / intrusiveness cap: passive (default) | safe-active.
      --max-active-requests <n>  Hard cap on active probe requests (default 60).
      --protocols         Also run the non-HTTP protocol checks against the host (see below).
      --store <dir>       Verification store directory (default scans/verify).
      --ttl-hours <n>     Challenge lifetime for 'verify issue' (default 24).
  protocols <host>        Check the host's other services (TLS, FTP, SMTP, IMAP, POP3, DNS) for
                          misconfigurations. Observation-only: reads banners and capability
                          handshakes, never attempts a login, relay, or zone transfer. Needs a
                          verification record for the host (any origin on it).
      --which <list>      Comma-separated subset: tls,ftp,smtp,imap,pop3,dns (default all).
      --out <file>        Write the JSON report.

An origin is scheme://host[:port]. Each origin (and each port) needs its own verification.`);
  exit(code);
}

const args = parseArgs(argv.slice(2));
if (args.help || !args._.length) usage(args.help ? 0 : 2);
const store = createStore(typeof args.store === 'string' ? resolve(process.cwd(), args.store) : undefined);

async function cmdVerify() {
  const sub = args._[1];
  if (sub === 'list') {
    const recs = store.loadVerified();
    if (!recs.length) { console.log('No verified origins.'); return; }
    const now = new Date();
    for (const r of recs) {
      const expired = Date.parse(r.expires) <= now.getTime();
      console.log(`${expired ? c.red('expired ') : c.green('valid   ')} ${r.origin}  ${c.dim(`via ${r.method}, verified ${r.verifiedAt}, expires ${r.expires}`)}`);
    }
    return;
  }
  const originArg = args._[2];
  if (!originArg || (sub !== 'issue' && sub !== 'check')) usage(2);
  let origin; try { origin = normalizeOrigin(originArg); } catch (e) { console.error(c.red(e.message)); exit(2); }

  if (sub === 'issue') {
    const ttl = args['ttl-hours'] ? Number(args['ttl-hours']) : undefined;
    const ch = issueChallenge(origin, { ttlHours: ttl });
    store.saveChallenge(ch);
    console.log(c.bold(`\nOwnership challenge for ${origin}`));
    console.log(`\n1. Create this file on the site:\n   ${c.cyan(ch.fileUrl)}\n\n   with exactly this content:\n`);
    console.log(ch.fileContents.split('\n').map((l) => '   ' + l).join('\n'));
    console.log(`2. Or, if you cannot place files, add this DNS record:\n   ${c.cyan(ch.dnsRecord.name)}  TXT  "${ch.dnsRecord.value}"\n`);
    console.log(`3. Then run:  ${c.bold(`node scripts/scan.mjs verify check ${origin}`)}`);
    console.log(c.dim(`\nChallenge expires ${ch.expires}. Serve the file as text/plain; it must not redirect to another origin.`));
    return;
  }

  // check
  const ch = store.findChallenge(origin);
  if (!ch) { console.error(c.red(`No pending challenge for ${origin}. Run: verify issue ${origin}`)); exit(1); }
  process.stdout.write(`Verifying ${origin}… `);
  const result = await verifyChallenge(ch);
  if (!result.ok) {
    console.log(c.red('FAILED'));
    for (const a of result.attempts) console.log(`  ${a.method}: ${a.error}`);
    exit(1);
  }
  store.saveVerified(result.record);
  store.removeChallenge(origin);
  console.log(c.green('VERIFIED') + c.dim(` via ${result.record.method}; valid until ${result.record.expires}`));
  for (const w of result.record.details?.warnings || []) console.log(c.yellow('  warning: ' + w));
  console.log(`\nYou can now run:  ${c.bold(`node scripts/scan.mjs scan ${origin}`)}`);
}

async function cmdScan() {
  const originArg = args._[1];
  if (!originArg) usage(2);
  if (args.mode !== undefined && !ANALYSIS_MODES.includes(args.mode)) { console.error(c.red(`--mode must be one of: ${ANALYSIS_MODES.join(', ')}`)); exit(2); }

  // ---- The gate. No override exists. ----
  const gate = isOriginVerified(store.loadVerified(), originArg);
  if (!gate.ok) {
    console.error(c.red('Refusing to scan: ') + gate.error);
    console.error(c.dim('QuillTest only scans origins you have proven you control. See docs/OWNERSHIP-VERIFICATION.md.'));
    exit(3);
  }
  const origin = gate.origin;

  console.log(c.bold(`\nQuillTest passive scan — ${origin}`));
  console.log(c.dim(`ownership verified via ${gate.record.method} on ${gate.record.verifiedAt}`));
  const maxPages = args['max-pages'] !== undefined ? Number.parseInt(args['max-pages'], 10) : 25;
  const maxDepth = args['max-depth'] !== undefined ? Number.parseInt(args['max-depth'], 10) : 3;
  if (!Number.isInteger(maxPages) || maxPages < 1 || !Number.isInteger(maxDepth) || maxDepth < 0) { console.error(c.red('--max-pages must be ≥ 1 and --max-depth ≥ 0')); exit(2); }
  const delayMs = args['delay-ms'] !== undefined ? Number.parseInt(args['delay-ms'], 10) : 0;
  const report = await runPassiveScan(origin, {
    probeSensitiveFiles: !args['no-file-probes'],
    crawl: maxPages > 1 ? { maxPages, maxDepth, respectRobots: !args['ignore-robots'], delayMs: Number.isFinite(delayMs) ? delayMs : 0 } : false,
    onlineCve: Boolean(args['online-cve']),
  });
  report.verification = { method: gate.record.method, verifiedAt: gate.record.verifiedAt, expires: gate.record.expires };

  // Optional: fold in the non-HTTP protocol checks for the same host.
  if (args.protocols) {
    const host = new URL(origin).hostname;
    const proto = await runProtocolScan(host);
    report.protocols = { host, services: proto.services, findings: proto.findings };
    const n = report.findings.length;
    proto.findings.forEach((f, i) => report.findings.push({ id: `P-${String(i + 1).padStart(3, '0')}`, ...f }));
    console.log(c.dim(`protocol checks on ${host}: ${proto.findings.length} finding(s) across ${proto.services.filter((s) => s.present).length} service(s)`));
  }

  // Optional: active checks (benign, non-state-changing; ownership already verified above).
  const profileName = typeof args.profile === 'string' ? args.profile : (args.active ? 'safe-active' : 'passive');
  if (!SCAN_PROFILES[profileName]) { console.error(c.red(`--profile must be one of: ${Object.keys(SCAN_PROFILES).join(', ')}`)); exit(2); }
  if (args.active || (profileName !== 'passive')) {
    const targets = [origin + '/', ...(report.pages || []).map((p) => p.url).filter(Boolean)];
    const maxActive = args['max-active-requests'] !== undefined ? Number.parseInt(args['max-active-requests'], 10) : 60;
    const active = await runActiveScan(origin, { targets, profile: profileName, maxRequests: Number.isInteger(maxActive) ? maxActive : 60, delayMs: Number.isFinite(delayMs) ? delayMs : 0 });
    report.active = { profile: active.profile, intrusivenessCap: active.intrusivenessCap, requests: active.requests, targetsProbed: active.targetsProbed };
    active.findings.forEach((f, i) => report.findings.push({ id: `A-${String(i + 1).padStart(3, '0')}`, ...f }));
    console.log(c.dim(`active checks (${active.profile}): ${active.findings.length} finding(s) from ${active.requests} probe(s) across ${active.targetsProbed} URL(s)`));
  }

  report.findings = sortFindings(report.findings);

  console.log(c.dim(`stack: ${report.stack.summary}`));
  const cr = report.crawl;
  console.log(c.dim(`${report.requests} requests · ${cr.pages} page(s) crawled${cr.skipped ? ` (skipped: ${cr.skipped.robots} robots, ${cr.skipped.external} external, ${cr.skipped.cap} over cap)` : ''} · ${report.findings.length} finding(s)\n`));
  if (report.observations.root?.error) console.log(c.red(`Root fetch failed: ${report.observations.root.error}\n`));
  for (const f of report.findings) {
    const col = SEV_COLOR[f.severity] || ((s) => s);
    console.log(`${col(f.severity.padEnd(8))} ${f.id}  ${f.title}`);
    console.log(c.dim(`         ${f.location}${f.evidence?.affectedPages ? `  (+${f.evidence.affectedPages - 1} more page${f.evidence.affectedPages > 2 ? 's' : ''})` : ''}`));
    console.log(c.dim(`         fix: ${f.remediation.split('\n')[0]}`));
  }

  if (args.fixes) {
    if (args.target && !TARGETS.includes(args.target)) { console.error(c.red(`--target must be one of: ${TARGETS.join(', ')}`)); exit(2); }
    const fx = generateFixes(report, { target: typeof args.target === 'string' ? args.target : undefined });
    report.fixes = fx;
    console.log(c.bold(`\nFix artifacts`) + c.dim(` — target: ${fx.target}`));
    for (const f of fx.files) console.log(`  • ${f.filename}  ${c.dim('[' + f.kind + (f.target !== fx.target ? ' · ' + f.target : '') + ']')}`);
    if (!fx.files.length) console.log(c.dim('  (no header/cookie/component findings → nothing to generate)'));
    for (const n of fx.notes) console.log(c.dim('  - ' + n));
    if (fx.coverage.manual.length) console.log(c.dim(`  ${fx.coverage.manual.length} finding(s) need a manual change; see their remediation text above.`));
  }

  if (args.analyze) {
    const cfgPath = resolve(process.cwd(), 'quilltest.ai.json');
    if (!existsSync(cfgPath)) {
      console.log(c.yellow('\n--analyze requested but quilltest.ai.json not found; run scripts/ai-setup-wizard.mjs first. Skipping analysis.'));
    } else {
      const config = JSON.parse(readFileSync(cfgPath, 'utf8'));
      const cfgCheck = validateConfig(config);
      if (!cfgCheck.ok) {
        console.log(c.yellow('\n--analyze requested but quilltest.ai.json is not valid; skipping analysis:'));
        console.log(formatValidation(cfgCheck));
        report.analysis = { error: 'config invalid', errors: cfgCheck.errors };
      } else {
      for (const w of cfgCheck.warnings) console.log(c.dim(`config warning: ${w}`));
      console.log(c.bold('\nAI analysis'));
      const analysis = await analyzeFindings(report.findings, config, {
        mode: typeof args.mode === 'string' ? args.mode : undefined,
        stack: { summary: report.stack.summary, server: report.stack.server, framework: report.stack.framework, cms: report.stack.cms },
      });
      report.analysis = analysis;
      if (analysis.error) console.log(c.red(analysis.error));
      for (const p of analysis.providers || []) {
        console.log(`  ${p.label}: ${p.ok ? (p.parsed ? c.green('OK') : c.yellow('OK (unparsed)')) : c.red('FAILED')}${p.ms ? c.dim(` ${p.ms}ms`) : ''}${p.filtered ? c.yellow(`  [${p.removedLines} payload-like line(s) removed]`) : ''}`);
        if (!p.ok) console.log('    ' + p.error);
        else if (p.parsed?.summary) console.log('    ' + p.parsed.summary);
      }
      const cons = Object.entries(analysis.consensus || {});
      if (cons.length) {
        console.log('  consensus:');
        for (const [id, v] of cons) console.log(`    ${id}: ${v.verdict} (${v.reviewers})${v.meanAttackerPriority != null ? `  attacker-priority≈${v.meanAttackerPriority.toFixed(1)}` : ''}`);
      }
      }
    }
  }

  const host = new URL(origin).host.replace(/[^a-z0-9.-]/gi, '_');
  const outPath = typeof args.out === 'string'
    ? resolve(process.cwd(), args.out)
    : resolve(process.cwd(), 'scans', host, `${report.startedAt.replace(/[:.]/g, '-')}.json`);
  mkdirSync(resolve(outPath, '..'), { recursive: true });
  writeFileSync(outPath, JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
  console.log(c.dim(`\nReport written to ${outPath}`));
  try { const t = createTargetStore().recordScan(origin, { findings: report.findings, reportPath: outPath }); if (t) console.log(c.dim(`target ${origin} updated with this scan's result`)); } catch { /* target store is optional */ }
  if (report.fixes?.files?.length) {
    const fixDir = outPath.replace(/\.json$/, '') + '-fixes';
    mkdirSync(fixDir, { recursive: true });
    for (const f of report.fixes.files) writeFileSync(resolve(fixDir, f.filename), f.contents, { mode: 0o600 });
    console.log(c.dim(`Fix files written to ${fixDir}/`));
  }
  if (args.export) {
    const fmt = typeof args.export === 'string' ? args.export : 'html';
    const EXPORTS = { html: renderHtml, md: renderMarkdown, csv: renderCsv };
    const wanted = fmt === 'all' ? Object.keys(EXPORTS) : [fmt];
    if (!wanted.every((w) => EXPORTS[w])) { console.error(c.red('--export must be one of: html, md, csv, all')); exit(2); }
    for (const w of wanted) {
      const p = outPath.replace(/\.json$/, '') + '.' + w;
      writeFileSync(p, EXPORTS[w](report), { mode: 0o600 });
      console.log(c.dim(`Report exported to ${p}`));
    }
  }
}

async function cmdProtocols() {
  const hostArg = args._[1];
  if (!hostArg) usage(2);
  // Accept a bare host or a URL; reduce a URL to its hostname.
  let host = hostArg;
  try { if (/:\/\//.test(hostArg)) host = new URL(hostArg).hostname; } catch { /* use as-is */ }

  const gate = isHostVerified(store.loadVerified(), host);
  if (!gate.ok) {
    console.error(c.red('Refusing to check: ') + gate.error);
    console.error(c.dim('QuillTest only checks hosts you have proven you control. See docs/OWNERSHIP-VERIFICATION.md.'));
    exit(3);
  }

  const which = typeof args.which === 'string' ? args.which.split(',').map((s) => s.trim()).filter(Boolean) : undefined;
  console.log(c.bold(`\nQuillTest protocol checks — ${gate.host}`));
  console.log(c.dim(`ownership verified via ${gate.record.method} on ${gate.record.verifiedAt}`));
  const report = await runProtocolScan(gate.host, { which });
  const present = report.services.filter((s) => s.present);
  console.log(c.dim(`services present: ${present.map((s) => `${s.service}:${s.port}`).join(', ') || '(none reachable)'} · ${report.findings.length} finding(s)\n`));
  for (const f of sortFindings(report.findings)) {
    const col = SEV_COLOR[f.severity] || ((s) => s);
    console.log(`${col(f.severity.padEnd(8))} ${f.checkId}  ${f.title}`);
    console.log(c.dim(`         ${f.location}`));
    console.log(c.dim(`         fix: ${f.remediation.split('\n')[0]}`));
  }

  const outPath = typeof args.out === 'string'
    ? resolve(process.cwd(), args.out)
    : resolve(process.cwd(), 'scans', gate.host.replace(/[^a-z0-9.-]/gi, '_'), `protocols-${report.startedAt.replace(/[:.]/g, '-')}.json`);
  mkdirSync(resolve(outPath, '..'), { recursive: true });
  writeFileSync(outPath, JSON.stringify(report, null, 2) + '\n', { mode: 0o600 });
  console.log(c.dim(`\nReport written to ${outPath}`));
}

try {
  if (args._[0] === 'verify') await cmdVerify();
  else if (args._[0] === 'scan') await cmdScan();
  else if (args._[0] === 'protocols') await cmdProtocols();
  else usage(2);
} catch (e) {
  console.error(c.red('Error: ' + (e?.message || e)));
  exit(1);
}
