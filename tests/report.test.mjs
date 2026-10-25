/*
 * QuillTest — report rendering, diff and review-package tests (offline)
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  summarize, findingKey, diffReports, renderMarkdown, renderHtml, renderCsv, buildReviewPackage, verifyManifest, escapeHtml, sha256, sortFindings, CSV_COLUMNS,
} from '../src/report/render.mjs';
import { generateFixes } from '../src/fix/artifacts.mjs';

const HOSTILE = '<script>alert(1)</script>';
const F = (id, checkId, title, severity, extra = {}) => ({
  id, checkId, title, severity, confidence: 'confirmed', cwe: 'CWE-693', owasp: 'A05:2021 Security Misconfiguration',
  location: 'https://w.test/', evidence: { snippet: `seen: ${title}` }, remediation: `Fix ${title}`, ...extra,
});
function report(overrides = {}) {
  return {
    origin: 'https://w.test', startedAt: '2026-10-25T10:00:00.000Z', finishedAt: '2026-10-25T10:00:09.000Z', requests: 31,
    verification: { method: 'http-file', verifiedAt: '2026-10-24T09:00:00.000Z', expires: '2026-11-24T09:00:00.000Z' },
    stack: { summary: `nginx/1.18.0 · PHP 7.4.3 · ${HOSTILE}`, server: { name: 'nginx' }, framework: [], cms: [] },
    crawl: { pages: 12, skipped: null, external: [], robots: null },
    assets: { scriptOrigins: ['https://cdn.test'], styleOrigins: [], frameOrigins: [], inlineScripts: false, inlineStyles: false, eventHandlers: false },
    findings: [
      F('F-001', 'headers.csp', 'Content-Security-Policy header missing', 'medium', { evidence: { snippet: 'none on 12 pages', affectedPages: 12, pages: ['https://w.test/', 'https://w.test/a'] } }),
      F('F-002', 'cookies.flags', `Session cookie without Secure ${HOSTILE}`, 'high', { location: 'https://w.test/login', evidence: { snippet: 'PHPSESSID lacks Secure', responseHeaders: { 'set-cookie': `PHPSESSID=***; Path=/ ${HOSTILE}` } } }),
      F('F-003', 'disclosure.server-banner', 'Server version disclosed | pipe, "quote", comma', 'low', { confidence: 'firm', remediation: 'server_tokens off;\nsecond line' }),
    ],
    observations: {},
    ...overrides,
  };
}

test('summarize counts by severity, confidence and category and reads optional sections', () => {
  const s = summarize(report());
  assert.equal(s.total, 3);
  assert.deepEqual(s.bySeverity, { critical: 0, high: 1, medium: 1, low: 1, info: 0 });
  assert.deepEqual(s.byConfidence, { confirmed: 2, firm: 1, tentative: 0 });
  assert.equal(s.byCategory['A05:2021 Security Misconfiguration'], 3);
  assert.equal(s.highest, 'high');
  assert.equal(s.pages, 12);
  assert.equal(s.verification.method, 'http-file');
  assert.equal(s.analysis, null);
  const withAi = summarize(report({ analysis: { providers: [{ label: 'A', ok: true }, { label: 'B', ok: false }], consensus: { 'F-001': { verdict: 'real' }, 'F-002': { verdict: 'split' }, 'F-003': { verdict: 'unreviewed' } } } }));
  assert.deepEqual(withAi.analysis.verdicts, { real: 1, 'false-positive': 0, split: 1, unreviewed: 1 });
  assert.deepEqual(withAi.analysis.providers, [{ label: 'A', ok: true }, { label: 'B', ok: false }]);
  assert.equal(summarize({}).total, 0);
});

test('findingKey ignores positional ids and the location of site-wide findings', () => {
  const a = F('F-001', 'headers.csp', 'CSP missing', 'medium', { evidence: { affectedPages: 5 }, location: 'https://w.test/' });
  const b = F('F-009', 'headers.csp', 'CSP missing', 'medium', { evidence: { affectedPages: 3 }, location: 'https://w.test/other' });
  assert.equal(findingKey(a), findingKey(b));
  const c = F('F-001', 'cookies.flags', 'x', 'high', { location: 'https://w.test/login/' });
  const d = F('F-002', 'cookies.flags', 'x', 'high', { location: 'https://w.test/login' });
  assert.equal(findingKey(c), findingKey(d), 'trailing slash is not a difference');
  const e = F('F-001', 'cookies.flags', 'x', 'high', { location: 'https://w.test/admin' });
  assert.notEqual(findingKey(c), findingKey(e), 'page-scoped findings keep their page');
});

test('diffReports classifies new, resolved, changed and unchanged, independent of ids and order', () => {
  const before = report();
  const after = report({ findings: [
    F('F-010', 'cookies.flags', `Session cookie without Secure ${HOSTILE}`, 'high', { location: 'https://w.test/login' }), // unchanged
    F('F-011', 'headers.csp', 'Content-Security-Policy header missing', 'high', { evidence: { affectedPages: 14 } }),      // severity + pages changed
    F('F-012', 'content.mixed', 'Mixed content', 'medium'),                                                                  // new
  ] });
  const d = diffReports(before, after);
  assert.deepEqual(d.summary, { new: 1, resolved: 1, changed: 1, unchanged: 1 });
  assert.equal(d.new[0].checkId, 'content.mixed');
  assert.equal(d.resolved[0].checkId, 'disclosure.server-banner');
  assert.deepEqual(d.changed[0].what, ['severity', 'pages']);
  assert.equal(d.changed[0].before.severity, 'medium'); assert.equal(d.changed[0].after.severity, 'high');
  assert.equal(d.sameOrigin, true);
  assert.equal(diffReports(before, { ...after, origin: 'https://other.test' }).sameOrigin, false);
  assert.deepEqual(diffReports({}, {}).summary, { new: 0, resolved: 0, changed: 0, unchanged: 0 });
});

test('renderCsv quotes commas, quotes and newlines and orders by severity', () => {
  const csv = renderCsv(report());
  const lines = csv.split('\r\n').filter(Boolean);
  assert.equal(lines[0], CSV_COLUMNS.join(','));
  assert.equal(lines.length, 4);
  assert.ok(lines[1].startsWith('F-002,high,'), 'high first');
  assert.ok(lines[3].includes('"Server version disclosed | pipe, ""quote"", comma"'));
  assert.ok(lines[3].includes('"server_tokens off;\nsecond line"'), 'newline kept inside quotes');
  assert.ok(lines[2].includes(',12,'), 'affectedPages column');
});

test('renderMarkdown has the summary table, findings table, per-finding sections and escapes pipes', () => {
  const md = renderMarkdown(report(), { diff: diffReports(report(), report()) });
  assert.match(md, /^# QuillTest report — https:\/\/w\.test/m);
  assert.match(md, /\| Findings \| \*\*3\*\* — 1 high, 1 medium, 1 low \|/);
  assert.match(md, /\| Ownership \| verified via http-file/);
  assert.match(md, /^\| F-003 \| low \| firm \| Server version disclosed \\\| pipe, "quote", comma \| https:\/\/w\.test\/ \|$/m);
  assert.match(md, /^\| F-001 \| medium \| confirmed \| Content-Security-Policy header missing \| https:\/\/w\.test\/ \(\+11\) \|$/m);
  assert.match(md, /### F-002 · Session cookie without Secure <script>alert\(1\)<\/script>/, 'Markdown keeps text verbatim');
  assert.match(md, /> Affected pages: 12 \(e\.g\. https:\/\/w\.test\/, https:\/\/w\.test\/a\)/);
  assert.match(md, /```json\n\{\n  "responseHeaders"/, 'structured evidence as a JSON block');
  assert.match(md, /\*\*Fix\*\*\n\nserver_tokens off;\nsecond line/);
  assert.match(md, /## Changes since previous scan[\s\S]*\| 0 \| 0 \| 0 \| 3 \|/);
  const bare = renderMarkdown(report(), { includeEvidence: false });
  assert.ok(!/\*\*Evidence\*\*/.test(bare));
  assert.match(renderMarkdown({ findings: [] }), /No findings\./);
});

test('renderHtml is self-contained, script-free and escapes everything from the target', () => {
  const r = report({
    fixes: generateFixes(report()),
    analysis: { providers: [{ label: 'Anthropic', ok: true, parsed: { summary: `Looks bad ${HOSTILE}` } }], consensus: { 'F-002': { verdict: 'real', reviewers: 1, meanAttackerPriority: 1 } } },
    protocols: { host: 'w.test', services: [{ service: 'smtp', port: 25, present: true, banner: `220 mail ${HOSTILE}` }, { service: 'ftp', port: 21, present: false, error: 'ECONNREFUSED' }] },
  });
  const html = renderHtml(r, { diff: diffReports(report({ findings: [] }), r) });
  assert.ok(html.startsWith('<!doctype html>'));
  assert.equal((html.match(/<script/gi) || []).length, 0, 'no script tags at all, even though the input contained many');
  assert.ok(!/\bsrc\s*=|<link\b|@import|url\(/i.test(html), 'no external resources');
  assert.match(html, /<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">/);
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(html, /<title>QuillTest report — https:\/\/w\.test<\/title>/);
  for (const id of ['F-001', 'F-002', 'F-003']) assert.match(html, new RegExp(`<section class="finding" id="${id}">`));
  assert.match(html, /<a href="#F-002">F-002<\/a>/);
  assert.match(html, /<span class="sev sev-high">high<\/span>/);
  assert.match(html, /AI consensus: real \(1 reviewer\(s\), attacker priority ≈ 1\.0\)/);
  assert.match(html, /<h2>Generated fix artifacts<\/h2>[\s\S]*quilltest-security-headers\.nginx\.conf/);
  assert.match(html, /<h2>Services checked<\/h2>[\s\S]*<td>smtp<\/td><td>25<\/td><td>yes<\/td>/);
  assert.match(html, /<h2>Changes since previous scan<\/h2>[\s\S]*<b>3<\/b>new/);
  assert.match(html, /server_tokens off;<br>second line/);
  const trimmed = renderHtml(r, { includeFixes: false, includeAnalysis: false, includeEvidence: false });
  assert.ok(!/Generated fix artifacts|AI review|Evidence detail/.test(trimmed));
  assert.equal(escapeHtml(`a&b<c>"d'`), 'a&amp;b&lt;c&gt;&quot;d&#39;');
});

test('buildReviewPackage bundles every format plus fixes with a manifest that verifyManifest accepts', () => {
  const r = report({ fixes: generateFixes(report()) });
  const prev = report({ findings: report().findings.slice(0, 2) });
  const { files, manifest } = buildReviewPackage(r, { diff: diffReports(prev, r), previousReport: prev, now: new Date('2026-10-25T12:00:00Z') });
  const names = files.map((f) => f.filename);
  for (const n of ['report.json', 'report.html', 'report.md', 'findings.csv', 'diff.json', 'previous-report.json', 'fixes/fixes.json', 'README.txt', 'manifest.json']) assert.ok(names.includes(n), n);
  assert.ok(names.includes('fixes/quilltest-security-headers.nginx.conf'));
  assert.equal(manifest.generatedAt, '2026-10-25T12:00:00.000Z');
  assert.equal(manifest.files.length, files.length - 1, 'manifest lists every file but itself');
  const byName = Object.fromEntries(files.map((f) => [f.filename, f.contents]));
  assert.ok(verifyManifest(manifest, (p) => byName[p]).ok);
  assert.equal(manifest.files.find((f) => f.path === 'report.json').sha256, sha256(byName['report.json']));
  const tampered = verifyManifest(manifest, (p) => (p === 'report.md' ? byName[p] + 'x' : p === 'findings.csv' ? null : byName[p]));
  assert.equal(tampered.ok, false);
  assert.deepEqual(tampered.results.filter((x) => !x.ok).map((x) => [x.path, x.reason]), [['report.md', 'hash mismatch'], ['findings.csv', 'missing']]);
  assert.match(byName['README.txt'], /Findings: 3 \(1 high, 1 medium, 1 low\)/);
  const minimal = buildReviewPackage({ origin: 'https://m.test', findings: [] });
  assert.ok(!minimal.files.some((f) => f.filename.startsWith('fixes/')) && !minimal.files.some((f) => f.filename === 'diff.json'));
});

test('reports surface active-scan metadata when present', () => {
  const r = report({ active: { profile: 'safe-active', intrusivenessCap: 1, requests: 7, targetsProbed: 3 } });
  const s = summarize(r);
  assert.deepEqual(s.activeScan, { profile: 'safe-active', requests: 7, targetsProbed: 3 });
  assert.match(renderMarkdown(r), /active profile: safe-active \(7 probe\(s\)\)/);
  assert.match(renderHtml(r), /<th>Active scan<\/th><td>profile safe-active, 7 probe\(s\) across 3 URL\(s\)<\/td>/);
  assert.equal(summarize(report()).activeScan, null, 'absent when no active scan ran');
});

test('sortFindings orders by severity, then confidence, then id', () => {
  const out = sortFindings([
    { id: 'F-003', severity: 'low', confidence: 'firm' }, { id: 'F-002', severity: 'high', confidence: 'tentative' },
    { id: 'F-001', severity: 'high', confidence: 'confirmed' }, { id: 'F-004', severity: 'critical', confidence: 'firm' }, { id: 'F-000', severity: 'high', confidence: 'confirmed' },
  ]).map((f) => f.id);
  assert.deepEqual(out, ['F-004', 'F-000', 'F-001', 'F-002', 'F-003']);
});

test('CLI: renders, diffs, packages and verifies from files; refuses non-reports', () => {
  const dir = mkdtempSync(join(tmpdir(), 'qt-report-'));
  const cur = join(dir, 'cur.json'), prev = join(dir, 'prev.json');
  writeFileSync(cur, JSON.stringify(report({ fixes: generateFixes(report()) })));
  writeFileSync(prev, JSON.stringify(report({ findings: report().findings.slice(1) })));
  const run = (...a) => execFileSync(process.execPath, ['scripts/report.mjs', ...a], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });

  let out = run('--report', cur);
  assert.match(out, /3 finding\(s\) \(1 high, 1 medium, 1 low\)/);
  assert.ok(existsSync(join(dir, 'cur.html')), 'default: html next to the report');

  out = run('--report', cur, '--format', 'all', '--out', join(dir, 'all') + '/', '--diff', prev);
  assert.match(out, /diff: \+1 new, −0 resolved, 0 changed/);
  assert.deepEqual(readdirSync(join(dir, 'all')).sort(), ['cur.csv', 'cur.diff.json', 'cur.html', 'cur.md']);
  assert.match(readFileSync(join(dir, 'all', 'cur.md'), 'utf8'), /## Changes since previous scan/);
  assert.equal(JSON.parse(readFileSync(join(dir, 'all', 'cur.diff.json'), 'utf8')).summary.new, 1);

  run('--report', cur, '--format', 'md', '--out', join(dir, 'named.md'));
  assert.ok(existsSync(join(dir, 'named.md')));

  out = run('--report', cur, '--package', join(dir, 'pkg'), '--diff', prev);
  assert.match(out, /Review package: \d+ file\(s\)/);
  assert.ok(existsSync(join(dir, 'pkg', 'fixes', 'quilltest-security-headers.nginx.conf')));
  assert.ok(existsSync(join(dir, 'pkg', 'previous-report.json')));
  out = run('--verify', join(dir, 'pkg'));
  assert.match(out, /Package intact/);
  writeFileSync(join(dir, 'pkg', 'report.md'), 'tampered');
  assert.throws(() => run('--verify', join(dir, 'pkg')), (e) => e.status === 4 && /hash mismatch/.test(e.stdout));

  writeFileSync(join(dir, 'notareport.json'), '{"hello":1}');
  assert.throws(() => run('--report', join(dir, 'notareport.json')), (e) => e.status === 1 && /no findings\[\]/.test(e.stderr));
  assert.throws(() => run('--report', cur, '--format', 'json'), (e) => e.status === 2 && /pass --diff/.test(e.stderr));
});
