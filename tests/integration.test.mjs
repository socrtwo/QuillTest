/*
 * QuillTest — end-to-end pipeline integration (offline)
 *
 * Proves the documented pipeline composes: one verified-origin fake site flows
 * through passive scan → fingerprint/EOL → active (safe profile) → fix
 * artifacts → applyable manifest patch → report render → staging mirror
 * capture+scan → findings diff. Unit tests cover each stage; this guards that
 * they chain into coherent output, which is the README's central claim.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runPassiveScan } from '../src/scan/passive.mjs';
import { runActiveScan } from '../src/scan/active.mjs';
import { generateFixes } from '../src/fix/artifacts.mjs';
import { generatePatchForFile } from '../src/fix/patch.mjs';
import { renderHtml, renderMarkdown, diffReports } from '../src/report/render.mjs';
import { captureMirror, scanMirror } from '../src/scan/mirror.mjs';

/** A small, deliberately-imperfect site: old nginx/PHP, missing CSP, jQuery on a CDN, a login form, a redirect param. */
function fakeSite() {
  const H = (o) => { const h = new Headers(o); h.getSetCookie = () => (o && o['set-cookie'] ? [].concat(o['set-cookie']) : []); return h; };
  const mk = (status, headers, body) => ({ status, headers: H(headers), text: async () => body ?? '' });
  const common = { 'content-type': 'text/html', server: 'nginx/1.18.0', 'x-powered-by': 'PHP/7.4.3' };
  const home = '<html><head></head><body>' +
    '<a href="/about">about</a> <a href="/login">login</a> <a href="/search?q=hello">search</a>' +
    '<script src="https://cdn.jsdelivr.net/npm/jquery@1.12.4/dist/jquery.min.js"></script></body></html>';
  const login = '<html><body><form action="/session" method="post"><input name="user"><input type="password" name="pw"></form></body></html>';
  return async (url, init) => {
    const u = new URL(url);
    if (u.protocol === 'http:') return mk(301, { location: 'https://shop.test/' });
    if (u.pathname === '/robots.txt') return mk(404, { 'content-type': 'text/plain' }, 'x');
    if (init && init.method === 'OPTIONS') return mk(204, { allow: 'GET, HEAD, OPTIONS, TRACE' });
    if (u.pathname === '/search') return mk(200, common, `<html><body>Results for ${u.searchParams.get('q') || ''}</body></html>`);
    if (u.pathname === '/' ) return mk(200, { ...common, 'set-cookie': 'PHPSESSID=abc; Path=/' }, home);
    if (u.pathname === '/about') return mk(200, common, '<html><body>about</body></html>');
    if (u.pathname === '/login') return mk(200, common, login);
    return mk(404, { 'content-type': 'text/html' }, 'nf');
  };
}

test('the documented pipeline composes end to end on one verified site', async () => {
  const fetchImpl = fakeSite();
  const origin = 'https://shop.test';

  // 1. passive scan (crawl + checks + fingerprint + EOL/CVE)
  const report = await runPassiveScan(origin, { fetchImpl, crawl: { maxPages: 5, maxDepth: 2, respectRobots: false } });
  report.verification = { method: 'http-file', verifiedAt: '2026-10-25T09:00:00Z', expires: '2026-11-25T09:00:00Z' };
  assert.match(report.stack.summary, /nginx\/1\.18\.0/);
  assert.ok(report.findings.some((f) => /Content-Security-Policy/i.test(f.title)), 'missing CSP found');
  assert.ok(report.findings.some((f) => /jQuery 1\.12\.4/.test(f.title)), 'vulnerable jQuery found');
  assert.ok(report.findings.some((f) => f.checkId === 'cookies.flags'), 'insecure cookie found');

  // 2. active scan (safe profile) over the crawled URLs
  const targets = [origin + '/', ...report.pages.map((p) => p.url)];
  const active = await runActiveScan(origin, { fetchImpl, profile: 'safe-active', targets });
  assert.equal(active.intrusivenessCap, 1);
  active.findings.forEach((f, i) => report.findings.push({ id: `A-${i + 1}`, ...f }));
  assert.ok(report.findings.some((f) => f.checkId === 'active.reflected-input'), 'reflected input found via a benign canary');
  assert.ok(report.findings.some((f) => f.checkId === 'active.http-trace'), 'TRACE flagged from OPTIONS');

  // 3. fix artifacts (headers + cookies + dependency bumps)
  report.fixes = generateFixes(report);
  assert.ok(report.fixes.files.some((f) => f.kind === 'headers'));
  assert.ok(report.fixes.files.some((f) => f.filename === 'quilltest-dependencies.md'));
  assert.ok(report.fixes.dependencies.bumps.some((b) => b.component === 'jQuery'));

  // 4. level-3 applyable patch against a provided manifest
  const patch = generatePatchForFile(report, { filename: 'package.json', contents: '{\n  "dependencies": {\n    "jquery": "^1.12.4"\n  }\n}\n' });
  assert.match(patch.patch, /-    "jquery": "\^1\.12\.4"/);
  assert.match(patch.patch, /\+    "jquery": "\^3\.7\.1"/);

  // 5. report render (self-contained HTML + Markdown)
  const html = renderHtml(report);
  assert.ok(html.startsWith('<!doctype html>'));
  assert.equal((html.match(/<script/gi) || []).length, 0, 'no script tags in the report');
  assert.match(html, /nginx\/1\.18\.0/);
  assert.match(renderMarkdown(report), /## Findings/);

  // 6. staging mirror: capture a snapshot, scan the copy offline, findings name the real origin
  const dir = mkdtempSync(join(tmpdir(), 'qt-int-'));
  await captureMirror(origin, { fetchImpl, outDir: dir, maxPages: 5, maxDepth: 2, respectRobots: false });
  const mirrorReport = await scanMirror(origin, { dir });
  assert.equal(mirrorReport.origin, origin);
  assert.ok(mirrorReport.findings.every((f) => !/127\.0\.0\.1/.test(f.location)), 'no loopback leak');
  assert.ok(mirrorReport.findings.some((f) => /jQuery 1\.12\.4/.test(f.title)), 'component finding survives the mirror');

  // 7. findings diff: the mirror scan vs the live scan (same site → mostly unchanged, no false churn)
  const diff = diffReports(report, mirrorReport);
  assert.equal(diff.sameOrigin, true);
  assert.ok(diff.summary.unchanged > 0, 'shared findings matched across scans');
});
