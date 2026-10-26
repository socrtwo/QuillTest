/*
 * Anne's Test — regression tests for the second review round (items first reported, then fixed)
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { unifiedDiff, restyleRange, patchPackageJson, patchComposerJson } from '../src/fix/patch.mjs';
import { renderMarkdown, verifyManifest, buildReviewPackage } from '../src/report/render.mjs';
import { dnsFindings, zoneCandidates } from '../src/scan/protocols.mjs';
import { analyzeFindings, ANALYSIS_MAX_TOKENS } from '../src/ai/analyze.mjs';
import { createStore } from '../src/verify/store.mjs';
import { isHostVerified } from '../src/verify/ownership.mjs';
import { observe, runPassiveScan } from '../src/scan/passive.mjs';
import { buildMirrorManifest, mirrorFetchFromManifest } from '../src/scan/mirror.mjs';
import { osvSeverity } from '../src/scan/versions.mjs';

const ROOT = resolve(new URL('..', import.meta.url).pathname);
const mk = (status, headers = {}, body = '', setCookies = []) => { const h = new Headers(headers); h.getSetCookie = () => setCookies; return { status, headers: h, text: async () => body }; };

// ----- patches -----

test('patch: the range operator is preserved and aliases/URLs/compound ranges are skipped, not rewritten', () => {
  assert.equal(restyleRange('^1.12.4', '3.7.1'), '^3.7.1');
  assert.equal(restyleRange('~1.12.4', '3.7.1'), '~3.7.1');
  assert.equal(restyleRange('1.12.4', '3.7.1'), '3.7.1');
  assert.equal(restyleRange('>=1.12.4', '3.7.1'), '>=3.7.1');
  for (const odd of ['npm:jquery@1.12.4', 'https://x/jquery.tgz', 'workspace:*', 'file:../jq', '*', 'latest', '>=1.0 <2.0', '1.x', 'git+https://x/y.git']) assert.equal(restyleRange(odd, '3.7.1'), null, odd);
  const pkg = '{\n  "dependencies": {\n    "jquery": "npm:jquery@1.12.4",\n    "bootstrap": "~4.6.2"\n  }\n}\n';
  const r = patchPackageJson(pkg, [{ component: 'jQuery', recommended: '3.7.1', ecosystem: 'npm' }, { component: 'Bootstrap', recommended: '5.3.3', ecosystem: 'npm' }]);
  assert.deepEqual(r.changes.map((c) => [c.pkg, c.to]), [['bootstrap', '~5.3.3']]);
  assert.ok(r.skipped.some((s) => s.pkg === 'jquery' && /alias, URL or compound/.test(s.reason)), JSON.stringify(r.skipped));
  const composer = patchComposerJson('{\n  "require": {\n    "drupal/core-recommended": "~9.5.0"\n  }\n}\n', [{ component: 'Drupal', recommended: '11.0.0', ecosystem: 'composer' }]);
  assert.equal(JSON.parse(composer.newText).require['drupal/core-recommended'], '~11.0.0');
});

test('unifiedDiff: a final-newline-only change and an empty-file insertion produce git-applicable hunks', () => {
  const d = unifiedDiff('a\nb', 'a\nb\n', { path: 'x.txt' });
  assert.match(d, /-b\n\\ No newline at end of file\n\+b\n/);
  const ins = unifiedDiff('', 'hello\n', { path: 'new.txt' });
  assert.match(ins, /@@ -0,0 \+1,1 @@\n\+hello\n/);
  const del = unifiedDiff('hello\n', '', { path: 'gone.txt' });
  assert.match(del, /@@ -1,1 \+0,0 @@\n-hello\n/);
  const dir = mkdtempSync(join(tmpdir(), 'qt-diff-'));
  execFileSync('git', ['init', '-q'], { cwd: dir });
  writeFileSync(join(dir, 'x.txt'), 'a\nb');
  writeFileSync(join(dir, 'x.patch'), d);
  execFileSync('git', ['apply', '--check', 'x.patch'], { cwd: dir });
  execFileSync('git', ['apply', 'x.patch'], { cwd: dir });
  assert.equal(readFileSync(join(dir, 'x.txt'), 'utf8'), 'a\nb\n');
});

// ----- reports -----

test('Markdown: snippets are fenced with a fence longer than any backtick run they contain', () => {
  const md = renderMarkdown({ origin: 'https://w.test', findings: [{ id: 'F-1', checkId: 'c', title: 'x', severity: 'low', confidence: 'firm', location: 'https://w.test/', evidence: { snippet: 'before\n```\n<script>alert(1)</script>\n```\nafter' }, remediation: 'r' }] });
  assert.match(md, /\n````\nbefore\n```\n<script>alert\(1\)<\/script>\n```\nafter\n````\n/);
});

test('review package: --verify fails on a file present in the package that the manifest does not list', () => {
  const pkg = buildReviewPackage({ origin: 'https://x.test', findings: [] });
  const byName = Object.fromEntries(pkg.files.map((f) => [f.filename, f.contents]));
  const res = verifyManifest(pkg.manifest, (p) => byName[p], { listFiles: () => [...Object.keys(byName), 'fixes/evil.sh'] });
  assert.equal(res.ok, false);
  assert.ok(res.results.some((r) => r.path === 'fixes/evil.sh' && r.reason === 'not in manifest'));
  assert.ok(verifyManifest(pkg.manifest, (p) => byName[p], { listFiles: () => Object.keys(byName) }).ok, 'manifest.json itself is not an extra');
  const dir = mkdtempSync(join(tmpdir(), 'qt-verify-'));
  for (const f of pkg.files) { mkdirSync(join(dir, f.filename, '..'), { recursive: true }); writeFileSync(join(dir, f.filename), f.contents); }
  assert.equal(spawnSync(process.execPath, [join(ROOT, 'scripts/report.mjs'), '--verify', dir], { encoding: 'utf8' }).status, 0);
  mkdirSync(join(dir, 'fixes'), { recursive: true }); writeFileSync(join(dir, 'fixes/evil.sh'), 'rm -rf /');
  const bad = spawnSync(process.execPath, [join(ROOT, 'scripts/report.mjs'), '--verify', dir], { encoding: 'utf8' });
  assert.equal(bad.status, 4);
  assert.match(bad.stdout, /FAILED\s+fixes\/evil\.sh\s+\(not in manifest\)/);
});

// ----- DNS -----

test('DNS: SPF, DMARC and CAA are found at a parent zone of a www host, and a miss names every zone queried', async () => {
  assert.deepEqual(zoneCandidates('www.example.com'), ['www.example.com', 'example.com']);
  assert.deepEqual(zoneCandidates('example.com'), ['example.com']);
  const apexOnly = {
    resolveTxt: async (n) => (n === 'example.com' ? [['v=spf1 -all']] : n === '_dmarc.example.com' ? [['v=DMARC1; p=reject']] : []),
    resolveCaa: async (n) => (n === 'example.com' ? [{ issue: 'letsencrypt.org' }] : []),
  };
  const ok = await dnsFindings('www.example.com', apexOnly);
  assert.deepEqual(ok.map((f) => f.checkId), [], JSON.stringify(ok.map((f) => f.checkId)));
  const weak = await dnsFindings('www.example.com', { ...apexOnly, resolveTxt: async (n) => (n === 'example.com' ? [['v=spf1 +all']] : n === '_dmarc.example.com' ? [['v=DMARC1; p=none']] : []) });
  assert.equal(weak.find((f) => f.checkId === 'dns.spf-weak').evidence.foundAt, 'example.com');
  assert.equal(weak.find((f) => f.checkId === 'dns.dmarc-weak').evidence.foundAt, '_dmarc.example.com');
  const none = await dnsFindings('www.example.com', { resolveTxt: async () => [], resolveCaa: async () => [] });
  assert.deepEqual(none.find((f) => f.checkId === 'dns.spf-missing').evidence.queried, ['www.example.com', 'example.com']);
  assert.match(none.find((f) => f.checkId === 'dns.dmarc-missing').remediation, /_dmarc\.example\.com/);
});

// ----- AI -----

test('AI: the output cap defaults to 8192 and --max-tokens reaches the request', async () => {
  assert.equal(ANALYSIS_MAX_TOKENS, 8192);
  const config = { version: 2, analysisMode: 'sequential', activeProviders: ['openai'], providers: { openai: { providerId: 'openai', base: 'https://api.openai.com/v1', model: 'gpt-5.4-mini', apiKeyEnv: 'OPENAI_API_KEY', apiKey: 'sk-testkey-0001' } } };
  const findings = [{ id: 'F-1', checkId: 'headers.csp', title: 'x', severity: 'low', confidence: 'firm', location: 'https://x/' }];
  const r = await analyzeFindings(findings, config, { dryRun: true, maxTokens: 20000 });
  assert.equal(JSON.parse(r.providers[0].request.init.body).max_completion_tokens, 20000);
  const bad = spawnSync(process.execPath, [join(ROOT, 'scripts/ai-analyze.mjs'), '--findings', join(ROOT, 'examples/findings.sample.json'), '--config', join(ROOT, 'quilltest.ai.example.json'), '--dry-run', '--max-tokens', 'lots'], { encoding: 'utf8' });
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /--max-tokens must be a positive integer/);
});

// ----- stores -----

test('store: a damaged JSON file is reported, not silently treated as empty and overwritten', () => {
  const dir = mkdtempSync(join(tmpdir(), 'qt-store-'));
  const store = createStore(dir);
  store.saveVerified({ origin: 'https://a.test', expires: '2030-01-01T00:00:00Z' });
  writeFileSync(join(dir, 'verified.json'), '{"truncated": [');
  assert.throws(() => store.loadVerified(), /verified\.json is not valid JSON/);
  assert.throws(() => store.saveVerified({ origin: 'https://b.test', expires: '2030-01-01T00:00:00Z' }), /not valid JSON/);
  assert.equal(readFileSync(join(dir, 'verified.json'), 'utf8'), '{"truncated": [', 'the damaged file is left for repair');
});

test('ownership: an IPv6 literal origin authorizes protocol checks on that host', () => {
  const recs = [{ origin: 'https://[2001:db8::1]', expires: '2030-01-01T00:00:00Z' }];
  assert.equal(isHostVerified(recs, '[2001:db8::1]').ok, true);
  assert.equal(isHostVerified(recs, '2001:db8::1').ok, true);
});

// ----- scan plumbing -----

test('observe: an unread redirect body is cancelled so the socket can be reused', async () => {
  let cancelled = 0;
  const fetchImpl = async (url) => (new URL(url).pathname === '/old'
    ? { ...mk(301, { location: '/new' }), body: { cancel: async () => { cancelled++; } } }
    : mk(200, { 'content-type': 'text/html' }, '<html>new</html>'));
  const r = await observe('https://s.test/old', { fetchImpl });
  assert.equal(r.status, 200);
  assert.equal(cancelled, 1);
});

test('fingerprint: a signal seen only on the root page is counted once, not once for root and once for pages[0]', async () => {
  // Angular has a single body signature (jQuery has two, which legitimately match the same tag).
  const home = '<html ng-version="17.0.0"><body><a href="/about">a</a></body></html>';
  const r = await runPassiveScan('https://s.test', {
    crawl: { maxPages: 3, maxDepth: 1, respectRobots: false },
    fetchImpl: async (url) => { const p = new URL(url).pathname; return p === '/' ? mk(200, { 'content-type': 'text/html' }, home) : p === '/about' ? mk(200, { 'content-type': 'text/html' }, '<html>about</html>') : mk(404); },
  });
  const ng = r.stack.signals.find((s) => s.name === 'Angular');
  assert.equal(ng.confidence, 0.4, 'was 0.8 when root and pages[0] (the same response) were both fingerprinted');
});

test('mirror: snapshot cookies are masked with ASCII and the manifest adapter tolerates an unreplayable header', async () => {
  const { manifest } = buildMirrorManifest({ pages: [
    { url: 'https://m.test/', requestedUrl: 'https://m.test/', status: 200, isHtml: true, body: '<html>x</html>', headers: { 'content-type': 'text/html', 'set-cookie': ['sid=SECRETVALUE; Path=/; HttpOnly'], 'x-odd': 'café — 中文' } },
  ], requests: 1 }, {});
  const sc = manifest.pages[0].headers['set-cookie'][0];
  assert.equal(sc, 'sid=***; Path=/; HttpOnly');
  assert.ok(!JSON.stringify(manifest).includes('SECRETVALUE'));
  const fetchImpl = mirrorFetchFromManifest({ ...manifest, origin: 'https://m.test', pages: manifest.pages.map((p) => ({ ...p, body: '<html>x</html>' })) });
  const res = await fetchImpl('https://m.test/');
  assert.equal(res.status, 200);
  assert.deepEqual(res.headers.getSetCookie?.() ?? [res.headers.get('set-cookie')], ['sid=***; Path=/; HttpOnly']);
  assert.equal(res.headers.get('x-odd'), null, 'the non-Latin-1 header was dropped instead of throwing');
});

test('OSV: severity comes from database_specific, never from the CVSS entry type', () => {
  assert.equal(osvSeverity({ database_specific: { severity: 'MODERATE' }, severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N' }] }), 'medium');
  assert.equal(osvSeverity({ database_specific: { severity: 'HIGH' } }), 'high');
  assert.equal(osvSeverity({ severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N' }] }), null);
});
