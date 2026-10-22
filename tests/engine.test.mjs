/*
 * QuillTest — M2 passive engine: HTML extraction, cookies, findings model, crawler, checks, orchestrator
 * Run: npm test
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { extractPage, parseAttributes, resolveUrl, inlineScripts } from '../src/crawl/html.mjs';
import { parseSetCookie, looksLikeSession } from '../src/crawl/cookies.mjs';
import { Crawler } from '../src/crawl/crawler.mjs';
import { createFinding, FindingSet, diffFindings, redactHeader, redactUrl, redactText, SEVERITIES, OWASP_2021, CWE } from '../src/findings/model.mjs';
import { exportFindings, toSarif } from '../src/findings/export.mjs';
import { allChecks, getCheck, describeCheck, CATEGORIES, defineCheck } from '../src/checks/index.mjs';
import { parseCsp, cspWeaknesses } from '../src/checks/passive/headers.mjs';
import { matchKnownVulnerable, KNOWN_VULNERABLE } from '../src/checks/passive/components.mjs';
import { SENSITIVE_PATHS } from '../src/checks/passive/disclosure.mjs';
import { compareVersions, versionBelow } from '../src/checks/version.mjs';
import { runScan, planChecks, PROFILES, assertScanPermitted } from '../src/scan/orchestrator.mjs';
import { ScanStore, DEFAULT_SETTINGS } from '../src/scan/store.mjs';
import { createContext, exec } from '../src/commands/index.mjs';
import { VerificationRequiredError } from '../src/verify/store.mjs';
import { AuthorizationRequiredError } from '../src/targets/store.mjs';
import { startServer, badSiteHandler, goodSiteHandler } from './helpers/badsite.mjs';

// ----- HTML / cookies -------------------------------------------------------------------------

test('extractPage finds links, assets, forms, meta and resolves against <base>', () => {
  const html = `<!doctype html><html><head><base href="/sub/"><title> T &amp; T </title><meta name="generator" content="WordPress 6.2"><meta http-equiv="refresh" content="5; url=/next">
    <link rel="stylesheet" href="s.css" integrity="sha384-x"><script src="a.js" integrity="sha384-y" crossorigin="anonymous"></script><script>var i=1;</script></head>
    <body><a href="page.html#frag">p</a><a href="mailto:x@y">m</a><a href="javascript:void(0)">j</a><a href="https://other.example/">o</a>
    <img src="img.png"><iframe src="//cdn.example/f"></iframe>
    <form action="post.php" method="POST"><input name="user"><input type="password" name="pw"><select name="s"></select><textarea name="t"></textarea></form>
    <form><input name="q"></form></body></html>`;
  const d = extractPage(html, 'https://site.example/dir/index.html');
  assert.equal(d.title, 'T & T');
  assert.equal(d.meta.generator, 'WordPress 6.2');
  assert.equal(d.metaRefresh, 'https://site.example/next');
  assert.ok(d.links.includes('https://site.example/sub/page.html'), d.links);
  assert.ok(d.links.includes('https://other.example/'));
  assert.ok(d.links.includes('https://site.example/next'));
  assert.ok(!d.links.some((l) => /mailto|javascript/.test(l)));
  assert.deepEqual(d.styles, [{ url: 'https://site.example/sub/s.css', integrity: 'sha384-x', crossorigin: undefined }]);
  assert.equal(d.scripts.length, 2);
  assert.equal(d.scripts[0].url, 'https://site.example/sub/a.js');
  assert.equal(d.scripts[1].inline, true);
  assert.deepEqual(d.images, ['https://site.example/sub/img.png']);
  assert.deepEqual(d.frames, ['https://cdn.example/f']);
  assert.equal(d.forms.length, 2);
  assert.equal(d.forms[0].action, 'https://site.example/sub/post.php');
  assert.equal(d.forms[0].method, 'post');
  assert.deepEqual(d.forms[0].inputs.map((i) => i.type), ['text', 'password', 'select', 'textarea']);
  assert.equal(d.forms[1].action, 'https://site.example/sub/', 'form without action posts to the page');
  assert.deepEqual(inlineScripts(html), ['var i=1;']);
  assert.deepEqual(parseAttributes(`a="1" b='2' c=3 d`), { a: '1', b: '2', c: '3', d: '' });
  assert.equal(resolveUrl('data:text/html,x', 'https://a'), null);
  assert.equal(resolveUrl('ftp://a/b', 'https://a'), null);
});

test('parseSetCookie reads attributes; looksLikeSession recognises session names and opaque values', () => {
  const c = parseSetCookie('PHPSESSID=abc; Path=/; Domain=.Example.com; Secure; HttpOnly; SameSite=lax; Max-Age=60');
  assert.deepEqual([c.name, c.value, c.path, c.domain, c.secure, c.httpOnly, c.sameSite, c.maxAge], ['PHPSESSID', 'abc', '/', 'example.com', true, true, 'Lax', 60]);
  assert.equal(looksLikeSession(c), true);
  assert.equal(looksLikeSession(parseSetCookie('theme=dark; Expires=Wed, 21 Oct 2026 07:28:00 GMT')), false);
  assert.equal(looksLikeSession(parseSetCookie('x=' + 'Ab1'.repeat(10))), true, 'opaque high-entropy value without expiry');
  assert.equal(parseSetCookie('flag; SameSite').sameSite, 'None');
});

// ----- findings model ----------------------------------------------------------------------

test('createFinding validates, maps standards, redacts evidence, and signatures ignore the query string', () => {
  const f = createFinding({ checkId: 'headers.csp', title: 'x', severity: 'medium', confidence: 'firm', origin: 'https://a.example', url: 'https://a.example/p?token=SECRET123&x=1', key: 'missing', cwe: [693], owasp: 'A05', evidence: { headers: { 'set-cookie': ['sid=abc; Path=/', 'b=2'], authorization: 'Bearer xyz', server: 'nginx' }, snippet: 'Authorization: Bearer AAAABBBBCCCCDDDDEEEEFFFF0000111122223333 ok', request: { url: 'https://a.example/?api_key=k1', headers: { cookie: 'a=b' } } } }, { now: new Date('2026-10-22T14:00:00Z') });
  assert.equal(f.url, 'https://a.example/p?token=%3Credacted%3E&x=1');
  assert.deepEqual(f.evidence.headers['set-cookie'], ['sid=<redacted>; Path=/', 'b=<redacted>']);
  assert.equal(f.evidence.headers.authorization, '<redacted>');
  assert.equal(f.evidence.headers.server, 'nginx');
  assert.match(f.evidence.snippet, /Bearer <redacted>/);
  assert.ok(!/AAAABBBB/.test(f.evidence.snippet));
  assert.equal(f.evidence.request.headers.cookie, '<redacted>');
  assert.match(f.evidence.request.url, /api_key=%3Credacted%3E/);
  assert.deepEqual(f.standards, { cwe: [693], owasp: 'A05', asvs: [] });
  assert.equal(f.status, 'open');
  assert.equal(f.foundAt, '2026-10-22T14:00:00Z');
  const g = createFinding({ checkId: 'headers.csp', title: 'x', severity: 'low', confidence: 'firm', origin: 'https://a.example', url: 'https://a.example/p?other=2', key: 'missing' });
  assert.equal(g.signature, f.signature, 'same check+origin+path+key → same signature');
  assert.notEqual(createFinding({ checkId: 'headers.csp', title: 'x', severity: 'low', confidence: 'firm', origin: 'https://a.example', url: 'https://a.example/q', key: 'missing' }).signature, f.signature);
  assert.throws(() => createFinding({ checkId: 'x', title: 'x', severity: 'huge', confidence: 'firm', origin: 'o', url: 'u' }), /Unknown severity/);
  assert.throws(() => createFinding({ checkId: 'x', title: 'x', severity: 'low', confidence: 'firm', origin: 'o', url: 'u', owasp: 'A99' }), /Unknown OWASP/);
  assert.equal(redactHeader('Set-Cookie', 'a=b; Secure'), 'a=<redacted>; Secure');
  assert.equal(redactUrl('https://u:p@h/x?password=1'), 'https://h/x?password=%3Credacted%3E');
  assert.equal(redactText('plain words here'), 'plain words here');
});

test('FindingSet dedupes by signature keeping the worst severity, filters and sorts, summarises, diffs', () => {
  const mk = (o) => createFinding({ checkId: 'c.a', title: 't', severity: 'low', confidence: 'firm', origin: 'https://a.example', url: 'https://a.example/', ...o });
  const set = new FindingSet();
  set.add(mk({ key: '1' }));
  const merged = set.add(mk({ key: '1', severity: 'high', confidence: 'confirmed' }));
  assert.equal(set.size, 1);
  assert.equal(merged.severity, 'high');
  assert.equal(merged.confidence, 'confirmed');
  assert.equal(merged.occurrences, 2);
  set.add(mk({ key: '2', severity: 'critical' }));
  set.add(mk({ key: '3', severity: 'informational', checkId: 'd.b' }));
  assert.deepEqual(set.list().map((f) => f.key), ['2', '1', '3']);
  assert.deepEqual(set.list({ minSeverity: 'high' }).map((f) => f.key), ['2', '1']);
  assert.deepEqual(set.list({ checkId: 'd' }).map((f) => f.key), ['3']);
  set.setStatus(set.list()[2].id, 'false-positive', 'nope');
  assert.deepEqual(set.summary(), { total: 3, open: 2, suppressed: 1, informational: 0, low: 0, medium: 0, high: 1, critical: 1 });
  assert.deepEqual(set.list({ includeSuppressed: false }).map((f) => f.key), ['2', '1']);
  assert.throws(() => set.setStatus('nope', 'fixed'), /No finding/);
  assert.throws(() => set.setStatus(set.list()[0].id, 'weird'), /Unknown status/);
  const later = new FindingSet([mk({ key: '1' }), mk({ key: '9', severity: 'medium' })]);
  const d = diffFindings(set, later);
  assert.deepEqual(d.added.map((f) => f.key), ['9']);
  assert.deepEqual(d.fixed.map((f) => f.key), ['2', '3']);
  assert.deepEqual(d.persisting.map((f) => f.key), ['1']);
  assert.deepEqual(FindingSet.fromJSON(JSON.parse(JSON.stringify(set.toJSON()))).summary(), set.summary());
});

// ----- check registry -------------------------------------------------------------------------

test('every passive check is well-formed, maps to known CWE/OWASP, and has a remediation', () => {
  const checks = allChecks().filter((c) => c.kind === 'passive');
  assert.ok(checks.length >= 25, `only ${checks.length} passive checks`);
  for (const c of checks) {
    assert.equal(c.kind, 'passive', c.id);
    assert.ok(c.intrusiveness <= 1, c.id);
    assert.ok(CATEGORIES[c.id.split('.')[0]], c.id);
    for (const n of c.cwe) assert.ok(CWE[n], `${c.id} CWE-${n}`);
    assert.ok(OWASP_2021[c.owasp], c.id);
    assert.ok(c.remediation.summary.length > 20 && c.remediation.references.length, c.id);
    if (c.probe) assert.ok(c.intrusiveness === 1 && c.requests, `${c.id}: probes must declare intrusiveness 1 and describe their requests`);
    const d = describeCheck(c);
    assert.equal(d.owasp.name, OWASP_2021[c.owasp]);
  }
  for (const cat of ['transport', 'headers', 'cookies', 'cors', 'disclosure', 'components', 'content']) assert.ok(checks.some((c) => c.id.startsWith(cat + '.')), `no checks in ${cat}`);
  assert.throws(() => defineCheck({ id: 'headers.csp', title: 'dup', kind: 'passive', intrusiveness: 0, severity: 'low', confidence: 'firm', cwe: [16], owasp: 'A05', description: 'd', remediation: { summary: 's', references: [] }, observe: () => [] }), /Duplicate check id/);
  assert.throws(() => defineCheck({ id: 'headers.zz', title: 'x', kind: 'passive', intrusiveness: 2, severity: 'low', confidence: 'firm', cwe: [16], owasp: 'A05', description: 'd', remediation: { summary: 's', references: [] }, observe: () => [] }), /passive check cannot have intrusiveness > 1/);
  assert.throws(() => defineCheck({ id: 'headers.zz', title: 'x', kind: 'passive', intrusiveness: 0, severity: 'low', confidence: 'firm', cwe: [16], owasp: 'A05', description: 'd', remediation: { summary: 's', references: [] }, probe: async () => [] }), /probe sends requests/);
  assert.throws(() => defineCheck({ id: 'headers.zz', title: 'x', kind: 'passive', intrusiveness: 0, severity: 'low', confidence: 'firm', cwe: [999999], owasp: 'A05', description: 'd', remediation: { summary: 's', references: [] }, observe: () => [] }), /known CWE ids/);
  // No payload library: nothing in the passive checks resembles an attack string.
  for (const c of checks) assert.ok(!/<script>alert|' OR 1=1|UNION SELECT|\.\.\/\.\.\/etc\/passwd/i.test(String(c.observe) + String(c.probe) + String(c.finalize)), c.id);
});

test('cookies.scope flags a parent-domain cookie on a subdomain host', () => {
  const check = getCheck('cookies.scope');
  const page = { finalUrl: 'https://app.example.com/', cookies: [parseSetCookie('sid=abc; Domain=.example.com; Path=/'), parseSetCookie('local=1; Domain=app.example.com'), parseSetCookie('nodomain=1')] };
  const out = check.observe(page, { origin: 'https://app.example.com' });
  assert.deepEqual(out.map((f) => f.key), ['sid']);
  assert.equal(out[0].severity, 'low');
});

test('CSP parsing and weakness detection', () => {
  const csp = parseCsp("default-src 'self'; script-src 'self' 'unsafe-inline' https:; object-src 'none'; base-uri 'self'; script-src ignored");
  assert.deepEqual(csp['script-src'], ["'self'", "'unsafe-inline'", 'https:']);
  assert.deepEqual(cspWeaknesses(csp).map((i) => i.key), ['unsafeInline', 'wildcard']);
  assert.deepEqual(cspWeaknesses(parseCsp("default-src 'self'; script-src 'self' 'nonce-abc' 'unsafe-inline'; object-src 'none'; base-uri 'none'")), [], 'unsafe-inline with a nonce is the backwards-compatibility pattern');
  assert.deepEqual(cspWeaknesses(parseCsp("img-src 'self'")).map((i) => i.key), ['noScriptSrc', 'objectSrc', 'baseUri']);
});

test('version comparison and known-vulnerable matching', () => {
  assert.equal(compareVersions('1.12.4', '3.5.0'), -1);
  assert.equal(compareVersions('3.5', '3.5.0'), 0);
  assert.equal(versionBelow('10.0', '9.9.9'), false);
  assert.ok(matchKnownVulnerable('jQuery', '1.12.4').some((k) => k.advisories.includes('CVE-2020-11022')));
  assert.ok(matchKnownVulnerable('jquery', '1.8.0').length >= 2, 'both ranges match 1.8');
  assert.deepEqual(matchKnownVulnerable('jQuery', '3.7.1'), []);
  assert.deepEqual(matchKnownVulnerable('jQuery', null), []);
  assert.equal(matchKnownVulnerable('Bootstrap', '4.1.0').length, 1);
  assert.equal(matchKnownVulnerable('Bootstrap', '4.3.1').length, 0);
  assert.ok(KNOWN_VULNERABLE.every((k) => k.name && (k.below || k.range) && SEVERITIES.includes(k.severity)));
  assert.ok(SENSITIVE_PATHS.every((p) => p.path.startsWith('/') && p.signature instanceof RegExp && SEVERITIES.includes(p.severity)));
});

// ----- crawler against the fixture --------------------------------------------------------------

let bad; let good;
before(async () => { bad = await startServer(badSiteHandler); good = await startServer(goodSiteHandler); });
after(async () => { await bad.close(); await good.close(); });

test('crawler: same-origin BFS, honours robots, respects depth/page/request limits and scope, logs every request', async () => {
  const c = new Crawler(bad.origin, { maxDepth: 3, concurrency: 2 });
  await c.run();
  const urls = c.pages.filter((p) => p.kind === 'page').map((p) => p.finalUrl.replace(bad.origin, ''));
  assert.ok(urls.includes('/') && urls.includes('/login') && urls.includes('/deep/3'), urls);
  assert.ok(!urls.includes('/deep/4'), 'depth 4 excluded');
  assert.ok(!urls.includes('/private/secret'), 'robots Disallow honoured');
  assert.deepEqual(c.robots.disallow, ['/private/']);
  assert.ok(c.pages.some((p) => p.kind === 'asset' && p.finalUrl.endsWith('jquery-1.12.4.min.js')), 'same-origin script fetched as asset');
  assert.ok(c.external.scripts.has('https://cdn.example.net/lib.js'));
  assert.ok(c.external.images.has('http://img.example.net/pixel.gif'));
  assert.ok(Array.isArray(c.result().external.scripts));
  assert.equal(c.requestLog.length, c.pages.length + 1, 'one log entry per page/asset plus robots.txt');
  assert.ok(c.requestLog.every((r) => r.method === 'GET' && r.status && r.at));
  const home = c.pages.find((p) => p.finalUrl === bad.origin + '/');
  assert.equal(home.cookies.length, 2);
  assert.equal(home.dom.meta.generator, 'WordPress 5.8');

  const noRobots = new Crawler(bad.origin, { honorRobots: false, maxDepth: 1 });
  await noRobots.run();
  assert.ok(noRobots.pages.some((p) => p.finalUrl.endsWith('/private/secret')));

  const scoped = new Crawler(bad.origin, { scope: (u) => !u.includes('/deep/'), maxDepth: 5 });
  await scoped.run();
  assert.ok(!scoped.pages.some((p) => p.finalUrl.includes('/deep/')));

  const capped = new Crawler(bad.origin, { maxPages: 3, maxDepth: 5 });
  await capped.run();
  assert.equal(capped.pages.filter((p) => p.kind === 'page').length, 3);
  assert.equal(capped.stopReason, 'page limit reached');

  const budget = new Crawler(bad.origin, { maxRequests: 4, maxDepth: 5 });
  await budget.run();
  assert.ok(budget.requestLog.length <= 4);
  assert.equal(budget.stopReason, 'request budget exhausted');
});

// ----- orchestrator -------------------------------------------------------------------------------

function readyContext(origin, opts = {}) {
  const ctx = createContext({ memory: true, ...opts });
  ctx.targets.add(origin, { name: 'fixture' });
  const ch = ctx.verifications.issue(origin);
  ctx.verifications.complete(ch, { ok: true, method: 'http', origin, url: origin + '/x' });
  ctx.targets.confirmAuthorization(origin, 'test fixture');
  return ctx;
}

test('runScan enforces the gate itself, before any request', async () => {
  const ctx = createContext({ memory: true });
  const { target } = ctx.targets.add(bad.origin);
  let fetched = 0;
  const spyFetch = (...a) => { fetched++; return fetch(...a); };
  await assert.rejects(runScan(ctx, { target, fetch: spyFetch }), VerificationRequiredError);
  const ch = ctx.verifications.issue(bad.origin);
  ctx.verifications.complete(ch, { ok: true, method: 'dns', origin: bad.origin, name: 'x' });
  await assert.rejects(runScan(ctx, { target: ctx.targets.get(bad.origin), fetch: spyFetch }), AuthorizationRequiredError);
  assert.equal(fetched, 0, 'no request may be sent before both proofs are present');
  ctx.targets.confirmAuthorization(bad.origin, 'ok');
  assert.ok(assertScanPermitted(ctx, ctx.targets.get(bad.origin)).tokenHash);
  const rec = await runScan(ctx, { target: ctx.targets.get(bad.origin), fetch: spyFetch });
  assert.ok(fetched > 10);
  assert.equal(rec.verification.method, 'dns');
  assert.equal(rec.authorization.statement, 'ok');
});

test('passive scan of the bad site finds the planted problems and nothing from the catch-all pages', async () => {
  const ctx = readyContext(bad.origin);
  const rec = await exec(ctx, 'scan.start');
  const by = (id) => rec.findings.filter((f) => f.checkId === id);
  const keys = (id) => by(id).map((f) => f.key).sort();
  assert.equal(rec.profile, 'passive');
  assert.ok(rec.crawl.pages >= 8 && rec.crawl.probes >= 30, JSON.stringify(rec.crawl));
  assert.deepEqual(rec.checks.errors, []);
  assert.ok(rec.checks.run.length >= 25);

  assert.deepEqual(keys('disclosure.sensitiveFiles'), ['/.env', '/.git/HEAD'], 'catch-all 200 pages must not match other paths');
  assert.equal(by('disclosure.sensitiveFiles').find((f) => f.key === '/.env').severity, 'critical');
  assert.deepEqual(keys('disclosure.directoryListing'), ['/js/', '/listing/']);
  assert.deepEqual(keys('disclosure.verboseErrors'), ['Python']);
  assert.deepEqual(keys('disclosure.serverBanner'), ['server', 'x-powered-by']);
  assert.equal(by('disclosure.sourceMaps').length, 1);
  assert.deepEqual(keys('cors.permissive').filter((k, i, a) => a.indexOf(k) === i), ['null', 'reflected']);
  assert.ok(by('cors.permissive').every((f) => f.severity === 'high'), 'reflected origin with credentials is high');
  assert.deepEqual(keys('cookies.secure'), ['PHPSESSID', 'prefs']);
  assert.equal(by('cookies.secure').find((f) => f.key === 'PHPSESSID').severity, 'medium', 'session cookie on http origin');
  assert.deepEqual(keys('cookies.httpOnly'), ['PHPSESSID', 'prefs']);
  assert.deepEqual(keys('cookies.scope'), [], 'Domain=.127.0.0.1 on an IP host is not a parent-domain scope');
  assert.equal(by('headers.csp').find((f) => f.key === 'missing').occurrences >= 5, true, 'site-wide header finding consolidated with occurrences');
  assert.ok(by('headers.csp').find((f) => f.key === 'missing').evidence.detail.affectedUrls.length >= 5);
  assert.equal(by('headers.csp').find((f) => f.key === 'weak').url, bad.origin + '/');
  assert.equal(by('headers.frameOptions').length, 1);
  assert.equal(by('headers.frameOptions')[0].url, bad.origin + '/', 'consolidated to the origin');
  assert.equal(by('transport.https')[0].severity, 'high', 'password form over http');
  assert.ok(by('content.formsOverHttp').some((f) => f.severity === 'high'));
  assert.deepEqual(keys('content.autocompleteSensitive'), ['cc_number']);
  assert.ok(keys('content.subresourceIntegrity').some((k) => k.startsWith('script:https://cdn.example.net/lib.js')));
  assert.deepEqual(keys('transport.mixedContent'), [], 'mixed content only applies to https origins');
  assert.deepEqual(rec.fingerprint.map((f) => `${f.name}@${f.version}`).sort(), ['PHP@7.4.3', 'WordPress@5.8', 'jQuery@1.12.4', 'nginx@1.18.0']);
  assert.ok(keys('components.knownVulnerable').some((k) => k.startsWith('jQuery@1.12.4')));
  assert.ok(by('components.knownVulnerable').every((f) => f.confidence === 'firm'));
  assert.equal(rec.summary.critical, 1);
  assert.ok(rec.summary.high >= 5);
  // Evidence never carries cookie values.
  assert.ok(!JSON.stringify(rec.findings).includes('abc123def456'), 'session cookie value must be redacted');
  assert.ok(!JSON.stringify(rec.findings).includes('hunter2') || JSON.stringify(rec.findings).includes('<redacted>'), '.env excerpt is redacted or not stored verbatim');
  assert.ok(rec.requestLog.some((r) => r.url.endsWith('/.git/HEAD') && r.kind === 'probe'));
  assert.ok(!rec.requestLog.some((r) => r.url.includes('/private/')), 'robots-disallowed path never requested');
});

test('passive scan of a well-configured site is quiet', async () => {
  const ctx = readyContext(good.origin);
  const rec = await exec(ctx, 'scan.passive');
  const ids = rec.findings.filter((f) => f.severity !== 'informational').map((f) => f.checkId);
  assert.deepEqual(ids, ['transport.https'], 'only the (true) plain-HTTP finding remains on an http fixture');
  assert.ok(rec.findings.some((f) => f.checkId === 'disclosure.sensitiveFiles' && f.key === '/.well-known/security.txt' && f.severity === 'informational'));
  assert.deepEqual(rec.checks.errors, []);
});

test('false-positive learning loop, status changes, diff, history, log, export, settings and preview through the commands', async () => {
  const ctx = readyContext(bad.origin);
  const first = await exec(ctx, 'scan.start');
  const list = await exec(ctx, 'findings.list', { minSeverity: 'high' });
  assert.ok(list.findings.length >= 5 && list.findings.every((f) => ['high', 'critical'].includes(f.severity)));
  const banner = (await exec(ctx, 'findings.list', { check: 'disclosure.serverBanner' })).findings[0];
  const marked = await exec(ctx, 'findings.markFalsePositive', { finding: banner.id, note: 'header is a decoy' });
  assert.equal(marked.status, 'false-positive');
  assert.equal((await exec(ctx, 'findings.falsePositives')).length, 1);
  const details = await exec(ctx, 'findings.details', banner.id);
  assert.equal(details.status, 'false-positive');
  assert.ok(details.standards.cweNames[0].startsWith('CWE-200'));

  const second = await exec(ctx, 'scan.rescan');
  assert.equal(second.suppressedByRules, 1);
  assert.equal(second.findings.find((f) => f.signature === banner.signature).status, 'false-positive');
  assert.equal(second.summary.open, second.findings.length - 1, 'one finding suppressed by the remembered rule');
  assert.equal(second.findings.length, first.findings.length);
  const diff = await exec(ctx, 'scan.diff');
  assert.deepEqual(diff.counts, { added: 0, fixed: 0, persisting: first.findings.length });
  assert.equal((await exec(ctx, 'scan.history')).scans.length, 2);
  assert.ok((await exec(ctx, 'scan.log')).requests.length > 30);

  await exec(ctx, 'findings.unmarkFalsePositive', banner.id);
  assert.equal((await exec(ctx, 'findings.falsePositives')).length, 0);
  const fixed = await exec(ctx, 'findings.markFixed', { finding: banner.id, note: 'removed header' });
  assert.equal(fixed.status, 'fixed');
  await assert.rejects(exec(ctx, 'findings.markAccepted', { finding: banner.id }), /reason is required/);
  assert.equal((await exec(ctx, 'findings.markAccepted', { finding: banner.id, reason: 'decoy' })).status, 'accepted');
  const grouped = await exec(ctx, 'findings.group', 'owasp');
  assert.ok(grouped.A05.length > 5);
  const sarif = JSON.parse(await exec(ctx, 'findings.export', 'sarif'));
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].results.length, second.findings.length);
  assert.ok(sarif.runs[0].results.some((r) => r.kind === 'pass' && r.suppressions));
  assert.ok(sarif.runs[0].tool.driver.rules.every((r) => r.properties['security-severity']));
  const csv = await exec(ctx, 'findings.export', 'csv');
  assert.equal(csv.split('\r\n').length - 2, second.findings.length);
  assert.match(csv.split('\r\n')[0], /^id,severity,confidence/);
  await assert.rejects(exec(ctx, 'findings.export', 'xml'), /format must be/);
  assert.match(await exec(ctx, 'findings.copy', banner.id), /^### Server software/);

  // Settings and preview.
  assert.equal((await exec(ctx, 'scan.profile')).profile.id, 'passive');
  assert.equal((await exec(ctx, 'scan.profile', 'quick')).profile.id, 'quick');
  await assert.rejects(exec(ctx, 'scan.profile', 'nuclear'), /Unknown profile/);
  const prev = await exec(ctx, 'scan.preview');
  assert.equal(prev.profile.id, 'quick');
  assert.equal(prev.crawl.maxDepth, 1);
  assert.ok(prev.checks.length >= 25 && prev.extraRequestChecks >= 4 && prev.activeChecks === 0, 'quick profile runs passive checks only');
  assert.ok(prev.skipped.some((s) => s.id === 'transport.tls') && prev.skipped.filter((s) => s.id.startsWith('xss.') || s.id.startsWith('injection.')).length >= 3, 'active checks skipped on the quick profile');
  await exec(ctx, 'checks.disable', 'headers.permissionsPolicy');
  await exec(ctx, 'checks.disableCategory', 'cors');
  const prev2 = await exec(ctx, 'scan.preview');
  assert.ok(prev2.skipped.some((s) => s.id === 'headers.permissionsPolicy' && /disabled/.test(s.reason)));
  assert.ok(prev2.skipped.some((s) => s.id === 'cors.permissive'));
  const third = await exec(ctx, 'scan.start');
  assert.equal(third.profile, 'quick');
  assert.ok(!third.checks.run.includes('cors.permissive'));
  assert.ok(!third.findings.some((f) => f.checkId === 'headers.permissionsPolicy'));
  await exec(ctx, 'checks.enableCategory', 'cors');
  assert.equal((await exec(ctx, 'checks.details', 'cors.permissive')).enabled, true);
  assert.equal((await exec(ctx, 'checks.details', 'headers.permissionsPolicy')).enabled, false);
  await assert.rejects(exec(ctx, 'checks.details', 'nope.x'), /Unknown check/);
  assert.ok((await exec(ctx, 'checks.list')).length >= 25);
  assert.ok((await exec(ctx, 'checks.search', 'cookie')).length >= 3);
  assert.ok((await exec(ctx, 'checks.byOwasp')).find((g) => g.id === 'A05').checks.length > 10);
  assert.deepEqual(await exec(ctx, 'target.robots', false), { honorRobots: false });
  assert.deepEqual(await exec(ctx, 'target.rateLimit', { delayMs: 5, concurrency: 1 }), { delayMs: 5, concurrency: 1 });
  assert.equal((await exec(ctx, 'scan.crawlDepth', '2')).maxDepth, 2);
  await assert.rejects(exec(ctx, 'scan.crawlLimits', { maxPages: -1 }), RangeError);
  const single = await exec(ctx, 'scan.single', bad.origin + '/login');
  assert.equal(single.crawl.pages, 1);
  assert.ok(single.findings.some((f) => f.checkId === 'content.formsOverHttp'));
  await assert.rejects(exec(ctx, 'scan.single', 'https://elsewhere.example/'), /outside the target's scope/);
  const recheck = await exec(ctx, 'findings.recheck', { finding: single.findings[0].id, scan: single.id });
  assert.equal(recheck.stillPresent, true);
  const spider = await exec(ctx, 'scan.spiderOnly');
  assert.equal(spider.findings.length, 0);
  assert.ok(spider.checks.skipped.length >= 25);
});

test('planChecks and profiles', () => {
  assert.deepEqual(Object.keys(PROFILES), ['passive', 'quick', 'standard', 'thorough']);
  const p = planChecks({ profile: 'passive', origin: 'https://x.example' });
  assert.ok(p.skipped.every((s) => s.check.kind === 'active'), 'passive profile skips only active checks');
  assert.equal(p.run.length, allChecks().filter((c) => c.kind === 'passive').length);
  assert.throws(() => planChecks({ profile: 'nope' }), /Unknown profile/);
  const d = planChecks({ profile: 'passive', disabledChecks: ['headers'] });
  const disabledSkips = d.skipped.filter((s) => /disabled/.test(s.reason));
  assert.ok(disabledSkips.length >= 6 && disabledSkips.every((s) => s.check.id.startsWith('headers.')));
  assert.ok(!d.run.some((c) => c.id.startsWith('headers.')));
});

test('ScanStore persists records, settings and false positives to disk with restricted modes', async () => {
  const { mkdtempSync, statSync, existsSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { tmpdir } = await import('node:os');
  const dir = join(mkdtempSync(join(tmpdir(), 'quilltest-scans-')), 'scans');
  const ctx = readyContext(bad.origin, { scansDir: dir });
  ctx.scans = ScanStore.load(dir, { now: ctx.now });
  const rec = await exec(ctx, 'scan.quick');
  assert.ok(existsSync(join(dir, rec.id + '.json')));
  if (process.platform !== 'win32') { assert.equal(statSync(join(dir, rec.id + '.json')).mode & 0o777, 0o600); assert.equal(statSync(join(dir, 'index.json')).mode & 0o777, 0o600); }
  const again = ScanStore.load(dir);
  assert.equal(again.list(bad.origin)[0].id, rec.id);
  assert.equal(again.get('last', bad.origin).findings.length, rec.findings.length);
  assert.deepEqual(again.settings(bad.origin), DEFAULT_SETTINGS);
  again.updateSettings(bad.origin, { maxPages: '20', honorRobots: 'false' });
  assert.equal(ScanStore.load(dir).settings(bad.origin).maxPages, 20);
  assert.equal(ScanStore.load(dir).settings(bad.origin).honorRobots, false);
  assert.throws(() => again.updateSettings(bad.origin, { bogus: 1 }), /Unknown scan setting/);
  again.addFalsePositive(bad.origin, rec.findings[0], 'n');
  assert.equal(ScanStore.load(dir).falsePositives(bad.origin).length, 1);
  assert.equal(again.remove(rec.id), true);
  assert.ok(!existsSync(join(dir, rec.id + '.json')));
  assert.equal(again.get(rec.id), null);
});

test('toSarif is well-formed for an empty scan', () => {
  const s = toSarif({ id: 'scan-x', origin: 'https://a', profile: 'passive', startedAt: 'x', finishedAt: 'y', verification: {}, authorization: {}, findings: [] });
  assert.deepEqual(s.runs[0].results, []);
  assert.match(exportFindings({ id: 'scan-x', origin: 'https://a', profile: 'passive', startedAt: 'x', finishedAt: 'y', verification: {}, authorization: {}, summary: {}, findings: [] }, 'json'), /"tool": "QuillTest"/);
});
