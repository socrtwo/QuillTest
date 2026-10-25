/*
 * Anne's Test — passive scan engine tests (offline; fetch is injected)
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  runPassiveScan, observe, sortFindings, parseHsts, parseCsp, parseCookie, maskCookie,
  PASSIVE_CHECKS, SENSITIVE_FILE_PROBES, CORS_PROBE_ORIGIN, USER_AGENT, MAX_BODY_BYTES,
} from '../src/scan/passive.mjs';

/** Build a fetch Response-alike with multiple Set-Cookie support. */
function mk(status, headers = {}, body = '', setCookies = []) {
  const h = new Headers(headers);
  h.getSetCookie = () => setCookies;
  return { status, headers: h, text: async () => body };
}

/** A site factory: pass a handler(pathname, init, url) → response. */
const site = (handler) => async (url, init) => handler(new URL(url).pathname, init, new URL(url));

const HARDENED_HEADERS = {
  'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
  'content-security-policy': "default-src 'self'; script-src 'self' 'nonce-r4nd0m'; object-src 'none'; frame-ancestors 'self'",
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=(), microphone=()',
  'content-type': 'text/html',
  server: 'nginx',
};

function hardened(path, init, u) {
  if (u.protocol === 'http:') return mk(301, { location: 'https://strong.test/' });
  if (path !== '/') return mk(404, { 'content-type': 'text/html' }, '<html>not found</html>');
  return mk(200, HARDENED_HEADERS, '<html><body>ok</body></html>', ['__Host-sid=v; Path=/; Secure; HttpOnly; SameSite=Strict']);
}

const byCheck = (report, id) => report.findings.filter((f) => f.checkId === id);

test('check registry is well-formed and every check has a remediation', () => {
  const ids = PASSIVE_CHECKS.map((c) => c.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const c of PASSIVE_CHECKS) {
    assert.ok(['critical', 'high', 'medium', 'low', 'info'].includes(c.severity), c.id);
    assert.ok(['confirmed', 'firm', 'tentative'].includes(c.confidence), c.id);
    assert.ok(typeof c.remediation === 'string' && c.remediation.length > 20, `${c.id} needs a concrete remediation`);
    assert.equal(typeof c.run, 'function');
  }
  for (const p of SENSITIVE_FILE_PROBES) assert.equal(typeof p.signature, 'function', p.path);
});

test('a hardened site yields zero findings (no false positives)', async () => {
  const r = await runPassiveScan('https://strong.test', { fetchImpl: site(hardened) });
  assert.deepEqual(r.findings, []);
  assert.ok(r.requests >= 3 + SENSITIVE_FILE_PROBES.length);
});

test('requests identify themselves and only follow same-origin redirects', async () => {
  const seen = [];
  const r = await observe('https://a.test/', { fetchImpl: async (url, init) => { seen.push({ url, init }); return mk(302, { location: 'https://b.test/' }); } });
  assert.equal(seen.length, 1, 'cross-origin redirect must not be followed');
  assert.equal(r.crossOriginRedirectTo, 'https://b.test/');
  assert.equal(seen[0].init.redirect, 'manual');
  assert.equal(seen[0].init.headers['user-agent'], USER_AGENT);
  let hops = 0;
  const loop = await observe('https://a.test/', { fetchImpl: async (url) => { hops++; return mk(302, { location: url.endsWith('/x') ? '/' : '/x' }); } });
  assert.ok(loop.error, 'redirect loops terminate with an error');
  assert.ok(hops <= 5);
});

test('observe returns network errors instead of throwing and caps bodies', async () => {
  const r = await observe('https://a.test/', { fetchImpl: async () => { const e = new Error('fetch failed'); e.cause = { code: 'CERT_HAS_EXPIRED', message: 'certificate has expired' }; throw e; } });
  assert.equal(r.errorCode, 'CERT_HAS_EXPIRED');
  const big = await observe('https://a.test/', { fetchImpl: async () => mk(200, {}, 'x'.repeat(MAX_BODY_BYTES + 100)) });
  assert.equal(big.body.length, MAX_BODY_BYTES);
});

test('transport checks: plaintext origin, missing https redirect, HSTS missing/weak, TLS error', async () => {
  const plain = await runPassiveScan('http://plain.test', { fetchImpl: site(() => mk(200, { 'content-type': 'text/html' }, '<html/>')) });
  assert.equal(byCheck(plain, 'transport.plaintext').length, 1);
  assert.equal(byCheck(plain, 'transport.hsts').length, 0, 'HSTS is not expected on an http origin');

  const noRedirect = await runPassiveScan('https://s.test', { fetchImpl: site((p, i, u) => (u.protocol === 'http:' ? mk(200, {}, 'served over http') : hardened(p, i, u))) });
  assert.equal(byCheck(noRedirect, 'transport.http-not-redirected').length, 1);

  const weakHsts = await runPassiveScan('https://s.test', { fetchImpl: site((p, i, u) => { const r = hardened(p, i, u); if (p === '/' && u.protocol === 'https:') return mk(200, { ...HARDENED_HEADERS, 'strict-transport-security': 'max-age=300' }, '', ['__Host-sid=v; Path=/; Secure; HttpOnly; SameSite=Strict']); return r; }) });
  const h = byCheck(weakHsts, 'transport.hsts');
  assert.equal(h.length, 1); assert.equal(h[0].severity, 'low'); assert.match(h[0].evidence.snippet, /below/);

  const tls = await runPassiveScan('https://bad.test', { fetchImpl: async () => { const e = new Error('fetch failed'); e.cause = { code: 'ERR_TLS_CERT_ALTNAME_INVALID', message: 'Hostname/IP does not match certificate' }; throw e; } });
  assert.equal(byCheck(tls, 'transport.tls-error').length, 1);
  assert.equal(tls.requests, 1, 'nothing else is probed when the root cannot be fetched');
});

test('header checks: CSP missing/report-only/weak, nosniff, frame, referrer, permissions', async () => {
  const bare = await runPassiveScan('https://h.test', { fetchImpl: site((p) => (p === '/' ? mk(200, { 'content-type': 'text/html' }, '<html/>') : mk(404))) });
  for (const id of ['headers.csp', 'headers.x-content-type-options', 'headers.frame', 'headers.referrer-policy', 'headers.permissions-policy']) {
    assert.equal(byCheck(bare, id).length, 1, id);
  }
  const ro = await runPassiveScan('https://h.test', { fetchImpl: site((p) => (p === '/' ? mk(200, { 'content-security-policy-report-only': "default-src 'self'" }, '') : mk(404))) });
  assert.match(byCheck(ro, 'headers.csp')[0].title, /report-only/);
  const weak = await runPassiveScan('https://h.test', { fetchImpl: site((p) => (p === '/' ? mk(200, { 'content-security-policy': "default-src *; script-src 'unsafe-inline' 'unsafe-eval' *" }, '') : mk(404))) });
  const w = byCheck(weak, 'headers.csp')[0];
  assert.match(w.title, /weak/); assert.match(w.evidence.snippet, /unsafe-inline/); assert.match(w.evidence.snippet, /unsafe-eval/);
  const faOnly = await runPassiveScan('https://h.test', { fetchImpl: site((p) => (p === '/' ? mk(200, { 'content-security-policy': "frame-ancestors 'none'" }, '') : mk(404))) });
  assert.equal(byCheck(faOnly, 'headers.frame').length, 0, 'frame-ancestors satisfies the clickjacking check');
});

test('cookie check: flags, session-like escalation, http origin does not demand Secure, values masked', async () => {
  const r = await runPassiveScan('https://c.test', { fetchImpl: site((p) => (p === '/' ? mk(200, {}, '', ['sessionid=TOPSECRET; Path=/', 'pref=1; Path=/; Secure', 'good=1; Secure; HttpOnly; SameSite=Lax']) : mk(404))) });
  const f = byCheck(r, 'cookies.flags');
  assert.equal(f.length, 2);
  const sess = f.find((x) => x.title.includes('sessionid'));
  assert.equal(sess.severity, 'high');
  assert.match(sess.title, /Secure, HttpOnly, SameSite/);
  assert.equal(f.find((x) => x.title.includes("'pref'")).severity, 'medium');
  assert.ok(!JSON.stringify(r).includes('TOPSECRET'), 'cookie values must be masked');
  const http = await runPassiveScan('http://c.test', { fetchImpl: site((p) => (p === '/' ? mk(200, {}, '', ['sid=v; HttpOnly; SameSite=Lax']) : mk(404))) });
  assert.equal(byCheck(http, 'cookies.flags').length, 0, 'Secure is not demanded on a plaintext origin (that is its own finding)');
});

test('CORS check: reflected origin with credentials, wildcard+credentials, null origin, and a safe allow-list', async () => {
  const reflect = await runPassiveScan('https://x.test', { fetchImpl: site((p, init) => (p === '/' ? mk(200, init.headers.origin ? { 'access-control-allow-origin': init.headers.origin, 'access-control-allow-credentials': 'true' } : {}, '') : mk(404))) });
  const rf = byCheck(reflect, 'cors.misconfig');
  assert.equal(rf.length, 1); assert.equal(rf[0].severity, 'high'); assert.equal(rf[0].evidence.requestHeaders.origin, CORS_PROBE_ORIGIN);
  const wild = await runPassiveScan('https://x.test', { fetchImpl: site((p) => (p === '/' ? mk(200, { 'access-control-allow-origin': '*', 'access-control-allow-credentials': 'true' }, '') : mk(404))) });
  assert.match(byCheck(wild, 'cors.misconfig')[0].title, /any origin with credentials/);
  const nul = await runPassiveScan('https://x.test', { fetchImpl: site((p) => (p === '/' ? mk(200, { 'access-control-allow-origin': 'null' }, '') : mk(404))) });
  assert.match(byCheck(nul, 'cors.misconfig')[0].title, /'null'/);
  const safe = await runPassiveScan('https://x.test', { fetchImpl: site((p) => (p === '/' ? mk(200, { 'access-control-allow-origin': 'https://app.x.test', vary: 'Origin' }, '') : mk(404))) });
  assert.equal(byCheck(safe, 'cors.misconfig').length, 0);
  const plainWild = await runPassiveScan('https://x.test', { fetchImpl: site((p) => (p === '/' ? mk(200, { 'access-control-allow-origin': '*' }, '') : mk(404))) });
  assert.equal(byCheck(plainWild, 'cors.misconfig').length, 0, 'a bare wildcard without credentials is a legitimate public-API pattern');
});

test('disclosure: version banners flagged only when a version is present', async () => {
  const v = await runPassiveScan('https://d.test', { fetchImpl: site((p) => (p === '/' ? mk(200, { server: 'Apache/2.4.41 (Ubuntu)', 'x-powered-by': 'PHP/7.4.3' }, '') : mk(404))) });
  const f = byCheck(v, 'disclosure.server-banner');
  assert.equal(f.length, 1); assert.match(f[0].evidence.snippet, /server, x-powered-by/);
  const nv = await runPassiveScan('https://d.test', { fetchImpl: site((p) => (p === '/' ? mk(200, { server: 'nginx', 'x-powered-by': 'Express' }, '') : mk(404))) });
  assert.equal(byCheck(nv, 'disclosure.server-banner').length, 0);
});

test('content checks: active vs passive mixed content, insecure form action, directory listing', async () => {
  const body = '<html><head><title>Index of /pub</title><script src="http://cdn.test/a.js"></script><link rel="stylesheet" href="http://cdn.test/a.css"></head><body><img src="http://img.test/a.png"><form action="http://api.test/login"></form></body></html>';
  const r = await runPassiveScan('https://m.test', { fetchImpl: site((p) => (p === '/' ? mk(200, {}, body) : mk(404))) });
  const mixed = byCheck(r, 'content.mixed');
  assert.equal(mixed.length, 2);
  assert.equal(mixed.find((f) => f.title.startsWith('Active')).severity, 'high');
  assert.equal(mixed.find((f) => f.title.startsWith('Passive')).severity, 'low');
  assert.equal(byCheck(r, 'content.form-insecure').length, 1);
  assert.equal(byCheck(r, 'content.directory-listing').length, 1);
  const httpSite = await runPassiveScan('http://m.test', { fetchImpl: site((p) => (p === '/' ? mk(200, {}, body) : mk(404))) });
  assert.equal(byCheck(httpSite, 'content.mixed').length, 0, 'mixed content only applies to https pages');
});

test('sensitive-file probes require a content signature, not just a 200', async () => {
  const softFourOhFour = await runPassiveScan('https://p.test', { fetchImpl: site(() => mk(200, { 'content-type': 'text/html' }, '<html><body>Welcome!</body></html>')) });
  assert.equal(byCheck(softFourOhFour, 'disclosure.sensitive-files').length, 0, 'a site that 200s everything must not trigger file findings');
  const exposed = await runPassiveScan('https://p.test', { fetchImpl: site((p) => {
    if (p === '/.git/HEAD') return mk(200, {}, 'ref: refs/heads/main\n');
    if (p === '/.env') return mk(200, {}, 'DB_PASSWORD=x\nAPP_KEY=y\n');
    if (p === '/phpinfo.php') return mk(200, {}, '<h1>PHP Version 8.2</h1>');
    return p === '/' ? mk(200, {}, '') : mk(404);
  }) });
  const f = byCheck(exposed, 'disclosure.sensitive-files');
  assert.deepEqual(f.map((x) => x.severity).sort(), ['critical', 'critical', 'high']);
  assert.ok(f.every((x) => x.remediation && x.cwe));
  const off = await runPassiveScan('https://p.test', { fetchImpl: site((p) => (p === '/.git/HEAD' ? mk(200, {}, 'ref: refs/heads/main') : mk(200, {}, ''))), probeSensitiveFiles: false });
  assert.equal(byCheck(off, 'disclosure.sensitive-files').length, 0);
  assert.equal(off.observations.probes.length, 0);
});

test('root redirecting off-origin is reported as info and not followed', async () => {
  const r = await runPassiveScan('https://apex.test', { fetchImpl: site((p, i, u) => (u.protocol === 'https:' && p === '/' ? mk(301, { location: 'https://www.apex.test/' }) : mk(404))) });
  assert.equal(byCheck(r, 'scan.root-redirects-off-origin').length, 1);
  assert.equal(r.observations.root.crossOriginRedirectTo, 'https://www.apex.test/');
});

test('findings carry the analyze.mjs shape and sort by severity then confidence', async () => {
  const r = await runPassiveScan('https://s.test', { fetchImpl: site((p) => (p === '/' ? mk(200, { server: 'nginx/1.0' }, '', ['sid=v']) : mk(404))) });
  for (const f of r.findings) {
    for (const k of ['id', 'checkId', 'title', 'severity', 'confidence', 'location', 'evidence', 'remediation']) assert.ok(k in f, `${f.checkId} missing ${k}`);
    assert.match(f.id, /^F-\d{3}$/);
  }
  const sorted = sortFindings(r.findings).map((f) => f.severity);
  const rank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  for (let i = 1; i < sorted.length; i++) assert.ok(rank[sorted[i - 1]] >= rank[sorted[i]]);
});

test('parsers: HSTS, CSP, cookies, masking', () => {
  assert.deepEqual(parseHsts('max-age=31536000; includeSubDomains; preload'), { maxAge: 31536000, includeSubDomains: true, preload: true });
  assert.equal(parseHsts(''), null);
  assert.deepEqual(parseCsp("default-src 'self'; script-src 'self' cdn.test")['script-src'], ["'self'", 'cdn.test']);
  assert.deepEqual(parseCookie('sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax'), { name: 'sid', secure: true, httpOnly: true, sameSite: 'Lax' });
  assert.deepEqual(parseCookie('x=1'), { name: 'x', secure: false, httpOnly: false, sameSite: null });
  assert.equal(maskCookie('sid=SECRET; Path=/; HttpOnly'), 'sid=…; Path=/; HttpOnly');
  assert.equal(maskCookie('empty=; Path=/'), 'empty=; Path=/');
});
