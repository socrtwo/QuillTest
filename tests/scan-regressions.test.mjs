/*
 * Anne's Test — scan-engine regression tests (offline; network is injected)
 * Each test pins a defect found in review so it cannot come back.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runPassiveScan, parseHsts } from '../src/scan/passive.mjs';
import { extractLinks, extractAssets } from '../src/scan/crawl.mjs';
import { fingerprint } from '../src/scan/fingerprint.mjs';
import { assessVersions } from '../src/scan/versions.mjs';
import { runProtocolScan, inspectTls, dnsFindings, probePop3 } from '../src/scan/protocols.mjs';
import { serveMirror } from '../src/scan/mirror.mjs';

function mk(status, headers = {}, body = '', setCookies = []) {
  const h = new Headers(headers);
  h.getSetCookie = () => setCookies;
  return { status, headers: h, text: async () => body };
}
const site = (handler) => async (url, init) => handler(new URL(url).pathname, init, new URL(url));
const byCheck = (report, id) => report.findings.filter((f) => f.checkId === id);

// ----- passive -----

test('HSTS: a quoted max-age (RFC 6797) parses instead of becoming NaN', () => {
  assert.equal(parseHsts('max-age="31536000"; includeSubDomains').maxAge, 31536000);
  assert.equal(parseHsts('max-age=31536000').maxAge, 31536000);
});

test('cookies: CSRF double-submit cookies are not session cookies and do not need HttpOnly', async () => {
  const r = await runPassiveScan('https://c.test', { fetchImpl: site((p) => (p === '/' ? mk(200, {}, '', ['XSRF-TOKEN=abc; Path=/; Secure; SameSite=Lax', 'csrftoken=def; Path=/; HttpOnly; SameSite=Lax']) : mk(404))) });
  const f = byCheck(r, 'cookies.flags');
  assert.equal(f.length, 1, 'XSRF-TOKEN with Secure+SameSite is fine; only csrftoken (no Secure) is flagged');
  assert.match(f[0].title, /^Cookie 'csrftoken' missing Secure$/);
  assert.equal(f[0].severity, 'medium', 'a CSRF cookie is not escalated to a high session-cookie finding');
});

test('mixed content: <link rel="canonical|alternate"> over http:// is not active mixed content', async () => {
  const body = '<html><head><link rel="canonical" href="http://m.test/"><link rel="alternate" type="application/rss+xml" href="http://m.test/feed"></head><body>x</body></html>';
  const r = await runPassiveScan('https://m.test', { fetchImpl: site((p) => (p === '/' ? mk(200, {}, body) : mk(404))) });
  assert.equal(byCheck(r, 'content.mixed').length, 0);
  const css = '<html><head><link rel="stylesheet" href="http://cdn.test/a.css"></head></html>';
  const r2 = await runPassiveScan('https://m.test', { fetchImpl: site((p) => (p === '/' ? mk(200, {}, css) : mk(404))) });
  assert.equal(byCheck(r2, 'content.mixed').length, 1, 'a stylesheet over http:// still is');
});

test('transport: the http→https redirect probe is skipped on a non-default https port', async () => {
  const urls = [];
  const r = await runPassiveScan('https://p.test:8443', { fetchImpl: async (url) => { urls.push(url); return new URL(url).pathname === '/' ? mk(200, {}, '<html>x</html>') : mk(404); } });
  assert.ok(!urls.some((u) => u.startsWith('http://')), `no plaintext request to a TLS port: ${urls.join(', ')}`);
  assert.equal(byCheck(r, 'transport.http-not-redirected').length, 0);
});

test('page checks are not run on crawled URLs that redirect off-origin', async () => {
  const hardened = {
    'strict-transport-security': 'max-age=63072000', 'content-security-policy': "default-src 'self'; object-src 'none'; frame-ancestors 'self'",
    'x-content-type-options': 'nosniff', 'referrer-policy': 'strict-origin-when-cross-origin', 'permissions-policy': 'camera=()', 'content-type': 'text/html',
  };
  const r = await runPassiveScan('https://s.test', {
    crawl: { maxPages: 5, maxDepth: 2, respectRobots: false },
    fetchImpl: site((p, init, u) => {
      if (u.protocol === 'http:') return mk(301, { location: 'https://s.test/' });
      if (p === '/') return mk(200, hardened, '<html><body><a href="/go">partner</a></body></html>');
      if (p === '/go') return mk(302, { location: 'https://partner.example/' });
      return mk(404, { 'content-type': 'text/html' }, 'no');
    }),
  });
  const onGo = r.findings.filter((f) => f.location === 'https://s.test/go');
  assert.deepEqual(onGo, [], `no header findings on a redirect: ${onGo.map((f) => f.checkId).join(', ')}`);
});

// ----- crawl -----

test('crawl: data-href / data-src are not read as href / src', () => {
  assert.deepEqual(extractLinks('<a data-href="/x">a</a><a href="/y">b</a>').links.map((l) => l), ['/y']);
  const a = extractAssets('<script data-src="/lazy.js"></script><img data-src="/i.png"><script src="/real.js"></script>', 'https://s.test/');
  assert.deepEqual(a.scripts.map((s) => s.src), ['https://s.test/real.js']);
});

// ----- fingerprint -----

test('fingerprint: Apache-Coyote (Tomcat) is not Apache httpd; laravel_session / ci_session are not Rails', () => {
  const coyote = fingerprint([{ headers: { server: 'Apache-Coyote/1.1' }, body: '' }]);
  assert.ok(!coyote.signals.some((s) => s.name === 'Apache'), JSON.stringify(coyote.signals));
  const httpd = fingerprint([{ headers: { server: 'Apache/2.4.41 (Ubuntu)' }, body: '' }]);
  assert.ok(httpd.signals.some((s) => s.name === 'Apache' && s.version === '2.4.41'));
  const laravel = fingerprint([{ headers: { 'set-cookie': ['laravel_session=x; Path=/', 'ci_session=y; Path=/'] }, body: '' }]);
  assert.ok(!laravel.signals.some((s) => s.name === 'Ruby on Rails'), JSON.stringify(laravel.signals));
  const rails = fingerprint([{ headers: { 'set-cookie': ['_myapp_session=x; Path=/'] }, body: '' }]);
  assert.ok(rails.signals.some((s) => s.name === 'Ruby on Rails'));
});

// ----- versions -----

test('versions: Bootstrap 4, Joomla 4 and Angular < 20 are end-of-life as of the table date', () => {
  const sig = (name, version) => ({ kind: 'library', name, version, evidence: ['test'], confidence: 1 });
  const eol = (name, version) => assessVersions({ signals: [sig(name, version)] }, { location: 'https://x/' }).some((p) => /end-of-life/i.test(p.title));
  assert.equal(eol('Bootstrap', '4.6.2'), true);
  assert.equal(eol('Bootstrap', '5.3.3'), false);
  assert.equal(eol('Joomla', '4.4.9'), true);
  assert.equal(eol('Joomla', '5.2.0'), false);
  assert.equal(eol('Angular', '19.2.0'), true);
  assert.equal(eol('Angular', '20.0.0'), false);
});

// ----- protocols -----

function tlsConn(info, seen = []) {
  return (opts) => new Promise((resolve, reject) => {
    seen.push(opts);
    if (opts.maxVersion) { const e = new Error('no'); return reject(e); }
    resolve({ getProtocol: () => 'TLSv1.3', getCipher: () => ({ name: 'TLS_AES_128_GCM_SHA256' }), getPeerCertificate: () => info.cert || {}, authorized: true, authorizationError: null, end() {} });
  });
}
const cert = (o = {}) => ({ subject: { CN: 'ok.test' }, issuer: { CN: 'R3' }, subjectaltname: 'DNS:ok.test', valid_from: 'Jan 1 2026 GMT', valid_to: 'Dec 31 2030 GMT', bits: 2048, ...o });

test('TLS: the legacy-protocol probe lowers the OpenSSL security level so TLS 1.0/1.1 can be detected', async () => {
  const seen = [];
  await inspectTls('ok.test', 443, { tlsConnect: tlsConn({ cert: cert() }, seen), probeLegacy: true });
  const legacy = seen.find((o) => o.maxVersion === 'TLSv1.1');
  assert.ok(legacy, 'legacy probe was attempted');
  assert.match(String(legacy.ciphers), /SECLEVEL=0/);
  assert.ok(!seen.find((o) => !o.maxVersion).ciphers, 'the main handshake keeps the default cipher list');
});

test('TLS: weak-key is decided by the key type and size, not by the string "RSA" in the subject', async () => {
  const run = (c) => runProtocolScan('ok.test', { which: ['tls'], probeLegacy: false, tlsConnect: tlsConn({ cert: cert(c) }) });
  const rsa1024 = await run({ bits: 1024 });
  assert.ok(rsa1024.findings.some((f) => f.checkId === 'tls.weak-key'), '1024-bit RSA is weak even though the subject never says RSA');
  const ec256 = await run({ bits: 256, asn1Curve: 'prime256v1', nistCurve: 'P-256' });
  assert.ok(!ec256.findings.some((f) => f.checkId === 'tls.weak-key'), 'a 256-bit EC key is not a weak RSA key');
  const rsa2048 = await run({ bits: 2048 });
  assert.ok(!rsa2048.findings.some((f) => f.checkId === 'tls.weak-key'));
});

test('POP3: a server answering -ERR to CAPA still yields a result instead of a read timeout', async () => {
  const sent = [];
  const dial = async () => {
    const queue = ['+OK POP3 ready'];
    return {
      readLine: async () => { if (!queue.length) { const e = new Error('closed'); e.code = 'closed'; throw e; } return queue.shift(); },
      send: async (s) => { sent.push(s); if (/^CAPA/i.test(s)) queue.push('-ERR unknown command'); },
      close() {},
    };
  };
  const info = await probePop3('h', 110, { dial, timeoutMs: 500 });
  assert.equal(info.present, true);
  assert.equal(info.error, undefined);
  assert.equal(info.capa, false);
  assert.equal(info.stls, false);
  assert.deepEqual(sent, ['CAPA', 'QUIT']);
});

test('DNS: without a DS resolver the DNSSEC check is "not checked", never "missing"', async () => {
  const none = await dnsFindings('ex.test', { resolveTxt: async () => [], resolveCaa: async () => [] });
  assert.ok(!none.some((f) => f.checkId === 'dns.dnssec-missing'), 'Node cannot query DS records, so no finding is fabricated');
  const injected = await dnsFindings('ex.test', { resolveTxt: async () => [], resolveCaa: async () => [], resolveDs: async () => [] });
  assert.ok(injected.some((f) => f.checkId === 'dns.dnssec-missing'), 'an injected resolver that returns no DS still reports it');
});

// ----- mirror -----

test('mirror serve: a captured header Node refuses is dropped, not fatal to the server', async () => {
  const manifest = {
    origin: 'https://site.test',
    pages: [{ url: 'https://site.test/', requestedUrl: 'https://site.test/', status: 200, headers: { 'content-type': 'text/html', 'x-odd': 'café — 中文', 'x-arr': ['a', 'b'] }, body: '<html>ok</html>' }],
  };
  const srv = await serveMirror(manifest);
  try {
    const r = await fetch(`${srv.url}/`);
    assert.equal(r.status, 200);
    assert.equal(await r.text(), '<html>ok</html>');
    assert.equal(r.headers.get('content-type'), 'text/html');
    assert.equal(r.headers.get('x-odd'), null, 'the non-Latin-1 header was skipped');
  } finally { await srv.close(); }
});
