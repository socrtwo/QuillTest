/*
 * QuillTest — HTTP verification method against a real local server
 * Run: npm test
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import {
  issueChallenge, renderVerificationFile, wellKnownPath, verifyByHttp, verifyChallenge,
  VerificationStore, computeChecksum,
} from '../src/verify/index.mjs';

// One server, many behaviours keyed by a prefix the test chooses via `base`.
// Routes are matched on the well-known path; the behaviour is selected by the
// host header's port alias — simpler: we use distinct challenges and a routing
// table filled per test.
const routes = new Map(); // path -> (req, res) => void
let server;
let origin;        // http://127.0.0.1:<port>
let otherOrigin;   // a second listener, to prove cross-origin redirects fail
let otherServer;

before(async () => {
  server = createServer((req, res) => {
    const handler = routes.get(req.url);
    if (!handler) { res.writeHead(404, { 'content-type': 'text/plain' }); res.end('not found'); return; }
    handler(req, res);
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  origin = `http://127.0.0.1:${server.address().port}`;

  otherServer = createServer((req, res) => {
    const handler = routes.get('OTHER' + req.url);
    if (!handler) { res.writeHead(404); res.end(); return; }
    handler(req, res);
  });
  await new Promise((r) => otherServer.listen(0, '127.0.0.1', r));
  otherOrigin = `http://127.0.0.1:${otherServer.address().port}`;
});

after(() => { server.close(); otherServer.close(); });

function serve(path, body, { status = 200, headers = {} } = {}) {
  routes.set(path, (req, res) => {
    res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8', ...headers });
    res.end(body);
  });
}

test('happy path: 200 text/plain with the exact file verifies', async () => {
  const c = issueChallenge(origin);
  serve(wellKnownPath(c), renderVerificationFile(c));
  const r = await verifyByHttp(c);
  assert.equal(r.ok, true, r.reasons.join('; '));
  assert.equal(r.method, 'http');
  assert.equal(r.status, 200);
  assert.equal(r.url, `${origin}${wellKnownPath(c)}`);
  assert.deepEqual(r.warnings, []);
  assert.match(r.checkedAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
});

test('verifier sends a QuillTest user agent and accepts text/plain', async () => {
  const c = issueChallenge(origin);
  let seen;
  routes.set(wellKnownPath(c), (req, res) => { seen = req.headers; res.writeHead(200, { 'content-type': 'text/plain' }); res.end(renderVerificationFile(c)); });
  const r = await verifyByHttp(c);
  assert.equal(r.ok, true);
  assert.match(seen['user-agent'], /^QuillTest-Verifier\//);
  assert.equal(seen.accept, 'text/plain');
});

test('wrong content type is a warning, not a failure', async () => {
  const c = issueChallenge(origin);
  serve(wellKnownPath(c), renderVerificationFile(c), { headers: { 'content-type': 'text/html' } });
  const r = await verifyByHttp(c);
  assert.equal(r.ok, true);
  assert.deepEqual(r.warnings, ['Content-Type is text/html (expected text/plain)']);
});

test('404 fails with the status in the reason', async () => {
  const c = issueChallenge(origin);
  const r = await verifyByHttp(c);
  assert.equal(r.ok, false);
  assert.equal(r.status, 404);
  assert.match(r.reasons[0], /HTTP 404 .* \(expected 200\)/);
});

test('a 200 with someone else\'s token or a tampered checksum fails', async () => {
  const c = issueChallenge(origin);
  const other = issueChallenge(origin);
  serve(wellKnownPath(c), renderVerificationFile(other));
  let r = await verifyByHttp(c);
  assert.equal(r.ok, false);
  assert.match(r.reasons.join(' '), /token in file does not match/);

  serve(wellKnownPath(c), `quilltest-site-verification=${c.token}\nchecksum=${computeChecksum(c.token, 'https://attacker.example')}\n`);
  r = await verifyByHttp(c);
  assert.deepEqual(r.reasons, ['checksum does not match sha256(token + "\\n" + origin)']);
});

test('a catch-all page that echoes the request path does not verify', async () => {
  // Many servers return 200 for any path (SPA fallback). The content check must still reject it.
  const c = issueChallenge(origin);
  routes.set(wellKnownPath(c), (req, res) => { res.writeHead(200, { 'content-type': 'text/html' }); res.end(`<html><body>${req.url}</body></html>`); });
  const r = await verifyByHttp(c);
  assert.equal(r.ok, false);
  assert.ok(r.reasons.includes('file has no quilltest-site-verification line'));
});

test('same-origin redirect is followed (with a warning); off-origin redirect fails', async () => {
  const c = issueChallenge(origin);
  serve(wellKnownPath(c), '', { status: 302, headers: { location: '/moved.txt' } });
  serve('/moved.txt', renderVerificationFile(c));
  let r = await verifyByHttp(c);
  assert.equal(r.ok, true, r.reasons.join('; '));
  assert.equal(r.url, `${origin}/moved.txt`);
  assert.match(r.warnings[0], /followed same-origin redirect 302/);

  // The other listener serves a perfect copy of the file — it must still fail,
  // because the file is not served by the origin being verified.
  const c2 = issueChallenge(origin);
  serve(wellKnownPath(c2), '', { status: 301, headers: { location: `${otherOrigin}${wellKnownPath(c2)}` } });
  routes.set('OTHER' + wellKnownPath(c2), (req, res) => { res.writeHead(200, { 'content-type': 'text/plain' }); res.end(renderVerificationFile(c2)); });
  r = await verifyByHttp(c2);
  assert.equal(r.ok, false);
  assert.equal(r.status, 301);
  assert.match(r.reasons[0], /redirected off-origin/);
});

test('redirect loops stop after MAX_REDIRECTS; redirect without Location fails', async () => {
  const c = issueChallenge(origin);
  serve(wellKnownPath(c), '', { status: 302, headers: { location: wellKnownPath(c) } });
  let r = await verifyByHttp(c);
  assert.equal(r.ok, false);
  assert.match(r.reasons[0], /more than 3 redirects/);

  const c2 = issueChallenge(origin);
  routes.set(wellKnownPath(c2), (req, res) => { res.writeHead(302); res.end(); });
  r = await verifyByHttp(c2);
  assert.match(r.reasons[0], /redirect without a Location header/);
});

test('bodies over 8 KiB are rejected without being read in full', async () => {
  const c = issueChallenge(origin);
  const big = renderVerificationFile(c) + '#'.padEnd(20_000, 'x') + '\n';
  serve(wellKnownPath(c), big);
  const r = await verifyByHttp(c);
  assert.equal(r.ok, false);
  assert.match(r.reasons[0], /exceeds 8192 bytes/);
  // A custom cap is honoured too.
  const small = await verifyByHttp(c, { maxBytes: 16 });
  assert.match(small.reasons[0], /exceeds 16 bytes/);
});

test('connection refused and timeouts produce a readable reason', async () => {
  const dead = createServer();
  await new Promise((r) => dead.listen(0, '127.0.0.1', r));
  const port = dead.address().port;
  await new Promise((r) => dead.close(r));
  const c = issueChallenge(`http://127.0.0.1:${port}`);
  let r = await verifyByHttp(c);
  assert.equal(r.ok, false);
  assert.match(r.reasons[0], /could not fetch .*ECONNREFUSED/);

  const c2 = issueChallenge(origin);
  routes.set(wellKnownPath(c2), () => { /* never answer */ });
  r = await verifyByHttp(c2, { timeoutMs: 200 });
  assert.match(r.reasons[0], /no response .* within the timeout/);
});

test('an expired challenge fails even when the file is correct', async () => {
  const c = issueChallenge(origin, { now: new Date(Date.now() - 2 * 86_400_000) });
  serve(wellKnownPath(c), renderVerificationFile(c));
  const r = await verifyByHttp(c);
  assert.equal(r.ok, false);
  assert.match(r.reasons[0], /challenge expired/);
});

test('end to end through the store: the gate opens only after a successful HTTP verification', async () => {
  const store = new VerificationStore();
  const c = store.issue(origin);
  assert.throws(() => store.assertVerified(origin));
  let r = await verifyChallenge(c, 'http');
  assert.equal(r.ok, false, 'nothing published yet');
  assert.throws(() => store.complete(c, r));

  serve(wellKnownPath(c), renderVerificationFile(c));
  r = await verifyChallenge(c, 'http');
  assert.equal(r.ok, true);
  const rec = store.complete(c, r);
  assert.equal(store.assertVerified(origin), rec);
  assert.equal(rec.url, `${origin}/.well-known/quilltest-verification/<token>.txt`);
});
