/*
 * QuillTest — TLS inspection against a local self-signed HTTPS server (needs openssl on PATH)
 * Run: npm test
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createServer } from 'node:https';
import { inspectTls } from '../src/crawl/tls.mjs';
import { getCheck } from '../src/checks/index.mjs';

let haveOpenssl = true;
try { execFileSync('openssl', ['version'], { stdio: 'ignore' }); } catch { haveOpenssl = false; }

test('inspectTls reports protocol, self-signed chain failure and expiry; transport.tls turns that into findings', { skip: !haveOpenssl && 'openssl not available' }, async () => {
  const dir = mkdtempSync(join(tmpdir(), 'quilltest-tls-'));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, 'key.pem'), '-out', join(dir, 'cert.pem'), '-days', '5', '-subj', '/CN=localhost'], { stdio: 'ignore' });
  const server = createServer({ key: readFileSync(join(dir, 'key.pem')), cert: readFileSync(join(dir, 'cert.pem')), minVersion: 'TLSv1.2' }, (req, res) => { res.writeHead(200); res.end('ok'); });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  try {
    const t = await inspectTls('127.0.0.1', port, { servername: 'localhost' });
    assert.equal(t.ok, true, t.error);
    assert.match(t.protocol, /^TLSv1\.[23]$/);
    assert.equal(t.authorized, false);
    assert.match(t.authorizationError, /SELF_SIGNED|DEPTH_ZERO_SELF_SIGNED_CERT/);
    assert.equal(t.cert.selfSigned, true);
    assert.ok(t.cert.daysLeft >= 3 && t.cert.daysLeft <= 5, String(t.cert.daysLeft));

    const check = getCheck('transport.tls');
    const site = { origin: `https://127.0.0.1:${port}`, inspectTls: (h, p) => inspectTls(h, p, { servername: 'localhost' }) };
    const findings = await check.probe(site);
    assert.deepEqual(findings.map((f) => f.key).sort(), ['chain', 'expiring']);
    assert.equal(findings.find((f) => f.key === 'chain').severity, 'high');
    assert.equal(findings.find((f) => f.key === 'expiring').severity, 'low');

    const dead = await inspectTls('127.0.0.1', 1, { timeoutMs: 2000 });
    assert.equal(dead.ok, false);
    assert.ok(dead.error);
    assert.equal((await check.probe({ origin: 'http://plain.example', inspectTls })).length, 0, 'not applicable to http origins');
  } finally {
    await new Promise((r) => server.close(r));
  }
});
