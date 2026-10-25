/*
 * Anne's Test — ownership verification tests (offline; fetch and DNS are injected)
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, statSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  normalizeOrigin, issueChallenge, checksumFor, parseVerificationFile, verifyHttp, verifyDns,
  verifyChallenge, isOriginVerified, isExpired, base32, MAX_FILE_BYTES, WELL_KNOWN_DIR, TXT_PREFIX,
} from '../src/verify/ownership.mjs';
import { createStore } from '../src/verify/store.mjs';

const TOKEN = 'TESTTOKEN2345ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJK';
const res = (status, body = '', headers = {}) => ({ status, headers: new Headers(headers), text: async () => body });

test('normalizeOrigin canonicalizes and rejects non-origins', () => {
  assert.equal(normalizeOrigin('Example.COM/path?x=1'), 'https://example.com');
  assert.equal(normalizeOrigin('https://a.b:443/'), 'https://a.b');
  assert.equal(normalizeOrigin('http://a.b:80'), 'http://a.b');
  assert.equal(normalizeOrigin('http://a.b:8080/x'), 'http://a.b:8080');
  assert.equal(normalizeOrigin('HTTPS://Sub.Example.org:8443'), 'https://sub.example.org:8443');
  for (const bad of ['', 'ftp://x', 'https://u:p@x.com', 'javascript:alert(1)', '::nope']) assert.throws(() => normalizeOrigin(bad), bad || '(empty)');
});

test('base32 produces unpadded RFC4648 and 256 bits → 52 chars', () => {
  assert.equal(base32(Buffer.from([0])), 'AA');
  assert.equal(base32(Buffer.alloc(32)).length, 52);
  assert.match(base32(Buffer.from('hello')), /^[A-Z2-7]+$/);
});

test('issueChallenge binds token to the normalized origin and emits file + DNS forms', () => {
  const ch = issueChallenge('Staging.Example.test', { token: TOKEN });
  assert.equal(ch.origin, 'https://staging.example.test');
  assert.equal(ch.fileUrl, `https://staging.example.test${WELL_KNOWN_DIR}${TOKEN}.txt`);
  assert.equal(ch.checksum, checksumFor(TOKEN, ch.origin));
  assert.ok(ch.fileContents.startsWith(`${TXT_PREFIX}${TOKEN}\nchecksum=${ch.checksum}\n`));
  assert.equal(ch.dnsRecord.name, '_quilltest-challenge.staging.example.test');
  assert.equal(ch.dnsRecord.value, `${TXT_PREFIX}${TOKEN}`);
  assert.ok(Date.parse(ch.expires) - Date.parse(ch.issued) === 24 * 3600_000);
  assert.ok(issueChallenge('https://x.test').token.length >= 52, 'real tokens are 256-bit');
  assert.notEqual(issueChallenge('https://x.test').token, issueChallenge('https://x.test').token);
});

test('checksum changes with origin, so a file cannot be moved to prove another origin', () => {
  assert.notEqual(checksumFor(TOKEN, 'https://a.test'), checksumFor(TOKEN, 'https://b.test'));
  assert.notEqual(checksumFor(TOKEN, 'https://a.test'), checksumFor(TOKEN, 'https://a.test:8443'));
});

test('parseVerificationFile reads the token line and key=value lines, tolerating BOM/CRLF', () => {
  const p = parseVerificationFile('﻿' + `${TXT_PREFIX}abc\r\nchecksum=DEAD\r\norigin=https://x\r\n`);
  assert.equal(p.token, 'abc'); assert.equal(p.checksum, 'DEAD'); assert.equal(p.origin, 'https://x');
  assert.equal(parseVerificationFile('garbage').token, undefined);
});

test('verifyHttp accepts a correct file and reports a non-text/plain content type as a warning', async () => {
  const ch = issueChallenge('https://ok.test', { token: TOKEN });
  const calls = [];
  const fetchImpl = async (url, init) => { calls.push({ url, init }); return res(200, ch.fileContents, { 'content-type': 'text/html' }); };
  const r = await verifyHttp(ch, { fetchImpl });
  assert.equal(r.ok, true);
  assert.equal(calls[0].url, ch.fileUrl);
  assert.equal(calls[0].init.redirect, 'manual', 'redirects must be handled manually');
  assert.match(r.details.warnings[0], /text\/plain/);
});

test('verifyHttp rejects wrong token, wrong checksum, non-200, oversized, and expired', async () => {
  const ch = issueChallenge('https://ok.test', { token: TOKEN });
  assert.match((await verifyHttp(ch, { fetchImpl: async () => res(200, ch.fileContents.replace(TOKEN, 'X'.repeat(52))) })).error, /Token/);
  assert.match((await verifyHttp(ch, { fetchImpl: async () => res(200, ch.fileContents.replace(/checksum=\w+/, 'checksum=00')) })).error, /Checksum/);
  assert.match((await verifyHttp(ch, { fetchImpl: async () => res(404, 'nf') })).error, /got 404/);
  assert.match((await verifyHttp(ch, { fetchImpl: async () => res(200, 'x'.repeat(MAX_FILE_BYTES + 1)) })).error, /larger than/);
  const old = issueChallenge('https://ok.test', { token: TOKEN, now: new Date(Date.now() - 48 * 3600_000) });
  assert.match((await verifyHttp(old, { fetchImpl: async () => res(200, old.fileContents) })).error, /expired/);
});

test('verifyHttp refuses a cross-origin redirect but tolerates one same-origin redirect', async () => {
  const ch = issueChallenge('https://ok.test', { token: TOKEN });
  const cross = await verifyHttp(ch, { fetchImpl: async () => res(302, '', { location: 'https://evil.test/' + TOKEN + '.txt' }) });
  assert.equal(cross.ok, false); assert.match(cross.error, /different origin/);
  let n = 0;
  const same = await verifyHttp(ch, { fetchImpl: async () => (n++ === 0 ? res(301, '', { location: '/.well-known/quilltest-verification/' + TOKEN + '.txt?v=2' }) : res(200, ch.fileContents)) });
  assert.equal(same.ok, true);
  // a redirect to a different port is a different origin
  const port = await verifyHttp(ch, { fetchImpl: async () => res(302, '', { location: 'https://ok.test:8443/x' }) });
  assert.equal(port.ok, false);
});

test('verifyHttp surfaces network/TLS errors without throwing', async () => {
  const ch = issueChallenge('https://ok.test', { token: TOKEN });
  const r = await verifyHttp(ch, { fetchImpl: async () => { const e = new Error('fetch failed'); e.cause = { message: 'CERT_HAS_EXPIRED' }; throw e; } });
  assert.equal(r.ok, false); assert.match(r.error, /CERT_HAS_EXPIRED/);
});

test('verifyDns matches the token in a (possibly chunked) TXT record', async () => {
  const ch = issueChallenge('https://ok.test', { token: TOKEN });
  const good = await verifyDns(ch, { resolveTxt: async (name) => { assert.equal(name, '_quilltest-challenge.ok.test'); return [['other'], [TXT_PREFIX + TOKEN.slice(0, 10), TOKEN.slice(10)]]; } });
  assert.equal(good.ok, true);
  assert.match((await verifyDns(ch, { resolveTxt: async () => [[TXT_PREFIX + 'WRONG']] })).error, /does not contain/);
  assert.match((await verifyDns(ch, { resolveTxt: async () => { const e = new Error('x'); e.code = 'ENOTFOUND'; throw e; } })).error, /ENOTFOUND/);
});

test('verifyChallenge falls back to DNS and never stores the token in the record', async () => {
  const ch = issueChallenge('https://ok.test', { token: TOKEN });
  const r = await verifyChallenge(ch, { fetchImpl: async () => res(404, ''), resolveTxt: async () => [[TXT_PREFIX + TOKEN]] });
  assert.equal(r.ok, true);
  assert.equal(r.record.method, 'dns');
  assert.equal(r.attempts.length, 2);
  assert.ok(!JSON.stringify(r.record).includes(TOKEN), 'token must not be persisted');
  assert.equal(r.record.tokenHash.length, 64);
  const viaHttp = await verifyChallenge(ch, { fetchImpl: async () => res(200, ch.fileContents) });
  assert.ok(!JSON.stringify(viaHttp.record).includes(TOKEN), 'token stripped from details.url too');
  assert.match(viaHttp.record.details.url, /<token>/);
  const none = await verifyChallenge(ch, { fetchImpl: async () => res(404, ''), resolveTxt: async () => [] });
  assert.equal(none.ok, false);
});

test('isOriginVerified is exact-origin and expiry-aware (the scan gate)', () => {
  const rec = { origin: 'https://ok.test', expires: new Date(Date.now() + 3600_000).toISOString() };
  assert.equal(isOriginVerified([rec], 'OK.test').ok, true);
  assert.equal(isOriginVerified([rec], 'https://ok.test/some/path').ok, true, 'path is ignored; origin is what was verified');
  assert.equal(isOriginVerified([rec], 'https://ok.test:8443').ok, false, 'another port is another origin');
  assert.equal(isOriginVerified([rec], 'http://ok.test').ok, false, 'another scheme is another origin');
  assert.equal(isOriginVerified([rec], 'https://sub.ok.test').ok, false, 'a subdomain is another origin');
  assert.match(isOriginVerified([], 'https://ok.test').error, /No ownership verification/);
  const stale = { origin: 'https://ok.test', expires: new Date(Date.now() - 1).toISOString() };
  assert.match(isOriginVerified([stale], 'https://ok.test').error, /expired/);
  assert.equal(isOriginVerified([rec], 'not a url').ok, false);
  assert.equal(isExpired({ expires: 'garbage' }), true, 'unparseable expiry counts as expired');
});

test('store round-trips challenges and records with 0600 permissions and one entry per origin', () => {
  const dir = mkdtempSync(join(tmpdir(), 'qt-store-'));
  try {
    const store = createStore(dir);
    const a = issueChallenge('https://a.test', { token: TOKEN });
    store.saveChallenge(a);
    store.saveChallenge(issueChallenge('https://a.test', { token: 'B'.repeat(52) })); // replaces
    assert.equal(store.loadChallenges().length, 1);
    assert.equal(store.findChallenge('https://a.test').token, 'B'.repeat(52));
    store.removeChallenge('https://a.test');
    assert.equal(store.findChallenge('https://a.test'), null);
    store.saveVerified({ origin: 'https://a.test', expires: 'x' });
    store.saveVerified({ origin: 'https://a.test', expires: 'y' });
    assert.deepEqual(store.loadVerified().map((r) => r.expires), ['y']);
    if (process.platform !== 'win32') {
      assert.equal(statSync(join(dir, 'verified.json')).mode & 0o777, 0o600);
    }
    assert.ok(readFileSync(join(dir, 'verified.json'), 'utf8').includes('"origin"'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
