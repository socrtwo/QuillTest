/*
 * QuillTest — ownership verification: origin, challenge, store, DNS, gate
 * Run: npm test
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  normalizeOrigin, parseOrigin, sameOrigin, InvalidOriginError,
  issueChallenge, generateToken, base32Encode, isValidToken, computeChecksum, hashToken,
  renderVerificationFile, parseVerificationFile, matchChallenge, isExpired,
  wellKnownPath, verificationUrl, dnsRecordName, dnsRecordValue, DEFAULT_TTL_MS,
  verifyByDns, dnsMethodAvailable, verifyChallenge, METHODS,
  VerificationStore, VerificationRequiredError, DEFAULT_VERIFIED_TTL_MS,
} from '../src/verify/index.mjs';

// ----- origin ------------------------------------------------------------------

test('normalizeOrigin: scheme/host lowercase, default port dropped, path/query/fragment removed', () => {
  assert.equal(normalizeOrigin('HTTPS://Example.COM:443/path?q=1#f'), 'https://example.com');
  assert.equal(normalizeOrigin('http://Example.com:80/'), 'http://example.com');
  assert.equal(normalizeOrigin('http://example.com:8080'), 'http://example.com:8080');
  assert.equal(normalizeOrigin('https://example.com:80'), 'https://example.com:80');
  assert.equal(normalizeOrigin('  example.com  '), 'https://example.com', 'bare host defaults to https');
  assert.equal(normalizeOrigin('localhost:3000'), 'https://localhost:3000');
  assert.equal(normalizeOrigin('http://[::1]:8080/x'), 'http://[::1]:8080');
});

test('normalizeOrigin rejects non-http schemes, credentials and garbage', () => {
  for (const bad of ['', '   ', 'ftp://example.com', 'file:///etc/passwd', 'javascript:alert(1)', 'https://user:pw@example.com', 'http://']) {
    assert.throws(() => normalizeOrigin(bad), InvalidOriginError, bad);
  }
});

test('parseOrigin and sameOrigin', () => {
  assert.deepEqual(parseOrigin('https://example.com'), { scheme: 'https', host: 'example.com', port: 443 });
  assert.deepEqual(parseOrigin('http://example.com:8080'), { scheme: 'http', host: 'example.com', port: 8080 });
  assert.equal(sameOrigin('HTTPS://EXAMPLE.com/', 'example.com'), true);
  assert.equal(sameOrigin('https://example.com', 'https://www.example.com'), false);
  assert.equal(sameOrigin('https://example.com', 'http://example.com'), false);
  assert.equal(sameOrigin('nope://x', 'https://x'), false);
});

// ----- token / challenge ---------------------------------------------------------

test('base32 matches RFC 4648 test vectors (unpadded)', () => {
  assert.equal(base32Encode(Buffer.from('')), '');
  assert.equal(base32Encode(Buffer.from('f')), 'MY');
  assert.equal(base32Encode(Buffer.from('fo')), 'MZXQ');
  assert.equal(base32Encode(Buffer.from('foo')), 'MZXW6');
  assert.equal(base32Encode(Buffer.from('foob')), 'MZXW6YQ');
  assert.equal(base32Encode(Buffer.from('fooba')), 'MZXW6YTB');
  assert.equal(base32Encode(Buffer.from('foobar')), 'MZXW6YTBOI');
});

test('tokens are 256-bit base32 without padding and unique', () => {
  const a = generateToken();
  const b = generateToken();
  assert.ok(isValidToken(a), a);
  assert.equal(a.length, 52);
  assert.notEqual(a, b);
  assert.equal(isValidToken(a.toLowerCase()), false);
  assert.equal(isValidToken(a + 'A'), false);
  assert.equal(isValidToken('MZXW6YTB'), false);
});

test('issueChallenge binds token to the normalized origin with a 24h default expiry', () => {
  const now = new Date('2026-10-22T14:00:00Z');
  const c = issueChallenge('HTTPS://Example.com/anything', { now });
  assert.equal(c.origin, 'https://example.com');
  assert.ok(isValidToken(c.token));
  assert.equal(c.issued, '2026-10-22T14:00:00Z');
  assert.equal(c.expires, '2026-10-23T14:00:00Z');
  assert.equal(DEFAULT_TTL_MS, 86_400_000);
  const expected = createHash('sha256').update(`${c.token}\nhttps://example.com`).digest('hex');
  assert.equal(c.checksum, expected);
  assert.equal(computeChecksum(c.token, 'https://EXAMPLE.com:443'), expected, 'checksum uses the normalized origin');
  assert.equal(isExpired(c, now), false);
  assert.equal(isExpired(c, new Date('2026-10-23T14:00:00Z')), true);
  assert.throws(() => issueChallenge('https://example.com', { ttlMs: 0 }), RangeError);
});

test('paths, URLs and DNS record follow the documented contract', () => {
  const c = issueChallenge('https://example.com:8443', { now: new Date('2026-10-22T14:00:00Z') });
  assert.equal(wellKnownPath(c), `/.well-known/quilltest-verification/${c.token}.txt`);
  assert.equal(verificationUrl(c), `https://example.com:8443/.well-known/quilltest-verification/${c.token}.txt`);
  assert.equal(dnsRecordName(c), '_quilltest-challenge.example.com');
  assert.equal(dnsRecordValue(c), `quilltest-site-verification=${c.token}`);
});

test('verification file renders per the reference format and round-trips through the parser', () => {
  const c = issueChallenge('https://example.com', { now: new Date('2026-10-22T14:00:00Z') });
  const text = renderVerificationFile(c);
  const lines = text.split('\n');
  assert.equal(lines[0], `quilltest-site-verification=${c.token}`);
  assert.equal(lines[1], `checksum=${c.checksum}`);
  assert.equal(lines[2], 'issued=2026-10-22T14:00:00Z');
  assert.equal(lines[3], 'origin=https://example.com');
  assert.equal(lines[4], 'expires=2026-10-23T14:00:00Z');
  assert.equal(lines[5], '', 'file ends with a newline');
  const parsed = parseVerificationFile(text);
  assert.equal(parsed.token, c.token);
  assert.equal(parsed.checksum, c.checksum);
  assert.deepEqual(matchChallenge(c, parsed, new Date('2026-10-22T15:00:00Z')), { ok: true, reasons: [] });
});

test('parser tolerates BOM, CRLF, whitespace, comments, upper-case keys/hex; keeps first duplicate', () => {
  const c = issueChallenge('https://example.com');
  const messy = `﻿  QUILLTEST-SITE-VERIFICATION = ${c.token} \r\n# comment\r\n\r\nChecksum=${c.checksum.toUpperCase()}\r\nchecksum=deadbeef\r\nnoequals\r\n`;
  const parsed = parseVerificationFile(messy);
  assert.equal(parsed.token, c.token);
  assert.equal(parsed.checksum, c.checksum);
  assert.equal(matchChallenge(c, parsed).ok, true);
});

test('matchChallenge rejects wrong token, wrong checksum, missing lines, expired challenge', () => {
  const now = new Date('2026-10-22T14:00:00Z');
  const c = issueChallenge('https://example.com', { now });
  const other = issueChallenge('https://example.com', { now });

  let r = matchChallenge(c, parseVerificationFile(renderVerificationFile(other)), now);
  assert.equal(r.ok, false);
  assert.match(r.reasons.join(' | '), /token in file does not match/);
  assert.match(r.reasons.join(' | '), /checksum does not match/);

  // Same token, but a checksum computed for a different origin: binding must hold.
  const crossOrigin = `quilltest-site-verification=${c.token}\nchecksum=${computeChecksum(c.token, 'https://evil.example')}\n`;
  r = matchChallenge(c, parseVerificationFile(crossOrigin), now);
  assert.deepEqual(r.reasons, ['checksum does not match sha256(token + "\\n" + origin)']);

  r = matchChallenge(c, parseVerificationFile('hello world'), now);
  assert.deepEqual(r.reasons, ['file has no quilltest-site-verification line', 'file has no checksum line']);

  r = matchChallenge(c, parseVerificationFile(renderVerificationFile(c)), new Date('2026-10-24T00:00:00Z'));
  assert.deepEqual(r.reasons, ['challenge expired at 2026-10-23T14:00:00Z']);
});

test('hashToken is sha256 hex of the token', () => {
  assert.equal(hashToken('abc'), createHash('sha256').update('abc').digest('hex'));
});

// ----- DNS method ---------------------------------------------------------------

test('verifyByDns accepts the matching TXT record (including chunked values) and rejects others', async () => {
  const c = issueChallenge('https://example.com');
  const value = dnsRecordValue(c);
  const split = [value.slice(0, 30), value.slice(30)];

  let r = await verifyByDns(c, { resolveTxt: async (name) => { assert.equal(name, '_quilltest-challenge.example.com'); return [['v=spf1 -all'], split]; } });
  assert.equal(r.ok, true, r.reasons.join('; '));
  assert.equal(r.method, 'dns');
  assert.equal(r.name, '_quilltest-challenge.example.com');

  r = await verifyByDns(c, { resolveTxt: async () => [[`quilltest-site-verification=${generateToken()}`]] });
  assert.equal(r.ok, false);
  assert.match(r.reasons[0], /different token/);

  r = await verifyByDns(c, { resolveTxt: async () => [['v=spf1 -all']] });
  assert.match(r.reasons[0], /no quilltest-site-verification value/);

  r = await verifyByDns(c, { resolveTxt: async () => { throw Object.assign(new Error('queryTxt ENOTFOUND'), { code: 'ENOTFOUND' }); } });
  assert.deepEqual(r.reasons, ['no TXT record found at _quilltest-challenge.example.com']);

  r = await verifyByDns(c, { resolveTxt: async () => { throw Object.assign(new Error('timeout'), { code: 'ETIMEOUT' }); } });
  assert.match(r.reasons[0], /DNS lookup .* failed: timeout/);

  r = await verifyByDns(c, { resolveTxt: async () => [[value]], now: new Date(new Date(c.expires).getTime() + 1) });
  assert.match(r.reasons[0], /expired/);

  r = await verifyByDns(c, { resolveTxt: async () => [[value], [`quilltest-site-verification=${generateToken()}`]] });
  assert.equal(r.ok, true);
  assert.equal(r.warnings.length, 1, 'stale extra record is a warning, not a failure');
});

test('DNS method is unavailable for IP-literal origins', async () => {
  const ipv4 = issueChallenge('http://127.0.0.1:8080');
  const ipv6 = issueChallenge('http://[::1]:8080');
  const named = issueChallenge('https://example.com');
  assert.equal(dnsMethodAvailable(ipv4), false);
  assert.equal(dnsMethodAvailable(ipv6), false);
  assert.equal(dnsMethodAvailable(named), true);
  let called = false;
  const r = await verifyByDns(ipv4, { resolveTxt: async () => { called = true; return [[dnsRecordValue(ipv4)]]; } });
  assert.equal(r.ok, false);
  assert.equal(called, false, 'no DNS query is made for an IP host');
  assert.match(r.reasons[0], /IP address; the DNS method needs a host name/);
});

test('verifyChallenge dispatches on method and rejects unknown ones', async () => {
  const c = issueChallenge('https://example.com');
  assert.deepEqual(METHODS, ['http', 'dns']);
  const r = await verifyChallenge(c, 'dns', { resolveTxt: async () => [[dnsRecordValue(c)]] });
  assert.equal(r.ok, true);
  assert.throws(() => verifyChallenge(c, 'carrier-pigeon'), RangeError);
});

// ----- store + gate ---------------------------------------------------------------

function clock(startIso) {
  let t = new Date(startIso).getTime();
  const fn = () => new Date(t);
  fn.advance = (ms) => { t += ms; };
  return fn;
}

test('store: issue → pending → complete → verified; token is discarded, hash kept', () => {
  const now = clock('2026-10-22T14:00:00Z');
  const store = new VerificationStore({ now });
  assert.equal(store.pending('https://example.com'), null);

  const c = store.issue('Example.com');
  assert.equal(c.origin, 'https://example.com');
  assert.deepEqual(store.pending('https://example.com/'), c);
  assert.equal(store.isVerified('https://example.com'), false);

  const record = store.complete(c, { ok: true, method: 'http', origin: c.origin, url: verificationUrl(c), warnings: ['Content-Type is text/html (expected text/plain)'] }, { targetAddress: '203.0.113.7' });
  assert.equal(record.origin, 'https://example.com');
  assert.equal(record.tokenHash, hashToken(c.token));
  assert.equal(record.method, 'http');
  assert.equal(record.verifiedAt, '2026-10-22T14:00:00Z');
  assert.equal(record.validUntil, '2026-11-21T14:00:00Z');
  assert.equal(record.targetAddress, '203.0.113.7');
  assert.equal(record.url, 'https://example.com/.well-known/quilltest-verification/<token>.txt', 'token redacted from the recorded URL');
  assert.deepEqual(record.warnings, ['Content-Type is text/html (expected text/plain)']);
  assert.equal(JSON.stringify(store.data).includes(c.token), false, 'the raw token must not persist after verification');
  assert.equal(store.pending('https://example.com'), null);
  assert.equal(store.isVerified('https://example.com'), true);
  assert.equal(DEFAULT_VERIFIED_TTL_MS, 30 * 86_400_000);
});

test('store refuses to complete from a failed or mismatched result', () => {
  const store = new VerificationStore();
  const c = store.issue('https://example.com');
  assert.throws(() => store.complete(c, { ok: false, method: 'http', origin: c.origin }), /successful verifier result/);
  assert.throws(() => store.complete(c, { ok: true, method: 'http', origin: 'https://other.example' }), /different origin/);
  assert.equal(store.isVerified('https://example.com'), false);
});

test('gate: assertVerified is exact-origin and time-bounded; pending challenges expire', () => {
  const now = clock('2026-10-22T14:00:00Z');
  const store = new VerificationStore({ now });
  assert.throws(() => store.assertVerified('https://example.com'), VerificationRequiredError);

  const c = store.issue('https://example.com', { ttlMs: 60_000 });
  now.advance(60_000);
  assert.equal(store.pending('https://example.com'), null, 'pending challenge pruned once expired');

  const c2 = store.issue('https://example.com');
  store.complete(c2, { ok: true, method: 'dns', origin: c2.origin, name: dnsRecordName(c2) });
  assert.equal(store.assertVerified('HTTPS://EXAMPLE.COM/').origin, 'https://example.com');

  for (const other of ['http://example.com', 'https://www.example.com', 'https://example.com:8443', 'https://sub.example.com']) {
    assert.throws(() => store.assertVerified(other), (e) => e instanceof VerificationRequiredError && e.origin === normalizeOrigin(other), other);
  }

  now.advance(DEFAULT_VERIFIED_TTL_MS);
  assert.throws(() => store.assertVerified('https://example.com'), /expired on 2026-11-21T14:01:00Z/);
  assert.equal(store.get('https://example.com'), null);
  assert.equal(store.list().verified[0].expired, true);

  assert.equal(store.revoke('https://example.com'), true);
  assert.equal(store.revoke('https://example.com'), false);
  assert.equal(store.cancel('https://nothing.example'), false);
  void c;
});

test('store persists to disk with mode 0600 and reloads; rejects unknown versions', async () => {
  const { mkdtempSync, statSync, readFileSync, writeFileSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { tmpdir } = await import('node:os');
  const dir = mkdtempSync(join(tmpdir(), 'quilltest-verify-'));
  const path = join(dir, 'nested', 'quilltest.verifications.json');

  const store = VerificationStore.load(path, { now: clock('2026-10-22T14:00:00Z') });
  const c = store.issue('https://example.com');
  store.complete(c, { ok: true, method: 'http', origin: c.origin, url: verificationUrl(c) });
  if (process.platform !== 'win32') assert.equal(statSync(path).mode & 0o777, 0o600);

  const again = VerificationStore.load(path, { now: clock('2026-10-23T14:00:00Z') });
  assert.equal(again.isVerified('https://example.com'), true);
  assert.equal(again.get('https://example.com').tokenHash, hashToken(c.token));
  assert.equal(JSON.parse(readFileSync(path, 'utf8')).version, 1);

  writeFileSync(path, JSON.stringify({ version: 99 }));
  assert.throws(() => VerificationStore.load(path), /Unsupported verification store version 99/);
});
