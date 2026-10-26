/*
 * Anne's Test — ownership verification
 * Part of the Anne's Office suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Every scan is gated behind proof that the operator controls the target
 * origin. The contract is docs/OWNERSHIP-VERIFICATION.md:
 *
 *   1. issueChallenge(origin) → a 256-bit token bound to the exact origin,
 *      a verification file to upload at
 *        https://<origin>/.well-known/quilltest-verification/<token>.txt
 *      and an equivalent DNS TXT record for hosts where files can't be placed.
 *   2. verifyChallenge(challenge) fetches that file over the exact origin and
 *      checks: HTTP 200, no cross-origin redirect, body ≤ 8 KiB, first line
 *      carries the token, checksum line matches sha256(token + "\n" + origin).
 *      Or resolves the TXT record. Either proof unlocks that origin only.
 *   3. A verification record carries an expiry; the scan gate refuses expired
 *      or missing records. There is no override.
 *
 * Everything network-facing takes injectable fetch/DNS so it is testable offline.
 */

import { randomBytes, createHash } from 'node:crypto';

export const WELL_KNOWN_DIR = '/.well-known/quilltest-verification/';
export const DNS_LABEL = '_quilltest-challenge';
export const TXT_PREFIX = 'quilltest-site-verification=';
export const MAX_FILE_BYTES = 8 * 1024;
export const DEFAULT_TTL_HOURS = 24;
export const DEFAULT_TIMEOUT_MS = 15_000;

// ---------------------------------------------------------------------------
// Origin normalization
// ---------------------------------------------------------------------------

/**
 * Normalize to scheme://host[:port] — lowercase, explicit port only when
 * non-default, no path, no trailing slash. Throws on anything that is not a
 * plain http(s) origin.
 */
export function normalizeOrigin(input) {
  if (typeof input !== 'string' || !input.trim()) throw new Error('Origin is required');
  let s = input.trim();
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'https://' + s;
  let u;
  try { u = new URL(s); } catch { throw new Error(`Not a valid origin: ${input}`); }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error(`Origin must be http(s), got ${u.protocol.replace(/:$/, '')}`);
  if (u.username || u.password) throw new Error('Origin must not contain credentials');
  if (!u.hostname) throw new Error(`Not a valid origin: ${input}`);
  const defaultPort = u.protocol === 'https:' ? '443' : '80';
  const port = u.port && u.port !== defaultPort ? `:${u.port}` : '';
  return `${u.protocol}//${u.hostname.toLowerCase()}${port}`;
}

/** Host part of a normalized origin, without port (used for the DNS label). */
export function hostOf(origin) {
  return new URL(origin).hostname;
}

// ---------------------------------------------------------------------------
// Challenge issuance
// ---------------------------------------------------------------------------

/** 256 bits as unpadded base32 (RFC 4648 alphabet), URL- and filename-safe. */
export function base32(buf) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0, out = '';
  for (const byte of buf) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}

export function checksumFor(token, origin) {
  return createHash('sha256').update(`${token}\n${origin}`, 'utf8').digest('hex');
}

/**
 * @param {string} originInput
 * @param {{ttlHours?:number, now?:Date, token?:string}} [opts]  (token is for tests only)
 */
export function issueChallenge(originInput, opts = {}) {
  const origin = normalizeOrigin(originInput);
  const token = opts.token || base32(randomBytes(32));
  const now = opts.now || new Date();
  const ttl = Number.isFinite(opts.ttlHours) && opts.ttlHours > 0 ? opts.ttlHours : DEFAULT_TTL_HOURS;
  const issued = now.toISOString();
  const expires = new Date(now.getTime() + ttl * 3600_000).toISOString();
  const checksum = checksumFor(token, origin);
  const fileName = `${token}.txt`;
  const filePath = WELL_KNOWN_DIR + fileName;
  const fileContents = [
    `${TXT_PREFIX}${token}`,
    `checksum=${checksum}`,
    `issued=${issued}`,
    `origin=${origin}`,
    `expires=${expires}`,
    '',
  ].join('\n');
  return {
    origin, token, checksum, issued, expires,
    fileName, filePath, fileUrl: origin + filePath, fileContents,
    dnsRecord: { name: `${DNS_LABEL}.${hostOf(origin)}`, type: 'TXT', value: `${TXT_PREFIX}${token}` },
  };
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

export function isExpired(challengeOrRecord, now = new Date()) {
  const t = Date.parse(challengeOrRecord?.expires || '');
  return !Number.isFinite(t) || t <= now.getTime();
}

function sameOrigin(a, b) {
  try { return normalizeOrigin(a) === normalizeOrigin(b); } catch { return false; }
}

/** Parse the verification file body into key/value pairs (first line is the token line). */
export function parseVerificationFile(body) {
  const lines = String(body ?? '').replace(/^﻿/, '').split(/\r?\n/);
  const out = {};
  const first = (lines[0] || '').trim();
  if (first.startsWith(TXT_PREFIX)) out.token = first.slice(TXT_PREFIX.length).trim();
  for (const line of lines.slice(1)) {
    const m = line.match(/^([a-z]+)=(.*)$/i);
    if (m) out[m[1].toLowerCase()] = m[2].trim();
  }
  return out;
}

/**
 * Verify via the well-known file over HTTP(S).
 * @param {object} challenge  from issueChallenge (or a stored copy)
 * @param {{fetchImpl?:Function, timeoutMs?:number, now?:Date}} [opts]
 * @returns {Promise<{ok:boolean, method:'http', error?:string, details?:object}>}
 */
export async function verifyHttp(challenge, opts = {}) {
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  const timeoutMs = opts.timeoutMs || DEFAULT_TIMEOUT_MS;
  const now = opts.now || new Date();
  const method = 'http';
  if (isExpired(challenge, now)) return { ok: false, method, error: 'Challenge has expired; issue a new one.' };

  const url = challenge.origin + WELL_KNOWN_DIR + challenge.token + '.txt';
  let res;
  try {
    res = await fetchImpl(url, {
      method: 'GET',
      redirect: 'manual',
      headers: { accept: 'text/plain', 'user-agent': 'QuillTest-Verify/0.1 (+ownership check)' },
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (e) {
    const msg = e?.name === 'TimeoutError' ? `No response within ${timeoutMs / 1000}s` : (e?.cause?.message || e.message);
    return { ok: false, method, error: `Could not fetch ${url}: ${msg}` };
  }

  // Redirects: a same-origin redirect is tolerated once by re-fetching; a
  // cross-origin redirect fails outright — otherwise an open redirect on the
  // target could be used to "prove" ownership of a site you don't control.
  if (res.status >= 300 && res.status < 400) {
    const loc = res.headers.get('location') || '';
    let abs; try { abs = new URL(loc, url).toString(); } catch { abs = ''; }
    if (!abs || !sameOrigin(abs, challenge.origin)) {
      return { ok: false, method, error: `Verification file redirected to a different origin (${loc || 'unknown'}); refusing.` };
    }
    // The redirect must also stay at the well-known path: on a shared origin a tenant who can
    // publish under /uploads/ but not /.well-known/ must not be able to satisfy the check.
    if (new URL(abs).pathname !== WELL_KNOWN_DIR + challenge.token + '.txt') {
      return { ok: false, method, error: `Verification file redirected away from ${WELL_KNOWN_DIR} (${loc}); refusing.` };
    }
    try {
      res = await fetchImpl(abs, { method: 'GET', redirect: 'manual', headers: { accept: 'text/plain', 'user-agent': 'QuillTest-Verify/0.1 (+ownership check)' }, signal: AbortSignal.timeout(timeoutMs) });
    } catch (e) {
      return { ok: false, method, error: `Could not fetch ${abs}: ${e?.cause?.message || e.message}` };
    }
    if (res.status >= 300 && res.status < 400) return { ok: false, method, error: 'Too many redirects for the verification file.' };
  }

  if (res.status !== 200) return { ok: false, method, error: `Expected HTTP 200 for ${url}, got ${res.status}.` };

  const declared = Number.parseInt(res.headers.get('content-length') || '', 10);
  if (Number.isFinite(declared) && declared > MAX_FILE_BYTES) return { ok: false, method, error: `Verification file is larger than ${MAX_FILE_BYTES} bytes; refusing.` };
  const text = await readCapped(res, MAX_FILE_BYTES);
  if (text === null) return { ok: false, method, error: `Verification file is larger than ${MAX_FILE_BYTES} bytes; refusing.` };

  const parsed = parseVerificationFile(text);
  const warnings = [];
  const ct = (res.headers.get('content-type') || '').toLowerCase();
  if (ct && !ct.startsWith('text/plain')) warnings.push(`Content-Type is "${ct}", expected text/plain.`);

  if (parsed.token !== challenge.token) return { ok: false, method, error: 'Token in the verification file does not match the issued token.' };
  const expected = checksumFor(challenge.token, challenge.origin);
  if ((parsed.checksum || '').toLowerCase() !== expected) return { ok: false, method, error: 'Checksum in the verification file does not match (token/origin mismatch or edited file).' };

  return { ok: true, method, details: { url, contentType: ct || null, warnings } };
}

/** Read a response body up to `max` bytes; null when it is larger (the download stops there). */
async function readCapped(res, max) {
  if (res.body && typeof res.body.getReader === 'function') {
    const reader = res.body.getReader();
    const chunks = []; let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > max) { try { await reader.cancel(); } catch { /* ignore */ } return null; }
      chunks.push(value);
    }
    return Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
  }
  const text = await res.text();
  return Buffer.byteLength(text, 'utf8') > max ? null : text;
}

/**
 * Verify via a DNS TXT record: _quilltest-challenge.<host> TXT "quilltest-site-verification=<token>"
 * @param {object} challenge
 * @param {{resolveTxt?:(name:string)=>Promise<string[][]>, now?:Date}} [opts]
 */
export async function verifyDns(challenge, opts = {}) {
  const method = 'dns';
  const now = opts.now || new Date();
  if (isExpired(challenge, now)) return { ok: false, method, error: 'Challenge has expired; issue a new one.' };
  let resolveTxt = opts.resolveTxt;
  if (!resolveTxt) {
    const dns = await import('node:dns/promises');
    resolveTxt = (name) => dns.resolveTxt(name);
  }
  const name = `${DNS_LABEL}.${hostOf(challenge.origin)}`;
  let records;
  try { records = await resolveTxt(name); } catch (e) {
    return { ok: false, method, error: `No TXT record at ${name} (${e?.code || e.message}).` };
  }
  const values = (records || []).map((chunks) => (Array.isArray(chunks) ? chunks.join('') : String(chunks)).trim());
  const want = `${TXT_PREFIX}${challenge.token}`;
  if (!values.includes(want)) return { ok: false, method, error: `TXT record at ${name} does not contain the issued token.` };
  return { ok: true, method, details: { name } };
}

/**
 * Try HTTP first, then DNS. Returns a verification record on success.
 * @returns {Promise<{ok:boolean, record?:object, attempts:object[]}>}
 */
export async function verifyChallenge(challenge, opts = {}) {
  const attempts = [];
  const http = await verifyHttp(challenge, opts);
  attempts.push(http);
  let winner = http.ok ? http : null;
  if (!winner && opts.tryDns !== false) {
    const dns = await verifyDns(challenge, opts);
    attempts.push(dns);
    if (dns.ok) winner = dns;
  }
  if (!winner) return { ok: false, attempts };
  const now = opts.now || new Date();
  // Never persist the token itself: hash it, and strip it from any detail
  // (the well-known URL contains it).
  const details = JSON.parse(JSON.stringify(winner.details || {}).split(challenge.token).join('<token>'));
  // The record is valid for the challenge's TTL counted from *verification*, not from issuance:
  // otherwise a file placed 23 hours after `verify issue` would unlock scanning for one hour.
  const ttlMs = Date.parse(challenge.expires) - Date.parse(challenge.issued);
  const expires = Number.isFinite(ttlMs) && ttlMs > 0 ? new Date(now.getTime() + ttlMs).toISOString() : challenge.expires;
  const record = {
    origin: challenge.origin,
    tokenHash: createHash('sha256').update(challenge.token).digest('hex'),
    method: winner.method,
    verifiedAt: now.toISOString(),
    expires,
    challengeExpires: challenge.expires,
    details,
  };
  return { ok: true, record, attempts };
}

/** The scan gate: is there a valid, unexpired record for exactly this origin? */
export function isOriginVerified(records, originInput, now = new Date()) {
  let origin; try { origin = normalizeOrigin(originInput); } catch { return { ok: false, error: 'Invalid origin' }; }
  const rec = (records || []).find((r) => r.origin === origin);
  if (!rec) return { ok: false, origin, error: `No ownership verification on file for ${origin}. Run: quilltest verify issue ${origin}` };
  if (isExpired(rec, now)) return { ok: false, origin, error: `Ownership verification for ${origin} expired at ${rec.expires}. Issue and verify a new challenge.` };
  return { ok: true, origin, record: rec };
}

/**
 * The protocol-scan gate. Protocol checks target a host, not a web origin, so
 * any unexpired verification record whose origin's hostname equals this host
 * (http or https, any port) authorizes checking that host's services. Proving
 * control of https://example.com is proof of control of the host example.com.
 */
export function isHostVerified(records, hostInput, now = new Date()) {
  const host = String(hostInput || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!host || /[/\\\s]/.test(host)) return { ok: false, host, error: `Invalid host: ${hostInput}` };
  // hostOf() keeps the brackets of an IPv6 literal; the input had them stripped above.
  const matches = (records || []).filter((r) => { try { return hostOf(r.origin).toLowerCase().replace(/^\[|\]$/g, '') === host; } catch { return false; } });
  if (!matches.length) return { ok: false, host, error: `No ownership verification on file for host ${host}. Run: quilltest verify issue https://${host}` };
  const valid = matches.find((r) => !isExpired(r, now));
  if (!valid) return { ok: false, host, error: `Ownership verification for ${host} has expired. Issue and verify a new challenge.` };
  return { ok: true, host, record: valid };
}
