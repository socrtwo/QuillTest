/*
 * QuillTest — HTTP (file-upload) verification method
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Fetches https://<origin>/.well-known/quilltest-verification/<token>.txt and
 * applies the checks listed in docs/OWNERSHIP-VERIFICATION.md §3:
 *   - HTTP 200
 *   - text/plain content type (anything else is a warning, not a failure)
 *   - token line matches, checksum line matches
 *   - no redirect that changes scheme/host/port (same-origin redirects are
 *     followed a bounded number of times)
 *   - body read is capped at 8 KiB
 * The fetch implementation is injectable for tests.
 */

import { normalizeOrigin } from './origin.mjs';
import {
  MAX_FILE_BYTES,
  matchChallenge,
  parseVerificationFile,
  verificationUrl,
} from './challenge.mjs';

export const DEFAULT_TIMEOUT_MS = 15_000;
export const MAX_REDIRECTS = 3;

/**
 * @typedef {Object} VerifyResult
 * @property {boolean}  ok
 * @property {'http'}   method
 * @property {string}   origin
 * @property {string}   url          final URL fetched
 * @property {number|null} status
 * @property {string[]} reasons      why it failed (empty when ok)
 * @property {string[]} warnings     non-fatal observations
 * @property {string}   checkedAt    ISO-8601 UTC
 */

/**
 * @param {import('./challenge.mjs').Challenge} challenge
 * @param {{fetch?:typeof fetch, timeoutMs?:number, maxBytes?:number, now?:Date, userAgent?:string}} [opts]
 * @returns {Promise<VerifyResult>}
 */
export async function verifyByHttp(challenge, opts = {}) {
  const {
    fetch: fetchImpl = globalThis.fetch,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    maxBytes = MAX_FILE_BYTES,
    now = new Date(),
    userAgent = 'QuillTest-Verifier/0.1 (+https://github.com/socrtwo/QuillTest)',
  } = opts;
  if (typeof fetchImpl !== 'function') throw new TypeError('No fetch implementation available (Node 18+ required)');

  const reasons = [];
  const warnings = [];
  const startUrl = verificationUrl(challenge);
  let url = startUrl;
  let status = null;

  try {
    let res = null;
    for (let hop = 0; ; hop++) {
      res = await fetchImpl(url, {
        method: 'GET',
        redirect: 'manual',
        headers: { accept: 'text/plain', 'user-agent': userAgent },
        signal: AbortSignal.timeout(timeoutMs),
      });
      status = res.status;
      if (status >= 300 && status < 400) {
        const location = res.headers.get('location');
        if (!location) {
          reasons.push(`HTTP ${status} redirect without a Location header`);
          return finish();
        }
        const next = new URL(location, url).toString();
        if (normalizeOrigin(next) !== challenge.origin) {
          reasons.push(`redirected off-origin to ${new URL(next).origin}; a verification file must be served by the origin being verified`);
          return finish();
        }
        if (hop >= MAX_REDIRECTS) {
          reasons.push(`more than ${MAX_REDIRECTS} redirects`);
          return finish();
        }
        warnings.push(`followed same-origin redirect ${status} to ${next}`);
        url = next;
        continue;
      }
      if (status !== 200) {
        reasons.push(`HTTP ${status} fetching ${url} (expected 200)`);
        return finish();
      }

      const type = (res.headers.get('content-type') || '').toLowerCase();
      if (!type) warnings.push('response has no Content-Type header (expected text/plain)');
      else if (!type.startsWith('text/plain')) warnings.push(`Content-Type is ${type.split(';')[0]} (expected text/plain)`);

      const { text, truncated } = await readCapped(res, maxBytes);
      if (truncated) {
        reasons.push(`response body exceeds ${maxBytes} bytes; the verification file must be small`);
        return finish();
      }
      const parsed = parseVerificationFile(text);
      const match = matchChallenge(challenge, parsed, now);
      reasons.push(...match.reasons);
      return finish();
    }
  } catch (e) {
    reasons.push(describeFetchError(e, url));
    return finish();
  }

  function finish() {
    return {
      ok: reasons.length === 0,
      method: 'http',
      origin: challenge.origin,
      url,
      status,
      reasons,
      warnings,
      checkedAt: now.toISOString().replace(/\.\d{3}Z$/, 'Z'),
    };
  }
}

/** Read at most `maxBytes` of a body; report whether more was available. */
async function readCapped(res, maxBytes) {
  if (!res.body || typeof res.body.getReader !== 'function') {
    const buf = Buffer.from(await res.arrayBuffer());
    return { text: buf.subarray(0, maxBytes).toString('utf8'), truncated: buf.length > maxBytes };
  }
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => {});
        return { text: '', truncated: true };
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock?.();
  }
  return { text: Buffer.concat(chunks).toString('utf8'), truncated: false };
}

function describeFetchError(e, url) {
  if (e?.name === 'TimeoutError') return `no response from ${url} within the timeout`;
  const cause = e?.cause?.code || e?.cause?.message;
  return `could not fetch ${url}: ${e?.message || e}${cause ? ` (${cause})` : ''}`;
}
