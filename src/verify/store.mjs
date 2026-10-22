/*
 * QuillTest — verification records store and the scan gate
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Keeps pending challenges (which must hold the secret token until the user
 * has published it) and completed verification records (which hold only the
 * token hash). Persisted as JSON; file-backed by default, in-memory for tests.
 *
 * The gate is assertVerified(): the scan orchestrator calls it before any
 * request to a target and refuses to run when it throws. There is no bypass
 * flag, by design (docs/OWNERSHIP-VERIFICATION.md).
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync } from 'node:fs';
import { dirname } from 'node:path';
import { normalizeOrigin } from './origin.mjs';
import { hashToken, isExpired, issueChallenge } from './challenge.mjs';

export const STORE_VERSION = 1;
/** How long a successful verification stays valid before it must be redone. */
export const DEFAULT_VERIFIED_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

export class VerificationRequiredError extends Error {
  constructor(origin, detail) {
    super(`Scanning ${origin} is not permitted: ${detail}. Run the ownership verification for this exact origin first.`);
    this.name = 'VerificationRequiredError';
    this.origin = origin;
    this.detail = detail;
  }
}

/**
 * @typedef {Object} VerificationRecord
 * @property {string} origin
 * @property {string} tokenHash     sha256 of the token that was verified
 * @property {'http'|'dns'} method
 * @property {string} verifiedAt    ISO-8601 UTC
 * @property {string} validUntil    ISO-8601 UTC
 * @property {string} [url]         for http: final URL fetched, token replaced by "<token>"
 * @property {string} [dnsName]     for dns: TXT owner name
 * @property {string} [targetAddress]  IP the target host resolved to at verification time (best effort)
 * @property {string[]} warnings
 */

export class VerificationStore {
  /**
   * @param {{path?:string|null, data?:object, now?:()=>Date, verifiedTtlMs?:number}} [opts]
   *   path: JSON file to load/save; omit (or null) for an in-memory store.
   */
  constructor({ path = null, data = null, now = () => new Date(), verifiedTtlMs = DEFAULT_VERIFIED_TTL_MS } = {}) {
    this.path = path;
    this.now = now;
    this.verifiedTtlMs = verifiedTtlMs;
    this.data = normalizeData(data ?? (path && existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : null));
  }

  static load(path, opts = {}) {
    return new VerificationStore({ ...opts, path });
  }

  save() {
    if (!this.path) return;
    mkdirSync(dirname(this.path), { recursive: true });
    writeFileSync(this.path, JSON.stringify(this.data, null, 2) + '\n', { mode: 0o600 });
    try { chmodSync(this.path, 0o600); } catch { /* best effort */ }
  }

  // ----- challenges ----------------------------------------------------------

  /** Issue (and remember) a challenge for an origin, replacing any pending one. */
  issue(originInput, { ttlMs } = {}) {
    const challenge = issueChallenge(originInput, { ttlMs, now: this.now() });
    this.data.pending[challenge.origin] = challenge;
    this.save();
    return challenge;
  }

  /** The pending challenge for an origin, or null (expired ones are pruned). */
  pending(originInput) {
    const origin = normalizeOrigin(originInput);
    const c = this.data.pending[origin];
    if (!c) return null;
    if (isExpired(c, this.now())) {
      delete this.data.pending[origin];
      this.save();
      return null;
    }
    return c;
  }

  cancel(originInput) {
    const origin = normalizeOrigin(originInput);
    const had = Boolean(this.data.pending[origin]);
    delete this.data.pending[origin];
    this.save();
    return had;
  }

  // ----- verification outcome --------------------------------------------------

  /**
   * Record a successful verifier result for a pending challenge. Discards the
   * token (keeps its hash) and the pending challenge.
   * @param {import('./challenge.mjs').Challenge} challenge
   * @param {{ok:boolean, method:'http'|'dns', url?:string, name?:string, warnings?:string[]}} result
   * @param {{targetAddress?:string}} [extra]
   * @returns {VerificationRecord}
   */
  complete(challenge, result, { targetAddress } = {}) {
    if (!result?.ok) throw new Error('complete() requires a successful verifier result');
    if (result.origin && result.origin !== challenge.origin) throw new Error('verifier result is for a different origin');
    const at = this.now();
    const record = {
      origin: challenge.origin,
      tokenHash: hashToken(challenge.token),
      method: result.method,
      verifiedAt: iso(at),
      validUntil: iso(new Date(at.getTime() + this.verifiedTtlMs)),
      // The token is public once published, but the record promises to hold
      // only its hash — so it is redacted from the recorded URL as well.
      ...(result.url ? { url: result.url.split(challenge.token).join('<token>') } : {}),
      ...(result.name ? { dnsName: result.name } : {}),
      ...(targetAddress ? { targetAddress } : {}),
      warnings: [...(result.warnings || [])],
    };
    this.data.verified[challenge.origin] = record;
    delete this.data.pending[challenge.origin];
    this.save();
    return record;
  }

  /** Current, unexpired verification record for an origin, or null. */
  get(originInput) {
    const origin = normalizeOrigin(originInput);
    const r = this.data.verified[origin];
    if (!r) return null;
    if (new Date(r.validUntil).getTime() <= this.now().getTime()) return null;
    return r;
  }

  isVerified(originInput) {
    return this.get(originInput) !== null;
  }

  revoke(originInput) {
    const origin = normalizeOrigin(originInput);
    const had = Boolean(this.data.verified[origin]);
    delete this.data.verified[origin];
    this.save();
    return had;
  }

  /**
   * THE GATE. Returns the record when scanning `origin` is permitted; throws
   * VerificationRequiredError otherwise. Exact-origin match only: a verified
   * https://example.com does not cover http://example.com, www.example.com,
   * or example.com:8443.
   */
  assertVerified(originInput) {
    const origin = normalizeOrigin(originInput);
    const r = this.data.verified[origin];
    if (!r) throw new VerificationRequiredError(origin, 'no ownership verification on record for this origin');
    if (new Date(r.validUntil).getTime() <= this.now().getTime()) {
      throw new VerificationRequiredError(origin, `the verification from ${r.verifiedAt} expired on ${r.validUntil}`);
    }
    return r;
  }

  /** Everything, for `quilltest verify list`. */
  list() {
    const now = this.now().getTime();
    return {
      pending: Object.values(this.data.pending).filter((c) => new Date(c.expires).getTime() > now),
      verified: Object.values(this.data.verified).map((r) => ({ ...r, expired: new Date(r.validUntil).getTime() <= now })),
    };
  }
}

function normalizeData(raw) {
  const data = { version: STORE_VERSION, pending: {}, verified: {} };
  if (!raw || typeof raw !== 'object') return data;
  if (raw.version !== undefined && raw.version !== STORE_VERSION) {
    throw new Error(`Unsupported verification store version ${raw.version} (expected ${STORE_VERSION})`);
  }
  if (raw.pending && typeof raw.pending === 'object') data.pending = { ...raw.pending };
  if (raw.verified && typeof raw.verified === 'object') data.verified = { ...raw.verified };
  return data;
}

function iso(d) {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}
