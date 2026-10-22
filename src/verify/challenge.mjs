/*
 * QuillTest — ownership-verification challenge (token, file, DNS record)
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Pure functions, no I/O. Implements the "Reference token format" section of
 * docs/OWNERSHIP-VERIFICATION.md exactly; the HTTP and DNS verifiers and the
 * store build on these.
 */

import { createHash, randomBytes } from 'node:crypto';
import { normalizeOrigin, parseOrigin } from './origin.mjs';

export const TOKEN_PREFIX = 'quilltest-site-verification=';
export const WELL_KNOWN_DIR = '/.well-known/quilltest-verification/';
export const DNS_LABEL = '_quilltest-challenge';
export const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000; // 24h, per the doc
export const MAX_FILE_BYTES = 8 * 1024;              // verifier reads at most 8 KiB

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** RFC 4648 base32, upper-case, no padding. */
export function base32Encode(bytes) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

/** 256-bit random token, base32, no padding (52 characters). */
export function generateToken(random = randomBytes) {
  return base32Encode(random(32));
}

export const TOKEN_PATTERN = /^[A-Z2-7]{52}$/;

export function isValidToken(token) {
  return typeof token === 'string' && TOKEN_PATTERN.test(token);
}

/** sha256( token + "\n" + normalizedOrigin ), lowercase hex. */
export function computeChecksum(token, origin) {
  return createHash('sha256').update(`${token}\n${normalizeOrigin(origin)}`).digest('hex');
}

/** sha256 of the token alone — what the report records instead of the token. */
export function hashToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

/**
 * @typedef {Object} Challenge
 * @property {string} origin    normalized origin the token is bound to
 * @property {string} token     base32 token (secret until verified)
 * @property {string} checksum  sha256 hex, see computeChecksum
 * @property {string} issued    ISO-8601 UTC
 * @property {string} expires   ISO-8601 UTC
 */

/**
 * Issue a new challenge for an origin.
 * @param {string} originInput  anything normalizeOrigin accepts
 * @param {{ttlMs?:number, now?:Date, random?:Function}} [opts]
 * @returns {Challenge}
 */
export function issueChallenge(originInput, { ttlMs = DEFAULT_TTL_MS, now = new Date(), random } = {}) {
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) throw new RangeError('ttlMs must be a positive number of milliseconds');
  const origin = normalizeOrigin(originInput);
  const token = generateToken(random);
  const issuedAt = new Date(now.getTime());
  return {
    origin,
    token,
    checksum: computeChecksum(token, origin),
    issued: toIso(issuedAt),
    expires: toIso(new Date(issuedAt.getTime() + ttlMs)),
  };
}

function toIso(d) {
  return d.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

export function isExpired(challenge, now = new Date()) {
  return new Date(challenge.expires).getTime() <= now.getTime();
}

/** File name the user must publish, e.g. "J3K7….txt". */
export function fileName(challenge) {
  return `${challenge.token}.txt`;
}

/** Absolute path on the origin, "/.well-known/quilltest-verification/<token>.txt". */
export function wellKnownPath(challenge) {
  return `${WELL_KNOWN_DIR}${fileName(challenge)}`;
}

/** Full URL QuillTest will fetch. */
export function verificationUrl(challenge) {
  return `${challenge.origin}${wellKnownPath(challenge)}`;
}

/** Owner name of the DNS TXT record for the DNS method. */
export function dnsRecordName(challenge) {
  return `${DNS_LABEL}.${parseOrigin(challenge.origin).host}`;
}

/** Value of the DNS TXT record for the DNS method. */
export function dnsRecordValue(challenge) {
  return `${TOKEN_PREFIX}${challenge.token}`;
}

/**
 * Contents of the verification file, exactly as documented. The first two
 * lines are what the verifier checks; the rest are human-readable context.
 */
export function renderVerificationFile(challenge) {
  return [
    `${TOKEN_PREFIX}${challenge.token}`,
    `checksum=${challenge.checksum}`,
    `issued=${challenge.issued}`,
    `origin=${challenge.origin}`,
    `expires=${challenge.expires}`,
    '',
  ].join('\n');
}

/**
 * Parse a fetched verification file. Tolerates BOM, CRLF, surrounding
 * whitespace, blank lines and unknown keys; the verifier decides what is
 * required. Keys are lower-cased; a repeated key keeps its first value.
 * @param {string} text
 * @returns {{token:string|null, checksum:string|null, fields:Record<string,string>}}
 */
export function parseVerificationFile(text) {
  const fields = {};
  const lines = String(text).replace(/^﻿/, '').split(/\r?\n/);
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq < 0) continue;
    const key = line.slice(0, eq).trim().toLowerCase();
    const value = line.slice(eq + 1).trim();
    if (key && !(key in fields)) fields[key] = value;
  }
  return {
    token: fields['quilltest-site-verification'] ?? null,
    checksum: fields.checksum ? fields.checksum.toLowerCase() : null,
    fields,
  };
}

/**
 * Compare parsed file content against a challenge. Pure; the HTTP verifier
 * adds transport-level checks (status, redirects, size, content-type) on top.
 * @returns {{ok:boolean, reasons:string[]}}
 */
export function matchChallenge(challenge, parsed, now = new Date()) {
  const reasons = [];
  if (isExpired(challenge, now)) reasons.push(`challenge expired at ${challenge.expires}`);
  if (!parsed.token) reasons.push('file has no quilltest-site-verification line');
  else if (!constantTimeEqual(parsed.token, challenge.token)) reasons.push('token in file does not match the issued token');
  if (!parsed.checksum) reasons.push('file has no checksum line');
  else if (!constantTimeEqual(parsed.checksum, computeChecksum(challenge.token, challenge.origin))) {
    reasons.push('checksum does not match sha256(token + "\\n" + origin)');
  }
  return { ok: reasons.length === 0, reasons };
}

function constantTimeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}
