/*
 * QuillTest — DNS TXT verification method
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Looks for   _quilltest-challenge.<host>.  TXT  "quilltest-site-verification=<token>"
 * The resolver is injectable for tests (defaults to node:dns/promises resolveTxt).
 */

import { resolveTxt as nodeResolveTxt } from 'node:dns/promises';
import { isIP } from 'node:net';
import { dnsRecordName, dnsRecordValue, isExpired } from './challenge.mjs';
import { parseOrigin } from './origin.mjs';

/** The DNS method needs a DNS name; an IP-literal origin has none. */
export function dnsMethodAvailable(challenge) {
  return isIP(parseOrigin(challenge.origin).host.replace(/^\[|\]$/g, '')) === 0;
}

/**
 * @param {import('./challenge.mjs').Challenge} challenge
 * @param {{resolveTxt?:(name:string)=>Promise<string[][]>, now?:Date}} [opts]
 * @returns {Promise<{ok:boolean, method:'dns', origin:string, name:string, reasons:string[], warnings:string[], checkedAt:string}>}
 */
export async function verifyByDns(challenge, { resolveTxt = nodeResolveTxt, now = new Date() } = {}) {
  const name = dnsRecordName(challenge);
  const wanted = dnsRecordValue(challenge);
  const reasons = [];
  const warnings = [];

  if (isExpired(challenge, now)) reasons.push(`challenge expired at ${challenge.expires}`);
  if (!dnsMethodAvailable(challenge)) {
    reasons.push(`${challenge.origin} is an IP address; the DNS method needs a host name — use the file-upload method`);
    return finish();
  }

  let records = [];
  try {
    records = await resolveTxt(name);
  } catch (e) {
    const code = e?.code || '';
    if (code === 'ENOTFOUND' || code === 'ENODATA') reasons.push(`no TXT record found at ${name}`);
    else reasons.push(`DNS lookup of ${name} failed: ${e?.message || e}`);
    return finish();
  }

  // resolveTxt returns each record as an array of character-string chunks.
  const values = records.map((chunks) => chunks.join('').trim());
  const ours = values.filter((v) => v.startsWith('quilltest-site-verification='));
  if (!ours.length) {
    reasons.push(`TXT record at ${name} has no quilltest-site-verification value`);
  } else if (!ours.includes(wanted)) {
    reasons.push(`TXT record at ${name} carries a different token than the one issued`);
  }
  if (ours.length > 1) warnings.push(`${ours.length} quilltest-site-verification TXT values present; stale records can be removed`);
  return finish();

  function finish() {
    return {
      ok: reasons.length === 0,
      method: 'dns',
      origin: challenge.origin,
      name,
      reasons,
      warnings,
      checkedAt: now.toISOString().replace(/\.\d{3}Z$/, 'Z'),
    };
  }
}
