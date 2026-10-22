/*
 * QuillTest — ownership verification (public surface)
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 *   const store = VerificationStore.load('quilltest.verifications.json');
 *   const challenge = store.issue('https://example.com');
 *   // user publishes renderVerificationFile(challenge) at wellKnownPath(challenge)
 *   const result = await verifyChallenge(challenge, 'http');
 *   if (result.ok) store.complete(challenge, result);
 *   store.assertVerified('https://example.com'); // the gate; throws otherwise
 */

export * from './origin.mjs';
export * from './challenge.mjs';
export { verifyByHttp, DEFAULT_TIMEOUT_MS, MAX_REDIRECTS } from './http.mjs';
export { verifyByDns, dnsMethodAvailable } from './dns.mjs';
export { VerificationStore, VerificationRequiredError, DEFAULT_VERIFIED_TTL_MS, STORE_VERSION } from './store.mjs';

import { verifyByHttp } from './http.mjs';
import { verifyByDns } from './dns.mjs';

export const METHODS = ['http', 'dns'];

/**
 * Run one verification method against a challenge.
 * @param {import('./challenge.mjs').Challenge} challenge
 * @param {'http'|'dns'} method
 * @param {object} [opts]  passed through to the method
 */
export function verifyChallenge(challenge, method = 'http', opts = {}) {
  switch (method) {
    case 'http': return verifyByHttp(challenge, opts);
    case 'dns': return verifyByDns(challenge, opts);
    default: throw new RangeError(`Unknown verification method ${JSON.stringify(method)}; expected one of ${METHODS.join(', ')}`);
  }
}
