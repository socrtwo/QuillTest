/** Verify tab — ownership verification, the scan gate. Implemented against src/verify/. */
import { def } from './registry.mjs';
import {
  verifyChallenge, renderVerificationFile, wellKnownPath, verificationUrl, fileName,
  dnsRecordName, dnsRecordValue, dnsMethodAvailable, parseOrigin, VerificationRequiredError,
} from '../verify/index.mjs';
import { scanReadiness } from './exec.mjs';
import { lookup } from 'node:dns/promises';
import { writeFileSync, mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';

const originOf = (ctx, arg) => (typeof arg === 'string' ? arg : arg?.origin) || ctx.targets.active()?.origin;
const need = (ctx, arg) => {
  const o = originOf(ctx, arg);
  if (!o) throw new RangeError('An origin is required (or select an active target).');
  return o;
};

def([
  {
    id: 'verify.issue', label: 'Issue Challenge', icon: 'key', tab: 'Verify', group: 'Challenge', keys: ['Ctrl+Shift+V'], popular: true,
    tip: 'Generate the verification file (and DNS record) for an origin',
    keywords: 'token ownership prove well-known',
    run: (ctx, arg) => {
      const origin = need(ctx, arg);
      const challenge = ctx.verifications.issue(origin, { ttlMs: arg?.ttlMs });
      return {
        challenge,
        file: renderVerificationFile(challenge),
        fileName: fileName(challenge),
        path: wellKnownPath(challenge),
        url: verificationUrl(challenge),
        dns: dnsMethodAvailable(challenge) ? { name: dnsRecordName(challenge), type: 'TXT', value: dnsRecordValue(challenge) } : null,
      };
    },
  },
  {
    id: 'verify.check', label: 'Check Verification', icon: 'verified', tab: 'Verify', group: 'Challenge', keys: ['Ctrl+Shift+K'], popular: true,
    tip: 'Fetch the published file and record the origin as verified when it matches',
    run: async (ctx, arg) => {
      const origin = need(ctx, arg);
      const method = arg?.method || 'http';
      const challenge = ctx.verifications.pending(origin);
      if (!challenge) throw new VerificationRequiredError(origin, 'no pending (unexpired) challenge — run verify.issue first');
      const result = await verifyChallenge(challenge, method, arg?.options || {});
      let record = null;
      if (result.ok) {
        const targetAddress = await lookup(parseOrigin(challenge.origin).host).then((r) => r.address).catch(() => undefined);
        record = ctx.verifications.complete(challenge, result, { targetAddress });
      }
      return { result, record };
    },
  },
  {
    id: 'verify.checkDns', label: 'Check via DNS', icon: 'dns', tab: 'Verify', group: 'Challenge',
    tip: 'Verify with the _quilltest-challenge TXT record instead of a file',
    run: (ctx, arg) => ctx.exec('verify.check', { ...(typeof arg === 'string' ? { origin: arg } : arg), method: 'dns' }),
  },
  {
    id: 'verify.writeFile', label: 'Save Verification File…', icon: 'save', tab: 'Verify', group: 'Challenge',
    tip: 'Write the verification file into a local web root (.well-known/quilltest-verification/)',
    run: (ctx, arg) => {
      const origin = need(ctx, arg);
      const challenge = ctx.verifications.pending(origin);
      if (!challenge) throw new VerificationRequiredError(origin, 'no pending (unexpired) challenge — run verify.issue first');
      const root = resolve(ctx.cwd, arg?.dir || '.');
      const dir = join(root, '.well-known', 'quilltest-verification');
      mkdirSync(dir, { recursive: true });
      const path = join(dir, fileName(challenge));
      writeFileSync(path, renderVerificationFile(challenge));
      return { path };
    },
  },
  {
    id: 'verify.status', label: 'Verification Status', icon: 'fact_check', tab: 'Verify', group: 'Status', popular: true, noRecord: true,
    tip: 'Is scanning this origin permitted right now?',
    run: (ctx, arg) => {
      const origin = need(ctx, arg);
      const readiness = scanReadiness(ctx, origin);
      const pending = ctx.verifications.pending(origin);
      return { origin, ...readiness, pending: pending ? { expires: pending.expires, url: verificationUrl(pending) } : null };
    },
  },
  {
    id: 'verify.list', label: 'All Verifications', icon: 'list_alt', tab: 'Verify', group: 'Status', noRecord: true,
    tip: 'Pending challenges and verification records',
    run: (ctx) => ctx.verifications.list(),
  },
  {
    id: 'verify.cancel', label: 'Cancel Challenge', icon: 'cancel', tab: 'Verify', group: 'Manage',
    run: (ctx, arg) => ({ cancelled: ctx.verifications.cancel(need(ctx, arg)) }),
  },
  {
    id: 'verify.revoke', label: 'Revoke Verification', icon: 'remove_moderator', tab: 'Verify', group: 'Manage',
    tip: 'Remove a verification record; the origin must be verified again before scanning',
    run: (ctx, arg) => ({ revoked: ctx.verifications.revoke(need(ctx, arg)) }),
  },
  { id: 'verify.reverify', label: 'Re-verify Before Expiry', icon: 'update', tab: 'Verify', group: 'Manage', tip: 'Issue and check a fresh challenge while the current record is still valid' },
  { id: 'verify.help', label: 'How Verification Works', icon: 'help_outline', tab: 'Verify', group: 'Help', noRecord: true, tip: 'Open docs/OWNERSHIP-VERIFICATION.md' },
]);
