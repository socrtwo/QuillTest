#!/usr/bin/env node
/*
 * QuillTest — ownership verification (CLI)
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Prove you control a target origin before QuillTest will scan it.
 * No third-party dependencies. Node 18+.
 *
 *   node scripts/verify.mjs issue  <origin> [--ttl 24h] [--write-file DIR]
 *   node scripts/verify.mjs check  <origin> [--method http|dns]
 *   node scripts/verify.mjs status <origin>
 *   node scripts/verify.mjs list
 *   node scripts/verify.mjs revoke <origin>
 *   node scripts/verify.mjs cancel <origin>
 *
 * Records live in quilltest.verifications.json (git-ignored); --store <path>
 * overrides. See docs/OWNERSHIP-VERIFICATION.md.
 */

import { resolve, join } from 'node:path';
import { writeFileSync, mkdirSync } from 'node:fs';
import { lookup } from 'node:dns/promises';
import { argv, exit } from 'node:process';

import {
  VerificationStore,
  VerificationRequiredError,
  InvalidOriginError,
  METHODS,
  verifyChallenge,
  renderVerificationFile,
  wellKnownPath,
  verificationUrl,
  fileName,
  dnsRecordName,
  dnsRecordValue,
  dnsMethodAvailable,
  parseOrigin,
} from '../src/verify/index.mjs';

const DEFAULT_STORE = 'quilltest.verifications.json';

const c = {
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  cyan: (s) => `\x1b[36m${s}\x1b[0m`,
};

function parseArgs(args) {
  const out = { _: [] };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--')) {
      const key = a.slice(2);
      const next = args[i + 1];
      if (next === undefined || next.startsWith('--')) out[key] = true;
      else { out[key] = next; i++; }
    } else {
      out._.push(a);
    }
  }
  return out;
}

/** "24h", "90m", "7d", "3600s" or a bare number of seconds → ms. */
export function parseDuration(text) {
  const m = /^(\d+(?:\.\d+)?)\s*([smhd]?)$/i.exec(String(text).trim());
  if (!m) throw new RangeError(`Bad duration ${JSON.stringify(text)}; use e.g. 24h, 90m, 7d`);
  const mult = { '': 1000, s: 1000, m: 60_000, h: 3_600_000, d: 86_400_000 }[m[2].toLowerCase()];
  return Math.round(Number(m[1]) * mult);
}

function printHelp() {
  console.log(`${c.bold('QuillTest ownership verification')}

Usage:
  node scripts/verify.mjs <command> [origin] [options]

Commands:
  issue  <origin>   Generate a challenge; prints the file to publish (and the DNS alternative).
  check  <origin>   Fetch the published file (or TXT record) and, if it matches, record the origin as verified.
  status <origin>   Show whether scanning this exact origin is currently permitted.
  list              Show pending challenges and verification records.
  cancel <origin>   Drop a pending challenge.
  revoke <origin>   Remove a verification record.

Options:
  --method http|dns   Verification method for check (default http).
  --ttl <dur>         Challenge lifetime for issue (default 24h; e.g. 90m, 7d).
  --write-file <dir>  issue: also write the verification file into <dir>/.well-known/quilltest-verification/.
  --store <path>      Records file (default ${DEFAULT_STORE}).
  --json              Machine-readable output.
  --help              This help.

An origin is scheme + host [+ port]; bare hosts default to https. Each origin
(scheme, host and port) needs its own verification.`);
}

async function main() {
  const args = parseArgs(argv.slice(2));
  const [cmd, originArg] = args._;
  if (!cmd || args.help) { printHelp(); return; }

  const storePath = resolve(process.cwd(), typeof args.store === 'string' ? args.store : DEFAULT_STORE);
  const store = VerificationStore.load(storePath);
  const json = Boolean(args.json);
  const out = (obj, human) => { if (json) console.log(JSON.stringify(obj, null, 2)); else human(); };

  const needOrigin = () => {
    if (!originArg) { console.error(c.red(`${cmd} needs an origin, e.g. https://example.com`)); exit(2); }
    return originArg;
  };

  switch (cmd) {
    case 'issue': {
      const ttlMs = args.ttl ? parseDuration(args.ttl) : undefined;
      const challenge = store.issue(needOrigin(), { ttlMs });
      const file = renderVerificationFile(challenge);
      let written = null;
      if (typeof args['write-file'] === 'string') {
        const dir = join(resolve(args['write-file']), '.well-known', 'quilltest-verification');
        mkdirSync(dir, { recursive: true });
        written = join(dir, fileName(challenge));
        writeFileSync(written, file);
      }
      const dns = dnsMethodAvailable(challenge) ? { name: dnsRecordName(challenge), type: 'TXT', value: dnsRecordValue(challenge) } : null;
      out({ challenge, file, url: verificationUrl(challenge), dns, written }, () => {
        console.log(c.bold(`\nChallenge issued for ${challenge.origin}`) + c.dim(`  (expires ${challenge.expires})`));
        console.log(`\n${c.bold('Method 1 — file upload.')} Publish this file so that it is served at:\n  ${c.cyan(verificationUrl(challenge))}\n`);
        console.log(c.dim('  ----- ' + fileName(challenge) + ' -----'));
        console.log(file.replace(/^/gm, '  ').trimEnd());
        console.log(c.dim('  -----------------------------'));
        if (written) console.log(`\n  Written to ${written}`);
        if (dns) console.log(`\n${c.bold('Method 2 — DNS TXT record')} (if you cannot publish files):\n  ${c.cyan(dns.name)}.  TXT  "${dns.value}"`);
        console.log(`\nThen run:\n  node scripts/verify.mjs check ${challenge.origin}${dns ? ' ' + c.dim('[--method dns]') : ''}\n`);
      });
      return;
    }

    case 'check': {
      const method = typeof args.method === 'string' ? args.method : 'http';
      if (!METHODS.includes(method)) { console.error(c.red(`--method must be one of ${METHODS.join(', ')}`)); exit(2); }
      const challenge = store.pending(needOrigin());
      if (!challenge) {
        console.error(c.red(`No pending (unexpired) challenge for ${originArg}. Run: node scripts/verify.mjs issue ${originArg}`));
        exit(1);
      }
      if (!json) process.stdout.write(`Checking ${challenge.origin} via ${method}… `);
      const result = await verifyChallenge(challenge, method);
      let record = null;
      if (result.ok) {
        const targetAddress = await lookup(parseOrigin(challenge.origin).host).then((r) => r.address).catch(() => undefined);
        record = store.complete(challenge, result, { targetAddress });
      }
      out({ result, record }, () => {
        if (result.ok) {
          console.log(c.green('VERIFIED'));
          console.log(`  ${challenge.origin} may now be scanned until ${record.validUntil}.`);
          if (record.targetAddress) console.log(c.dim(`  target resolved to ${record.targetAddress}`));
        } else {
          console.log(c.red('NOT VERIFIED'));
          for (const r of result.reasons) console.log('  ' + c.red('✗ ' + r));
        }
        for (const w of result.warnings) console.log('  ' + c.yellow('! ' + w));
        if (!result.ok) console.log(c.dim(`\n  The challenge stays pending until ${challenge.expires}; fix the above and re-run check.`));
      });
      exit(result.ok ? 0 : 1);
      return;
    }

    case 'status': {
      const origin = needOrigin();
      let record = null;
      let error = null;
      try { record = store.assertVerified(origin); } catch (e) {
        if (!(e instanceof VerificationRequiredError)) throw e;
        error = e.message;
      }
      const pending = store.pending(origin);
      out({ verified: Boolean(record), record, pending: pending ? { origin: pending.origin, expires: pending.expires } : null, error }, () => {
        if (record) console.log(c.green(`VERIFIED  ${record.origin}`) + c.dim(`  (${record.method}, ${record.verifiedAt} → ${record.validUntil})`));
        else console.log(c.red('NOT VERIFIED') + '  ' + error);
        if (pending) console.log(c.yellow(`pending challenge expires ${pending.expires}`));
      });
      exit(record ? 0 : 1);
      return;
    }

    case 'list': {
      const data = store.list();
      out(data, () => {
        console.log(c.bold('\nPending challenges:'));
        if (!data.pending.length) console.log(c.dim('  (none)'));
        for (const p of data.pending) console.log(`  ${c.cyan(p.origin)}  expires ${p.expires}  ${c.dim(wellKnownPath(p))}`);
        console.log(c.bold('\nVerification records:'));
        if (!data.verified.length) console.log(c.dim('  (none)'));
        for (const r of data.verified) {
          const state = r.expired ? c.red('expired') : c.green('valid');
          console.log(`  ${c.cyan(r.origin)}  ${state}  ${r.method}  ${r.verifiedAt} → ${r.validUntil}`);
        }
        console.log(c.dim(`\nstore: ${storePath}\n`));
      });
      return;
    }

    case 'cancel': {
      const had = store.cancel(needOrigin());
      out({ cancelled: had }, () => console.log(had ? 'Pending challenge cancelled.' : 'Nothing pending for that origin.'));
      return;
    }

    case 'revoke': {
      const had = store.revoke(needOrigin());
      out({ revoked: had }, () => console.log(had ? 'Verification record removed.' : 'No verification record for that origin.'));
      return;
    }

    default:
      console.error(c.red(`Unknown command ${JSON.stringify(cmd)}.`));
      printHelp();
      exit(2);
  }
}

main().catch((e) => {
  if (e instanceof InvalidOriginError || e instanceof RangeError) {
    console.error(c.red(e.message));
    exit(2);
  }
  console.error(c.red('\nverify error: ' + (e?.stack || e?.message || e)));
  exit(1);
});
