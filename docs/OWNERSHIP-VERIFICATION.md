# Ownership verification

Every scan in QuillTest is gated behind proof that you control the target. There is no "scan anyway" override. This protects third parties, keeps QuillTest on the right side of anti-hacking law, and makes the tool safe to ship open-source.

The model is the same one used by Let's Encrypt (ACME HTTP-01), Google/Bing Search Console, and most CDN domain-claim flows: QuillTest hands you a unique file, you place it on the site, QuillTest fetches it back and checks it matches.

## Flow

1. **Issue.** You enter a target origin (scheme + host + optional port). QuillTest generates:
   - a random 256-bit `token` (base32, no padding),
   - a `verification file` named `<token>.txt`,
   - whose contents are `quilltest-site-verification=<token>` on the first line and a SHA-256 `checksum=<hex>` of the token plus the normalized origin on the second line,
   - and an issue timestamp. The token is bound to the exact origin and expires after a configurable window (default 24h).
2. **Upload.** You place the file at the well-known path on the target:
   ```
   https://<target-origin>/.well-known/quilltest-verification/<token>.txt
   ```
   An alternate DNS method is available where you cannot write files (see below).
3. **Verify.** QuillTest fetches that URL and confirms, over the exact origin you entered:
   - HTTP 200,
   - `Content-Type` is `text/plain` (or close; a mislabeled type is a warning, not a hard fail),
   - the body's first line token matches the issued token,
   - the checksum line matches a freshly computed SHA-256,
   - the response was not a redirect to a different origin (a redirect that changes host/scheme/port fails — otherwise an open redirect could be used to "prove" ownership of a site you don't control),
   - the file is small (QuillTest reads at most 8 KiB).
4. **Gate.** Only a fully successful verify unlocks scanning *for that origin only*. Subdomains, sibling hosts, and other ports each require their own verification. The verification record (origin, token hash, time, method, verifying IP) is written into the scan report.

## Why a file upload specifically

Requiring a file **write** to a controlled path proves a materially stronger claim than "the site answered a request": it shows you can publish content at that origin, which a passer-by or an attacker targeting someone else's site cannot do. It is also friction the casual misuse case will not clear.

## DNS alternative

For origins where you cannot write to `.well-known/` (some managed platforms, APIs with no static hosting), QuillTest accepts a DNS TXT record instead:

```
_quilltest-challenge.<host>.  TXT  "quilltest-site-verification=<token>"
```

QuillTest resolves the TXT record and checks the token. DNS control is an equally accepted proof of domain ownership.

## What verification does NOT grant

- It does not authenticate you to the site's application. QuillTest never asks for or stores site logins; authenticated scanning, when added, will use credentials you supply per-scan and never persist them.
- It does not authorize destructive testing. Verification unlocks QuillTest's normal, non-destructive check set. Checks that could affect data or availability are off by default and separately gated.
- It does not transfer to other origins. One token, one origin.

## Reference token format

```
quilltest-site-verification=J3K7...   (the 256-bit token, base32)
checksum=9f2c...                      (sha256( token + "\n" + normalizedOrigin ))
issued=2026-10-22T14:00:00Z
origin=https://example.com
expires=2026-10-23T14:00:00Z
```

Normalized origin = lowercase scheme + host + explicit port only when non-default, no trailing slash, no path.

## Implementation

`src/verify/` implements this document; `scripts/verify.mjs` is the CLI. The scan orchestrator (not yet built) will call `VerificationStore.assertVerified(origin)` before its first request and refuse to run when it throws.

```bash
node scripts/verify.mjs issue  https://example.com          # prints the file to publish + the DNS alternative
node scripts/verify.mjs issue  https://example.com --write-file ./public   # also writes it under ./public/.well-known/…
node scripts/verify.mjs check  https://example.com          # fetches the file; records the origin as verified on success
node scripts/verify.mjs check  https://example.com --method dns
node scripts/verify.mjs status https://example.com          # exit 0 when scanning is permitted, 1 otherwise
node scripts/verify.mjs list | revoke <origin> | cancel <origin>
```

Programmatic use:

```js
import { VerificationStore, verifyChallenge, renderVerificationFile, wellKnownPath } from './src/verify/index.mjs';

const store = VerificationStore.load('quilltest.verifications.json');
const challenge = store.issue('https://example.com');
// publish renderVerificationFile(challenge) at wellKnownPath(challenge), then:
const result = await verifyChallenge(challenge, 'http');     // or 'dns'
if (result.ok) store.complete(challenge, result);
store.assertVerified('https://example.com');                 // the gate: throws VerificationRequiredError otherwise
```

Decisions the implementation makes where this document left room:

- **Records file.** Pending challenges and verification records live in `quilltest.verifications.json` (mode `0600`, git-ignored). A pending challenge stores the token, because the verifier must compare against it; a completed record stores only `sha256(token)` and a URL with the token replaced by `<token>`.
- **Validity of a verification.** A successful verification permits scanning that origin for **30 days** (`DEFAULT_VERIFIED_TTL_MS`), after which `assertVerified` throws and the challenge must be redone. `revoke` removes a record early.
- **Redirects.** Same-origin redirects are followed, at most 3, and noted as warnings. Any redirect to a different scheme, host or port fails immediately; the file is never fetched from the redirect target.
- **Catch-all pages.** A server that returns 200 for every path does not pass: the body must carry the exact token and checksum lines.
- **IP-literal origins** (`http://192.0.2.10:8080`) can only use the file method; the DNS method is reported as unavailable rather than attempted.
- **Verifying IP.** The record's `targetAddress` is the address the target host resolved to at verification time (best effort), for the scan report.
- **Timeouts.** HTTP fetches time out after 15 s. The file is parsed leniently (BOM, CRLF, surrounding whitespace, comment lines, upper-case keys) but matched strictly, with constant-time comparison of the token and checksum.
- **Expired challenges** are pruned when next touched; `check` on an origin with no live challenge tells you to `issue` a new one.
