# Ownership verification

Every scan in Anne's Test is gated behind proof that you control the target. There is no "scan anyway" override. This protects third parties, keeps Anne's Test on the right side of anti-hacking law, and makes the tool safe to ship open-source.

The model is the same one used by Let's Encrypt (ACME HTTP-01), Google/Bing Search Console, and most CDN domain-claim flows: Anne's Test hands you a unique file, you place it on the site, Anne's Test fetches it back and checks it matches.

## Flow

1. **Issue.** You enter a target origin (scheme + host + optional port). Anne's Test generates:
   - a random 256-bit `token` (base32, no padding),
   - a `verification file` named `<token>.txt`,
   - whose contents are `quilltest-site-verification=<token>` on the first line and a SHA-256 `checksum=<hex>` of the token plus the normalized origin on the second line,
   - and an issue timestamp. The token is bound to the exact origin and expires after a configurable window (default 24h). A successful verification is then valid for that same window counted from the moment of verification (the record keeps the challenge's own expiry as `challengeExpires`).
2. **Upload.** You place the file at the well-known path on the target:
   ```
   https://<target-origin>/.well-known/quilltest-verification/<token>.txt
   ```
   An alternate DNS method is available where you cannot write files (see below).
3. **Verify.** Anne's Test fetches that URL and confirms, over the exact origin you entered:
   - HTTP 200,
   - `Content-Type` is `text/plain` (or close; a mislabeled type is a warning, not a hard fail),
   - the body's first line token matches the issued token,
   - the checksum line matches a freshly computed SHA-256,
   - the response was not a redirect to a different origin or away from the well-known path (a redirect that changes host/scheme/port, or lands anywhere but `/.well-known/quilltest-verification/<token>.txt`, fails — otherwise an open redirect, or a tenant who can publish under some other path of a shared origin, could be used to "prove" ownership),
   - the file is small (Anne's Test stops reading at 8 KiB and refuses a larger declared `Content-Length`).
4. **Gate.** Only a fully successful verify unlocks scanning *for that origin only*. Subdomains, sibling hosts, and other ports each require their own verification. The verification record (origin, token hash, time, method) is kept in the local store and its method, time and expiry are written into the scan report.

## Why a file upload specifically

Requiring a file **write** to a controlled path proves a materially stronger claim than "the site answered a request": it shows you can publish content at that origin, which a passer-by or an attacker targeting someone else's site cannot do. It is also friction the casual misuse case will not clear.

## DNS alternative

For origins where you cannot write to `.well-known/` (some managed platforms, APIs with no static hosting), Anne's Test accepts a DNS TXT record instead:

```
_quilltest-challenge.<host>.  TXT  "quilltest-site-verification=<token>"
```

Anne's Test resolves the TXT record and checks the token. DNS control is an equally accepted proof of domain ownership.

## What verification does NOT grant

- It does not authenticate you to the site's application. Anne's Test never asks for or stores site logins; authenticated scanning, when added, will use credentials you supply per-scan and never persist them.
- It does not authorize destructive testing. Verification unlocks Anne's Test's normal, non-destructive check set. Checks that could affect data or availability are off by default and separately gated.
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

## Status

Implemented in `src/verify/ownership.mjs` (challenge issuance, HTTP and DNS verification, expiry, the `isOriginVerified` gate) and `src/verify/store.mjs` (0600-mode JSON store; records hold a token *hash*, never the token). Driven by `scripts/scan.mjs verify issue|check|list`. Covered by offline tests in `tests/verify.test.mjs`, including cross-origin-redirect refusal, size cap, tampered checksum, and expiry.
