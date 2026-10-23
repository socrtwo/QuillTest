# Vulnerability-check inventory (planned)

Checks are data, registered against ids, same as commands. Each check declares: id, category (OWASP/CWE), severity default, whether it is passive or active, how intrusive it is, and the remediation it maps to (see [FIXES.md](FIXES.md)). Active checks run only after ownership verification ([OWNERSHIP-VERIFICATION.md](OWNERSHIP-VERIFICATION.md)) and never go beyond the least-intrusive probe that proves the finding.

All detection is non-destructive: QuillTest confirms a flaw exists, it does not exploit it, pivot, or alter data.

## Passive checks (observation only)

| Area | Checks |
|---|---|
| Transport | TLS version/cipher, certificate validity/chain, HSTS presence and max-age, mixed content |
| Security headers | CSP presence/quality, X-Content-Type-Options, X-Frame-Options / frame-ancestors, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP |
| Cookies | Secure, HttpOnly, SameSite, overly broad Domain/Path, session cookie scoping |
| CORS | Reflected Origin, wildcard with credentials, null origin acceptance |
| Information disclosure | Server/version banners, verbose errors and stack traces, source maps, `.git`/`.env`/backup files, directory listing |
| Components | Fingerprint libraries/frameworks/servers and flag versions with known CVEs |
| Content | Autocomplete on sensitive fields, forms posting over HTTP, external script integrity (SRI) |

## Active checks (require verified ownership; least-intrusive probe)

| Category (OWASP/CWE) | Checks |
|---|---|
| Injection | SQLi (error/boolean/time-based detection), command injection, template injection (SSTI), host/header injection, CRLF |
| XSS | Reflected, stored, DOM-based — detected by safe canary markers, not weaponized payloads |
| CSRF | Missing/weak anti-CSRF tokens on state-changing endpoints |
| SSRF | Parameters that fetch URLs, out-of-band detection via a user-controlled callback host |
| XXE | XML endpoints accepting external entities |
| Access control | IDOR / horizontal and vertical privilege checks using only accounts you supply, forced browsing to admin paths |
| Authentication/session | Weak lockout, session fixation, predictable tokens, password-reset flaws (detection only) |
| Deserialization | Endpoints accepting serialized objects |
| Redirects | Open redirects |
| Business-logic hints | Surfaces candidates for manual review rather than auto-asserting |

## Severity and confidence

Each finding gets a severity (informational → critical) and a confidence (tentative/firm/confirmed). Confidence reflects how directly the evidence proves the flaw. The AI layer, when enabled, re-scores confidence and flags likely false positives, but the deterministic engine assigns the baseline.

## Beyond HTTP

A host usually exposes more than its web app. QuillTest also checks FTP, mail, DNS, and TLS on hosts you have verified you own — detection only, no credential guessing or exploitation. Those checks and their guardrails are specified in [PROTOCOLS.md](PROTOCOLS.md).

## Standards alignment

Findings map to OWASP Top 10 (2021), OWASP ASVS, and CWE identifiers, so reports slot into existing workflows and the remediations reference recognized guidance.

## Status

Planning. This is the target inventory; no checks are implemented yet.
