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

## Standards alignment

Findings map to OWASP Top 10 (2021), OWASP ASVS, and CWE identifiers, so reports slot into existing workflows and the remediations reference recognized guidance.

## Status

The passive set is implemented (M2); the active set is planned (M3). Checks are data in `src/checks/`, run by `src/scan/orchestrator.mjs`, and every scan is gated on a verified, authorized target. Findings are recorded per `src/findings/model.mjs`: severity, confidence, CWE/OWASP/ASVS mapping, secret-scrubbed evidence, and a stable signature that drives deduplication, the scan-to-scan diff and the false-positive learning loop.

Design points of the passive engine:

- **Observation first.** Most checks read the crawled responses only (intrusiveness 0). Five send a bounded number of extra benign requests (intrusiveness 1): one TLS handshake, two GETs with an `Origin` header, GETs of ~30 well-known file paths confirmed by content signature, GETs of discovered asset directories, GETs of referenced source maps. The Passive profile permits nothing above 1.
- **No false positives from catch-all pages.** A server that answers 200 to every path does not trigger the sensitive-file check: each path has a content signature that must match.
- **Site-wide findings are consolidated.** A header missing on every page is one finding listing the affected URLs, not one finding per page.
- **Version matches are firm, not confirmed.** Component versions come from file names and banners; a patched fork or backport can carry an old string. The known-vulnerable table (`src/checks/data/known-vulnerable.json`) is a starting set and documented as such.

Active checks (M3) add detection, never exploitation. Each confirms a flaw class by the least intrusive benign signal and then stops:

- **Reflected XSS** sends a unique non-executing canary (a random token plus the characters `' " < >`) and reports when they come back unencoded in a context that would allow injection. No `<script>`, no event handler, no payload that runs.
- **SQL injection** is detected by error signature: a single quote provokes a database error that a balanced control value does not. No boolean, timing, UNION or data extraction.
- **Template injection** sends a benign arithmetic marker (`{{49*49}}` and variants) and reports when it comes back evaluated.
- **CRLF / header injection** sends an encoded newline plus an inert marker header and checks whether it appears as a real response header.
- **Open redirect** supplies a benign off-origin marker URL and observes whether the server redirects to it; the redirect is never followed.
- **CSRF** reads the forms the crawl already saw and flags state-changing forms with no visible token and no SameSite protection — a candidate for review, not an assertion.
- **Forced browsing** GETs a short list of conventional admin/operational paths, compared against a random baseline, with no credentials and no writes.
- **Host-header injection** sends a benign marker in forwarding headers (X-Forwarded-Host and friends) pointing at a `.invalid` host and reports when the server reflects it into an absolute URL or a redirect. Nothing is poisoned, cached, or followed.
- **HTTP methods** asks the server with a single OPTIONS request which methods it advertises and flags TRACE (cross-site tracing) and the write methods. QuillTest never sends TRACE, PUT, DELETE or any state-changing method; it reports what the `Allow` header advertises.

Active checks run only on the Standard and Thorough profiles, only against a verified and authorized target, each parameter is tested in isolation with one value changed (GET values in the query, POST values in a urlencoded body), and every active request is capped by a per-scan budget and logged for audit. IDOR and privilege checks that need accounts you supply, SSRF out-of-band detection, XXE and deserialization are planned next and will be gated the same way.

<!-- checks:start (generated by npm run catalog — do not edit by hand) -->

## Implemented checks (36)

Registered in `src/checks/`. Intrusiveness: 0 = reads crawled responses only; 1 = a bounded number of extra benign requests (listed). Every check below is passive; none sends test input.

### Transport security (4)

| Check | ID | Default severity | Intrusiveness | OWASP | CWE | Extra requests |
|---|---|---|---|---|---|---|
| Site served over plain HTTP | `transport.https` | medium | 0 | A02 | CWE-319, CWE-311 | none |
| Strict-Transport-Security missing or weak | `transport.hsts` | low | 0 | A05 | CWE-319, CWE-693 | none |
| Mixed content on an HTTPS page | `transport.mixedContent` | medium | 0 | A02 | CWE-319 | none |
| TLS configuration or certificate problem | `transport.tls` | medium | 1 | A02 | CWE-326, CWE-295 | one TLS handshake to the origin (no HTTP request) |

### Security headers (7)

| Check | ID | Default severity | Intrusiveness | OWASP | CWE | Extra requests |
|---|---|---|---|---|---|---|
| Content-Security-Policy missing or weak | `headers.csp` | medium | 0 | A05 | CWE-693, CWE-16 | none |
| X-Content-Type-Options: nosniff missing | `headers.contentTypeOptions` | low | 0 | A05 | CWE-16, CWE-693 | none |
| Clickjacking protection missing (no X-Frame-Options or frame-ancestors) | `headers.frameOptions` | medium | 0 | A05 | CWE-1021 | none |
| Referrer-Policy missing or leaky | `headers.referrerPolicy` | low | 0 | A05 | CWE-200 | none |
| Permissions-Policy not set | `headers.permissionsPolicy` | informational | 0 | A05 | CWE-16 | none |
| Cross-origin isolation headers not set (COOP / CORP) | `headers.crossOriginIsolation` | informational | 0 | A05 | CWE-16 | none |
| Response that sets a cookie is cacheable | `headers.cacheControlSensitive` | low | 0 | A05 | CWE-525 | none |

### Cookies (4)

| Check | ID | Default severity | Intrusiveness | OWASP | CWE | Extra requests |
|---|---|---|---|---|---|---|
| Cookie set without the Secure attribute | `cookies.secure` | medium | 0 | A05 | CWE-614 | none |
| Cookie set without HttpOnly | `cookies.httpOnly` | low | 0 | A05 | CWE-1004 | none |
| Cookie without a SameSite attribute, or SameSite=None without Secure | `cookies.sameSite` | low | 0 | A05 | CWE-1275, CWE-352 | none |
| Cookie scoped more broadly than the host | `cookies.scope` | low | 0 | A05 | CWE-16 | none |

### Cross-origin resource sharing (1)

| Check | ID | Default severity | Intrusiveness | OWASP | CWE | Extra requests |
|---|---|---|---|---|---|---|
| CORS policy trusts arbitrary origins | `cors.permissive` | medium | 1 | A05 | CWE-942 | two GETs of the start page (and up to two JSON/XML pages) with Origin headers: a .invalid origin, and "null" |

### Information disclosure (5)

| Check | ID | Default severity | Intrusiveness | OWASP | CWE | Extra requests |
|---|---|---|---|---|---|---|
| Server software and version disclosed in headers | `disclosure.serverBanner` | low | 0 | A05 | CWE-200 | none |
| Verbose error message or stack trace in response | `disclosure.verboseErrors` | medium | 0 | A05 | CWE-209, CWE-497 | none |
| JavaScript source map exposed | `disclosure.sourceMaps` | low | 1 | A05 | CWE-200, CWE-538 | one GET per referenced .map file (bounded) |
| Sensitive file exposed at a well-known path | `disclosure.sensitiveFiles` | high | 1 | A05 | CWE-538, CWE-527, CWE-200 | one GET per well-known path (28 paths), bodies capped at 16 KiB |
| Directory listing enabled | `disclosure.directoryListing` | medium | 1 | A05 | CWE-548 | one GET per asset directory discovered during the crawl (bounded to 15) |

### Components and versions (2)

| Check | ID | Default severity | Intrusiveness | OWASP | CWE | Extra requests |
|---|---|---|---|---|---|---|
| Component detected | `components.fingerprint` | informational | 0 | A06 | CWE-200 | none |
| Component version with known vulnerabilities or end of life | `components.knownVulnerable` | medium | 0 | A06 | CWE-1395, CWE-1104 | none |

### Page content (4)

| Check | ID | Default severity | Intrusiveness | OWASP | CWE | Extra requests |
|---|---|---|---|---|---|---|
| Form submits to a plain-HTTP URL | `content.formsOverHttp` | high | 0 | A02 | CWE-319, CWE-523 | none |
| Sensitive form field allows browser autocomplete | `content.autocompleteSensitive` | low | 0 | A04 | CWE-359, CWE-525 | none |
| Third-party script or stylesheet without Subresource Integrity | `content.subresourceIntegrity` | low | 0 | A08 | CWE-353, CWE-345 | none |
| External link opens in a new window without rel="noopener" | `content.targetBlankOpener` | informational | 0 | A05 | CWE-1021 | none |

### Injection (4)

| Check | ID | Default severity | Intrusiveness | OWASP | CWE | Extra requests |
|---|---|---|---|---|---|---|
| SQL error provoked by an unbalanced quote (possible SQL injection) | `injection.sqlError` | high | 2 | A03 | CWE-89 | two requests per parameter: one value containing a single quote, one balanced control; responses are compared for database error signatures |
| Server-side template expression evaluated (possible template injection) | `injection.templateEval` | high | 2 | A03 | CWE-1336, CWE-94 | a few requests per parameter carrying benign arithmetic markers such as {{7*7}}; the response is checked for the evaluated result |
| Newline in a parameter reaches a response header (CRLF / header injection) | `injection.crlf` | medium | 2 | A03 | CWE-113, CWE-93 | one request per parameter whose value contains an encoded newline and an inert marker header name; the response headers are inspected |
| Host / forwarding header reflected into the response | `injection.hostHeader` | medium | 2 | A03 | CWE-644, CWE-601 | one request per sampled page carrying benign X-Forwarded-Host / X-Host / Forwarded headers pointing at a .invalid host; the response is inspected for reflection |

### Cross-site scripting (1)

| Check | ID | Default severity | Intrusiveness | OWASP | CWE | Extra requests |
|---|---|---|---|---|---|---|
| Reflected input without output encoding (reflected XSS) | `xss.reflected` | high | 2 | A03 | CWE-79 | one request per parameter carrying a unique non-executing canary token plus the characters ' " < >; the response is inspected for unencoded reflection |

### Cross-site request forgery (1)

| Check | ID | Default severity | Intrusiveness | OWASP | CWE | Extra requests |
|---|---|---|---|---|---|---|
| State-changing form without an anti-CSRF token | `csrf.formToken` | medium | 1 | A01 | CWE-352 | none — reads the forms already seen during the crawl |

### Open redirects (1)

| Check | ID | Default severity | Intrusiveness | OWASP | CWE | Extra requests |
|---|---|---|---|---|---|---|
| Open redirect | `redirects.open` | medium | 2 | A01 | CWE-601 | one request per redirect-like parameter, carrying a benign off-origin marker URL; the redirect is observed, never followed |

### Access control (1)

| Check | ID | Default severity | Intrusiveness | OWASP | CWE | Extra requests |
|---|---|---|---|---|---|---|
| Conventional sensitive path reachable without authentication | `access.forcedBrowsing` | medium | 2 | A01 | CWE-200, CWE-548 | a random baseline GET plus one GET per path in a short list (16 paths); no credentials, no writes |

### HTTP methods (1)

| Check | ID | Default severity | Intrusiveness | OWASP | CWE | Extra requests |
|---|---|---|---|---|---|---|
| Unsafe HTTP methods advertised | `methods.enabled` | low | 2 | A05 | CWE-650, CWE-16 | one OPTIONS request to the origin root and a sample page; the Allow header is read. QuillTest never sends TRACE or any write method. |

OWASP categories: A01 = Broken Access Control; A02 = Cryptographic Failures; A03 = Injection; A04 = Insecure Design; A05 = Security Misconfiguration; A06 = Vulnerable and Outdated Components; A08 = Software and Data Integrity Failures.

<!-- checks:end -->
