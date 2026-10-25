# Vulnerability-check inventory

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

Active checks send a request the target would not otherwise receive. In QuillTest every active check is still **observation**: it sends a benign input and reads the response. There is no payload library. The engine sends only GET and OPTIONS, never submits a form or uses a state-changing method, and never follows a redirect off the verified origin. Intrusiveness is a declared property of each check and is capped by the scan profile (`passive` by default, `safe-active` for the benign probes below); see [PROFILES.md](PROFILES.md).

**Implemented (`src/scan/active.mjs`, `scan --active`):**

| Check | What it does |
|---|---|
| HTTP methods / Cross-Site Tracing (`active.http-trace`, `active.http-methods`) | One OPTIONS request; reads the advertised `Allow` set. Flags TRACE/TRACK (Cross-Site Tracing, CWE-693) and advertised state-changing methods for review. No TRACE/PUT/DELETE is ever sent. |
| Open redirect (`active.open-redirect`, CWE-601) | Re-requests a URL with a redirect-looking parameter set to a benign non-resolving marker host; flags the parameter when the `Location` header forwards to it. The redirect is observed, never followed. |
| Input reflection (`active.reflected-input`, CWE-79) | Re-requests with a query parameter set to a benign alphanumeric canary (no HTML metacharacters, so it cannot execute); flags unescaped reflection in an HTML response as a reflected-XSS **precondition** for manual review, at low/tentative. |

**Planned** (specified here; deferred behind a future higher-intrusiveness profile because they send inputs meant to probe backend handling):


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

The **passive** set is implemented in `src/scan/passive.mjs` (checks are data in `PASSIVE_CHECKS`): transport (plaintext origin, TLS errors, missing http→https redirect, HSTS), security headers (CSP missing/report-only/weak, nosniff, clickjacking, Referrer-Policy, Permissions-Policy), cookie flags with session-cookie escalation, CORS (reflected origin, wildcard+credentials, null), version banners, active/passive mixed content, insecure form actions, directory listing, and signature-matched exposed-file probes (`.git/HEAD`, `.env`, `.DS_Store`, `server-status`, `phpinfo.php`, `.svn/entries`). Also, from the crawl: third-party scripts without Subresource Integrity, login forms without an anti-CSRF token, and password fields submitted via GET. Each finding ships with a concrete remediation.

**Site-wide by default.** `scripts/scan.mjs scan <origin>` crawls up to 25 same-origin pages (`--max-pages`, `--max-depth`), honoring `robots.txt` unless `--ignore-robots`, seeding from `sitemap.xml`, and never following logout/delete-style links. Page-scoped checks (headers, cookies, content, forms) run on every page; identical findings collapse into one with an `affectedPages` count, so a missing CSP across 25 pages is one finding, not 25. Origin-scoped checks (transport, CORS, exposed files) run once. The report also carries a **stack fingerprint** (server, framework, CMS, libraries — each with its evidence) so remediations and the AI layer address the actual stack.

**Component versions.** Fingerprinted versions are assessed against an offline table of end-of-life lines and well-known advisories (`src/scan/versions.mjs`, dated `KNOWN_DATA_AS_OF`): jQuery, Bootstrap, PHP, nginx, Apache httpd, IIS, Drupal, WordPress, Joomla, Angular. Findings `components.eol` and `components.known-vulnerable` name the CVEs and the fixed version. Because distributions backport fixes without changing banners, these are reported with confidence *firm* and a caveat to confirm against the vendor advisory. With `--online-cve`, libraries that map to a package ecosystem (jQuery and Bootstrap on npm, Drupal on Packagist) are also looked up in [OSV.dev](https://osv.dev) (`components.osv`); this is the only check that leaves the machine for anything other than the target, and it is off by default.

**Protocol checks** (TLS, FTP, SMTP, IMAP, POP3, DNS) are implemented, observation-only, in `src/scan/protocols.mjs`; see [PROTOCOLS.md](PROTOCOLS.md). **Active checks** (injection, XSS, CSRF, SSRF, XXE, access control, open redirects) remain planned; see [ROADMAP.md](ROADMAP.md) M3.
