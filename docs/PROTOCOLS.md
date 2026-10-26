# Protocol checks beyond HTTP

Anne's Test's first target is web applications over HTTP(S), but a site rarely runs HTTP alone. The same host often exposes FTP, mail, and other internet-facing services, and a weakness in any of them is a weakness in the site. Anne's Test therefore checks additional protocols for **known misconfigurations and exposure** — detection only, under the same gates as the web checks.

Every rule from [ETHICS.md](ETHICS.md) applies without exception:

- **Ownership-gated.** A protocol check runs only against a host whose ownership you have verified ([OWNERSHIP-VERIFICATION.md](OWNERSHIP-VERIFICATION.md)). Verification is per origin/host; a web verification does not silently authorize scanning an unrelated host on another port.
- **Detection, not intrusion.** Checks observe banners, negotiate capabilities, and read what the service volunteers. They do **not** brute-force credentials, exploit, upload, delete, or alter anything.
- **Non-destructive.** A check confirms a weakness with the least-intrusive observation that proves it, then stops.

## Protocols and what is checked

| Protocol | Detection checks (non-destructive) |
|---|---|
| **FTP** | Plaintext FTP in use where FTPS/SFTP should be; anonymous login *permitted* (a single benign capability check, not a credential attack); server banner/version fingerprint against known-vulnerable releases; directory listing exposed to anonymous users; cleartext credentials implied by lack of `AUTH TLS`. |
| **FTPS / SFTP** | TLS version and cipher quality (FTPS); host-key and algorithm hygiene (SFTP); confirm encryption is actually enforced, not optional. |
| **SMTP / mail submission** | Open relay *indicators* via advertised capabilities (not by relaying mail); STARTTLS offered and enforced; TLS quality; SPF/DKIM/DMARC DNS records present and well-formed. |
| **IMAP / POP3** | Plaintext auth offered without TLS; STARTTLS support; TLS quality. |
| **DNS** | Zone-transfer (AXFR) *allowed to the public* (a capability check); missing DNSSEC; wildcard and dangling-record hygiene; CAA records. |
| **TLS (any service)** | Protocol versions, cipher suites, certificate validity/chain/expiry, OCSP/CT, reuse of weak keys — shared with the web transport checks. |
| **Generic service exposure** | Service banner/version fingerprinting on responsive ports you have verified you own, matched against known-CVE version ranges, to flag outdated software. No port is treated as in-scope without host ownership verification. |

## What these checks deliberately exclude

- No credential guessing or brute force of any kind.
- No exploitation of a detected weakness, and no proof-of-concept payloads.
- No writing, deleting, moving, or reading of private data on the service.
- No scanning of hosts or ports you have not verified you own.

## Remediations

Each protocol finding carries a mapped fix the same way web findings do (see [FIXES.md](FIXES.md)): switch FTP to SFTP/FTPS and disable plaintext; disable anonymous access; enforce STARTTLS; publish SPF/DKIM/DMARC; disable public AXFR; upgrade a fingerprinted vulnerable version. Where the fix is a config artifact, Anne's Test generates it.

## Status

Implemented in `src/scan/protocols.mjs`, run with `scripts/scan.mjs protocols <host>` (or `scan <origin> --protocols`). It is **observation-only**: it opens each service on its standard port and reads what the service advertises — the TLS certificate and protocol, and the capability handshakes every ordinary client issues (`FEAT`, `EHLO`, `CAPABILITY`, `CAPA`), each followed by a clean `QUIT`/`LOGOUT`. It never sends credentials, never attempts a login, never issues `MAIL`/`RCPT`/`DATA`, never requests a zone transfer, and never writes anything. A verified end-to-end test confirms the only bytes that reach a real FTP/SMTP server are those capability verbs.

Checks:

- **TLS** (on 443/465/993/995/990): expired or soon-to-expire certificate, self-signed or untrusted chain, hostname mismatch, legacy protocol (TLS 1.0/1.1) still accepted, weak key.
- **FTP** (21): no `AUTH TLS` advertised → plaintext credentials (`ftp.plaintext`); version banner disclosure. Anonymous access is surfaced as a **manual verification item** (`ftp.anonymous-manual`), not tested.
- **SMTP** (25, 587): no STARTTLS (`smtp.no-starttls`); AUTH offered on a cleartext connection (`smtp.auth-before-tls`). Open-relay status is a **manual verification item** (`smtp.open-relay-manual`), not probed.
- **IMAP** (143) / **POP3** (110): STARTTLS/STLS not offered; plaintext login not disabled before TLS.
- **DNS** (resolver lookups only): missing or `+all` SPF, missing or `p=none` DMARC, missing CAA. The DNSSEC (DS record) check only runs when a DS-capable resolver is injected (`resolveDs`); Node's built-in resolver cannot query DS records, so from the CLI DNSSEC is reported as not checked rather than missing. The lookups are made against the verified host name itself (for `www.example.com` that is `www.example.com`, not the apex), so a zone that publishes SPF/DMARC only at the apex will show those as missing for a `www` host.

Each finding carries a concrete remediation. Weaknesses that require an action to confirm are reported as manual items rather than performed, by design.

The gate: protocol checks need a verification record for the **host** (`isHostVerified`); proving control of any origin on a host — `https://example.com` — authorizes checking that host's services. An unverified host exits with code 3; there is no override.
