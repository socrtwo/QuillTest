# Protocol checks beyond HTTP

QuillTest's first target is web applications over HTTP(S), but a site rarely runs HTTP alone. The same host often exposes FTP, mail, and other internet-facing services, and a weakness in any of them is a weakness in the site. QuillTest therefore checks additional protocols for **known misconfigurations and exposure** — detection only, under the same gates as the web checks.

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

Each protocol finding carries a mapped fix the same way web findings do (see [FIXES.md](FIXES.md)): switch FTP to SFTP/FTPS and disable plaintext; disable anonymous access; enforce STARTTLS; publish SPF/DKIM/DMARC; disable public AXFR; upgrade a fingerprinted vulnerable version. Where the fix is a config artifact, QuillTest generates it.

## Status

Planning. The web transport and header checks are the first to be implemented; the broader protocol set is specified here and not yet built.
