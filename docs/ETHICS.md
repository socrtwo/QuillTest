# Responsible use

QuillTest is built to help people secure sites they are responsible for. That intent is enforced, not just stated.

## The rules QuillTest enforces

1. **No scan without proof of ownership.** Every scan requires a verified ownership challenge for the exact target origin (file upload or DNS TXT). There is no override. See [OWNERSHIP-VERIFICATION.md](OWNERSHIP-VERIFICATION.md).
2. **Non-destructive by construction.** The check engine contains detection probes only. There is no payload or exploit library. Checks confirm a flaw with the least-intrusive probe and stop.
3. **No exploitation, ever.** QuillTest does not compromise, deface, exfiltrate from, pivot through, or damage a target — and it does not generate exploit code or attack payloads, including as "examples." It finds and it fixes.
4. **No autonomous changes.** Remediations and patches are generated for you to review and apply. QuillTest does not modify a live site.
5. **Local-first, no phone-home.** Scans run from your machine. QuillTest has no server component and does not transmit target data anywhere except, if you enable AI, to the provider endpoint you configured — and then only secret-scrubbed, size-capped fragments.

## The rules that are on you

- Scan only what you own or are **authorized in writing** to test. The ownership challenge is a strong technical check, but you are still responsible for having authorization — for example, authorization from the application owner even when you control the host.
- Follow your jurisdiction's law. In the United States, unauthorized testing can violate the Computer Fraud and Abuse Act; other countries have equivalents.
- Respect scope, rate limits, and any bug-bounty or pentest agreement you are operating under.
- Handle findings responsibly. A findings report is sensitive; store and share it accordingly.

## If you are reporting a flaw in someone else's site

QuillTest is not the right tool — it will not let you scan a site you cannot verify you control. Use the site's responsible-disclosure or bug-bounty channel.

## Reporting a vulnerability in QuillTest itself

See SECURITY.md (planned). Until then, open a private advisory via the repository's Security tab.
