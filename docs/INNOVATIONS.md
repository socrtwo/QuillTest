# Innovations

A survey of web application security scanners and what QuillTest adopts and adds. QuillTest is a clean-room project; this records influences, not code lineage.

## What the field does well (and QuillTest adopts)

- **OWASP ZAP** — open-source, passive + active scanning, a spider, and an API. QuillTest adopts the passive/active split, the standards mapping, and the scriptable-check model.
- **Burp Suite (PortSwigger)** — the gold standard for manual-assisted testing; the "surface candidates for human review" idea comes from here.
- **Nikto / Nuclei** — fast, template-driven checks. QuillTest's "checks are data" registry is in this spirit: a check is a declaration, not bespoke code.
- **Nessus / OpenVAS** — severity + confidence scoring and CVE mapping on findings.
- **testssl.sh / SSL Labs** — thorough TLS/transport analysis as a first-class passive check.
- **Dependency scanners (Dependabot, Snyk, OWASP Dependency-Check)** — fingerprint components and flag known-vulnerable versions, with a remediation being a version bump.

## What QuillTest adds

- **Prove-you-own-it gate.** Most scanners trust the operator to only scan what they should. QuillTest makes it a technical precondition: upload a verification file (or DNS TXT) for the origin, or no scan runs. See [OWNERSHIP-VERIFICATION.md](OWNERSHIP-VERIFICATION.md).
- **Test *and* fix in one tool.** Findings ship with mapped, generated remediations — a header block, a CSP, a cookie-flag change, a dependency bump — not just descriptions. See [FIXES.md](FIXES.md).
- **Attacker's-eye priority queue.** The optional AI layer ranks QuillTest's own findings the way an attacker would choose targets, so remediation effort goes to the highest-leverage flaw first.
- **Several-AI corroboration.** Ask two or three providers the same triage question and use agreement/disagreement as a confidence signal — and as a concrete way to reason about "what another AI might notice."
- **False-positive learning loop.** Mark a finding as a false positive and QuillTest remembers the signature for future scans of the same target.
- **Findings diff across scans.** See what a deploy fixed, regressed, or newly introduced.
- **Plain-language remediation writer.** Turn findings into a report a non-specialist site owner can act on.
- **Export-ready review packages.** Bundle findings, evidence, remediations, and the verification record for a client or an auditor.
- **Office-suite ergonomics.** Ribbon, Quick Access Bar, command search (Alt+Q), macros — the Quill suite UX applied to security testing, so the tool is approachable, not a wall of flags.

## Status

Planning. This documents intent.
