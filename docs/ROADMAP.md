# Roadmap

Milestones, roughly ordered. Dates omitted deliberately; this is a planning repo.

## M0 — Foundations (in progress)

- [x] Repository, license, documentation plan
- [x] AI provider registry (`src/ai/providers.mjs`)
- [x] AI setup wizard — CLI (`scripts/ai-setup-wizard.mjs`)
- [x] AI setup wizard — browser (`public/ai-wizard.html`)
- [x] Config module + schema validation for `quilltest.ai.json` (`src/ai/config.mjs`)
- [ ] Project scaffold matching QuillStage stack (Vite, Capacitor, Electron, CI)

## M1 — Ownership and shell (in progress)

- [x] Ownership verification module (file-upload + DNS TXT), the scan gate (`src/verify/`, `scripts/verify.mjs`)
- [ ] Command registry + minimal ribbon/QAB shell
- [ ] Target management

## M2 — Passive engine

- [ ] Crawler/spider
- [ ] Passive checks (transport, headers, cookies, CORS, disclosure, component fingerprinting)
- [ ] Findings model with CWE/OWASP mapping, severity + confidence

## M3 — Active engine

- [ ] Active checks (injection, XSS, CSRF, SSRF, XXE, access control, redirects) — detection only, gated on verification
- [ ] Scan profiles and intrusiveness caps

## M4 — Fix layer

- [ ] Remediation registry + artifact generators (nginx/Apache/Caddy/IIS headers, CSP, cookies, CORS, dependency bumps)
- [ ] Applyable patch/diff generation for provided or verified artifacts

## M5 — AI analysis

- [ ] Analysis layer: triage, prioritize, explain, draft remediations, flag false positives
- [ ] Secret-scrubbing + `--dry-run`
- [ ] Several-AI corroboration mode

## M6 — Report and release

- [ ] Report/export, review packages, findings diff
- [ ] Cross-platform builds and release workflow (parity with QuillStage)
- [ ] SECURITY.md and responsible-disclosure policy
