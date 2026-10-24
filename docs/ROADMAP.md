# Roadmap

Milestones, roughly ordered. Dates omitted deliberately; this is a planning repo.

## M0 — Foundations (in progress)

- [x] Repository, license, documentation plan
- [x] AI provider registry (`src/ai/providers.mjs`)
- [x] AI setup wizard — CLI (`scripts/ai-setup-wizard.mjs`), multi-provider + mode
- [x] AI setup wizard — browser (`public/ai-wizard.html`), multi-provider + mode
- [x] Multi-provider config (v2: `activeProviders`, `analysisMode`) + v1 normalization
- [ ] Config module + schema validation for `quilltest.ai.json`
- [ ] Project scaffold matching QuillStage stack (Vite, Capacitor, Electron, CI)

## M1 — Ownership and shell

- [ ] Ownership verification module (file-upload + DNS TXT), the scan gate
- [ ] Command registry + minimal ribbon/QAB shell
- [ ] Target management
- [ ] Staging-mirror capture/serve pipeline (own-site snapshot, loopback serve)

## M2 — Passive engine

- [ ] Crawler/spider
- [ ] Passive checks (transport, headers, cookies, CORS, disclosure, component fingerprinting)
- [ ] Findings model with CWE/OWASP mapping, severity + confidence

## M3 — Active engine

- [ ] Active checks (injection, XSS, CSRF, SSRF, XXE, access control, redirects) — detection only, gated on verification
- [ ] Protocol checks beyond HTTP (FTP, mail, DNS, TLS) — detection only, per-host ownership-gated
- [ ] Scan profiles and intrusiveness caps

## M4 — Fix layer

- [ ] Remediation registry + artifact generators (nginx/Apache/Caddy/IIS headers, CSP, cookies, CORS, dependency bumps)
- [ ] Applyable patch/diff generation for provided or verified artifacts

## M5 — AI analysis

- [x] Analysis layer (`src/ai/analyze.mjs`): triage, prioritize, explain, draft remediations, flag false positives
- [x] Secret-scrubbing, size caps, output filter, `--dry-run`
- [x] Several-AI corroboration: sequential/concurrent consultation + per-finding consensus
- [ ] Wire the analysis layer to the scanner's findings output once the engine exists

## M6 — Report and release

- [ ] Report/export, review packages, findings diff
- [ ] Cross-platform builds and release workflow (parity with QuillStage)
- [x] SECURITY.md and responsible-disclosure policy
- [x] CI (GitHub Actions): registry-sync check, syntax, offline tests, keyless dry-run, secret scan
