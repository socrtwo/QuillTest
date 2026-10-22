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
- [x] Command registry (`src/commands/`, 241 commands as data, 40 implemented), default tab layout (`src/ui/ribbonLayout.mjs`), executor with the scan gate (`exec.mjs`), command-line shell (`scripts/quilltest.mjs`), generated `docs/COMMANDS.md`
- [ ] Ribbon/QAB UI shell (Vite) over the registry
- [x] Target management (`src/targets/`): origins, authorization statements, path scope, active target

## M2 — Passive engine (done)

- [x] Crawler/spider (`src/crawl/`: same-origin BFS, scope, robots.txt, redirect handling, body caps, request log)
- [x] Passive checks (`src/checks/passive/`: 27 checks — transport, headers, cookies, CORS, disclosure, components, content)
- [x] Findings model with CWE/OWASP/ASVS mapping, severity + confidence, secret scrubbing, signatures, diff (`src/findings/`)
- [x] Scan orchestrator with profiles, per-target settings, scan records, false-positive learning loop, JSON/CSV/SARIF export (`src/scan/`)

## M3 — Active engine (in progress)

- [x] Active-check framework: injection-point model from the crawl (`src/scan/params.mjs`), active phase and request budget in the orchestrator, `active()` hook in the check registry
- [x] Detection-only active checks (`src/checks/active/`): reflected XSS (safe canary), SQL-error, template-eval and CRLF injection, open redirect, CSRF-token, forced browsing
- [x] Scan profiles and intrusiveness caps (Standard/Thorough now run the active set; Passive/Quick skip it)
- [ ] SSRF (out-of-band callback), XXE, deserialization, stored/DOM XSS, IDOR with supplied accounts
- [ ] Boolean/time-based SQLi detection

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
