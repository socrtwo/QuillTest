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

- [x] Ownership verification module (file-upload + DNS TXT), the scan gate (`src/verify/`, `scripts/scan.mjs verify`)
- [ ] Command registry + minimal ribbon/QAB shell
- [ ] Target management
- [ ] Staging-mirror capture/serve pipeline (own-site snapshot, loopback serve)

## M2 — Passive engine

- [x] Crawler/spider — `src/scan/crawl.mjs`: same-origin, robots/sitemap-aware, page/depth/query caps, never follows state-changing links; page checks run site-wide with aggregation
- [x] Passive checks (transport, headers, cookies, CORS, disclosure, mixed content, exposed files) — `src/scan/passive.mjs`
- [x] Findings model with CWE/OWASP mapping, severity + confidence, per-finding remediation
- [x] Stack fingerprinting (server / framework / CMS / libraries, with evidence) — `src/scan/fingerprint.mjs`
- [x] Match fingerprinted versions against EOL lines and known-CVE ranges (offline table) + optional OSV.dev lookup — `src/scan/versions.mjs`

## M3 — Active engine

- [ ] Active checks (injection, XSS, CSRF, SSRF, XXE, access control, redirects) — detection only, gated on verification
- [ ] Protocol checks beyond HTTP (FTP, mail, DNS, TLS) — detection only, per-host ownership-gated
- [ ] Scan profiles and intrusiveness caps

## M4 — Fix layer

- [x] Artifact generators: server header blocks (nginx/Apache/Caddy/IIS/Express/Netlify), crawl-derived CSP, framework cookie settings — `src/fix/artifacts.mjs`, `scripts/fix.mjs`, `scan --fixes`
- [ ] Dependency-bump artifacts (package manifests) for fingerprinted libraries
- [ ] Applyable patch/diff generation for provided or verified artifacts

## M5 — AI analysis

- [x] Analysis layer (`src/ai/analyze.mjs`): triage, prioritize, explain, draft remediations, flag false positives
- [x] Secret-scrubbing, size caps, output filter, `--dry-run`
- [x] Several-AI corroboration: sequential/concurrent consultation + per-finding consensus
- [x] Wire the analysis layer to the scanner's findings output (`scripts/scan.mjs scan --analyze`)

## M6 — Report and release

- [ ] Report/export, review packages, findings diff
- [ ] Cross-platform builds and release workflow (parity with QuillStage)
- [x] SECURITY.md and responsible-disclosure policy
- [x] CI (GitHub Actions): registry-sync check, syntax, offline tests, keyless dry-run, secret scan
