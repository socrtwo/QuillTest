# Roadmap

Milestones, roughly ordered. Dates omitted deliberately; this is a planning repo.

## M0 — Foundations (in progress)

- [x] Repository, license, documentation plan
- [x] AI provider registry (`src/ai/providers.mjs`)
- [x] AI setup wizard — CLI (`scripts/ai-setup-wizard.mjs`), multi-provider + mode
- [x] AI setup wizard — browser (`public/ai-wizard.html`), multi-provider + mode
- [x] Multi-provider config (v2: `activeProviders`, `analysisMode`) + v1 normalization
- [x] Config module + schema validation for `quilltest.ai.json` — `src/ai/config-schema.mjs`, `ai-setup-wizard.mjs --validate`, enforced before every analysis run
- [x] Project scaffold (Vite, Electron, Capacitor, CI) — `vite.config.js` web build (verified), `electron/` desktop main + guarded command bridge, `capacitor.config.json`; CI builds the web app, `release.yml` packages the desktop app on a tag. See [BUILD.md](BUILD.md).

## M1 — Ownership and shell

- [x] Ownership verification module (file-upload + DNS TXT), the scan gate (`src/verify/`, `scripts/scan.mjs verify`)
- [x] Command registry + minimal ribbon/QAB shell — `src/commands/registry.mjs` (commands as data, Alt+Q palette search), CLI `scripts/commands.mjs`, and a self-contained web shell `public/shell.html` (ribbon, quick-access bar, Alt+Q palette) rendered from the registry. The full Vite/Capacitor/Electron shell remains part of the M0 scaffold.
- [x] Target management — `src/targets/store.mjs`, `scripts/targets.mjs` (add/list/show/remove with tags/notes, joined with verification status; scans record their outcome on a tracked target)
- [x] Staging-mirror capture/serve pipeline — `src/scan/mirror.mjs`, `scripts/mirror.mjs` (capture a bounded own-site snapshot, serve it on loopback, scan the copy offline with real-origin findings)

## M2 — Passive engine

- [x] Crawler/spider — `src/scan/crawl.mjs`: same-origin, robots/sitemap-aware, page/depth/query caps, never follows state-changing links; page checks run site-wide with aggregation
- [x] Passive checks (transport, headers, cookies, CORS, disclosure, mixed content, exposed files) — `src/scan/passive.mjs`
- [x] Findings model with CWE/OWASP mapping, severity + confidence, per-finding remediation
- [x] Stack fingerprinting (server / framework / CMS / libraries, with evidence) — `src/scan/fingerprint.mjs`
- [x] Match fingerprinted versions against EOL lines and known-CVE ranges (offline table) + optional OSV.dev lookup — `src/scan/versions.mjs`

## M3 — Active engine

- [~] Active checks — detection-only, ownership-gated engine with scan profiles (`src/scan/active.mjs`, `scan --active`): HTTP method / Cross-Site Tracing, open redirect, and input-reflection (reflected-XSS precondition) implemented; the injection family (SQLi, command, SSTI, SSRF, XXE) remains specified in CHECKS.md, behind a future higher-intrusiveness profile
- [x] Protocol checks beyond HTTP (TLS, FTP, mail, DNS) — observation-only, per-host ownership-gated — `src/scan/protocols.mjs`, `scripts/scan.mjs protocols`
- [x] Scan profiles and intrusiveness caps — `SCAN_PROFILES` (passive | safe-active) with a declared per-check intrusiveness level and a hard request budget — `src/scan/active.mjs`

## M4 — Fix layer

- [x] Artifact generators: server header blocks (nginx/Apache/Caddy/IIS/Express/Netlify), crawl-derived CSP, framework cookie settings — `src/fix/artifacts.mjs`, `scripts/fix.mjs`, `scan --fixes`
- [x] Dependency-bump artifacts for fingerprinted components: package.json / composer.json fragments, replacement CDN tags, upgrade commands, per-component summary — `src/fix/dependencies.mjs` (emitted by `generateFixes`)
- [x] Applyable patch/diff generation for dependency manifests: `fix.mjs --patch package.json|composer.json` emits a `git apply`-ready unified diff that bumps flagged versions, never applied — `src/fix/patch.mjs`

## M5 — AI analysis

- [x] Analysis layer (`src/ai/analyze.mjs`): triage, prioritize, explain, draft remediations, flag false positives
- [x] Secret-scrubbing, size caps, output filter, `--dry-run`
- [x] Several-AI corroboration: sequential/concurrent consultation + per-finding consensus
- [x] Wire the analysis layer to the scanner's findings output (`scripts/scan.mjs scan --analyze`)

## M6 — Report and release

- [x] Report/export (self-contained HTML, Markdown, CSV), findings diff between scans, review packages with SHA-256 manifest — `src/report/render.mjs`, `scripts/report.mjs`, `scan --export`
- [x] Cross-platform builds and release workflow — electron-builder targets (AppImage/deb, dmg/zip, nsis/portable) and `.github/workflows/release.yml` (tag-driven, per-OS matrix). Mobile packaging runs from a maintainer machine with the SDKs.
- [x] SECURITY.md and responsible-disclosure policy
- [x] CI (GitHub Actions): registry-sync check, syntax, offline tests, keyless dry-run, secret scan
