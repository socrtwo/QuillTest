# Architecture plan

QuillTest follows the same shape as the rest of the Quill suite: a thin cross-platform shell over a command registry, with the domain engine behind it. Stack and CI/release mirror QuillStage (TypeScript, Vite, Capacitor, Electron).

## Layers

```
┌───────────────────────────────────────────────────────┐
│ Shell (ribbon, QAB, command search Alt+Q, panels)      │  TS + Vite UI
├───────────────────────────────────────────────────────┤
│ Command registry (commands are data: ids, not code)    │  src/commands/
├───────────────────────────────────────────────────────┤
│ Ownership verification  │  Scan orchestrator           │  src/verify/, src/scan/
├─────────────────────────┼─────────────────────────────┤
│ Crawler / spider        │  Check engine (passive+active)│ src/crawl/, src/checks/
├─────────────────────────┴─────────────────────────────┤
│ Findings model (normalized, CWE/OWASP-mapped)          │  src/findings/
├───────────────────────────────────────────────────────┤
│ Fix/remediation registry + artifact generators        │  src/fixes/
├───────────────────────────────────────────────────────┤
│ AI analysis layer (optional, multi-provider)           │  src/ai/
├───────────────────────────────────────────────────────┤
│ Report / export / review packages                      │  src/report/
└───────────────────────────────────────────────────────┘
```

## Key decisions

- **Verification gates the orchestrator.** The scan orchestrator refuses to start a run for an origin without a valid, unexpired verification record. This is enforced in code, not UI.
- **Commands and checks are data.** Adding a check or a command is a registry entry, matching the suite's "no missing commands" principle and keeping the UI generic.
- **Deterministic engine, optional AI.** The crawler and checks are plain code with reproducible output. AI is a layer on top that reads findings; the product is fully functional with AI disabled.
- **Non-destructive by construction.** The check engine's probe library contains only detection probes. There is no payload library. Intrusiveness is a declared property of each check and capped per scan profile.
- **Secret hygiene.** API keys default to env-var references. Target request/response fragments are secret-scrubbed before any AI call. `quilltest.ai.json` is git-ignored.
- **Local-first.** Scans run from the user's machine/network. No QuillTest server, no phoning home. A local model option means the whole pipeline can run offline.

## Platforms and builds

Android, iOS/iPadOS, Windows, macOS, Linux (incl. Raspberry Pi OS), ChromeOS and web — same stack and CI/release workflows as QuillStage. The scanner's network calls run in the shell's privileged context (Electron main / Capacitor native) so CORS does not constrain testing from the desktop/mobile builds; the pure-web build is limited to same-origin and CORS-permitted targets and leans on the desktop build for full active scanning.

## Status

Planning. Built so far:

- `src/ai/` — provider registry, config loader/validator, setup wizard.
- `src/verify/` — ownership verification; `VerificationStore.assertVerified` is the gate.
- `src/targets/` — target list with authorization statements and path scope.
- `src/commands/` — the command registry (every command as data, `area.name` ids), and `exec.mjs`, the one path that runs a command: it refuses any `requiresVerification` command unless the active target is verified **and** authorized. `src/ui/ribbonLayout.mjs` is the default tab layout, ids only. `scripts/quilltest.mjs` runs any command from the terminal; `docs/COMMANDS.md` is generated from the registry.

- `src/crawl/` — crawler, HTML extraction, cookie parsing, TLS inspection.
- `src/checks/` — check registry, 27 passive checks (observe / finalize / probe, intrusiveness 0–1) and 7 detection-only active checks (`active()` hook, intrusiveness 2, run only on active profiles against a verified, authorized target).
- `src/findings/` — findings model (severity, confidence, CWE/OWASP/ASVS, scrubbed evidence, signatures, diff) and JSON/CSV/SARIF export.
- `src/scan/` — orchestrator (calls the gate itself before any request; passive then active phases, each budgeted), the injection-point model, profiles, scan store with per-target settings and false-positive rules.

The UI shell, the remaining active checks (SSRF out-of-band, XXE, deserialization, stored/DOM XSS, account-based IDOR), fixes (M4), AI analysis (M5) and reports (M6) are specified, not built. Planned commands exist in the registry now so the shell can be generic from day one; running one reports "planned but not implemented".
