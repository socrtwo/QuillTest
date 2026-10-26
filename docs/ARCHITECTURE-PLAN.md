# Architecture plan

Anne's Test follows the same shape as the rest of the Anne's Office suite: a thin cross-platform shell over a command registry, with the domain engine behind it. Stack and CI/release mirror Anne's Stage (TypeScript, Vite, Capacitor, Electron).

## Layers

```
┌───────────────────────────────────────────────────────┐
│ Shell (ribbon, QAB, command search Alt+Q, panels)      │  TS + Vite UI
├───────────────────────────────────────────────────────┤
│ Command registry (commands are data: ids, not code)    │  src/commands/registry.mjs
├───────────────────────────────────────────────────────┤
│ Ownership verification  │  Scan orchestrator           │  src/verify/, scripts/scan.mjs
├─────────────────────────┼─────────────────────────────┤
│ Crawler / spider        │  Check engine (passive+active)│ src/scan/crawl.mjs, passive.mjs, active.mjs
│ Staging mirror (capture/serve/scan a copy)             │ src/scan/mirror.mjs
│ Fingerprint + versions  │  Protocol checks             │ src/scan/fingerprint.mjs, versions.mjs, protocols.mjs
├─────────────────────────┴─────────────────────────────┤
│ Findings model (normalized, CWE/OWASP-mapped)          │  emitted by src/scan/*, shape in examples/
├───────────────────────────────────────────────────────┤
│ Fix/remediation registry + artifact generators        │  src/fix/
├───────────────────────────────────────────────────────┤
│ AI analysis layer (optional, multi-provider)           │  src/ai/
├───────────────────────────────────────────────────────┤
│ Report / export / diff / review packages               │  src/report/render.mjs
└───────────────────────────────────────────────────────┘
```

## Key decisions

- **Verification gates the orchestrator.** The scan orchestrator refuses to start a run for an origin without a valid, unexpired verification record. This is enforced in code, not UI.
- **Commands and checks are data.** Adding a check or a command is a registry entry, matching the suite's "no missing commands" principle and keeping the UI generic.
- **Deterministic engine, optional AI.** The crawler and checks are plain code with reproducible output. AI is a layer on top that reads findings; the product is fully functional with AI disabled.
- **Non-destructive by construction.** The check engine's probe library contains only detection probes. There is no payload library. Intrusiveness is a declared property of each check and capped per scan profile.
- **Secret hygiene.** API keys default to env-var references. Target request/response fragments are secret-scrubbed before any AI call. `quilltest.ai.json` is git-ignored.
- **Local-first.** Scans run from the user's machine/network. No Anne's Test server, no phoning home. A local model option means the whole pipeline can run offline.

## Platforms and builds

Android, iOS/iPadOS, Windows, macOS, Linux (incl. Raspberry Pi OS), ChromeOS and web — same stack and CI/release workflows as QuillStage. The scanner's network calls run in the shell's privileged context (Electron main / Capacitor native) so CORS does not constrain testing from the desktop/mobile builds; the pure-web build is limited to same-origin and CORS-permitted targets and leans on the desktop build for full active scanning.

## Status

Partially built, runnable from the command line. Implemented: ownership verification (`src/verify/`), the crawler, the passive check engine, stack fingerprinting with EOL/CVE assessment, observation-only protocol checks (`src/scan/`), fix-artifact generators (`src/fix/`), the report/export layer (`src/report/`), and the AI provider registry, wizard and analysis layer (`src/ai/`). The orchestrator is `scripts/scan.mjs`; it enforces the verification gate before any check runs. Not yet built: the injection family of active checks, and the native mobile projects (Capacitor needs the Android/iOS SDKs, scaffolded but not generated here). Built: the command registry (`src/commands/registry.mjs`, commands as data with palette search), target management (`src/targets/store.mjs`), a detection-only active engine with scan profiles (`src/scan/active.mjs`), applyable manifest patches (`src/fix/patch.mjs`), and the staging-mirror pipeline (`src/scan/mirror.mjs`). The web shell (`public/shell.html`), Electron desktop app (`electron/`) and Vite build (`vite.config.js`) are built; see [BUILD.md](BUILD.md). The shell is a renderer over the command registry. The module layout above names files that exist today; `src/report/` is `src/report/render.mjs`. See [ROADMAP.md](ROADMAP.md).
