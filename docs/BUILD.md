# Building Anne's Test

The engine and CLIs are dependency-free and run on Node 18+ with nothing installed. The **apps** need a newer Node: Vite 8 requires Node 20.19+ or 22.12+ (and `vite.config.js` uses `import.meta.dirname`), so `npm run build`, `dev`, `preview`, `electron:build` and `cap:sync` do not run on Node 18 even though the scanner does. The **apps** — the web build, the Electron desktop app and the Capacitor mobile app — are built with the same stack as the rest of the Anne's Office suite (Vite, Electron, Capacitor). Install the build tooling with `npm ci` first.

## Web

```sh
npm run build       # → dist/ (static: index.html, public/shell.html, public/ai-wizard.html)
npm run preview     # serve dist/ locally on 127.0.0.1
npm run dev         # Vite dev server with HMR
```

The pages are self-contained (inline CSS and inline module scripts), so Vite just minifies and fingerprints them — there is no framework runtime. `base` is relative, so the build works served from a subpath or inside an Electron bundle. Serve `dist/` with any static host (`npm run preview`): Vite extracts the module scripts into `dist/assets/`, and browsers refuse module scripts from `file://`, so the *built* pages need a server. The *source* pages (`public/shell.html`, `public/ai-wizard.html`) are self-contained and can be opened directly from disk.

## Desktop (Electron)

```sh
npm run electron:dev     # Vite dev server + Electron, pointed at it
npm run electron:build   # vite build, then electron-builder → release/
```

The desktop build loads the same web app but in a privileged context: the main process makes the scanner's network calls, which the pure-web build cannot do across origins because of browser CORS (see [ARCHITECTURE-PLAN.md](ARCHITECTURE-PLAN.md)).

**Security posture.** The renderer runs with `contextIsolation` on, `nodeIntegration` off and `sandbox` on. Its only privileged capability, via the preload bridge, is to ask the main process to run a **known** Anne's Test command by its registry id with string arguments — never an arbitrary command line. `electron/bridge.mjs` validates the id against the command registry and the argument types; the main process spawns the mapped script with an argument array (no shell), so there is no command-injection surface, and it only honours requests whose sender frame is the app's own page. New windows are denied and `http(s)` links are handed to the system browser. That boundary is unit-tested (`tests/electron-bridge.test.mjs`) without launching Electron.

**Packaged layout.** electron-builder packs the app into `app.asar`; `src/` and `scripts/` are listed in `build.asarUnpack` so the main process can spawn them as plain Node from `app.asar.unpacked/`. When packaged, the scripts run with the user data folder as their working directory, so reports (`scans/`), the verification store and `quilltest.ai.json` land there rather than in the read-only archive. The Capacitor native packages are excluded from the desktop bundle. (The packaged flow is exercised by the release workflow, not by the per-commit CI.)

`electron-builder` targets AppImage/deb (Linux x64), dmg/zip (macOS, Apple silicon and Intel) and an NSIS installer (`…-setup.exe`) plus a portable executable (`…-portable.exe`) on Windows; the two Windows targets carry distinct artifact names because the shared default name made the portable build overwrite the installer. The `release.yml` workflow builds all three on a version tag and attaches the installers to the GitHub Release for that tag (via `softprops/action-gh-release`), so they appear on the release page for download.

## Mobile (Capacitor)

```sh
npm run cap:sync            # vite build, then copy the web app into the native projects
npm run cap:add:android     # scaffold the Android project (needs Android SDK)
npm run cap:add:ios         # scaffold the iOS project (needs Xcode, macOS)
```

`capacitor.config.json` points `webDir` at `dist`. Adding and building the native projects needs the platform SDKs (Android Studio / Xcode), so it is done on a maintainer machine, not in the per-commit CI.

## What CI builds

The per-commit `CI` workflow runs the offline test suite on Node 18/20/22 and, in a separate job, `npm run build` (the web app) with a check that the output and the registry sync are current. The desktop and mobile packaging run on demand (`release.yml` on a tag), where the build hosts and SDKs are available.
