# Building QuillTest

The engine and CLIs are dependency-free and run on Node 18+ with nothing installed. The **apps** — the web build, the Electron desktop app and the Capacitor mobile app — are built with the same stack as the rest of the Quill suite (Vite, Electron, Capacitor). Install the build tooling with `npm ci` first.

## Web

```sh
npm run build       # → dist/ (static: index.html, public/shell.html, public/ai-wizard.html)
npm run preview     # serve dist/ locally on 127.0.0.1
npm run dev         # Vite dev server with HMR
```

The pages are self-contained (inline CSS and inline module scripts), so Vite just minifies and fingerprints them — there is no framework runtime. `base` is relative, so the build works served from a subpath, from `file://`, or inside an Electron bundle. Serve `dist/` with any static host.

## Desktop (Electron)

```sh
npm run electron:dev     # Vite dev server + Electron, pointed at it
npm run electron:build   # vite build, then electron-builder → release/
```

The desktop build loads the same web app but in a privileged context: the main process makes the scanner's network calls, which the pure-web build cannot do across origins because of browser CORS (see [ARCHITECTURE-PLAN.md](ARCHITECTURE-PLAN.md)).

**Security posture.** The renderer runs with `contextIsolation` on, `nodeIntegration` off and `sandbox` on. Its only privileged capability, via the preload bridge, is to ask the main process to run a **known** QuillTest command by its registry id with string arguments — never an arbitrary command line. `electron/bridge.mjs` validates the id against the command registry and the argument types; the main process spawns the mapped script with an argument array (no shell), so there is no command-injection surface. That boundary is unit-tested (`tests/electron-bridge.test.mjs`) without launching Electron.

`electron-builder` targets AppImage/deb (Linux), dmg/zip (macOS) and nsis/portable (Windows). The `release.yml` workflow builds all three on a version tag and attaches the installers to the GitHub Release for that tag (via `softprops/action-gh-release`), so they appear on the release page for download.

## Mobile (Capacitor)

```sh
npm run cap:sync            # vite build, then copy the web app into the native projects
npm run cap:add:android     # scaffold the Android project (needs Android SDK)
npm run cap:add:ios         # scaffold the iOS project (needs Xcode, macOS)
```

`capacitor.config.json` points `webDir` at `dist`. Adding and building the native projects needs the platform SDKs (Android Studio / Xcode), so it is done on a maintainer machine, not in the per-commit CI.

## What CI builds

The per-commit `CI` workflow runs the offline test suite on Node 18/20/22 and, in a separate job, `npm run build` (the web app) with a check that the output and the registry sync are current. The desktop and mobile packaging run on demand (`release.yml` on a tag), where the build hosts and SDKs are available.
