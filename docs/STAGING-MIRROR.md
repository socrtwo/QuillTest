# Staging-mirror scan mode

Anne's Test can test a **copy of your own verified site** instead of the live production system. This is the recommended way to run the fuller, more thorough check set, and it is what the concurrent multi-AI analysis mode is built around.

## Why test a copy

- **Production stays untouched.** Even non-destructive checks add load and noise (log entries, rate-limit counters, alerting). Running them against a mirror leaves the live site and its users unaffected.
- **Thorough checks become safe.** Checks you would hesitate to run against production — anything that exercises forms, state-changing endpoints, or error paths — can run freely against a disposable copy.
- **Parallel AI review.** With a stable snapshot to point at, several AI providers can review the findings at the same time (concurrent mode), rather than one after another against a moving target.
- **Reproducibility.** A snapshot is a fixed artifact. Re-running a scan, or diffing two scans, compares like with like.

## What "mirror" means here

The mirror is a local, sandboxed copy of **your own** site, created only after ownership of the source origin is verified ([OWNERSHIP-VERIFICATION.md](OWNERSHIP-VERIFICATION.md)). Anne's Test supports two ways to supply it:

1. **You provide the copy.** Point Anne's Test at a staging/QA environment you already run, or at a local export of the site (a static capture, a container, a `docker compose` stack). This is preferred — it is unambiguously yours and matches your real stack.
2. **Anne's Test captures a static snapshot.** For a site you have verified you own, Anne's Test can fetch a bounded, same-origin crawl into a local directory (respecting `robots` directives and a page/byte cap) and serve it locally for analysis. This captures the client-delivered surface (HTML, headers, scripts, forms) — it does not reproduce server-side code or data, and Anne's Test does not copy sites you have not verified.

The mirror is stored under `./scans/<target>/<timestamp>/` (git-ignored) and is yours to delete.

## Guardrails

- **Ownership first.** No capture and no mirror scan without a valid verification record for the source origin.
- **Isolation.** A captured snapshot is served on a local loopback address for analysis; it is not re-published anywhere.
- **Same scope, not a wider one.** Testing a copy does not unlock exploitation or any destructive check. The copy is tested with the same non-destructive detection set; the only thing that changes is *what* is tested (a disposable replica) and *how many reviewers* look at the results at once.
- **No third-party sites.** The capture refuses any origin not covered by a verification record. Anne's Test is not a general-purpose website cloner.

## How it pairs with multi-AI

Configure several providers and the `concurrent` analysis mode in the wizard (see [AI-WIZARD.md](AI-WIZARD.md)). When a scan runs against a mirror, Anne's Test hands the findings to all enabled providers in parallel; agreement across providers raises a finding's confidence, disagreement flags it for review (see [AI.md](AI.md)). Against live production, `sequential` mode is gentler and is the default.

## Status

Implemented in `src/scan/mirror.mjs`, CLI `scripts/mirror.mjs` (`npm run mirror`):

- `mirror capture <origin>` runs a bounded, same-origin, robots-aware crawl (reusing `src/scan/crawl.mjs`) and writes the snapshot to `scans/<host>/<timestamp>/` — a `mirror.json` manifest (URL, status, captured response headers, content-type per page) plus the HTML bodies as files, capped by `--max-pages` and `--max-bytes`. Hop-by-hop headers are stripped; nothing is captured for an origin without a verification record.
- `mirror serve <dir>` replays the snapshot on a `127.0.0.1` address (loopback only, never re-published) so a browser or external tool can inspect the copy.
- `mirror scan <origin> [--dir <snapshot>]` runs the normal passive engine against the snapshot through an offline fetch adapter that reads the captured responses. The scan is reproducible and network-free, and its findings name the real origin, not the loopback address. With `--analyze` it hands the findings to the configured providers (use `concurrent` mode for parallel review).

**Scope note.** A mirror reproduces the client-delivered surface — headers, HTML, scripts, forms — so header, cookie, CORS, disclosure, fingerprint and component checks run exactly as on a live scan. Checks that depend on live scheme behavior (the http→https redirect) reflect the capture, not production; run those against the live origin. The capture and the mirror scan are gated on ownership identically to a live scan, and the copy is tested with the same non-destructive set.
