# Staging-mirror scan mode

QuillTest can test a **copy of your own verified site** instead of the live production system. This is the recommended way to run the fuller, more thorough check set, and it is what the concurrent multi-AI analysis mode is built around.

## Why test a copy

- **Production stays untouched.** Even non-destructive checks add load and noise (log entries, rate-limit counters, alerting). Running them against a mirror leaves the live site and its users unaffected.
- **Thorough checks become safe.** Checks you would hesitate to run against production — anything that exercises forms, state-changing endpoints, or error paths — can run freely against a disposable copy.
- **Parallel AI review.** With a stable snapshot to point at, several AI providers can review the findings at the same time (concurrent mode), rather than one after another against a moving target.
- **Reproducibility.** A snapshot is a fixed artifact. Re-running a scan, or diffing two scans, compares like with like.

## What "mirror" means here

The mirror is a local, sandboxed copy of **your own** site, created only after ownership of the source origin is verified ([OWNERSHIP-VERIFICATION.md](OWNERSHIP-VERIFICATION.md)). QuillTest supports two ways to supply it:

1. **You provide the copy.** Point QuillTest at a staging/QA environment you already run, or at a local export of the site (a static capture, a container, a `docker compose` stack). This is preferred — it is unambiguously yours and matches your real stack.
2. **QuillTest captures a static snapshot.** For a site you have verified you own, QuillTest can fetch a bounded, same-origin crawl into a local directory (respecting `robots` directives and a page/byte cap) and serve it locally for analysis. This captures the client-delivered surface (HTML, headers, scripts, forms) — it does not reproduce server-side code or data, and QuillTest does not copy sites you have not verified.

The mirror is stored under `./scans/<target>/<timestamp>/` (git-ignored) and is yours to delete.

## Guardrails

- **Ownership first.** No capture and no mirror scan without a valid verification record for the source origin.
- **Isolation.** A captured snapshot is served on a local loopback address for analysis; it is not re-published anywhere.
- **Same scope, not a wider one.** Testing a copy does not unlock exploitation or any destructive check. The copy is tested with the same non-destructive detection set; the only thing that changes is *what* is tested (a disposable replica) and *how many reviewers* look at the results at once.
- **No third-party sites.** The capture refuses any origin not covered by a verification record. QuillTest is not a general-purpose website cloner.

## How it pairs with multi-AI

Configure several providers and the `concurrent` analysis mode in the wizard (see [AI-WIZARD.md](AI-WIZARD.md)). When a scan runs against a mirror, QuillTest hands the findings to all enabled providers in parallel; agreement across providers raises a finding's confidence, disagreement flags it for review (see [AI.md](AI.md)). Against live production, `sequential` mode is gentler and is the default.

## Status

Planning. The capture/serve pipeline and the mirror scan profile are specified here and not yet implemented.
