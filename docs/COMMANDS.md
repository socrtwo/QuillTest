# Commands and targets

Two pieces of the shell layer exist as data and CLIs today, ahead of the ribbon/QAB UI: the **command registry** (what QuillTest can do) and **target management** (the sites you work with).

## Command registry

`src/commands/registry.mjs` is the single catalogue of QuillTest operations. Each command is data — an id (`group.verb`), a human title, a ribbon group, search keywords, a one-line summary, a precondition (`when`), and a `cli` descriptor of how it runs today. Nothing in the file executes; the registry is what a dispatcher reads. This is the suite's "no missing commands" principle made literal: adding a capability is adding an entry, and the CLI, a desktop shell and a web build all render the same list.

```sh
node scripts/commands.mjs                 # every command by group
node scripts/commands.mjs redirect        # search — what the Alt+Q palette does
node scripts/commands.mjs --id scan.active
node scripts/commands.mjs --json
node scripts/commands.mjs --validate      # unique ids, known groups/conditions (also a CI check)
```

`searchCommands(query)` ranks matches (exact id > prefix > word-boundary in title > substring > keyword > group), and multi-word queries require every token to hit. That function is the palette; the shell, when built, is a thin renderer over it.

Groups follow the office-suite ribbon: File, Verify, Targets, Scan, Fix, AI, Report, Help. Preconditions (`always`, `hasTarget`, `targetVerified`, `hasReport`, `aiConfigured`) let a shell enable or grey out a command.

## Target management

`src/targets/store.mjs` / `scripts/targets.mjs` track the origins you work with. A target is bookkeeping — an origin, a label, tags, a note, when it was added and last scanned. **Adding a target grants nothing**; it is kept deliberately separate from the verification store, and `list`/`show` join the two so you can see, per target, whether ownership is currently verified.

```sh
node scripts/targets.mjs add https://example.com --label "Prod" --tag prod --tag eu --note "main site"
node scripts/targets.mjs list                 # verification + last-scan status per target
node scripts/targets.mjs list --tag prod
node scripts/targets.mjs show https://example.com
node scripts/targets.mjs remove https://example.com
```

When `scripts/scan.mjs` or `scripts/mirror.mjs` scans an origin that is already a tracked target, it records the outcome (timestamp, finding counts by severity, report path) on that target, so `targets list` reflects the latest result. Re-adding an existing origin merges the new label/note and unions tags; it never duplicates. The store is one JSON file under `scans/` (git-ignored), written mode `0600`.

## Web shell

`public/shell.html` is a self-contained, build-free shell rendered from the registry: a ribbon (group tabs and command buttons), a quick-access bar with pinnable commands, and an Alt+Q (or Cmd/Ctrl-K) command palette whose search mirrors `searchCommands`. Open it via `file://` or any static server. It is dark-mode aware and keeps your pinned commands in `localStorage`.

This shell is a command launcher and reference: selecting a command shows what it does and the exact CLI line to run it, which you can copy. Executing a scan from the UI belongs to the privileged desktop/mobile build (Electron main / Capacitor native), where the scanner's network calls are not constrained by browser CORS — see [ARCHITECTURE-PLAN.md](ARCHITECTURE-PLAN.md). The inlined command catalogue is kept current by `node scripts/sync-shell-registry.mjs` (a CI check fails if it drifts), the same arrangement as the AI wizard's provider registry.
