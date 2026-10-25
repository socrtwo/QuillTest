# Scan profiles and intrusiveness

Every QuillTest check declares how intrusive it is, and every scan runs under a profile that caps that level. This is how the tool keeps a promise it can state plainly: with the default profile it only observes; it never sends the target a request it would not have received anyway.

## Intrusiveness levels

| Level | Name | Meaning |
|---|---|---|
| 0 | passive | Observation without an extra request — the passive engine (headers, cookies, CORS, fingerprinting, exposed-file signatures). |
| 1 | benign-active | One or more extra requests, each with harmless input and non-state-changing semantics: GET or OPTIONS only, no form submission, no redirect following. |
| 2 | reserved | Inputs designed to probe backend handling (the injection family). **No level-2 check exists yet, and no profile enables it.** |

## Profiles

| Profile | Active? | Cap | Use |
|---|---|---|---|
| `passive` | no | 0 | Default. Runs the passive engine only. |
| `safe-active` | yes | 1 | Adds the benign active probes: HTTP method / Cross-Site Tracing, open redirect, and input reflection. |

```sh
node scripts/scan.mjs scan https://example.com --active                 # implies --profile safe-active
node scripts/scan.mjs scan https://example.com --profile safe-active
node scripts/scan.mjs scan https://example.com --active --max-active-requests 20
```

Active checks run only after the same ownership gate as the passive scan — an unverified origin exits with code 3, and there is no override. They are additive: a `--active` scan still runs the full passive engine, the fingerprinting and (with `--protocols`) the protocol checks, and folds the active findings in with `A-###` ids.

## Guarantees of the active engine

These are enforced in `src/scan/active.mjs` and pinned by `tests/active.test.mjs`:

- **Only GET and OPTIONS are sent.** No POST, PUT, DELETE, PATCH or CONNECT; no form is ever submitted.
- **Redirects are never followed** (`redirect: 'manual'`). A redirect's destination is read as evidence, not visited.
- **Benign markers only.** Reflection uses a random alphanumeric canary (`qtref…`) that contains no HTML metacharacters and so cannot execute even if echoed verbatim. Open-redirect detection uses a clearly-labelled host under the reserved `.invalid` TLD, which cannot resolve.
- **Off-origin targets are dropped.** Only URLs on the verified origin are probed.
- **A hard request budget** (`--max-active-requests`, default 60) and a per-scan URL cap bound the number of extra requests, so even your own site is not hammered.

## What is deliberately not here

The injection family — SQL injection, command injection, server-side template injection, SSRF, XXE — is specified in [CHECKS.md](CHECKS.md) but not implemented. Those checks send inputs intended to trigger backend execution, which is level 2 and outside this tool's non-destructive remit as it stands. They are a future addition behind a profile that a future version would gate explicitly; nothing enables level 2 today.
