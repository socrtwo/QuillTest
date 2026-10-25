# QuillTest

*Part of the Quill suite: [QuillPen](https://github.com/socrtwo/QuillPen) (documents), [QuillGrid](https://github.com/socrtwo/QuillGrid) (spreadsheets), [QuillPost](https://github.com/socrtwo/QuillPost) (email), [QuillStage](https://github.com/socrtwo/QuillStage) (presentations), [QuillLoom](https://github.com/socrtwo/QuillLoom) (web authoring), [QuillPress](https://github.com/socrtwo/QuillPress) (desktop publishing), and [QuillFolio](https://github.com/socrtwo/QuillFolio) (PDF).*

**Quill Test** (repository `QuillTest`) is an original, open-source web application security **testing and fixing** tool for Windows, macOS, Linux, ChromeOS and the web. It tests a target website for known classes of security flaws and uses AI, through the major provider APIs, to reason about the vulnerabilities an attacker — including an AI-assisted one — would look for, then helps you **fix** them with concrete, mapped remediations. It does not exploit anything. Its goal is the same as the rest of the Quill suite: **no missing commands**. It provides the familiar office-suite workflow plus the best ideas from current and former web security scanners.

> **Status: early, runnable.** Implemented today: the ownership-verification gate, a same-origin crawler, a site-wide passive scan engine (headers, transport, cookies, CORS, disclosure, mixed content, forms, SRI, exposed files — each finding with a concrete fix), stack fingerprinting with EOL/CVE assessment, fix-artifact generation (server header blocks, a crawl-derived CSP, cookie settings), the multi-provider AI setup wizard, and the AI analysis layer with cross-provider consensus. Not yet implemented: active checks (injection/XSS detection), applyable patches, and the desktop/mobile shell. The pipeline below runs end-to-end from the command line.

## Scope and ethics — read first

QuillTest is a **defensive** tool. It **detects, reports, and helps fix** weaknesses; it does not ship working exploit code, payloads, or anything whose purpose is to compromise, deface, exfiltrate from, or damage a target.

- **Proof of ownership is mandatory.** Before any scan, QuillTest issues a unique verification file and requires you to upload it to a well-known path on the target (e.g. `https://target/.well-known/quilltest-verification/<token>.txt`). QuillTest fetches that file and confirms the token and checksum match before a single check runs. No valid verification file, no scan. This is the same domain-control challenge model used by ACME/Let's Encrypt (HTTP-01) and Search Console. See [docs/OWNERSHIP-VERIFICATION.md](docs/OWNERSHIP-VERIFICATION.md).
- **Authorization is mandatory.** Scan only sites you own or are explicitly authorized in writing to test. Scanning systems without authorization is illegal in most jurisdictions (in the United States, the Computer Fraud and Abuse Act). The ownership check above is the technical gate; you also confirm authorization for each target, and QuillTest records both in the scan report.
- **Detect, don't weaponize.** Like OWASP ZAP, nuclei, and Nikto, QuillTest confirms a finding with the least intrusive probe that proves it, then stops. It does not escalate, pivot, or carry out an attack.
- **AI is for analysis, not attack.** The AI providers are used to triage findings, explain risk, reduce false positives, map findings to CWE/OWASP categories, and reason about what an attacker would prioritize. Prompts are constructed so the models analyze the target's responses; they are not used to generate live attack payloads against third-party systems.

See [docs/LEGAL.md](docs/LEGAL.md) and [docs/ETHICS.md](docs/ETHICS.md).

## Features and plan

- **A complete command set.** Every command a modern web security scanner offers, patterned after Microsoft Office and the rest of the Quill suite: File, Verify, Scan, Targets, Checks, Findings, Fix, AI, Report, Review, Share, Help.
- **No missing commands.** Commands are data. The ribbon, Quick Access Bar, custom tabs, context menus, shortcuts, macros and command search (Alt+Q) all refer to command ids.
- **Known-flaw coverage.** Passive and active checks mapped to the OWASP Top 10, OWASP ASVS, and CWE: injection (SQLi, command, template, header), cross-site scripting (reflected, stored, DOM), CSRF, SSRF, XXE, insecure deserialization, broken authentication and session handling, broken access control / IDOR, security-header and TLS misconfiguration, cookie flags, CORS misconfiguration, open redirects, directory listing and sensitive-file exposure, outdated/vulnerable components, and information disclosure. See [docs/CHECKS.md](docs/CHECKS.md).
- **Test *and* fix.** Every finding carries a remediation: the specific config change, header, code pattern, or dependency bump that closes it, mapped to the framework/server QuillTest detected. Where the fix is a copy-pasteable artifact — a security-header block for nginx/Apache/Caddy, a Content-Security-Policy, a cookie-flag change, a dependency version bump — QuillTest generates it, and (for assets you can verify you own) can produce a ready-to-apply patch or config file. It never changes a live site on its own. See [docs/FIXES.md](docs/FIXES.md).
- **AI-assisted analysis (optional), with as many models as you like.** The setup wizard has a checkbox per provider; enable one or several, and QuillTest consults each over the same findings — **sequentially** (one after another) or **concurrently** (all at once). More models means more corroboration: findings they all agree on surface first, disagreements get flagged for review. The AI layer reviews *QuillTest's own findings and the target's observed responses* — it never runs the scan for you and never emits attack payloads. See [docs/AI.md](docs/AI.md).
- **Bring-your-own-model setup wizard.** Enable any of the major API providers — OpenAI, Anthropic, Google (Gemini), xAI (Grok), Meta (Llama, via a hosted gateway), DeepSeek, Alibaba (Qwen), and Mistral — or a local model (Ollama / llama.cpp / LM Studio) and any OpenAI-compatible endpoint. Tick several at once and pick the analysis mode; each is connectivity-tested. Keys are stored locally (env-var references by default), never committed. See [docs/AI-WIZARD.md](docs/AI-WIZARD.md).
- **Test a copy of your own site.** Point QuillTest at a staging mirror of a site you have verified you own (or let it capture a bounded same-origin snapshot), so production is never stressed and several AI reviewers can work a stable snapshot in parallel. Same non-destructive check set — just run against a disposable copy. See [docs/STAGING-MIRROR.md](docs/STAGING-MIRROR.md).
- **More than HTTP.** On hosts you have verified you own, QuillTest also checks FTP, mail (SMTP/IMAP/POP3), DNS, and TLS for known weaknesses — plaintext where encryption should be, anonymous access, outdated vulnerable versions, missing SPF/DKIM/DMARC, public zone transfer. Detection only: no credential guessing, no exploitation. See [docs/PROTOCOLS.md](docs/PROTOCOLS.md).
- **Original ideas.** An attacker's-eye priority queue, a findings diff across scans, a plain-language remediation writer, a false-positive learning loop, scan-as-you-configure preview, and export-ready review packages. See [docs/INNOVATIONS.md](docs/INNOVATIONS.md).

## Checking other protocols

A host usually runs more than its web app. After verifying a host you can check its other services — observation-only, and gated the same way:

```bash
node scripts/scan.mjs protocols example.com            # TLS, FTP, SMTP, IMAP, POP3, DNS
node scripts/scan.mjs scan https://example.com --protocols   # fold them into a web scan
```

It reads the TLS certificate and the capability handshakes servers advertise (`FEAT`, `EHLO`, `CAPABILITY`, `CAPA`) to find plaintext FTP/mail, missing STARTTLS, AUTH before TLS, expired or mismatched certificates, weak SPF/DMARC, and missing CAA/DNSSEC. It never sends credentials, attempts a login, relays mail, or requests a zone transfer; anonymous-FTP and open-relay status are flagged as manual checks rather than performed.

## Running a scan

Three commands. The first two prove you control the origin; the third refuses to run without that proof.

```bash
# 1. Get a verification file to place on your site (a DNS TXT alternative is printed too)
node scripts/scan.mjs verify issue https://staging.example.com

# 2. After uploading it to /.well-known/quilltest-verification/<token>.txt, confirm it
node scripts/scan.mjs verify check https://staging.example.com

# 3. Scan. Add --analyze to have every configured AI provider review the findings.
node scripts/scan.mjs scan https://staging.example.com --analyze --mode concurrent
```

Add `--fixes` to get ready-to-review config files: a security-header block for the server QuillTest detected (nginx, Apache, Caddy, IIS, Express, Netlify), a Content-Security-Policy whose allow-list is exactly the third-party origins the crawler saw on your pages (emitted report-only first, with the enforced version alongside), cookie settings for your framework, and — for every component the fingerprint found end-of-life or vulnerable — a `package.json`/`composer.json` fragment, replacement CDN tags, the upgrade commands, and a summary of detected → minimum safe → recommended versions with the CVEs behind each. `scripts/fix.mjs --report <scan.json> --target apache` regenerates from a saved report. Add `--online-cve` to also check fingerprinted libraries against OSV.dev (off by default; the scan is otherwise fully offline apart from the target itself).

Add `--export html` (or `md`, `csv`, `all`) to write a human-readable report next to the JSON. `scripts/report.mjs` does the rest from a saved report: `--diff previous.json` adds a new / resolved / changed section, `--package review/` writes the report in every format plus the fix artifacts and a manifest with a SHA-256 per file, and `--verify review/` checks a package against its manifest. The HTML is self-contained and script-free; open it in a browser and print to PDF. See [docs/REPORTS.md](docs/REPORTS.md).

Scanning an origin without a valid verification exits with code 3; there is no override flag. By default the scan crawls up to 25 same-origin pages (honoring `robots.txt`, never following logout/delete-style links) and runs the header, cookie, content and form checks on every one, collapsing site-wide gaps into single findings with page counts. It also fingerprints the stack (server, framework, CMS) so fixes are phrased for what you actually run. Reports are written under `scans/<host>/` (git-ignored) with cookie values masked. Each origin — scheme, host, *and* port — needs its own verification.

## The AI setup wizard

A runnable wizard is included now, ahead of the scanner. It walks you through selecting one or more providers, entering credentials, picking a model and analysis mode, and running a connectivity test against each, then writes a local `quilltest.ai.json` config (git-ignored).

```bash
# Interactive CLI wizard (Node 18+) — multi-select providers, choose mode
node scripts/ai-setup-wizard.mjs

# Enable several providers at once and test each (--yes suppresses prompts;
# each key is read from its env var, e.g. $OPENAI_API_KEY, or pass --key-env / --key)
node scripts/ai-setup-wizard.mjs --providers openai,anthropic,xai,deepseek --mode concurrent --yes --test

# Single provider
node scripts/ai-setup-wizard.mjs --provider anthropic --model claude-opus-5-5 --yes --test

# Show the exact request the connectivity test would send, without sending it
node scripts/ai-setup-wizard.mjs --provider openai --yes --dry-run --no-save
```

With providers configured, the **analysis layer** can be run today over a findings file (the scanner that will produce findings is not built yet; a sample is included):

```bash
# See exactly what would be sent to each provider — scrubbed, capped, no keys needed
node scripts/ai-analyze.mjs --findings examples/findings.sample.json --dry-run

# Consult every enabled provider and print the cross-provider consensus
node scripts/ai-analyze.mjs --findings examples/findings.sample.json --mode concurrent --out analysis.json
```

Guardrails are in code, not just policy: secrets are scrubbed from findings before they leave the machine, payloads are capped, the model is confined to analysis and remediation, and payload-shaped lines in a reply are filtered out and flagged. See [docs/AI.md](docs/AI.md).

A browser version of the same wizard lives at `public/ai-wizard.html` (open it directly; it runs entirely client-side and stores config in `localStorage`). Both are driven by the single provider registry in [`src/ai/providers.mjs`](src/ai/providers.mjs). The browser page is a static file and cannot import that module, so it carries a generated copy: after editing the registry run `npm run ai:sync-browser` (the test suite fails if the copy is stale).

Supported providers out of the box:

| Provider | Models (examples) | Endpoint base | API style |
|---|---|---|---|
| OpenAI | gpt-5.4, gpt-5.4-mini, gpt-5.4-nano | `https://api.openai.com/v1` | OpenAI (sends `max_completion_tokens`) |
| Anthropic | claude-opus-5-5, claude-sonnet-5-5, claude-haiku-5-5 | `https://api.anthropic.com/v1` | Anthropic Messages |
| Google (Gemini) | gemini-3.1-pro-preview, gemini-3-flash-preview | `https://generativelanguage.googleapis.com/v1beta` | Gemini (key in `x-goog-api-key` header) |
| xAI (Grok) | grok-4.6, grok-4.5, grok-4.3 | `https://api.x.ai/v1` | OpenAI-compatible |
| Meta (Llama) | Llama-4-Maverick-17B-128E-Instruct-FP8, Llama-3.3-70B-Instruct | `https://api.llama.com/compat/v1` or a gateway (Together, Groq, Fireworks, OpenRouter) | OpenAI-compatible |
| DeepSeek | deepseek-chat, deepseek-reasoner | `https://api.deepseek.com` | OpenAI-compatible |
| Alibaba (Qwen) | qwen3-max, qwen-plus, qwen3-coder-plus | `https://dashscope-intl.aliyuncs.com/compatible-mode/v1` | OpenAI-compatible |
| Mistral | mistral-large-latest, mistral-medium-latest, mistral-small-latest | `https://api.mistral.ai/v1` | OpenAI-compatible |
| Local | any (Ollama / llama.cpp / LM Studio) | `http://localhost:11434/v1` | OpenAI-compatible |
| Custom | any | user-supplied | OpenAI-compatible |

> Model names drift. The wizard treats the lists above as suggestions and lets you type any model id the provider accepts; it fetches the live model list where the provider exposes one (every provider above does, at `GET {base}/models`). Vendor-hosted Llama model ids in particular differ from gateway to gateway.

## Platforms (planned)

Windows, macOS, Linux (including Raspberry Pi OS), ChromeOS and the web, with the same stack and CI/release workflows as QuillStage (TypeScript, Vite, Capacitor, Electron).

## Documentation

| File | Contents |
|---|---|
| [docs/AI-WIZARD.md](docs/AI-WIZARD.md) | The provider setup wizard: flow, config format, adding providers |
| [docs/AI.md](docs/AI.md) | How AI is used for analysis, and the guardrails on it |
| [docs/OWNERSHIP-VERIFICATION.md](docs/OWNERSHIP-VERIFICATION.md) | The prove-you-own-it file-upload challenge that gates every scan |
| [docs/STAGING-MIRROR.md](docs/STAGING-MIRROR.md) | Testing a copy of your own verified site, and concurrent AI review |
| [docs/PROTOCOLS.md](docs/PROTOCOLS.md) | FTP, mail, DNS, TLS checks beyond HTTP — detection only |
| [docs/FIXES.md](docs/FIXES.md) | How findings become remediations and applyable fixes |
| [docs/REPORTS.md](docs/REPORTS.md) | Report formats, the findings diff, and review packages |
| [docs/CHECKS.md](docs/CHECKS.md) | Vulnerability-check inventory by category, with what is implemented |
| [docs/ARCHITECTURE-PLAN.md](docs/ARCHITECTURE-PLAN.md) | Shell, crawler, check engine, findings model, AI layer, report, builds |
| [docs/INNOVATIONS.md](docs/INNOVATIONS.md) | Survey of web scanners and what QuillTest adopts |
| [docs/ETHICS.md](docs/ETHICS.md) | Authorization, responsible use, and what QuillTest will not do |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Milestones |
| [docs/LEGAL.md](docs/LEGAL.md) | Clean-room, trademark and licensing notes |

## License

[MIT](LICENSE). Copyright (c) 2026 Paul D Pruitt.

## Legal

QuillTest is an independent, clean-room project. It is not affiliated with, endorsed by, or sponsored by OWASP, PortSwigger (Burp Suite), the ZAP project, Tenable (Nessus/Nikto), OpenAI, Anthropic, Google, xAI, Meta, DeepSeek, Alibaba, Mistral, or any other vendor named in the docs. Names are used only to describe compatibility, provider APIs, and history.
