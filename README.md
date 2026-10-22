# QuillTest

*Part of the Quill suite: [QuillPen](https://github.com/socrtwo/QuillPen) (documents), [QuillGrid](https://github.com/socrtwo/QuillGrid) (spreadsheets), [QuillPost](https://github.com/socrtwo/QuillPost) (email), [QuillStage](https://github.com/socrtwo/QuillStage) (presentations), [QuillLoom](https://github.com/socrtwo/QuillLoom) (web authoring), [QuillPress](https://github.com/socrtwo/QuillPress) (desktop publishing), and [QuillFolio](https://github.com/socrtwo/QuillFolio) (PDF).*

**Quill Test** (repository `QuillTest`) is an original, open-source web application security **testing and fixing** tool for Windows, macOS, Linux, ChromeOS and the web. It tests a target website for known classes of security flaws and uses AI, through the major provider APIs, to reason about the vulnerabilities an attacker — including an AI-assisted one — would look for, then helps you **fix** them with concrete, mapped remediations. It does not exploit anything. Its goal is the same as the rest of the Quill suite: **no missing commands**. It provides the familiar office-suite workflow plus the best ideas from current and former web security scanners.

> **Status: planning. There is no scanner engine yet.** This repository holds the plan, the documentation, a runnable AI-provider setup wizard (`scripts/ai-setup-wizard.mjs`, `src/ai/`), and the ownership-verification module and CLI that will gate every scan (`scripts/verify.mjs`, `src/verify/`). The scanning and remediation engine described below is not implemented.

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
- **AI-assisted analysis (optional).** A setup wizard, and several-AI modes: triage and deduplicate findings, rank by exploitability, explain each flaw in plain language, draft and refine the remediations, map to CWE/OWASP, draft the executive summary, and flag likely false positives. The AI layer reviews *QuillTest's own findings and the target's observed responses* — it never runs the scan for you and never emits attack payloads. See [docs/AI.md](docs/AI.md).
- **Bring-your-own-model setup wizard.** Configure any of the major API providers — OpenAI, Anthropic, Google (Gemini), xAI (Grok), Meta (Llama, via a hosted gateway), DeepSeek, Alibaba (Qwen), and Mistral — or a local model (Ollama / llama.cpp / LM Studio) and any OpenAI-compatible endpoint. Keys are stored locally, never committed. See [docs/AI-WIZARD.md](docs/AI-WIZARD.md).
- **Original ideas.** An attacker's-eye priority queue, a findings diff across scans, a plain-language remediation writer, a false-positive learning loop, scan-as-you-configure preview, and export-ready review packages. See [docs/INNOVATIONS.md](docs/INNOVATIONS.md).

## Ownership verification (built)

The scan gate exists ahead of the scanner. It issues a challenge bound to one exact origin, checks the published file (or DNS TXT record), and records the result; the future orchestrator refuses to run for any origin without a current record.

```bash
node scripts/verify.mjs issue  https://example.com      # prints the file to publish at /.well-known/quilltest-verification/<token>.txt
node scripts/verify.mjs check  https://example.com      # fetches it back; on success the origin is verified for 30 days
node scripts/verify.mjs status https://example.com      # exit 0 if scanning is permitted
```

Details, including the exact file format, redirect rules and the DNS alternative, are in [docs/OWNERSHIP-VERIFICATION.md](docs/OWNERSHIP-VERIFICATION.md).

## Passive scanning (built)

The M2 engine is in: a polite same-origin crawler, 27 passive checks, and a findings model with CWE/OWASP/ASVS mapping and secret-scrubbed evidence. Every scan runs through the gate: verified origin **and** confirmed authorization, checked again inside the orchestrator before the first request.

```bash
node scripts/quilltest.mjs scan start            # passive profile: crawl, observe, a few benign probes
node scripts/quilltest.mjs findings list         # latest scan's findings, worst first
node scripts/quilltest.mjs findings details <id>
node scripts/quilltest.mjs findings markFalsePositive <id> --note "decoy header"   # remembered for future scans
node scripts/quilltest.mjs scan diff             # new / fixed / persisting since the previous scan
node scripts/quilltest.mjs findings export sarif --json > findings.sarif
```

What the passive profile sends: the crawl itself, one TLS handshake, two GETs with an `Origin` header, GETs of about thirty well-known file paths (each confirmed by content signature, so catch-all pages do not count), GETs of discovered asset directories and referenced source maps. No test input, ever. The full list is in [docs/CHECKS.md](docs/CHECKS.md).

## Commands (built as data, UI pending)

The full command set exists now as a registry (`src/commands/`), 243 commands across File, Verify, Scan, Targets, Checks, Findings, Fix, AI, Report, Review, Share, View, Developer and Help, with ids like `verify.issue` and `scan.start`. Verify, Targets, Scan (passive), Checks, Findings, AI setup, macros and Help are implemented; the rest are defined and waiting on their engines. The generated reference is [docs/COMMANDS.md](docs/COMMANDS.md). Any command runs from the terminal:

```bash
node scripts/quilltest.mjs commands verify                 # search the registry
node scripts/quilltest.mjs target add https://example.com --name "Prod"
node scripts/quilltest.mjs target confirmAuthorization --statement "I own this site"
node scripts/quilltest.mjs verify issue && node scripts/quilltest.mjs verify check
node scripts/quilltest.mjs target status                   # READY TO SCAN only when verified AND authorized
node scripts/quilltest.mjs scan start                      # refused by the executor until then
```

Commands that send requests to a target are marked *gated*: the executor (`src/commands/exec.mjs`) refuses them unless the active target's origin has a current ownership verification and you have recorded an authorization statement for it. The UI will never call a command's implementation directly, so this cannot be bypassed from a button.

## The AI setup wizard

A runnable wizard is included now, ahead of the scanner. It walks you through selecting a provider, entering credentials, picking a model, and running a connectivity test, then writes a local `quilltest.ai.json` config (git-ignored).

```bash
# Interactive CLI wizard (Node 18+)
node scripts/ai-setup-wizard.mjs

# Non-interactive, e.g. for CI or scripting (--yes suppresses every prompt;
# the key is read from $ANTHROPIC_API_KEY, or pass --key-env / --key)
node scripts/ai-setup-wizard.mjs --provider anthropic --model claude-opus-5-5 --yes --test

# Show the exact request the connectivity test would send, without sending it
node scripts/ai-setup-wizard.mjs --provider openai --yes --dry-run --no-save
```

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
| [docs/FIXES.md](docs/FIXES.md) | How findings become remediations and applyable fixes |
| [docs/CHECKS.md](docs/CHECKS.md) | Planned vulnerability-check inventory by category |
| [docs/ARCHITECTURE-PLAN.md](docs/ARCHITECTURE-PLAN.md) | Shell, crawler, check engine, findings model, AI layer, report, builds |
| [docs/INNOVATIONS.md](docs/INNOVATIONS.md) | Survey of web scanners and what QuillTest adopts |
| [docs/ETHICS.md](docs/ETHICS.md) | Authorization, responsible use, and what QuillTest will not do |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Milestones |
| [docs/LEGAL.md](docs/LEGAL.md) | Clean-room, trademark and licensing notes |

## License

[MIT](LICENSE). Copyright (c) 2026 Paul D Pruitt.

## Legal

QuillTest is an independent, clean-room project. It is not affiliated with, endorsed by, or sponsored by OWASP, PortSwigger (Burp Suite), the ZAP project, Tenable (Nessus/Nikto), OpenAI, Anthropic, Google, xAI, Meta, DeepSeek, Alibaba, Mistral, or any other vendor named in the docs. Names are used only to describe compatibility, provider APIs, and history.
