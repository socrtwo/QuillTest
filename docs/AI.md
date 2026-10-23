# AI in QuillTest

AI is an **optional analysis layer**, not the scanner. QuillTest's checks find the evidence; the AI, when configured, helps you make sense of it and fix it faster. Everything works with the AI turned off — you just lose the triage, plain-language explanations, and drafted summaries.

## What the AI does

- **Triage and dedupe.** Collapse near-duplicate findings, group by root cause.
- **Prioritize.** Rank findings by likely exploitability and blast radius, so you fix the worst first — an "attacker's-eye" ordering of QuillTest's own results.
- **Explain.** Turn a terse finding into a plain-language description of the flaw, its impact, and the CWE/OWASP mapping.
- **Draft remediations.** Tailor the fix (see [FIXES.md](FIXES.md)) to the exact server/framework QuillTest fingerprinted.
- **Summarize.** Write the executive summary and the per-finding narrative for the report.
- **Flag false positives.** Judge whether observed evidence really supports a finding and mark low-confidence ones for review.

## What the AI does NOT do

- It does not run or direct the scan. The crawler and check engine are deterministic code; the AI only sees their output.
- It does not generate attack payloads or exploit code — not against the target, not as examples. The guardrail is in the prompt construction and the output filter, not just policy.
- It does not receive your credentials or the ownership token.
- It does not act. Nothing the AI drafts is applied to a live site.

## How target data reaches the model

The analysis layer sends the model: the finding records (check id, location, severity, evidence snippet), the observed response headers and relevant response fragments, and the detected stack fingerprint. Request/response fragments are size-capped and secret-scrubbed (auth headers, cookies, tokens redacted) before they leave the machine. You can run `--dry-run` to see exactly what would be sent.

## Several-AI mode

You may enable any number of providers in the setup wizard and have QuillTest consult each of them over the same findings. Two consultation modes:

- **Sequential** (default) — consult each enabled provider one after another, in the order you selected them. Gentle on rate limits, and a later model can see earlier models' notes. Default for scans against live production.
- **Concurrent** — consult all enabled providers at once. Faster, and the natural pairing for the staging-mirror scan mode ([STAGING-MIRROR.md](STAGING-MIRROR.md)), where there is a stable snapshot for several reviewers to look at simultaneously.

In both modes the models receive the **same** input — QuillTest's findings and the observed responses — and return their analysis. None of them runs the scan, and none is asked to produce attack payloads; the mode only changes the order and parallelism of the reviews.

Divergence across providers is a useful signal: findings all enabled models agree are real get surfaced first; ones they disagree on are flagged for human review. This is also how QuillTest reasons about "what another AI might notice" — by actually asking several and comparing. Adding a provider is one entry in the registry and one checkbox in the wizard, so the set of reviewers is open-ended.

## Provider setup

See [AI-WIZARD.md](AI-WIZARD.md). Providers and models are configured through the wizard and stored in `quilltest.ai.json`.

## Status

Planning. The analysis layer (`src/ai/analyze.mjs`) is specified here; only the provider registry and setup wizard are implemented so far.
