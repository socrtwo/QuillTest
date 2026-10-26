# AI in Anne's Test

AI is an **optional analysis layer**, not the scanner. Anne's Test's checks find the evidence; the AI, when configured, helps you make sense of it and fix it faster. Everything works with the AI turned off — you just lose the triage, plain-language explanations, and drafted summaries.

## What the AI does

- **Triage and dedupe.** Collapse near-duplicate findings, group by root cause.
- **Prioritize.** Rank findings by likely exploitability and blast radius, so you fix the worst first — an "attacker's-eye" ordering of Anne's Test's own results.
- **Explain.** Turn a terse finding into a plain-language description of the flaw, its impact, and the CWE/OWASP mapping.
- **Draft remediations.** Tailor the fix (see [FIXES.md](FIXES.md)) to the exact server/framework Anne's Test fingerprinted.
- **Summarize.** Write the executive summary and the per-finding narrative for the report.
- **Flag false positives.** Judge whether observed evidence really supports a finding and mark low-confidence ones for review.

## What the AI does NOT do

- It does not run or direct the scan. The crawler and check engine are deterministic code; the AI only sees their output.
- It does not generate attack payloads or exploit code — not against the target, not as examples. The guardrail is in the prompt construction and the output filter, not just policy.
- It does not receive your credentials or the ownership token.
- It does not act. Nothing the AI drafts is applied to a live site.

## How target data reaches the model

The analysis layer (`src/ai/analyze.mjs`) sends the model: the finding records (check id, location, severity, evidence), the observed response headers and relevant response fragments, and the detected stack fingerprint. Before anything leaves the machine:

- **Secret scrubbing.** `Authorization`, `Cookie`/`Set-Cookie`, `X-API-Key`, and any header whose name contains *token*, *secret*, *session*, *password*, or *credential* is redacted; so are `token=`, `key=`, `session=`, `password=` and similar query/body parameters; so are key-shaped strings (`sk-…`, `AIza…`, `Bearer …`). You can pass extra exact strings that must never be sent (the ownership token, say).
- **Size caps.** Each evidence field is capped at 2,000 characters and the whole payload at 60,000; trailing findings are dropped rather than sending truncated JSON.
- **Prompt injection defense.** The system prompt tells the model that everything inside the findings is untrusted target data, never instructions.
- **Output filter.** Payload-shaped text (`<script>`, `UNION SELECT`, `' OR 1=1`, path traversal, shell paths, JNDI, …) is removed from a reply and the result is flagged `filtered`, so a misbehaving model cannot turn Anne's Test into a relay for attack strings. In the parsed JSON reply each matched fragment is replaced with `[filtered]` field by field (a rationale that merely *mentions* a `<script>` block keeps its finding); in free text, whole lines are dropped. A reply the provider cut off at its output limit is reported as `truncated` rather than as a malformed reply.

Run `node scripts/ai-analyze.mjs --findings <file> --dry-run` to see the exact, redacted requests that would be sent; it needs no API keys.

### Finding record shape

```json
{
  "id": "F-002",
  "checkId": "cookies.flags",
  "title": "Session cookie set without Secure and HttpOnly",
  "severity": "high",
  "confidence": "confirmed",
  "cwe": "CWE-614",
  "owasp": "A05:2021 Security Misconfiguration",
  "location": "https://staging.example.test/login",
  "evidence": {
    "request": "GET /login HTTP/1.1",
    "requestHeaders": { "accept": "text/html" },
    "responseHeaders": { "set-cookie": "session=…; Path=/" },
    "snippet": "Cookie 'session' lacks Secure, HttpOnly and SameSite attributes."
  }
}
```

See `examples/findings.sample.json`. The model returns, per finding: `falsePositive`, `confidence`, `severity`, `cwe`, `owasp`, `attackerPriority` (1 = what an attacker would go after first), `rootCauseGroup`, `rationale`, `remediation`; plus an executive `summary` and a `worthChecking` list of adjacent weaknesses (described, never with payloads).

## Several-AI mode

You may enable any number of providers in the setup wizard and have Anne's Test consult each of them over the same findings. Two consultation modes:

- **Sequential** (default) — consult each enabled provider one after another, in the order you selected them. Gentle on rate limits, and a later model can see earlier models' notes. Default for scans against live production.
- **Concurrent** — consult all enabled providers at once. Faster, and the natural pairing for the staging-mirror scan mode ([STAGING-MIRROR.md](STAGING-MIRROR.md)), where there is a stable snapshot for several reviewers to look at simultaneously.

In both modes the models receive the **same** input — Anne's Test's findings and the observed responses — and return their analysis. None of them runs the scan, and none is asked to produce attack payloads; the mode only changes the order and parallelism of the reviews.

Divergence across providers is a useful signal: findings all enabled models agree are real get surfaced first; ones they disagree on are flagged for human review. This is also how Anne's Test reasons about "what another AI might notice" — by actually asking several and comparing. Adding a provider is one entry in the registry and one checkbox in the wizard, so the set of reviewers is open-ended.

The analysis layer computes a per-finding **consensus** from the replies: `real` (every reviewer says it is not a false positive), `false-positive` (every reviewer says it is), `split` (they disagree — review by hand), or `unreviewed` (no reviewer returned a verdict), along with the mean `attackerPriority` across reviewers so the fix list can be ordered by what an attacker would reach first.

## Provider setup

See [AI-WIZARD.md](AI-WIZARD.md). Providers and models are configured through the wizard and stored in `quilltest.ai.json`.

## Status

Implemented: the provider registry, the setup wizard, and the analysis layer (`src/ai/analyze.mjs`, runnable via `scripts/ai-analyze.mjs`) with scrubbing, size caps, output filtering, sequential/concurrent consultation, and consensus — all covered by offline tests. The scanner feeds it directly: `scripts/scan.mjs scan <origin> --analyze` runs the configured providers over the scan's findings. It also accepts a saved report or any findings file in the documented shape (`examples/findings.sample.json`) via `scripts/ai-analyze.mjs`.
