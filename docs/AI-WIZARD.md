# AI setup wizard

QuillTest uses AI only as an optional analysis layer, and it is bring-your-own-model. The setup wizard configures which provider and model QuillTest talks to, stores the credential locally, and runs a connectivity test. It exists in two forms that share one provider registry.

## Running it

### CLI (Node 18+, no dependencies)

```bash
node scripts/ai-setup-wizard.mjs
```

Interactive prompts walk through: pick provider → endpoint base (pre-filled, editable) → API key (hidden input; defaults to the provider's env var if set) → model (suggested list or type your own; can fetch the live list) → run a test request → save.

Non-interactive flags for CI/scripting. `--yes` together with `--provider` is what suppresses the prompts; without `--yes` the wizard still asks for anything you did not pass:

```bash
node scripts/ai-setup-wizard.mjs \
  --provider openai \
  --model gpt-5.4-mini \
  --base https://api.openai.com/v1 \
  --key-env OPENAI_API_KEY \
  --yes \
  --test \
  --out quilltest.ai.json

# Preview the exact connectivity-test request (headers redacted) without sending it
node scripts/ai-setup-wizard.mjs --provider anthropic --yes --dry-run --no-save

# List supported providers and exit
node scripts/ai-setup-wizard.mjs --list

# Test an existing config without changing it
node scripts/ai-setup-wizard.mjs --config quilltest.ai.json --test-only
```

Flags: `--provider <id>`, `--model <id>`, `--base <url>`, `--key <value>` (or `--key-env <VAR>`; prefer the latter so the key never enters shell history), `--test` (run connectivity test before saving), `--test-only`, `--dry-run` (print the request, send nothing), `--out <path>` (default `quilltest.ai.json`), `--config <path>`, `--save-key` (write the literal key into the file; off by default), `--list`, `--no-save`, `--yes` (accept defaults; with `--provider`, no prompts at all), `--help`.

Network requests (the connectivity test and the live model list) time out after 30 seconds.

### Browser

Open `public/ai-wizard.html` directly in any browser. It runs entirely client-side, uses the same registry, stores config in `localStorage` under `quilltest.ai`, and can export the same `quilltest.ai.json`. The connectivity test runs from the browser, so a provider that blocks cross-origin requests may need the CLI instead. Anthropic requires the `anthropic-dangerous-direct-browser-access` opt-in header for browser calls; the page sends it.

The page is a static file and cannot import `src/ai/providers.mjs`, so it carries a generated copy of the registry between two marker comments. Regenerate it after any registry change with `npm run ai:sync-browser` (`node scripts/sync-browser-registry.mjs`; `--check` exits non-zero when stale). `npm test` includes that check.

## Supported providers

Driven by `src/ai/providers.mjs`. Out of the box: OpenAI, Anthropic (Claude), Google (Gemini), xAI (Grok), Meta (Llama, via a hosted gateway or Meta's own API), DeepSeek, Alibaba (Qwen/DashScope), Mistral, a Local option (Ollama/llama.cpp/LM Studio), and a Custom OpenAI-compatible endpoint.

Three API styles are handled: OpenAI Chat Completions (most providers), Anthropic Messages, and Gemini generateContent. Because most providers expose an OpenAI-compatible endpoint, adding one is usually a single registry entry.

Credentials travel as headers in every case: `Authorization: Bearer` (OpenAI-style), `x-api-key` plus `anthropic-version` (Anthropic), `x-goog-api-key` (Gemini). No key is ever placed in a URL, so it cannot end up in proxy or server logs. OpenAI's own endpoint receives `max_completion_tokens` (its reasoning models reject `max_tokens`); every other OpenAI-compatible host receives `max_tokens`, controlled per provider by `maxTokensParam`.

## Config file format

`quilltest.ai.json` (git-ignored by default):

```json
{
  "version": 1,
  "active": "anthropic",
  "providers": {
    "anthropic": {
      "providerId": "anthropic",
      "base": "https://api.anthropic.com/v1",
      "model": "claude-opus-5-5",
      "apiKeyEnv": "ANTHROPIC_API_KEY",
      "apiKey": null
    }
  }
}
```

By default the wizard stores a **reference to an environment variable** (`apiKeyEnv`), not the key itself, so secrets never land in the file. Pass `--save-key` (CLI) or tick "store key in this browser" (browser) only if you accept the key being written to disk / localStorage. The CLI writes the file with mode `0600`. Re-running the wizard for a second provider merges into the existing file and leaves other providers' entries, including any key they stored with `--save-key`, untouched. The `.gitignore` excludes `quilltest.ai.json`.

`src/ai/config.mjs` loads and validates this file (`loadAiConfig`, `validateAiConfig`, `resolveApiKey`). The wizard validates before writing and refuses to write a file it would not load back; `--test-only` reports every schema problem by path (for example `providers.openai.base must not end with a slash`). Unknown fields, unknown provider ids, an `active` that names no provider, and a non-local provider with neither `apiKeyEnv` nor `apiKey` are all errors.

## Adding a provider

Add one object to the `PROVIDERS` array in `src/ai/providers.mjs`: `id`, `label`, `apiStyle`, `defaultBase`, `baseEditable`, `keyEnv`, `keysUrl`, `models`, `listModelsPath`, `notes`, and optionally `requiresBase` and `maxTokensParam`. Then run `npm run ai:sync-browser` to refresh the browser copy and `npm test`. The CLI wizard and the (future) analysis layer pick it up with no other changes. If the provider is OpenAI-compatible, that single entry is all that is needed.

## Security notes

- Keys default to env-var references, never written to the repo.
- The connectivity test sends a trivial prompt ("reply OK") with a 64-token output cap; it does not send any target data. A model that spends the cap on reasoning returns an empty reply, which the wizard still reports as a successful connection.
- The wizard never transmits your key anywhere except to the provider endpoint you configured, to run the test you requested.
