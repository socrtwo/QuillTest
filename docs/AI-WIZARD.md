# AI setup wizard

QuillTest uses AI only as an optional analysis layer, and it is bring-your-own-model. The setup wizard configures **which providers** QuillTest consults (one or many), which model and endpoint each uses, how they are consulted (sequential or concurrent), stores the credentials locally, and runs a connectivity test against each. It exists in two forms that share one provider registry.

## Running it

### CLI (Node 18+, no dependencies)

```bash
node scripts/ai-setup-wizard.mjs
```

Interactive prompts walk through: select providers (numbers or ids, comma-separated, or `all`) → for each, endpoint base (pre-filled, editable) → API key (hidden input; defaults to the provider's env var if set) → model (suggested list or type your own; can fetch the live list) → analysis mode when more than one is selected → test each → save.

Non-interactive flags for CI/scripting. `--yes` together with `--providers`/`--provider` is what suppresses the prompts; without `--yes` the wizard still asks for anything you did not pass:

```bash
# Enable several providers at once and test each
node scripts/ai-setup-wizard.mjs \
  --providers openai,anthropic,xai,deepseek \
  --mode concurrent \
  --yes --test

# Single provider with explicit model/base/key
node scripts/ai-setup-wizard.mjs \
  --provider openai \
  --model gpt-5.4-mini \
  --base https://api.openai.com/v1 \
  --key-env OPENAI_API_KEY \
  --yes --test --out quilltest.ai.json

# Preview the exact connectivity-test request(s) (headers redacted) without sending
node scripts/ai-setup-wizard.mjs --providers anthropic,openai --yes --dry-run --no-save

# List supported providers and exit
node scripts/ai-setup-wizard.mjs --list

# Test every provider in an existing config without changing it
node scripts/ai-setup-wizard.mjs --config quilltest.ai.json --test-only
```

Flags: `--providers <ids>` (comma-separated) or `--provider <id>` (single), `--mode <sequential|concurrent>`, `--model <id>` / `--base <url>` / `--key <value>` / `--key-env <VAR>` (applied to the single selected provider; prefer `--key-env` so the key never enters shell history), `--test` (connectivity-test every selected provider before saving), `--test-only`, `--dry-run` (print the request(s), send nothing), `--out <path>` (default `quilltest.ai.json`), `--config <path>`, `--save-key` (write literal keys into the file; off by default), `--list`, `--no-save`, `--yes` (accept defaults; with a provider selection, no prompts at all), `--help`.

When several providers are selected non-interactively, per-provider model/base/key come from the registry defaults and environment variables; run the wizard interactively to set each one individually. Network requests (the connectivity test and the live model list) time out after 30 seconds.

### Browser

Open `public/ai-wizard.html` directly in any browser. Tick each provider you want, set its model/base/key, choose the analysis mode, and click **Test all enabled** (which honors the mode — concurrent fires the tests in parallel). It runs entirely client-side, uses the same registry, stores config in `localStorage` under `quilltest.ai`, and can export the same `quilltest.ai.json`. The connectivity test runs from the browser, so a provider that blocks cross-origin requests may need the CLI instead. Anthropic requires the `anthropic-dangerous-direct-browser-access` opt-in header for browser calls; the page sends it.

The page is a static file and cannot import `src/ai/providers.mjs`, so it carries a generated copy of the registry between two marker comments. Regenerate it after any registry change with `npm run ai:sync-browser` (`node scripts/sync-browser-registry.mjs`; `--check` exits non-zero when stale). `npm test` includes that check.

## Supported providers

Driven by `src/ai/providers.mjs`. Out of the box: OpenAI, Anthropic (Claude), Google (Gemini), xAI (Grok), Meta (Llama, via a hosted gateway or Meta's own API), DeepSeek, Alibaba (Qwen/DashScope), Mistral, a Local option (Ollama/llama.cpp/LM Studio), and a Custom OpenAI-compatible endpoint.

Three API styles are handled: OpenAI Chat Completions (most providers), Anthropic Messages, and Gemini generateContent. Because most providers expose an OpenAI-compatible endpoint, adding one is usually a single registry entry.

Credentials travel as headers in every case: `Authorization: Bearer` (OpenAI-style), `x-api-key` plus `anthropic-version` (Anthropic), `x-goog-api-key` (Gemini). No key is ever placed in a URL, so it cannot end up in proxy or server logs. OpenAI's own endpoint receives `max_completion_tokens` (its reasoning models reject `max_tokens`); every other OpenAI-compatible host receives `max_tokens`, controlled per provider by `maxTokensParam`.

## Config file format

`quilltest.ai.json` (git-ignored by default). Version 2 holds an ordered list of enabled providers and the analysis mode:

```json
{
  "version": 2,
  "analysisMode": "concurrent",
  "activeProviders": ["openai", "anthropic", "xai"],
  "active": "openai",
  "providers": {
    "openai":    { "providerId": "openai",    "base": "https://api.openai.com/v1",    "model": "gpt-5.4-mini",      "apiKeyEnv": "OPENAI_API_KEY",    "apiKey": null },
    "anthropic": { "providerId": "anthropic", "base": "https://api.anthropic.com/v1", "model": "claude-opus-5-5",   "apiKeyEnv": "ANTHROPIC_API_KEY", "apiKey": null },
    "xai":       { "providerId": "xai",       "base": "https://api.x.ai/v1",          "model": "grok-4.6",          "apiKeyEnv": "XAI_API_KEY",       "apiKey": null }
  }
}
```

- `analysisMode` is `sequential` or `concurrent` (see [AI.md](AI.md)).
- `activeProviders` is the ordered set QuillTest consults; `active` is kept as a backward-compatible pointer to the first one.
- Version 1 configs (single `active` provider, no `activeProviders`/`analysisMode`) are still read: the wizard and the `--test-only` path normalize them to a one-provider, sequential config.

By default the wizard stores a **reference to an environment variable** (`apiKeyEnv`), not the key itself, so secrets never land in the file. Pass `--save-key` (CLI) or tick "store keys in this browser" (browser) only if you accept the keys being written to disk / localStorage. The CLI writes the file with mode `0600`. Re-running the wizard merges into the existing file and leaves other providers' entries, including any key they stored with `--save-key`, untouched. The `.gitignore` excludes `quilltest.ai.json`.

## Adding a provider

Add one object to the `PROVIDERS` array in `src/ai/providers.mjs`: `id`, `label`, `apiStyle`, `defaultBase`, `baseEditable`, `keyEnv`, `keysUrl`, `models`, `listModelsPath`, `notes`, and optionally `requiresBase` and `maxTokensParam`. Then run `npm run ai:sync-browser` to refresh the browser copy and `npm test`. The CLI wizard and the (future) analysis layer pick it up with no other changes. If the provider is OpenAI-compatible, that single entry is all that is needed.

## Security notes

- **Plaintext endpoints are refused.** An endpoint base must be `http(s)`; `http://` is accepted only for loopback hosts (`localhost`, `127.x`, `::1`), because a key sent over plaintext to a remote host travels in cleartext. Both wizards enforce this before any request. For a trusted LAN gateway you can override with `--allow-insecure-base` (CLI), which downgrades the refusal to a warning. URLs with embedded `user:pass@` are refused outright.
- **Keys never appear in output.** Provider error messages and test replies are scrubbed of the key value and of well-known key shapes before they are printed, so a provider that echoes the request cannot leak a credential into your terminal.
- Keys default to env-var references, never written to the repo.
- The connectivity test sends a trivial prompt ("reply OK") with a 64-token output cap; it does not send any target data. A model that spends the cap on reasoning returns an empty reply, which the wizard still reports as a successful connection.
- The wizard never transmits your key anywhere except to the provider endpoint you configured, to run the test you requested.
