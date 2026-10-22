# AI setup wizard

QuillTest uses AI only as an optional analysis layer, and it is bring-your-own-model. The setup wizard configures which provider and model QuillTest talks to, stores the credential locally, and runs a connectivity test. It exists in two forms that share one provider registry.

## Running it

### CLI (Node 18+, no dependencies)

```bash
node scripts/ai-setup-wizard.mjs
```

Interactive prompts walk through: pick provider → endpoint base (pre-filled, editable) → API key (hidden input; defaults to the provider's env var if set) → model (suggested list or type your own; can fetch the live list) → run a test request → save.

Non-interactive flags for CI/scripting:

```bash
node scripts/ai-setup-wizard.mjs \
  --provider openai \
  --model gpt-4o-mini \
  --base https://api.openai.com/v1 \
  --key "$OPENAI_API_KEY" \
  --test \
  --out quilltest.ai.json

# List supported providers and exit
node scripts/ai-setup-wizard.mjs --list

# Test an existing config without changing it
node scripts/ai-setup-wizard.mjs --config quilltest.ai.json --test-only
```

Flags: `--provider <id>`, `--model <id>`, `--base <url>`, `--key <value>` (or `--key-env <VAR>`), `--test` (run connectivity test before saving), `--test-only`, `--out <path>` (default `quilltest.ai.json`), `--config <path>`, `--list`, `--no-save`, `--yes` (accept defaults), `--help`.

### Browser

Open `public/ai-wizard.html` directly in any browser. It runs entirely client-side, uses the same registry, stores config in `localStorage` under `quilltest.ai`, and can export the same `quilltest.ai.json`. The connectivity test runs from the browser, so a provider that blocks cross-origin requests may need the CLI instead.

## Supported providers

Driven by `src/ai/providers.mjs`. Out of the box: OpenAI, Anthropic (Claude), Google (Gemini), xAI (Grok), Meta (Llama, via a hosted gateway or Meta's own API), DeepSeek, Alibaba (Qwen/DashScope), Mistral, a Local option (Ollama/llama.cpp/LM Studio), and a Custom OpenAI-compatible endpoint.

Three API styles are handled: OpenAI Chat Completions (most providers), Anthropic Messages, and Gemini generateContent. Because most providers expose an OpenAI-compatible endpoint, adding one is usually a single registry entry.

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
      "model": "claude-sonnet-4-5",
      "apiKeyEnv": "ANTHROPIC_API_KEY",
      "apiKey": null
    }
  }
}
```

By default the wizard stores a **reference to an environment variable** (`apiKeyEnv`), not the key itself, so secrets never land in the file. Pass `--save-key` (CLI) or tick "store key in file" (browser) only if you accept the key being written to disk / localStorage. QuillTest refuses to commit a config containing a literal key and the `.gitignore` excludes `quilltest.ai.json`.

## Adding a provider

Add one object to the `PROVIDERS` array in `src/ai/providers.mjs`: `id`, `label`, `apiStyle`, `defaultBase`, `keyEnv`, `keysUrl`, `models`, `listModelsPath`, `notes`. Both wizards and the (future) analysis layer pick it up with no other changes. If the provider is OpenAI-compatible, that single entry is all that is needed.

## Security notes

- Keys default to env-var references, never written to the repo.
- The connectivity test sends a trivial prompt ("reply OK") and a 16-token cap; it does not send any target data.
- The wizard never transmits your key anywhere except to the provider endpoint you configured, to run the test you requested.
