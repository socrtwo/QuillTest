/*
 * QuillTest — AI provider registry
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Single source of truth for the AI setup wizard (CLI and browser).
 * Add a provider by adding one entry here; both wizards pick it up.
 * (public/ai-wizard.html inlines a copy of PROVIDERS because it is served as a
 * static file; tests/providers.test.mjs fails if the two copies drift.)
 *
 * Model lists are *suggestions* — model ids drift, so the wizard always lets
 * the user type any id. Where a provider exposes a model-list endpoint,
 * `listModelsPath` is set and the wizard offers to fetch the live list.
 *
 * API "style" determines how a connectivity test request is shaped:
 *   - "openai"    : POST {base}/chat/completions, Bearer auth
 *   - "anthropic" : POST {base}/messages, x-api-key + anthropic-version
 *   - "gemini"    : POST {base}/models/{model}:generateContent, x-goog-api-key
 * Most providers below are OpenAI-compatible, which is why the registry is short.
 */

export const API_STYLES = {
  OPENAI: 'openai',
  ANTHROPIC: 'anthropic',
  GEMINI: 'gemini',
};

/** Output cap for the connectivity-test request. Small, but with headroom for
 *  models that spend tokens on reasoning before the visible reply. */
export const TEST_MAX_TOKENS = 64;

/**
 * @typedef {Object} Provider
 * @property {string}  id            stable key used in config
 * @property {string}  label         display name
 * @property {string}  apiStyle      one of API_STYLES
 * @property {string}  defaultBase   default endpoint base (no trailing slash)
 * @property {boolean} baseEditable  whether the wizard lets the user change the base
 * @property {string}  keyEnv        environment variable the wizard reads/writes as default
 * @property {string}  keysUrl       where to obtain an API key
 * @property {string[]} models       suggested model ids (first is the wizard default)
 * @property {string|null} listModelsPath  GET path (relative to base) returning available models, or null
 * @property {string}  notes         one-line guidance shown in the wizard
 * @property {boolean} [requiresBase] true when the user MUST supply a base (e.g. Meta gateway, custom, local)
 * @property {string}  [maxTokensParam] OpenAI-style only: name of the output-cap field.
 *                                  OpenAI itself rejects `max_tokens` on reasoning models and wants
 *                                  `max_completion_tokens`; most compatible hosts only know `max_tokens`.
 */

/** @type {Provider[]} */
export const PROVIDERS = [
  {
    id: 'openai',
    label: 'OpenAI',
    apiStyle: API_STYLES.OPENAI,
    defaultBase: 'https://api.openai.com/v1',
    baseEditable: true,
    keyEnv: 'OPENAI_API_KEY',
    keysUrl: 'https://platform.openai.com/api-keys',
    models: ['gpt-5.4', 'gpt-5.4-mini', 'gpt-5.4-nano'],
    listModelsPath: '/models',
    maxTokensParam: 'max_completion_tokens',
    notes: 'Standard OpenAI Chat Completions API (uses max_completion_tokens, which all current OpenAI models accept).',
  },
  {
    id: 'anthropic',
    label: 'Anthropic (Claude)',
    apiStyle: API_STYLES.ANTHROPIC,
    defaultBase: 'https://api.anthropic.com/v1',
    baseEditable: true,
    keyEnv: 'ANTHROPIC_API_KEY',
    keysUrl: 'https://console.anthropic.com/settings/keys',
    models: ['claude-opus-5-5', 'claude-sonnet-5-5', 'claude-haiku-5-5'],
    listModelsPath: '/models',
    notes: 'Uses the Messages API with x-api-key and anthropic-version headers.',
  },
  {
    id: 'google',
    label: 'Google (Gemini)',
    apiStyle: API_STYLES.GEMINI,
    defaultBase: 'https://generativelanguage.googleapis.com/v1beta',
    baseEditable: true,
    keyEnv: 'GEMINI_API_KEY',
    keysUrl: 'https://aistudio.google.com/apikey',
    models: ['gemini-3.1-pro-preview', 'gemini-3-flash-preview'],
    listModelsPath: '/models',
    notes: 'Gemini generateContent API; key sent in the x-goog-api-key header (never in the URL).',
  },
  {
    id: 'xai',
    label: 'xAI (Grok)',
    apiStyle: API_STYLES.OPENAI,
    defaultBase: 'https://api.x.ai/v1',
    baseEditable: true,
    keyEnv: 'XAI_API_KEY',
    keysUrl: 'https://console.x.ai',
    models: ['grok-4.6', 'grok-4.5', 'grok-4.3'],
    listModelsPath: '/models',
    notes: 'OpenAI-compatible endpoint hosted by xAI.',
  },
  {
    id: 'meta',
    label: 'Meta (Llama)',
    apiStyle: API_STYLES.OPENAI,
    defaultBase: 'https://api.llama.com/compat/v1',
    baseEditable: true,
    requiresBase: true,
    keyEnv: 'LLAMA_API_KEY',
    keysUrl: 'https://llama.developer.meta.com  (or a host: Together, Groq, Fireworks, OpenRouter)',
    models: ['Llama-4-Maverick-17B-128E-Instruct-FP8', 'Llama-4-Scout-17B-16E-Instruct-FP8', 'Llama-3.3-70B-Instruct'],
    listModelsPath: '/models',
    notes: 'Llama models are open-weight; reach them via Meta\'s own API (the /compat/v1 base speaks OpenAI Chat Completions; /v1 is Meta\'s native format) or any OpenAI-compatible host. Model ids differ per host — confirm the base URL and ids for yours.',
  },
  {
    id: 'deepseek',
    label: 'DeepSeek',
    apiStyle: API_STYLES.OPENAI,
    defaultBase: 'https://api.deepseek.com',
    baseEditable: true,
    keyEnv: 'DEEPSEEK_API_KEY',
    keysUrl: 'https://platform.deepseek.com/api_keys',
    models: ['deepseek-chat', 'deepseek-reasoner'],
    listModelsPath: '/models',
    notes: 'OpenAI-compatible. DeepSeek serves /chat/completions directly off the root; https://api.deepseek.com/v1 also works.',
  },
  {
    id: 'qwen',
    label: 'Alibaba (Qwen / DashScope)',
    apiStyle: API_STYLES.OPENAI,
    defaultBase: 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1',
    baseEditable: true,
    keyEnv: 'DASHSCOPE_API_KEY',
    keysUrl: 'https://bailian.console.alibabacloud.com',
    models: ['qwen3-max', 'qwen-plus', 'qwen-turbo', 'qwen3-coder-plus'],
    listModelsPath: '/models',
    notes: 'OpenAI-compatible mode. Use dashscope-intl.aliyuncs.com (international) or dashscope.aliyuncs.com (mainland China) to match your account region.',
  },
  {
    id: 'mistral',
    label: 'Mistral',
    apiStyle: API_STYLES.OPENAI,
    defaultBase: 'https://api.mistral.ai/v1',
    baseEditable: true,
    keyEnv: 'MISTRAL_API_KEY',
    keysUrl: 'https://console.mistral.ai/api-keys',
    models: ['mistral-large-latest', 'mistral-medium-latest', 'mistral-small-latest', 'codestral-latest'],
    listModelsPath: '/models',
    notes: 'OpenAI-compatible endpoint. The -latest aliases track the current release of each tier.',
  },
  {
    id: 'local',
    label: 'Local model (Ollama / llama.cpp / LM Studio)',
    apiStyle: API_STYLES.OPENAI,
    defaultBase: 'http://localhost:11434/v1',
    baseEditable: true,
    requiresBase: true,
    keyEnv: 'QUILLTEST_LOCAL_API_KEY',
    keysUrl: '(no key needed for most local servers — leave blank or use any placeholder)',
    models: ['llama3.1', 'qwen3', 'gemma3', 'mistral'],
    listModelsPath: '/models',
    notes: 'Any OpenAI-compatible local server. Ollama defaults to :11434, LM Studio to :1234, llama.cpp to :8080.',
  },
  {
    id: 'custom',
    label: 'Custom OpenAI-compatible endpoint',
    apiStyle: API_STYLES.OPENAI,
    defaultBase: '',
    baseEditable: true,
    requiresBase: true,
    keyEnv: 'QUILLTEST_CUSTOM_API_KEY',
    keysUrl: '(depends on the service)',
    models: [],
    listModelsPath: '/models',
    notes: 'Any gateway or proxy that speaks the OpenAI Chat Completions API (OpenRouter, Together, Groq, Azure OpenAI, a corporate proxy, etc.).',
  },
];

export function getProvider(id) {
  return PROVIDERS.find((p) => p.id === id) || null;
}

/** Providers that work without a credential (the key is a placeholder). */
export function keyOptional(providerId) {
  return providerId === 'local';
}

/**
 * Authentication headers for a provider, shared by the test request and the
 * model-list request so each key travels the same way everywhere.
 * @param {Provider} provider
 * @param {string} apiKey
 * @returns {Record<string,string>}
 */
export function authHeaders(provider, apiKey) {
  switch (provider.apiStyle) {
    case API_STYLES.ANTHROPIC:
      return { 'x-api-key': apiKey || '', 'anthropic-version': '2023-06-01' };
    case API_STYLES.GEMINI:
      return { 'x-goog-api-key': apiKey || '' };
    case API_STYLES.OPENAI:
    default:
      // Local servers ignore the value but some reject a missing header.
      return { authorization: `Bearer ${apiKey || 'not-needed'}` };
  }
}

function normalizeBase(cfg, provider) {
  return (cfg.base || provider.defaultBase).replace(/\/+$/, '');
}

/**
 * Build the connectivity-test request (URL + fetch init) for a chosen config,
 * without sending it. Keeps request-shaping in one place for both wizards and,
 * later, the analysis layer.
 *
 * @param {{providerId:string, base?:string, apiKey?:string, model?:string}} cfg
 * @param {string} userMessage
 * @returns {{url:string, init:RequestInit}}
 */
export function buildTestRequest(cfg, userMessage = 'Reply with the single word: OK') {
  const provider = getProvider(cfg.providerId);
  if (!provider) throw new Error(`Unknown provider: ${cfg.providerId}`);
  const base = normalizeBase(cfg, provider);
  const model = cfg.model || provider.models[0];
  if (!model) throw new Error(`A model id is required for provider ${provider.id}`);
  const headers = { 'content-type': 'application/json', ...authHeaders(provider, cfg.apiKey) };

  switch (provider.apiStyle) {
    case API_STYLES.ANTHROPIC:
      return {
        url: `${base}/messages`,
        init: {
          method: 'POST',
          headers,
          body: JSON.stringify({
            model,
            max_tokens: TEST_MAX_TOKENS,
            messages: [{ role: 'user', content: userMessage }],
          }),
        },
      };

    case API_STYLES.GEMINI:
      return {
        url: `${base}/models/${encodeURIComponent(model)}:generateContent`,
        init: {
          method: 'POST',
          headers,
          body: JSON.stringify({
            contents: [{ role: 'user', parts: [{ text: userMessage }] }],
            generationConfig: { maxOutputTokens: TEST_MAX_TOKENS },
          }),
        },
      };

    case API_STYLES.OPENAI:
    default:
      return {
        url: `${base}/chat/completions`,
        init: {
          method: 'POST',
          headers,
          body: JSON.stringify({
            model,
            [provider.maxTokensParam || 'max_tokens']: TEST_MAX_TOKENS,
            messages: [{ role: 'user', content: userMessage }],
          }),
        },
      };
  }
}

/**
 * Build the live model-list request for a provider, or null when the provider
 * has no list endpoint.
 * @param {{providerId:string, base?:string, apiKey?:string}} cfg
 * @returns {{url:string, init:RequestInit}|null}
 */
export function buildListModelsRequest(cfg) {
  const provider = getProvider(cfg.providerId);
  if (!provider) throw new Error(`Unknown provider: ${cfg.providerId}`);
  if (!provider.listModelsPath) return null;
  const base = normalizeBase(cfg, provider);
  return {
    url: `${base}${provider.listModelsPath}`,
    init: { method: 'GET', headers: authHeaders(provider, cfg.apiKey) },
  };
}

/** Normalize a model-list response from any API style to an array of ids. */
export function extractModelIds(json) {
  if (Array.isArray(json?.data)) return json.data.map((m) => m.id).filter(Boolean);              // OpenAI / Anthropic
  if (Array.isArray(json?.models)) {                                                               // Gemini
    return json.models.map((m) => (m.name || m.id || '').replace(/^models\//, '')).filter(Boolean);
  }
  return [];
}

/** Extract assistant text from any provider's response JSON, for the test. */
export function extractText(apiStyle, json) {
  try {
    switch (apiStyle) {
      case API_STYLES.ANTHROPIC:
        return (json.content || []).filter((b) => b.type === 'text').map((b) => b.text || '').join('').trim();
      case API_STYLES.GEMINI:
        return (json.candidates?.[0]?.content?.parts || []).map((p) => p.text || '').join('').trim();
      case API_STYLES.OPENAI:
      default:
        return (json.choices?.[0]?.message?.content || '').trim();
    }
  } catch {
    return '';
  }
}
