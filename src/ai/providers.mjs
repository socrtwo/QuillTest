/*
 * QuillTest — AI provider registry
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Single source of truth for the AI setup wizard (CLI and browser).
 * Add a provider by adding one entry here; both wizards pick it up.
 *
 * Model lists are *suggestions* — model ids drift, so the wizard always lets
 * the user type any id. Where a provider exposes a model-list endpoint,
 * `listModelsPath` is set and the wizard offers to fetch the live list.
 *
 * API "style" determines how a connectivity test request is shaped:
 *   - "openai"    : POST {base}/chat/completions, Bearer auth
 *   - "anthropic" : POST {base}/messages, x-api-key + anthropic-version
 *   - "gemini"    : POST {base}/models/{model}:generateContent?key=...
 * Most providers below are OpenAI-compatible, which is why the registry is short.
 */

export const API_STYLES = {
  OPENAI: 'openai',
  ANTHROPIC: 'anthropic',
  GEMINI: 'gemini',
};

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
    models: ['gpt-4o', 'gpt-4o-mini', 'o3', 'o4-mini'],
    listModelsPath: '/models',
    notes: 'Standard OpenAI Chat Completions API.',
  },
  {
    id: 'anthropic',
    label: 'Anthropic (Claude)',
    apiStyle: API_STYLES.ANTHROPIC,
    defaultBase: 'https://api.anthropic.com/v1',
    baseEditable: true,
    keyEnv: 'ANTHROPIC_API_KEY',
    keysUrl: 'https://console.anthropic.com/settings/keys',
    models: ['claude-sonnet-4-5', 'claude-opus-4-1', 'claude-haiku-4-5'],
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
    models: ['gemini-2.5-pro', 'gemini-2.5-flash', 'gemini-2.5-flash-lite'],
    listModelsPath: '/models',
    notes: 'Gemini generateContent API; key passed as ?key= query parameter.',
  },
  {
    id: 'xai',
    label: 'xAI (Grok)',
    apiStyle: API_STYLES.OPENAI,
    defaultBase: 'https://api.x.ai/v1',
    baseEditable: true,
    keyEnv: 'XAI_API_KEY',
    keysUrl: 'https://console.x.ai',
    models: ['grok-4', 'grok-3', 'grok-3-mini'],
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
    models: ['llama-4-scout', 'llama-4-maverick', 'llama-3.3-70b-instruct'],
    listModelsPath: '/models',
    notes: 'Llama models are open-weight; reach them via Meta\'s own API or any OpenAI-compatible host. Confirm the base URL for your host.',
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
    notes: 'OpenAI-compatible. Note: base has no /v1; the wizard appends the correct path.',
  },
  {
    id: 'qwen',
    label: 'Alibaba (Qwen / DashScope)',
    apiStyle: API_STYLES.OPENAI,
    defaultBase: 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1',
    baseEditable: true,
    keyEnv: 'DASHSCOPE_API_KEY',
    keysUrl: 'https://bailian.console.alibabacloud.com',
    models: ['qwen-max', 'qwen-plus', 'qwen-turbo', 'qwen3-coder-plus'],
    listModelsPath: '/models',
    notes: 'OpenAI-compatible mode. Use the .com (international) or .com.cn (mainland China) base to match your account region.',
  },
  {
    id: 'mistral',
    label: 'Mistral',
    apiStyle: API_STYLES.OPENAI,
    defaultBase: 'https://api.mistral.ai/v1',
    baseEditable: true,
    keyEnv: 'MISTRAL_API_KEY',
    keysUrl: 'https://console.mistral.ai/api-keys',
    models: ['mistral-large-latest', 'mistral-small-latest', 'codestral-latest'],
    listModelsPath: '/models',
    notes: 'OpenAI-compatible endpoint.',
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
    models: ['llama3.1', 'qwen2.5', 'mistral', 'phi4'],
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

/**
 * Build the connectivity-test request (URL + fetch init) for a chosen config,
 * without sending it. Keeps request-shaping in one place for both wizards and,
 * later, the analysis layer.
 *
 * @param {{providerId:string, base:string, apiKey:string, model:string}} cfg
 * @param {string} userMessage
 * @returns {{url:string, init:RequestInit}}
 */
export function buildTestRequest(cfg, userMessage = 'Reply with the single word: OK') {
  const provider = getProvider(cfg.providerId);
  if (!provider) throw new Error(`Unknown provider: ${cfg.providerId}`);
  const base = (cfg.base || provider.defaultBase).replace(/\/+$/, '');
  const model = cfg.model || provider.models[0];

  switch (provider.apiStyle) {
    case API_STYLES.ANTHROPIC:
      return {
        url: `${base}/messages`,
        init: {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-api-key': cfg.apiKey,
            'anthropic-version': '2023-06-01',
          },
          body: JSON.stringify({
            model,
            max_tokens: 16,
            messages: [{ role: 'user', content: userMessage }],
          }),
        },
      };

    case API_STYLES.GEMINI:
      return {
        url: `${base}/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(cfg.apiKey)}`,
        init: {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            contents: [{ role: 'user', parts: [{ text: userMessage }] }],
            generationConfig: { maxOutputTokens: 16 },
          }),
        },
      };

    case API_STYLES.OPENAI:
    default: {
      // DeepSeek's base has no /v1 and expects /chat/completions directly off the root.
      const path = base.endsWith('/v1') || base.includes('/compat') || base.includes('/compatible-mode')
        ? '/chat/completions'
        : '/chat/completions';
      return {
        url: `${base}${path}`,
        init: {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            authorization: `Bearer ${cfg.apiKey || 'not-needed'}`,
          },
          body: JSON.stringify({
            model,
            max_tokens: 16,
            messages: [{ role: 'user', content: userMessage }],
          }),
        },
      };
    }
  }
}

/** Extract assistant text from any provider's response JSON, for the test. */
export function extractText(apiStyle, json) {
  try {
    switch (apiStyle) {
      case API_STYLES.ANTHROPIC:
        return (json.content || []).map((b) => b.text || '').join('').trim();
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
