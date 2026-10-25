/*
 * Anne's Test — AI provider registry
 * Part of the Anne's Office suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
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

/** Hosts that stay on this machine, where plaintext HTTP cannot leak a key onto the network. */
export function isLoopbackHost(hostname) {
  const h = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  return h === 'localhost' || h === '::1' || h === '0.0.0.0' || h.endsWith('.localhost')
    || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h);
}

/**
 * Validate an endpoint base URL before any key is sent to it.
 *
 * Rejects anything that is not http(s), and rejects plaintext http to a
 * non-loopback host — an API key sent that way travels in cleartext. Pass
 * `allowInsecure: true` to downgrade that rejection to a warning (for a
 * trusted LAN gateway, say).
 *
 * @param {string} base
 * @param {{allowInsecure?: boolean}} [opts]
 * @returns {{ok: boolean, error?: string, warning?: string, url?: URL}}
 */
export function validateBase(base, opts = {}) {
  if (typeof base !== 'string' || !base.trim()) return { ok: false, error: 'Endpoint base URL is required.' };
  let url;
  try { url = new URL(base.trim()); } catch { return { ok: false, error: `Not a valid URL: ${base}` }; }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { ok: false, error: `Endpoint must use http(s), got ${url.protocol.replace(/:$/, '')}://` };
  }
  if (url.username || url.password) return { ok: false, error: 'Do not embed credentials in the endpoint URL; use the API key field.' };
  if (url.protocol === 'http:' && !isLoopbackHost(url.hostname)) {
    const msg = `Plaintext http:// to ${url.hostname} would send your API key in cleartext. Use https://.`;
    return opts.allowInsecure ? { ok: true, warning: msg, url } : { ok: false, error: msg };
  }
  return { ok: true, url };
}

/**
 * Replace secrets in free text before it is logged or displayed. Takes the
 * exact key values in play plus a few well-known key shapes, so a provider
 * error that echoes a request never prints a credential.
 * @param {string} text
 * @param {Array<string|null|undefined>} [secrets]
 */
export function scrubSecrets(text, secrets = []) {
  let out = String(text ?? '');
  for (const s of secrets) {
    if (typeof s === 'string' && s.length >= 6) out = out.split(s).join('[REDACTED]');
  }
  return out
    .replace(/\b(Bearer)\s+[A-Za-z0-9._~+/=-]{8,}/g, '$1 [REDACTED]')
    .replace(/\bsk-[A-Za-z0-9_-]{8,}/g, '[REDACTED]')
    .replace(/\bAIza[0-9A-Za-z_-]{30,}/g, '[REDACTED]')
    .replace(/\bxai-[A-Za-z0-9]{16,}/g, '[REDACTED]');
}

/**
 * Build a chat request (URL + fetch init) for a chosen config, without sending
 * it. This is the single place request shaping lives, shared by the wizards'
 * connectivity test and the analysis layer.
 *
 * Messages use a provider-neutral shape: { role: 'user' | 'assistant', content }.
 * An optional `system` string is mapped to each provider's own mechanism.
 *
 * @param {{providerId:string, base?:string, apiKey?:string, model?:string}} cfg
 * @param {{system?:string, messages:Array<{role:string, content:string}>, maxTokens?:number}} chat
 * @returns {{url:string, init:RequestInit}}
 */
export function buildChatRequest(cfg, chat) {
  const provider = getProvider(cfg.providerId);
  if (!provider) throw new Error(`Unknown provider: ${cfg.providerId}`);
  const base = normalizeBase(cfg, provider);
  const model = cfg.model || provider.models[0];
  if (!model) throw new Error(`A model id is required for provider ${provider.id}`);
  const headers = { 'content-type': 'application/json', ...authHeaders(provider, cfg.apiKey) };
  const maxTokens = Number.isInteger(chat.maxTokens) && chat.maxTokens > 0 ? chat.maxTokens : TEST_MAX_TOKENS;
  const messages = Array.isArray(chat.messages) ? chat.messages : [];
  if (!messages.length) throw new Error('At least one message is required');

  switch (provider.apiStyle) {
    case API_STYLES.ANTHROPIC: {
      const body = {
        model,
        max_tokens: maxTokens,
        messages: messages.map((m) => ({ role: m.role === 'assistant' ? 'assistant' : 'user', content: m.content })),
      };
      if (chat.system) body.system = chat.system;
      return { url: `${base}/messages`, init: { method: 'POST', headers, body: JSON.stringify(body) } };
    }

    case API_STYLES.GEMINI: {
      const body = {
        contents: messages.map((m) => ({ role: m.role === 'assistant' ? 'model' : 'user', parts: [{ text: m.content }] })),
        generationConfig: { maxOutputTokens: maxTokens },
      };
      if (chat.system) body.systemInstruction = { parts: [{ text: chat.system }] };
      return {
        url: `${base}/models/${encodeURIComponent(model)}:generateContent`,
        init: { method: 'POST', headers, body: JSON.stringify(body) },
      };
    }

    case API_STYLES.OPENAI:
    default: {
      const body = {
        model,
        [provider.maxTokensParam || 'max_tokens']: maxTokens,
        messages: [
          ...(chat.system ? [{ role: 'system', content: chat.system }] : []),
          ...messages.map((m) => ({ role: m.role === 'assistant' ? 'assistant' : 'user', content: m.content })),
        ],
      };
      return { url: `${base}/chat/completions`, init: { method: 'POST', headers, body: JSON.stringify(body) } };
    }
  }
}

/**
 * Build the connectivity-test request: one short user message, small output cap.
 * @param {{providerId:string, base?:string, apiKey?:string, model?:string}} cfg
 * @param {string} userMessage
 */
export function buildTestRequest(cfg, userMessage = 'Reply with the single word: OK') {
  return buildChatRequest(cfg, { messages: [{ role: 'user', content: userMessage }], maxTokens: TEST_MAX_TOKENS });
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
        // Thinking models return reasoning parts flagged `thought: true`; skip them.
        return (json.candidates?.[0]?.content?.parts || []).filter((p) => !p.thought).map((p) => p.text || '').join('').trim();
      case API_STYLES.OPENAI:
      default:
        return (json.choices?.[0]?.message?.content || '').trim();
    }
  } catch {
    return '';
  }
}

// ---------------------------------------------------------------------------
// Multi-provider configuration
//
// Anne's Test's analysis layer can consult more than one provider over the same
// set of findings. The wizard lets the user enable any subset of providers and
// an analysis mode:
//   - "sequential": consult each enabled provider in turn (deterministic order,
//     gentle on rate limits, lets a later model react to earlier output).
//   - "concurrent": consult all enabled providers at once (faster; pairs with
//     the staging-mirror scan mode so several reviews run against a snapshot).
// In both modes the providers analyze Anne's Test's findings and the observed
// responses. They do not run the scan and never emit attack payloads.
// ---------------------------------------------------------------------------

export const CONFIG_VERSION = 2;
export const ANALYSIS_MODES = ['sequential', 'concurrent'];

/**
 * Build an Anne's Test AI config object from an ordered list of provider selections.
 * @param {Array<{providerId:string, base?:string, model?:string, apiKey?:string|null, apiKeyEnv?:string|null, saveKey?:boolean}>} selections
 * @param {{mode?:string}} [opts]
 */
export function buildMultiConfig(selections, opts = {}) {
  const mode = ANALYSIS_MODES.includes(opts.mode) ? opts.mode : 'sequential';
  const providers = {};
  const order = [];
  for (const sel of selections) {
    const provider = getProvider(sel.providerId);
    if (!provider) throw new Error(`Unknown provider: ${sel.providerId}`);
    if (providers[provider.id]) continue; // de-dupe, keep first occurrence
    const base = (sel.base || provider.defaultBase || '').replace(/\/+$/, '');
    const v = validateBase(base, { allowInsecure: Boolean(opts.allowInsecure) });
    if (!v.ok) throw new Error(`${provider.label}: ${v.error}`);
    providers[provider.id] = {
      providerId: provider.id,
      base,
      model: sel.model || provider.models[0] || '',
      apiKeyEnv: sel.apiKeyEnv || provider.keyEnv || null,
      apiKey: sel.saveKey ? (sel.apiKey || null) : null,
    };
    order.push(provider.id);
  }
  return {
    version: CONFIG_VERSION,
    analysisMode: mode,
    activeProviders: order,
    active: order[0] || null, // backward-compatible single-provider pointer
    providers,
  };
}

/**
 * Normalize a config read from disk (v1 single-provider or v2 multi-provider)
 * into a common { analysisMode, activeProviders[], providers{} } shape.
 */
export function normalizeConfig(obj) {
  if (!obj || typeof obj !== 'object') return { analysisMode: 'sequential', activeProviders: [], providers: {} };
  const providers = obj.providers || {};
  let activeProviders = Array.isArray(obj.activeProviders) && obj.activeProviders.length
    ? obj.activeProviders.slice()
    : (obj.active ? [obj.active] : Object.keys(providers));
  activeProviders = activeProviders.filter((id) => providers[id]);
  const analysisMode = ANALYSIS_MODES.includes(obj.analysisMode) ? obj.analysisMode : 'sequential';
  return { analysisMode, activeProviders, providers };
}
