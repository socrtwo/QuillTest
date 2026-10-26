/*
 * Anne's Test — schema validation for quilltest.ai.json
 * Part of the Anne's Office suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * normalizeConfig() in providers.mjs is forgiving by design: it reads whatever
 * it can and silently drops the rest, so the analysis layer never crashes on a
 * hand-edited file. That forgiveness hides mistakes. This module is the strict
 * counterpart: it reports exactly what is wrong with a config so the wizard and
 * the CLIs can tell the user, instead of quietly ignoring a misspelled provider
 * id or an endpoint that would leak a key.
 *
 * validateConfig() returns { ok, version, errors[], warnings[] } and never
 * throws. Errors mean the file will not work as written (a referenced provider
 * has no entry, an endpoint is plaintext to a remote host, analysisMode is
 * unknown). Warnings mean it will work but probably not as intended (a stored
 * plaintext key, a providerId that does not match the built-in registry, an
 * entry present in `providers` but not enabled).
 *
 * Validation is offline and reads nothing but the object passed in. It knows
 * the built-in provider ids, but an unknown id is only a warning: a custom or
 * self-hosted OpenAI-compatible gateway is legitimate.
 */
import { PROVIDERS, ANALYSIS_MODES, CONFIG_VERSION, validateBase } from './providers.mjs';

const KNOWN_PROVIDER_IDS = new Set(PROVIDERS.map((p) => p.id));
const ENV_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** A dotted path into the config, for error messages. */
const at = (...parts) => parts.join('.');

/**
 * Validate a parsed quilltest.ai.json object.
 * @param {*} config  the parsed JSON (any type; non-objects are an error)
 * @param {{allowInsecureBase?:boolean}} [opts]
 * @returns {{ok:boolean, version:number|null, errors:string[], warnings:string[]}}
 */
export function validateConfig(config, opts = {}) {
  const errors = [];
  const warnings = [];
  const err = (msg) => errors.push(msg);
  const warn = (msg) => warnings.push(msg);

  if (!config || typeof config !== 'object' || Array.isArray(config)) {
    return { ok: false, version: null, errors: ['Config must be a JSON object.'], warnings };
  }

  // ---- version ----
  let version = null;
  if (config.version === undefined) {
    warn('No "version" field; treating it as a version 1 (single-provider) config.');
    version = 1;
  } else if (!Number.isInteger(config.version) || config.version < 1) {
    err(`"version" must be a positive integer (got ${JSON.stringify(config.version)}).`);
  } else {
    version = config.version;
    if (version > CONFIG_VERSION) warn(`"version" is ${version}, newer than this build understands (${CONFIG_VERSION}); unknown fields will be ignored.`);
  }

  // ---- providers map ----
  const providers = config.providers;
  if (providers === undefined) {
    err('Missing "providers" object.');
  } else if (typeof providers !== 'object' || Array.isArray(providers)) {
    err('"providers" must be an object keyed by provider id.');
  } else {
    for (const [key, entry] of Object.entries(providers)) {
      validateProviderEntry(key, entry, { err, warn, allowInsecureBase: opts.allowInsecureBase });
    }
    if (!Object.keys(providers).length) warn('"providers" is empty; the analysis layer will have nothing to consult.');
  }
  const providerKeys = providers && typeof providers === 'object' && !Array.isArray(providers) ? Object.keys(providers) : [];

  // ---- analysisMode ----
  if (config.analysisMode !== undefined && !ANALYSIS_MODES.includes(config.analysisMode)) {
    err(`"analysisMode" must be one of ${ANALYSIS_MODES.join(', ')} (got ${JSON.stringify(config.analysisMode)}).`);
  } else if (config.analysisMode === undefined && version >= 2) {
    warn('No "analysisMode"; it will default to "sequential".');
  }

  // ---- activeProviders ----
  const active = config.activeProviders;
  if (active !== undefined) {
    if (!Array.isArray(active)) {
      err('"activeProviders" must be an array of provider ids.');
    } else {
      if (!active.length) warn('"activeProviders" is empty; no provider will be consulted.');
      const seen = new Set();
      for (const id of active) {
        if (typeof id !== 'string') { err(`"activeProviders" entries must be strings (got ${JSON.stringify(id)}).`); continue; }
        if (seen.has(id)) warn(`"activeProviders" lists "${id}" more than once; the duplicate is ignored.`);
        seen.add(id);
        if (!providerKeys.includes(id)) err(`"activeProviders" references "${id}", which has no entry in "providers".`);
      }
    }
  } else if (version >= 2) {
    warn('No "activeProviders"; every entry in "providers" will be treated as active.');
  }

  // ---- active (back-compat pointer) ----
  if (config.active !== undefined && config.active !== null) {
    if (typeof config.active !== 'string') err(`"active" must be a provider id string or null (got ${JSON.stringify(config.active)}).`);
    else if (!providerKeys.includes(config.active)) err(`"active" points to "${config.active}", which has no entry in "providers".`);
  }

  // A v1 config with neither activeProviders nor active and more than one
  // provider is ambiguous about which to use.
  if (active === undefined && (config.active === undefined || config.active === null) && providerKeys.length > 1) {
    warn('Neither "activeProviders" nor "active" is set with multiple providers defined; order is undefined. Set "activeProviders".');
  }

  // Entries defined but never enabled.
  if (Array.isArray(active)) {
    for (const key of providerKeys) if (!active.includes(key)) warn(`Provider "${key}" is defined but not in "activeProviders"; it will not be consulted.`);
  }

  return { ok: errors.length === 0, version, errors, warnings };
}

function validateProviderEntry(key, entry, { err, warn, allowInsecureBase }) {
  const scope = at('providers', key);
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) { err(`${scope} must be an object.`); return; }

  // providerId — must be present; mismatch with its key is an error, unknown id a warning.
  if (entry.providerId === undefined) {
    warn(`${at(scope, 'providerId')} is missing; assuming "${key}".`);
  } else if (typeof entry.providerId !== 'string') {
    err(`${at(scope, 'providerId')} must be a string.`);
  } else {
    if (entry.providerId !== key) err(`${at(scope, 'providerId')} is "${entry.providerId}" but the key is "${key}"; they must match.`);
    if (!KNOWN_PROVIDER_IDS.has(entry.providerId)) warn(`${at(scope, 'providerId')} "${entry.providerId}" is not a built-in provider; it will use the custom/OpenAI-compatible path.`);
  }

  // base — required and validated through the same rule the wizard enforces.
  if (entry.base === undefined || entry.base === null || entry.base === '') {
    err(`${at(scope, 'base')} is required (the endpoint URL).`);
  } else if (typeof entry.base !== 'string') {
    err(`${at(scope, 'base')} must be a string URL.`);
  } else {
    const v = validateBase(entry.base, { allowInsecure: Boolean(allowInsecureBase) });
    if (!v.ok) err(`${at(scope, 'base')}: ${v.error}`);
    else if (v.warning) warn(`${at(scope, 'base')}: ${v.warning}`);
  }

  // model — required, non-empty string.
  if (entry.model === undefined || entry.model === null || entry.model === '') err(`${at(scope, 'model')} is required (the model id to call).`);
  else if (typeof entry.model !== 'string') err(`${at(scope, 'model')} must be a string.`);

  // apiKeyEnv — optional, but if present must be a plausible env var name.
  if (entry.apiKeyEnv !== undefined && entry.apiKeyEnv !== null) {
    if (typeof entry.apiKeyEnv !== 'string') err(`${at(scope, 'apiKeyEnv')} must be a string (an environment variable name) or null.`);
    else if (!ENV_NAME_RE.test(entry.apiKeyEnv)) warn(`${at(scope, 'apiKeyEnv')} "${entry.apiKeyEnv}" is not a valid environment variable name.`);
  }

  // apiKey — optional; a stored non-null key is a security warning.
  if (entry.apiKey !== undefined && entry.apiKey !== null) {
    if (typeof entry.apiKey !== 'string') err(`${at(scope, 'apiKey')} must be a string or null.`);
    else if (entry.apiKey !== '') warn(`${at(scope, 'apiKey')} stores a key in plaintext. Prefer "apiKeyEnv" so the secret stays out of the file.`);
  }

  // No apiKey and no apiKeyEnv means the provider cannot authenticate (unless it is keyless).
  const hasKey = typeof entry.apiKey === 'string' && entry.apiKey !== '';
  const hasEnv = typeof entry.apiKeyEnv === 'string' && entry.apiKeyEnv !== '';
  if (!hasKey && !hasEnv) warn(`${scope} has neither "apiKey" nor "apiKeyEnv"; it will only work if the provider needs no key (e.g. a local model).`);
}

/** Format a result for the terminal. Returns a string (empty when clean). */
export function formatValidation(result) {
  const lines = [];
  for (const e of result.errors) lines.push(`  error:   ${e}`);
  for (const w of result.warnings) lines.push(`  warning: ${w}`);
  return lines.join('\n');
}
