/*
 * QuillTest — quilltest.ai.json loader and validator
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Schema (version 1), see docs/AI-WIZARD.md:
 *   {
 *     "version": 1,
 *     "active": "<providerId>",
 *     "providers": {
 *       "<providerId>": { providerId, base, model, apiKeyEnv: string|null, apiKey: string|null }
 *     }
 *   }
 */

import { readFileSync, existsSync } from 'node:fs';
import { PROVIDERS, getProvider, keyOptional } from './providers.mjs';

export const CONFIG_VERSION = 1;
export const DEFAULT_CONFIG_FILE = 'quilltest.ai.json';

export class AiConfigError extends Error {
  constructor(problems, path) {
    super(`Invalid AI config${path ? ` ${path}` : ''}:\n  - ${problems.join('\n  - ')}`);
    this.name = 'AiConfigError';
    this.problems = problems;
    this.path = path;
  }
}

const ENV_NAME = /^[A-Z_][A-Z0-9_]*$/;

/**
 * Validate a parsed config object. Returns the list of problems (empty when valid).
 * @param {unknown} cfg
 * @returns {string[]}
 */
export function validateAiConfig(cfg) {
  const problems = [];
  if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) return ['config must be a JSON object'];

  if (cfg.version !== CONFIG_VERSION) problems.push(`version must be ${CONFIG_VERSION} (got ${JSON.stringify(cfg.version)})`);

  if (!cfg.providers || typeof cfg.providers !== 'object' || Array.isArray(cfg.providers)) {
    problems.push('providers must be an object keyed by provider id');
    return problems;
  }
  const ids = Object.keys(cfg.providers);
  if (!ids.length) problems.push('providers is empty');

  for (const id of ids) {
    const p = cfg.providers[id];
    const where = `providers.${id}`;
    if (!p || typeof p !== 'object' || Array.isArray(p)) { problems.push(`${where} must be an object`); continue; }
    const known = getProvider(id);
    if (!known) problems.push(`${where}: unknown provider id (known: ${PROVIDERS.map((x) => x.id).join(', ')})`);
    if (p.providerId !== id) problems.push(`${where}.providerId must equal the key "${id}" (got ${JSON.stringify(p.providerId)})`);
    if (typeof p.base !== 'string' || !p.base) problems.push(`${where}.base must be a non-empty string`);
    else if (!/^https?:\/\//i.test(p.base)) problems.push(`${where}.base must start with http:// or https://`);
    else if (/\/$/.test(p.base)) problems.push(`${where}.base must not end with a slash`);
    if (typeof p.model !== 'string' || !p.model.trim()) problems.push(`${where}.model must be a non-empty string`);
    if (p.apiKeyEnv !== null && p.apiKeyEnv !== undefined) {
      if (typeof p.apiKeyEnv !== 'string' || !ENV_NAME.test(p.apiKeyEnv)) problems.push(`${where}.apiKeyEnv must be null or an environment variable name like OPENAI_API_KEY`);
    }
    if (p.apiKey !== null && p.apiKey !== undefined && typeof p.apiKey !== 'string') problems.push(`${where}.apiKey must be null or a string`);
    if (known && !keyOptional(id) && !p.apiKey && !p.apiKeyEnv) problems.push(`${where}: needs apiKeyEnv or apiKey (this provider requires a credential)`);
    for (const k of Object.keys(p)) {
      if (!['providerId', 'base', 'model', 'apiKeyEnv', 'apiKey'].includes(k)) problems.push(`${where}.${k}: unknown field`);
    }
  }

  if (typeof cfg.active !== 'string' || !cfg.active) problems.push('active must name a provider id');
  else if (!ids.includes(cfg.active)) problems.push(`active "${cfg.active}" is not one of providers (${ids.join(', ') || 'none'})`);

  for (const k of Object.keys(cfg)) {
    if (!['version', 'active', 'providers'].includes(k)) problems.push(`${k}: unknown top-level field`);
  }
  return problems;
}

/** Validate and return the config, or throw AiConfigError. */
export function assertAiConfig(cfg, path) {
  const problems = validateAiConfig(cfg);
  if (problems.length) throw new AiConfigError(problems, path);
  return cfg;
}

/**
 * Read, parse and validate a config file.
 * @param {string} path
 * @returns {{config:object, path:string}}
 */
export function loadAiConfig(path = DEFAULT_CONFIG_FILE) {
  if (!existsSync(path)) throw new AiConfigError([`file not found`], path);
  let parsed;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'));
  } catch (e) {
    throw new AiConfigError([`not valid JSON: ${e.message}`], path);
  }
  return { config: assertAiConfig(parsed, path), path };
}

/** The active provider entry of a (valid) config. */
export function activeProvider(config) {
  return config.providers[config.active];
}

/**
 * Resolve the credential for a provider entry: literal key, else the named
 * environment variable, else '' (callers decide whether that is acceptable).
 * @param {{apiKey?:string|null, apiKeyEnv?:string|null}} entry
 * @param {Record<string,string|undefined>} env
 */
export function resolveApiKey(entry, env = process.env) {
  if (entry.apiKey) return entry.apiKey;
  if (entry.apiKeyEnv && env[entry.apiKeyEnv]) return env[entry.apiKeyEnv];
  return '';
}
