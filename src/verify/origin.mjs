/*
 * QuillTest — origin normalization
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * A verification token is bound to exactly one origin. "Origin" here follows
 * docs/OWNERSHIP-VERIFICATION.md: lowercase scheme + host, explicit port only
 * when it is not the scheme default, no trailing slash, no path/query/fragment.
 */

const DEFAULT_PORTS = { 'http:': '80', 'https:': '443' };

export class InvalidOriginError extends Error {
  constructor(input, reason) {
    super(`Invalid target origin ${JSON.stringify(input)}: ${reason}`);
    this.name = 'InvalidOriginError';
    this.input = input;
    this.reason = reason;
  }
}

/**
 * Normalize user input to a canonical origin string.
 * Accepts a bare host ("example.com" → https), a host:port, or any http(s) URL
 * (path, query, fragment and credentials are dropped).
 * @param {string} input
 * @returns {string} e.g. "https://example.com" or "http://localhost:8080"
 */
export function normalizeOrigin(input) {
  if (typeof input !== 'string' || !input.trim()) throw new InvalidOriginError(input, 'empty');
  let text = input.trim();
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) text = 'https://' + text;

  let url;
  try {
    url = new URL(text);
  } catch {
    throw new InvalidOriginError(input, 'not a parseable URL');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new InvalidOriginError(input, `scheme must be http or https (got ${url.protocol.replace(/:$/, '')})`);
  }
  if (!url.hostname) throw new InvalidOriginError(input, 'missing host');
  if (url.username || url.password) throw new InvalidOriginError(input, 'credentials are not allowed in an origin');

  // URL already lowercases scheme/host and drops default ports in .origin,
  // but be explicit so the rule is visible here and stable across runtimes.
  const port = url.port && url.port !== DEFAULT_PORTS[url.protocol] ? `:${url.port}` : '';
  return `${url.protocol}//${url.hostname.toLowerCase()}${port}`;
}

/** Split a normalized origin into its parts. */
export function parseOrigin(origin) {
  const url = new URL(origin);
  return {
    scheme: url.protocol.replace(/:$/, ''),
    host: url.hostname,
    port: url.port ? Number(url.port) : Number(DEFAULT_PORTS[url.protocol]),
  };
}

/** True when two inputs denote the same origin after normalization. */
export function sameOrigin(a, b) {
  try {
    return normalizeOrigin(a) === normalizeOrigin(b);
  } catch {
    return false;
  }
}
