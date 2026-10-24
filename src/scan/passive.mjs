/*
 * QuillTest — passive scan engine
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Observation-only checks over an origin the operator has verified they own
 * (the gate lives in scripts/scan.mjs and src/verify/). The engine:
 *
 *   - GETs the site root (following same-origin redirects only, max 3),
 *   - GETs the root once more with a synthetic Origin header to observe CORS,
 *   - GETs the plain-http variant of an https origin to see if it redirects,
 *   - GETs a short, fixed list of commonly exposed files and matches content
 *     signatures (never guesses credentials, never writes, never escalates),
 *
 * then runs every check in PASSIVE_CHECKS over what it observed. Checks are
 * data: id, category mapping, severity, a concrete remediation, and a run()
 * that returns zero or more findings in the shape src/ai/analyze.mjs expects.
 *
 * Cookie values are masked at capture time; the AI layer scrubs again before
 * anything leaves the machine.
 */

import { normalizeOrigin } from '../verify/ownership.mjs';

export const USER_AGENT = 'QuillTest-Scan/0.1 (+passive; owner-verified)';
export const DEFAULT_TIMEOUT_MS = 20_000;
export const MAX_BODY_BYTES = 256 * 1024;
export const SNIPPET_CHARS = 500;
export const HSTS_MIN_MAX_AGE = 15_552_000; // 180 days
export const CORS_PROBE_ORIGIN = 'https://quilltest-cors-probe.invalid';

/** Commonly exposed files, each with a content signature so a soft-404 cannot trigger it. */
export const SENSITIVE_FILE_PROBES = [
  { path: '/.git/HEAD', signature: (b) => /^ref:\s*refs\//.test(b), severity: 'critical', cwe: 'CWE-538', title: 'Git repository metadata exposed (.git/HEAD)', remediation: 'Deny web access to the .git directory (nginx: `location ~ /\\.git { deny all; }`; Apache: `RedirectMatch 404 /\\.git`). Rotate any secrets that were ever committed.' },
  { path: '/.env', signature: (b) => /^[A-Z][A-Z0-9_]*=.+/m.test(b) && !/<html/i.test(b), severity: 'critical', cwe: 'CWE-538', title: 'Environment file exposed (.env)', remediation: 'Move .env outside the web root or deny access to dotfiles (nginx: `location ~ /\\. { deny all; }`). Rotate every credential it contains.' },
  { path: '/.DS_Store', signature: (b) => b.includes('Bud1'), severity: 'low', cwe: 'CWE-538', title: 'macOS .DS_Store file exposed', remediation: 'Delete .DS_Store files from the deployment and deny access to dotfiles. They reveal directory contents.' },
  { path: '/server-status', signature: (b) => /Apache Server Status/i.test(b), severity: 'medium', cwe: 'CWE-200', title: 'Apache mod_status page exposed', remediation: 'Restrict /server-status to loopback/admin IPs (`Require ip 127.0.0.1`) or disable mod_status.' },
  { path: '/phpinfo.php', signature: (b) => /phpinfo\(\)|PHP Version/i.test(b), severity: 'high', cwe: 'CWE-200', title: 'phpinfo() page exposed', remediation: 'Remove phpinfo.php from production. It discloses paths, modules, and environment variables.' },
  { path: '/.svn/entries', signature: (b) => /^\d+\s*$/m.test(b.split('\n')[0] || '') || /^dir\b/m.test(b), severity: 'high', cwe: 'CWE-538', title: 'Subversion metadata exposed (.svn)', remediation: 'Deny web access to the .svn directory and remove it from deployments.' },
];

// ---------------------------------------------------------------------------
// Fetch helpers
// ---------------------------------------------------------------------------

function headersToObject(h) {
  const out = {};
  const setCookies = typeof h.getSetCookie === 'function' ? h.getSetCookie() : null;
  h.forEach((v, k) => { out[k.toLowerCase()] = v; });
  if (setCookies && setCookies.length) out['set-cookie'] = setCookies;
  else if (out['set-cookie']) out['set-cookie'] = [out['set-cookie']];
  return out;
}

/** Mask cookie values so a session id never lands in a findings file. */
export function maskCookie(setCookie) {
  return String(setCookie).replace(/^([^=;\s]+)=([^;]*)/, (m, name, val) => `${name}=${val ? '…' : ''}`);
}

async function readBodyCapped(res) {
  const text = await res.text();
  return text.length > MAX_BODY_BYTES ? text.slice(0, MAX_BODY_BYTES) : text;
}

/**
 * GET a URL, following only same-origin redirects (max 3). Returns a plain
 * observation object; network errors are returned, not thrown.
 */
export async function observe(url, { fetchImpl = globalThis.fetch, timeoutMs = DEFAULT_TIMEOUT_MS, headers = {} } = {}) {
  const chain = [];
  let current = url;
  const startOrigin = new URL(url).origin;
  for (let hop = 0; hop <= 3; hop++) {
    let res;
    try {
      res = await fetchImpl(current, {
        method: 'GET', redirect: 'manual',
        headers: { 'user-agent': USER_AGENT, accept: 'text/html,*/*;q=0.8', ...headers },
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (e) {
      const code = e?.cause?.code || e?.code || e?.name || 'ERR';
      return { url: current, requestedUrl: url, error: `${code}: ${e?.cause?.message || e.message}`, errorCode: code, chain };
    }
    const hdrs = headersToObject(res.headers);
    if (res.status >= 300 && res.status < 400 && hdrs.location) {
      let next; try { next = new URL(hdrs.location, current).toString(); } catch { next = null; }
      chain.push({ url: current, status: res.status, location: hdrs.location });
      if (!next) break;
      if (new URL(next).origin !== startOrigin) {
        // Cross-origin redirect: record it and stop (do not follow off the verified origin).
        return { url: current, requestedUrl: url, status: res.status, headers: hdrs, body: '', chain, crossOriginRedirectTo: next };
      }
      if (hop === 3) return { url: current, requestedUrl: url, status: res.status, headers: hdrs, body: '', chain, error: 'Too many redirects' };
      current = next;
      continue;
    }
    const body = await readBodyCapped(res);
    return { url: current, requestedUrl: url, status: res.status, headers: hdrs, body, chain };
  }
  return { url: current, requestedUrl: url, error: 'Redirect loop', chain };
}

// ---------------------------------------------------------------------------
// Small parsers
// ---------------------------------------------------------------------------

export function parseHsts(value) {
  if (!value) return null;
  const out = { maxAge: null, includeSubDomains: false, preload: false };
  for (const part of String(value).split(';')) {
    const [k, v] = part.trim().split('=');
    const key = (k || '').toLowerCase();
    if (key === 'max-age') out.maxAge = Number.parseInt(v, 10);
    else if (key === 'includesubdomains') out.includeSubDomains = true;
    else if (key === 'preload') out.preload = true;
  }
  return out;
}

export function parseCsp(value) {
  const out = {};
  if (!value) return out;
  for (const d of String(value).split(';')) {
    const toks = d.trim().split(/\s+/).filter(Boolean);
    if (!toks.length) continue;
    out[toks[0].toLowerCase()] = toks.slice(1);
  }
  return out;
}

export function parseCookie(setCookie) {
  const parts = String(setCookie).split(';').map((s) => s.trim());
  const [nameVal, ...attrs] = parts;
  const name = (nameVal.split('=')[0] || '').trim();
  const flags = { secure: false, httpOnly: false, sameSite: null };
  for (const a of attrs) {
    const [k, v] = a.split('=');
    const key = (k || '').toLowerCase();
    if (key === 'secure') flags.secure = true;
    else if (key === 'httponly') flags.httpOnly = true;
    else if (key === 'samesite') flags.sameSite = (v || '').trim() || 'present';
  }
  return { name, ...flags };
}

const SESSION_COOKIE_RE = /sess|sid|token|auth|jwt|login|remember|csrf|xsrf/i;
const VERSION_RE = /\d+\.\d+/;

function snippet(s, n = SNIPPET_CHARS) {
  const t = String(s ?? '');
  return t.length > n ? t.slice(0, n) + '…' : t;
}

// ---------------------------------------------------------------------------
// Checks (data)
// ---------------------------------------------------------------------------

/**
 * Each check: { id, title, severity, confidence, cwe, owasp, remediation, run(ctx) → partial findings[] }
 * ctx = { origin, isHttps, root, cors, httpVariant, probes[] }
 * run() returns objects with at least { location, evidence }; optional overrides for title/severity/etc.
 */
export const PASSIVE_CHECKS = [
  {
    id: 'scan.root-redirects-off-origin', title: 'Root redirects to a different origin', severity: 'info', confidence: 'confirmed',
    cwe: null, owasp: null,
    remediation: 'This origin hands visitors to another origin. Verify ownership of the destination and scan it; the checks below describe only what this origin itself serves.',
    run: ({ origin, root }) => (root?.crossOriginRedirectTo ? [{ location: origin + '/', evidence: { responseHeaders: pick(root.headers, ['location']), snippet: `HTTP ${root.status} → ${root.crossOriginRedirectTo} (not followed: outside the verified origin).` } }] : []),
  },
  {
    id: 'transport.plaintext', title: 'Site served over plaintext HTTP', severity: 'high', confidence: 'confirmed',
    cwe: 'CWE-319', owasp: 'A02:2021 Cryptographic Failures',
    remediation: 'Serve the site over HTTPS only. Obtain a certificate (e.g. Let\'s Encrypt), listen on 443, and 301-redirect every http:// request to https://.',
    run: ({ origin, isHttps, root }) => (!isHttps && root && !root.error ? [{ location: origin + '/', evidence: { responseHeaders: pick(root.headers, ['server', 'location']), snippet: 'Origin uses http://; credentials, cookies and content travel in cleartext.' } }] : []),
  },
  {
    id: 'transport.tls-error', title: 'TLS certificate problem on the origin', severity: 'critical', confidence: 'confirmed',
    cwe: 'CWE-295', owasp: 'A02:2021 Cryptographic Failures',
    remediation: 'Install a valid certificate for this hostname (correct name, trusted chain, not expired) and serve the full chain.',
    run: ({ origin, root }) => (root?.error && /CERT|TLS|SSL|ALTNAME|self.signed|certificate/i.test(root.error) ? [{ location: origin + '/', evidence: { snippet: root.error } }] : []),
  },
  {
    id: 'transport.http-not-redirected', title: 'HTTP is not redirected to HTTPS', severity: 'medium', confidence: 'firm',
    cwe: 'CWE-319', owasp: 'A02:2021 Cryptographic Failures',
    remediation: 'Redirect all http:// requests to https:// with a 301 (nginx: `return 301 https://$host$request_uri;`). Then add HSTS.',
    run: ({ origin, isHttps, httpVariant }) => {
      if (!isHttps || !httpVariant || httpVariant.error) return [];
      const landedHttps = (httpVariant.crossOriginRedirectTo || httpVariant.url || '').startsWith('https://');
      return landedHttps ? [] : [{ location: httpVariant.requestedUrl, evidence: { responseHeaders: pick(httpVariant.headers, ['location', 'server']), snippet: `HTTP ${httpVariant.status} served directly over http:// without redirecting to the https:// origin.` } }];
    },
  },
  {
    id: 'transport.hsts', title: 'Strict-Transport-Security missing or weak', severity: 'medium', confidence: 'confirmed',
    cwe: 'CWE-319', owasp: 'A05:2021 Security Misconfiguration',
    remediation: 'Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on every https response (add `preload` once you are ready to submit to the preload list).',
    run: ({ origin, isHttps, root }) => {
      if (!isHttps || !root || root.error) return [];
      const h = parseHsts(root.headers['strict-transport-security']);
      if (!h) return [{ location: origin + '/', evidence: { responseHeaders: pick(root.headers, ['strict-transport-security']), snippet: 'No Strict-Transport-Security header.' } }];
      if (!Number.isFinite(h.maxAge) || h.maxAge < HSTS_MIN_MAX_AGE) return [{ location: origin + '/', severity: 'low', evidence: { responseHeaders: pick(root.headers, ['strict-transport-security']), snippet: `HSTS max-age=${h.maxAge} is below ${HSTS_MIN_MAX_AGE} (180 days).` } }];
      return [];
    },
  },
  {
    id: 'headers.csp', title: 'Content-Security-Policy missing', severity: 'medium', confidence: 'confirmed',
    cwe: 'CWE-693', owasp: 'A05:2021 Security Misconfiguration',
    remediation: 'Add a Content-Security-Policy. Start in report-only, e.g. `Content-Security-Policy-Report-Only: default-src \'self\'; script-src \'self\'; object-src \'none\'; base-uri \'self\'; frame-ancestors \'self\'`, fix violations, then enforce.',
    run: ({ origin, root }) => {
      if (!root || root.error) return [];
      const csp = root.headers['content-security-policy'];
      const ro = root.headers['content-security-policy-report-only'];
      if (!csp && !ro) return [{ location: origin + '/', evidence: { snippet: 'No Content-Security-Policy or Content-Security-Policy-Report-Only header on the root page.' } }];
      if (!csp && ro) return [{ location: origin + '/', severity: 'low', title: 'Content-Security-Policy is report-only', evidence: { responseHeaders: pick(root.headers, ['content-security-policy-report-only']), snippet: 'Only a report-only policy is set; nothing is enforced.' } }];
      const d = parseCsp(csp);
      const script = d['script-src'] || d['default-src'] || [];
      const weak = [];
      if (script.includes("'unsafe-inline'") && !script.some((t) => t.startsWith("'nonce-") || t.startsWith("'sha"))) weak.push("'unsafe-inline' in script-src without a nonce/hash");
      if (script.includes("'unsafe-eval'")) weak.push("'unsafe-eval' in script-src");
      if (script.includes('*')) weak.push("wildcard '*' in script-src");
      if (!d['object-src'] && !d['default-src']) weak.push('no object-src or default-src');
      return weak.length ? [{ location: origin + '/', severity: 'low', title: 'Content-Security-Policy is weak', evidence: { responseHeaders: pick(root.headers, ['content-security-policy']), snippet: weak.join('; ') } }] : [];
    },
  },
  {
    id: 'headers.x-content-type-options', title: 'X-Content-Type-Options: nosniff missing', severity: 'low', confidence: 'confirmed',
    cwe: 'CWE-16', owasp: 'A05:2021 Security Misconfiguration',
    remediation: 'Send `X-Content-Type-Options: nosniff` on all responses.',
    run: ({ origin, root }) => (root && !root.error && (root.headers['x-content-type-options'] || '').toLowerCase() !== 'nosniff' ? [{ location: origin + '/', evidence: { responseHeaders: pick(root.headers, ['x-content-type-options', 'content-type']) } }] : []),
  },
  {
    id: 'headers.frame', title: 'No clickjacking protection (X-Frame-Options / frame-ancestors)', severity: 'medium', confidence: 'confirmed',
    cwe: 'CWE-1021', owasp: 'A05:2021 Security Misconfiguration',
    remediation: 'Send `Content-Security-Policy: frame-ancestors \'self\'` (preferred) and/or `X-Frame-Options: SAMEORIGIN`.',
    run: ({ origin, root }) => {
      if (!root || root.error) return [];
      const xfo = root.headers['x-frame-options'];
      const fa = parseCsp(root.headers['content-security-policy'])['frame-ancestors'];
      return xfo || fa ? [] : [{ location: origin + '/', evidence: { responseHeaders: pick(root.headers, ['x-frame-options', 'content-security-policy']) } }];
    },
  },
  {
    id: 'headers.referrer-policy', title: 'Referrer-Policy missing', severity: 'low', confidence: 'confirmed',
    cwe: 'CWE-200', owasp: 'A05:2021 Security Misconfiguration',
    remediation: 'Send `Referrer-Policy: strict-origin-when-cross-origin` (or stricter).',
    run: ({ origin, root }) => (root && !root.error && !root.headers['referrer-policy'] ? [{ location: origin + '/', evidence: { snippet: 'No Referrer-Policy header; full URLs may leak to third parties.' } }] : []),
  },
  {
    id: 'headers.permissions-policy', title: 'Permissions-Policy missing', severity: 'info', confidence: 'confirmed',
    cwe: 'CWE-16', owasp: 'A05:2021 Security Misconfiguration',
    remediation: 'Send a Permissions-Policy that disables features you do not use, e.g. `Permissions-Policy: camera=(), microphone=(), geolocation=()`.',
    run: ({ origin, root }) => (root && !root.error && !root.headers['permissions-policy'] ? [{ location: origin + '/', evidence: { snippet: 'No Permissions-Policy header.' } }] : []),
  },
  {
    id: 'cookies.flags', title: 'Cookie set without recommended security attributes', severity: 'medium', confidence: 'confirmed',
    cwe: 'CWE-614', owasp: 'A05:2021 Security Misconfiguration',
    remediation: 'Set cookies with `Secure; HttpOnly; SameSite=Lax` (or Strict). Session cookies must have all three; use the `__Host-` prefix where possible.',
    run: ({ origin, isHttps, root }) => {
      if (!root || root.error) return [];
      const out = [];
      for (const sc of root.headers['set-cookie'] || []) {
        const c = parseCookie(sc);
        const missing = [];
        if (isHttps && !c.secure) missing.push('Secure');
        if (!c.httpOnly) missing.push('HttpOnly');
        if (!c.sameSite) missing.push('SameSite');
        if (!missing.length) continue;
        const sessionLike = SESSION_COOKIE_RE.test(c.name);
        out.push({
          location: origin + '/',
          severity: sessionLike ? 'high' : 'medium',
          title: `${sessionLike ? 'Session cookie' : 'Cookie'} '${c.name}' missing ${missing.join(', ')}`,
          evidence: { responseHeaders: { 'set-cookie': maskCookie(sc) }, snippet: `Missing: ${missing.join(', ')}.` },
        });
      }
      return out;
    },
  },
  {
    id: 'cors.misconfig', title: 'CORS misconfiguration', severity: 'medium', confidence: 'firm',
    cwe: 'CWE-942', owasp: 'A05:2021 Security Misconfiguration',
    remediation: 'Only echo Access-Control-Allow-Origin for an explicit allow-list of trusted origins; never reflect arbitrary origins, and never combine a wildcard or reflected origin with Access-Control-Allow-Credentials: true.',
    run: ({ origin, root, cors }) => {
      const out = [];
      const check = (resp, label) => {
        if (!resp || resp.error) return;
        const acao = resp.headers['access-control-allow-origin'];
        const acac = (resp.headers['access-control-allow-credentials'] || '').toLowerCase() === 'true';
        if (!acao) return;
        if (acao === '*' && acac) out.push({ location: origin + '/', severity: 'high', title: 'CORS allows any origin with credentials', evidence: { responseHeaders: pick(resp.headers, ['access-control-allow-origin', 'access-control-allow-credentials']), snippet: label } });
        else if (acao === 'null') out.push({ location: origin + '/', title: "CORS allows the 'null' origin", evidence: { responseHeaders: pick(resp.headers, ['access-control-allow-origin', 'access-control-allow-credentials']), snippet: label } });
        else if (acao === CORS_PROBE_ORIGIN) out.push({ location: origin + '/', severity: acac ? 'high' : 'medium', title: `CORS reflects arbitrary origins${acac ? ' with credentials' : ''}`, evidence: { requestHeaders: { origin: CORS_PROBE_ORIGIN }, responseHeaders: pick(resp.headers, ['access-control-allow-origin', 'access-control-allow-credentials', 'vary']), snippet: 'The Origin header value was echoed back in Access-Control-Allow-Origin.' } });
      };
      check(root, 'Observed on a plain GET of the root.');
      check(cors, 'Observed on a GET of the root with a synthetic Origin header.');
      // de-dupe identical titles
      const seen = new Set();
      return out.filter((f) => (seen.has(f.title) ? false : (seen.add(f.title), true)));
    },
  },
  {
    id: 'disclosure.server-banner', title: 'Server software version disclosed', severity: 'low', confidence: 'confirmed',
    cwe: 'CWE-200', owasp: 'A05:2021 Security Misconfiguration',
    remediation: 'Suppress version strings (nginx: `server_tokens off;`; Apache: `ServerTokens Prod` + `ServerSignature Off`; Express: `app.disable(\'x-powered-by\')`; ASP.NET: remove X-AspNet-Version/X-Powered-By in web.config).',
    run: ({ origin, root }) => {
      if (!root || root.error) return [];
      const keys = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator'];
      const leaking = keys.filter((k) => root.headers[k] && VERSION_RE.test(root.headers[k]));
      return leaking.length ? [{ location: origin + '/', evidence: { responseHeaders: pick(root.headers, leaking), snippet: `Version numbers in: ${leaking.join(', ')}.` } }] : [];
    },
  },
  {
    id: 'content.mixed', title: 'Mixed content on an HTTPS page', severity: 'medium', confidence: 'firm',
    cwe: 'CWE-311', owasp: 'A02:2021 Cryptographic Failures',
    remediation: 'Load all scripts, styles, frames and images over https:// (or protocol-relative/absolute https URLs). Add `Content-Security-Policy: upgrade-insecure-requests` as a backstop.',
    run: ({ origin, isHttps, root }) => {
      if (!isHttps || !root || root.error || !root.body) return [];
      const active = [...root.body.matchAll(/<(script|iframe|link)\b[^>]*\b(?:src|href)\s*=\s*["']http:\/\/[^"']+/gi)].map((m) => m[0]);
      const passive = [...root.body.matchAll(/<(img|video|audio|source)\b[^>]*\bsrc\s*=\s*["']http:\/\/[^"']+/gi)].map((m) => m[0]);
      const out = [];
      if (active.length) out.push({ location: origin + '/', severity: 'high', title: 'Active mixed content (script/iframe/stylesheet over http://)', evidence: { snippet: snippet(active.slice(0, 5).join('\n')) } });
      if (passive.length) out.push({ location: origin + '/', severity: 'low', title: 'Passive mixed content (media over http://)', evidence: { snippet: snippet(passive.slice(0, 5).join('\n')) } });
      return out;
    },
  },
  {
    id: 'content.form-insecure', title: 'Form submits over plaintext HTTP', severity: 'high', confidence: 'firm',
    cwe: 'CWE-319', owasp: 'A02:2021 Cryptographic Failures',
    remediation: 'Point every form action at an https:// URL (or a relative path on the https origin).',
    run: ({ origin, root }) => {
      if (!root || root.error || !root.body) return [];
      const forms = [...root.body.matchAll(/<form\b[^>]*\baction\s*=\s*["']http:\/\/[^"']+["'][^>]*>/gi)].map((m) => m[0]);
      return forms.length ? [{ location: origin + '/', evidence: { snippet: snippet(forms.slice(0, 3).join('\n')) } }] : [];
    },
  },
  {
    id: 'content.directory-listing', title: 'Directory listing enabled', severity: 'medium', confidence: 'confirmed',
    cwe: 'CWE-548', owasp: 'A05:2021 Security Misconfiguration',
    remediation: 'Disable autoindex (nginx: `autoindex off;`; Apache: `Options -Indexes`) and add an index document.',
    run: ({ root, probes }) => {
      const out = [];
      for (const r of [root, ...probes]) {
        if (r && !r.error && r.status === 200 && /<title>\s*Index of \//i.test(r.body || '')) out.push({ location: r.url, evidence: { snippet: snippet((r.body.match(/<title>[^<]*<\/title>/i) || [''])[0]) } });
      }
      return out;
    },
  },
  {
    id: 'disclosure.sensitive-files', title: 'Sensitive file exposed', severity: 'high', confidence: 'confirmed',
    cwe: 'CWE-538', owasp: 'A05:2021 Security Misconfiguration',
    remediation: 'Remove the file from the web root or deny access to it at the server.',
    run: ({ probes }) => {
      const out = [];
      for (const r of probes) {
        if (!r || r.error || r.status !== 200 || !r.probe) continue;
        if (r.probe.signature(r.body || '')) {
          out.push({ location: r.url, severity: r.probe.severity, title: r.probe.title, cwe: r.probe.cwe, remediation: r.probe.remediation, evidence: { responseHeaders: pick(r.headers, ['content-type', 'content-length']), snippet: snippet(r.body, 160) } });
        }
      }
      return out;
    },
  },
];

function pick(headers, keys) {
  const out = {};
  for (const k of keys) if (headers && headers[k] !== undefined) out[k] = Array.isArray(headers[k]) && k === 'set-cookie' ? headers[k].map(maskCookie) : headers[k];
  return out;
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

/**
 * Run the passive scan against a verified origin.
 * @param {string} originInput
 * @param {{fetchImpl?:Function, timeoutMs?:number, probeSensitiveFiles?:boolean, now?:Date}} [opts]
 * @returns {Promise<{origin:string, startedAt:string, finishedAt:string, requests:number, findings:object[], observations:object}>}
 */
export async function runPassiveScan(originInput, opts = {}) {
  const origin = normalizeOrigin(originInput);
  const isHttps = origin.startsWith('https://');
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  const timeoutMs = opts.timeoutMs || DEFAULT_TIMEOUT_MS;
  const startedAt = (opts.now || new Date()).toISOString();
  let requests = 0;
  const get = async (url, extra) => { requests++; return observe(url, { fetchImpl, timeoutMs, headers: extra }); };

  const root = await get(origin + '/');
  const cors = root.error ? null : await get(origin + '/', { origin: CORS_PROBE_ORIGIN });
  const httpVariant = isHttps && !root.error ? await get('http://' + new URL(origin).host + '/') : null;

  const probes = [];
  if (opts.probeSensitiveFiles !== false && !root.error) {
    for (const probe of SENSITIVE_FILE_PROBES) {
      const r = await get(origin + probe.path);
      probes.push({ ...r, probe });
    }
  }

  const ctx = { origin, isHttps, root, cors, httpVariant, probes };
  const findings = [];
  let n = 0;
  for (const check of PASSIVE_CHECKS) {
    let partials = [];
    try { partials = check.run(ctx) || []; } catch (e) { partials = []; }
    for (const p of partials) {
      n++;
      findings.push({
        id: `F-${String(n).padStart(3, '0')}`,
        checkId: check.id,
        title: p.title || check.title,
        severity: p.severity || check.severity,
        confidence: p.confidence || check.confidence,
        cwe: p.cwe || check.cwe,
        owasp: p.owasp !== undefined ? p.owasp : check.owasp,
        location: p.location,
        evidence: p.evidence || {},
        remediation: p.remediation || check.remediation,
      });
    }
  }

  // Strip bodies from stored observations; keep status/headers/url for the report.
  const slim = (r) => (r ? { url: r.url, requestedUrl: r.requestedUrl, status: r.status ?? null, error: r.error ?? null, crossOriginRedirectTo: r.crossOriginRedirectTo ?? null, headers: r.headers ? pick(r.headers, Object.keys(r.headers)) : null } : null);
  return {
    origin, startedAt, finishedAt: new Date().toISOString(), requests,
    findings,
    observations: { root: slim(root), cors: slim(cors), httpVariant: slim(httpVariant), probes: probes.map((p) => ({ path: p.probe.path, status: p.status ?? null, error: p.error ?? null })) },
  };
}

/** Order findings for the fix list: severity desc, then confidence. */
export function sortFindings(findings) {
  const sev = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  const conf = { confirmed: 3, firm: 2, tentative: 1 };
  return [...findings].sort((a, b) => (sev[b.severity] || 0) - (sev[a.severity] || 0) || (conf[b.confidence] || 0) - (conf[a.confidence] || 0));
}
