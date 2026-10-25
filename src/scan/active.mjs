/*
 * QuillTest — active scan engine (detection only, ownership-gated)
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Active checks differ from passive ones only in that they send a request the
 * target would not otherwise receive. Everything here is still observation:
 * each probe sends a BENIGN input and reads the response. There is no payload
 * library. Specifically, this engine:
 *
 *   - sends only GET and OPTIONS — never POST/PUT/DELETE/PATCH, never submits
 *     a form, never changes state;
 *   - never follows a redirect off the verified origin (redirect: 'manual');
 *   - uses benign markers only: a random alphanumeric canary for reflection,
 *     and a clearly-labelled non-resolving host (…​.invalid) for redirects.
 *     No marker contains an executable construct, so nothing can run even if
 *     the target echoes it verbatim;
 *   - reports a *candidate* for manual review (e.g. "input is reflected
 *     unescaped") rather than asserting exploitation, and assigns a
 *     conservative confidence.
 *
 * Intrusiveness is a declared property of every check and is capped per scan
 * profile. The injection family (SQLi, command, template, SSRF, XXE) is
 * deliberately NOT implemented here: those require inputs designed to trigger
 * backend execution, which is outside this tool's non-destructive remit. They
 * remain specified in docs/CHECKS.md as future work behind a higher profile.
 *
 * The caller (scripts/scan.mjs) must pass only origins proven owned; the gate
 * lives there and in src/verify/, exactly as for the passive engine.
 */
import { USER_AGENT, DEFAULT_TIMEOUT_MS } from './passive.mjs';

// ---------------------------------------------------------------------------
// Intrusiveness levels and scan profiles
// ---------------------------------------------------------------------------

/**
 * 0  passive — observation without an extra request (the passive engine).
 * 1  benign-active — one or more extra requests, each with harmless input and
 *    non-state-changing semantics (GET/OPTIONS, no redirect following).
 * 2  reserved — inputs intended to probe backend handling (injection family).
 *    No level-2 check exists yet; no profile enables it.
 */
export const INTRUSIVENESS = { passive: 0, benignActive: 1, reserved: 2 };

export const SCAN_PROFILES = {
  passive: { active: false, maxIntrusiveness: 0, description: 'Observation only; no active requests (default).' },
  'safe-active': { active: true, maxIntrusiveness: 1, description: 'Adds benign, non-state-changing active probes (HTTP methods, open redirect, input reflection).' },
};
export const DEFAULT_PROFILE = 'passive';

/** Query-parameter names that commonly carry a redirect destination. */
export const REDIRECT_PARAMS = new Set([
  'next', 'url', 'redirect', 'redirect_uri', 'redirect_url', 'redirecturl', 'return', 'returnurl',
  'return_url', 'return_to', 'returnto', 'dest', 'destination', 'continue', 'goto', 'target', 'to',
  'out', 'link', 'forward', 'r', 'u',
]);

/** A host that does not and cannot resolve, so a reflected redirect goes nowhere even if a human follows it. */
export const REDIRECT_MARKER_HOST = 'quilltest-redirect-probe.invalid';

const STATE_CHANGING_METHODS = ['PUT', 'DELETE', 'PATCH', 'CONNECT'];

// ---------------------------------------------------------------------------
// Request helper — benign, non-following, method-explicit
// ---------------------------------------------------------------------------

function newToken() {
  return Math.random().toString(16).slice(2, 12).padEnd(10, '0');
}

async function sendProbe(url, { method = 'GET', fetchImpl = globalThis.fetch, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  let res;
  try {
    res = await fetchImpl(url, {
      method,
      redirect: 'manual', // never follow — a redirect's destination is the evidence, not a place to go
      headers: { 'user-agent': USER_AGENT, accept: 'text/html,*/*;q=0.8' },
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (e) {
    const code = e?.cause?.code || e?.code || e?.name || 'ERR';
    return { url, method, error: `${code}: ${e?.cause?.message || e.message}`, errorCode: code };
  }
  const headers = {};
  res.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
  let body = '';
  const ctype = headers['content-type'] || '';
  if (method === 'GET' && /text|html|json|xml|javascript/i.test(ctype)) {
    try { body = (await res.text()).slice(0, 256 * 1024); } catch { /* ignore body read errors */ }
  }
  return { url, method, status: res.status, headers, body, contentType: ctype };
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

/** Parse an Allow / Access-Control-Allow-Methods header into an upper-case set. */
export function parseAllowedMethods(obs) {
  const raw = `${obs.headers?.allow || ''},${obs.headers?.['access-control-allow-methods'] || ''}`;
  return new Set(raw.split(',').map((m) => m.trim().toUpperCase()).filter(Boolean));
}

/**
 * HTTP method check. Sends ONE OPTIONS request to the origin root and reads
 * what the server advertises. TRACE enabled is Cross-Site Tracing (CWE-693);
 * advertised state-changing methods are a review item. No TRACE/PUT/DELETE is
 * ever sent — the Allow header is the evidence.
 */
export async function checkHttpMethods(origin, ctx) {
  const obs = await ctx.request(origin + '/', { method: 'OPTIONS' });
  if (obs.error) return [];
  const methods = parseAllowedMethods(obs);
  if (!methods.size) return [];
  const out = [];
  if (methods.has('TRACE') || methods.has('TRACK')) {
    out.push({
      checkId: 'active.http-trace', title: 'HTTP TRACE/TRACK method enabled (Cross-Site Tracing)',
      severity: 'low', confidence: 'firm', cwe: 'CWE-693', owasp: 'A05:2021 Security Misconfiguration',
      location: origin + '/', evidence: { snippet: `OPTIONS advertised: ${[...methods].join(', ')}`, method: 'OPTIONS (TRACE not sent)' },
      remediation: 'Disable TRACE/TRACK on the server (nginx: it is off by default; Apache: `TraceEnable off`; IIS: remove the TRACE verb). It can be abused to read headers like cookies via Cross-Site Tracing.',
    });
  }
  const risky = STATE_CHANGING_METHODS.filter((m) => methods.has(m));
  if (risky.length) {
    out.push({
      checkId: 'active.http-methods', title: `State-changing HTTP methods advertised (${risky.join(', ')})`,
      severity: 'info', confidence: 'tentative', cwe: 'CWE-650', owasp: 'A05:2021 Security Misconfiguration',
      location: origin + '/', evidence: { snippet: `OPTIONS advertised: ${[...methods].join(', ')}`, method: 'OPTIONS (none of these were sent)' },
      remediation: `Confirm ${risky.join(', ')} are meant to be reachable here and are authenticated and authorized. If the resource is read-only, restrict the allowed methods to GET, HEAD and OPTIONS.`,
    });
  }
  return out;
}

/**
 * Open-redirect check. For each redirect-looking query parameter on a URL, it
 * re-requests the URL with that parameter set to a benign non-resolving marker
 * and observes the Location header. The redirect is never followed.
 */
export async function checkOpenRedirect(urlStr, ctx) {
  let url; try { url = new URL(urlStr); } catch { return []; }
  const params = [...url.searchParams.keys()].filter((k) => REDIRECT_PARAMS.has(k.toLowerCase()));
  const out = [];
  for (const param of params) {
    if (!ctx.budget()) break;
    const token = newToken();
    const marker = `https://${REDIRECT_MARKER_HOST}/qt-${token}`;
    const probe = new URL(url);
    probe.searchParams.set(param, marker);
    const obs = await ctx.request(probe.toString(), { method: 'GET' });
    if (obs.error) continue;
    const loc = obs.headers?.location;
    if (obs.status >= 300 && obs.status < 400 && loc) {
      let dest; try { dest = new URL(loc, probe); } catch { dest = null; }
      if (dest && dest.hostname === REDIRECT_MARKER_HOST) {
        out.push({
          checkId: 'active.open-redirect', title: `Open redirect via "${param}" parameter`,
          severity: 'medium', confidence: 'firm', cwe: 'CWE-601', owasp: 'A01:2021 Broken Access Control',
          location: probe.toString(),
          evidence: { snippet: `Setting ${param} to a foreign host redirected there (Location: ${String(loc).slice(0, 200)}). The destination host was not followed.`, parameter: param },
          remediation: `Do not use user input as a redirect target. Redirect only to a fixed allow-list of paths, or validate that the destination is same-origin before issuing the redirect. The "${param}" parameter currently forwards to any host.`,
        });
      }
    }
  }
  return out;
}

/**
 * Reflected-input check. For each query parameter, re-requests the URL with
 * the value set to a unique benign alphanumeric canary and looks for the canary
 * echoed verbatim in an HTML response. The canary contains no HTML
 * metacharacters, so it cannot execute; a hit means the parameter is reflected
 * and should be reviewed for output encoding (the precondition for reflected
 * XSS), reported at low severity / tentative confidence.
 */
export async function checkReflectedInput(urlStr, ctx, { maxParams = 5 } = {}) {
  let url; try { url = new URL(urlStr); } catch { return []; }
  const keys = [...url.searchParams.keys()].slice(0, maxParams);
  const out = [];
  for (const param of keys) {
    if (!ctx.budget()) break;
    const canary = `qtref${newToken()}`;
    const probe = new URL(url);
    probe.searchParams.set(param, canary);
    const obs = await ctx.request(probe.toString(), { method: 'GET' });
    if (obs.error || !obs.body) continue;
    if (/html/i.test(obs.contentType) && obs.body.includes(canary)) {
      out.push({
        checkId: 'active.reflected-input', title: `Query parameter "${param}" is reflected in the HTML response`,
        severity: 'low', confidence: 'tentative', cwe: 'CWE-79', owasp: 'A03:2021 Injection',
        location: probe.toString(),
        evidence: { snippet: `A benign marker sent as ${param} appeared unchanged in the HTML body. This is reflection, not proof of XSS; review the output encoding for this parameter.`, parameter: param, marker: canary },
        remediation: `Confirm the value of "${param}" is contextually output-encoded (HTML-escaped in body text, attribute-encoded in attributes) or rejected. Reflected input that is not encoded is the precondition for reflected cross-site scripting. A Content-Security-Policy adds defense in depth.`,
      });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

/** De-duplicate target URLs by path + sorted query-parameter *names* (values vary, shape does not). */
export function dedupeTargets(urls) {
  const seen = new Map();
  for (const u of urls) {
    let parsed; try { parsed = new URL(u); } catch { continue; }
    const key = parsed.origin + parsed.pathname + '?' + [...parsed.searchParams.keys()].sort().join(',');
    if (!seen.has(key)) seen.set(key, parsed.toString());
  }
  return [...seen.values()];
}

/**
 * Run the active checks against a verified origin.
 *
 * @param {string} origin  scheme://host[:port], already verified by the caller
 * @param {object} opts
 * @param {string[]} [opts.targets]     URLs discovered by the crawl to probe (defaults to the origin root)
 * @param {string}   [opts.profile]     scan profile name (default 'passive' → runs nothing)
 * @param {Function} [opts.fetchImpl]   fetch replacement (tests)
 * @param {number}   [opts.maxRequests] hard cap on active requests (default 60)
 * @param {number}   [opts.maxTargets]  cap on distinct URLs probed (default 20)
 * @param {number}   [opts.delayMs]     pause between requests
 * @returns {Promise<{origin, profile, intrusivenessCap, requests, targetsProbed, findings}>}
 */
export async function runActiveScan(origin, opts = {}) {
  const profileName = opts.profile || DEFAULT_PROFILE;
  const profile = SCAN_PROFILES[profileName];
  if (!profile) throw new Error(`Unknown scan profile "${profileName}". Known: ${Object.keys(SCAN_PROFILES).join(', ')}.`);

  const base = { origin, profile: profileName, intrusivenessCap: profile.maxIntrusiveness, requests: 0, targetsProbed: 0, findings: [] };
  if (!profile.active) return base;

  const maxRequests = Number.isInteger(opts.maxRequests) ? opts.maxRequests : 60;
  const maxTargets = Number.isInteger(opts.maxTargets) ? opts.maxTargets : 20;
  const delayMs = Number.isFinite(opts.delayMs) ? opts.delayMs : 0;
  let requests = 0;

  const ctx = {
    budget: () => requests < maxRequests,
    request: async (url, reqOpts) => {
      requests++;
      const r = await sendProbe(url, { ...reqOpts, fetchImpl: opts.fetchImpl, timeoutMs: opts.timeoutMs });
      if (delayMs) await new Promise((res) => setTimeout(res, delayMs));
      return r;
    },
  };

  const findings = [];
  // Origin-scoped: one OPTIONS.
  if (ctx.budget()) findings.push(...await checkHttpMethods(origin, ctx));

  // URL-scoped checks, only on same-origin URLs that carry query parameters.
  const sameOrigin = (opts.targets || [origin + '/']).filter((u) => { try { return new URL(u).origin === new URL(origin).origin; } catch { return false; } });
  const withParams = dedupeTargets(sameOrigin).filter((u) => { try { return [...new URL(u).searchParams.keys()].length > 0; } catch { return false; } }).slice(0, maxTargets);
  let probed = 0;
  for (const u of withParams) {
    if (!ctx.budget()) break;
    probed++;
    findings.push(...await checkOpenRedirect(u, ctx));
    if (ctx.budget()) findings.push(...await checkReflectedInput(u, ctx));
  }

  return { ...base, requests, targetsProbed: probed, findings };
}

/** Order findings for display: severity desc, then confidence. Mirrors passive.sortFindings. */
export function sortActiveFindings(findings) {
  const sev = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  const conf = { confirmed: 3, firm: 2, tentative: 1 };
  return [...findings].sort((a, b) => (sev[b.severity] || 0) - (sev[a.severity] || 0) || (conf[b.confidence] || 0) - (conf[a.confidence] || 0));
}
