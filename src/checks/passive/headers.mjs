/** Security headers on HTML responses. */
import { defineCheck } from '../registry.mjs';

const htmlOk = (p) => p.kind === 'page' && p.status >= 200 && p.status < 400 && /text\/html|application\/xhtml/.test(p.contentType);
const REFS = { csp: 'https://developer.mozilla.org/docs/Web/HTTP/CSP', headers: 'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html' };

/** Parse a CSP header into a directive map. */
export function parseCsp(value) {
  const map = {};
  for (const part of String(value).split(';')) {
    const toks = part.trim().split(/\s+/).filter(Boolean);
    if (!toks.length) continue;
    const name = toks[0].toLowerCase();
    if (!(name in map)) map[name] = toks.slice(1).map((t) => t.toLowerCase());
  }
  return map;
}

export function cspWeaknesses(csp) {
  const issues = [];
  const script = csp['script-src'] || csp['default-src'];
  if (!script) issues.push({ key: 'noScriptSrc', text: 'neither script-src nor default-src is set, so scripts from any origin are allowed' });
  else {
    if (script.includes("'unsafe-inline'") && !script.some((s) => s.startsWith("'nonce-") || s.startsWith("'sha"))) issues.push({ key: 'unsafeInline', text: "'unsafe-inline' in script-src defeats CSP's XSS protection" });
    if (script.includes("'unsafe-eval'")) issues.push({ key: 'unsafeEval', text: "'unsafe-eval' allows eval()/Function() of attacker-controlled strings" });
    if (script.includes('*') || script.some((s) => /^https?:$/.test(s))) issues.push({ key: 'wildcard', text: 'script-src allows any https: (or *) origin' });
    if (script.includes('data:')) issues.push({ key: 'dataScript', text: 'data: URIs are allowed as script sources' });
  }
  if (!csp['object-src'] && !(csp['default-src'] || []).includes("'none'")) issues.push({ key: 'objectSrc', text: "object-src is not restricted (set object-src 'none')" });
  if (!csp['base-uri']) issues.push({ key: 'baseUri', text: "base-uri is not set (set base-uri 'self' or 'none')" });
  return issues;
}

export function pickHeaders(h) {
  const names = ['content-security-policy', 'content-security-policy-report-only', 'x-content-type-options', 'x-frame-options', 'referrer-policy', 'permissions-policy', 'strict-transport-security', 'cross-origin-opener-policy', 'cross-origin-embedder-policy', 'cross-origin-resource-policy', 'server', 'x-powered-by', 'content-type'];
  const out = {};
  for (const n of names) if (h[n] !== undefined) out[n] = h[n];
  return out;
}

defineCheck([
  {
    id: 'headers.csp', consolidate: true, title: 'Content-Security-Policy missing or weak', kind: 'passive', intrusiveness: 0,
    severity: 'medium', confidence: 'confirmed', cwe: [693, 16], owasp: 'A05', asvs: ['V14.4.3'],
    description: 'A Content-Security-Policy restricts where scripts, styles, frames and other resources may load from, which contains the damage of a cross-site scripting bug. Missing, report-only, or permissive policies leave that defence off.',
    remediation: { summary: "Start with `Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'`, tune it from the resources the crawl observed, then enforce it. Prefer nonces/hashes over 'unsafe-inline'.", references: [REFS.csp, 'https://csp-evaluator.withgoogle.com/'], fixId: 'fix.csp' },
    observe: (page) => {
      if (!htmlOk(page)) return [];
      const h = page.headers['content-security-policy'];
      const ro = page.headers['content-security-policy-report-only'];
      const meta = page.dom?.meta?.['content-security-policy'];
      const value = h || meta;
      if (!value) {
        if (ro) return [{ url: page.finalUrl, key: 'reportOnly', severity: 'low', description: 'Only a Content-Security-Policy-Report-Only header is present; it reports violations but blocks nothing.', evidence: { headers: { 'content-security-policy-report-only': ro } } }];
        return [{ url: page.finalUrl, key: 'missing', description: 'No Content-Security-Policy header (or meta tag) on this HTML response.', evidence: { headers: pickHeaders(page.headers) } }];
      }
      const issues = cspWeaknesses(parseCsp(value));
      if (!issues.length) return [];
      return [{ url: page.finalUrl, key: 'weak', severity: issues.some((i) => ['unsafeInline', 'noScriptSrc', 'wildcard'].includes(i.key)) ? 'medium' : 'low', description: 'The Content-Security-Policy is present but weak: ' + issues.map((i) => i.text).join('; ') + '.', evidence: { headers: { 'content-security-policy': value }, detail: { issues: issues.map((i) => i.key), source: h ? 'header' : 'meta' } } }];
    },
  },
  {
    id: 'headers.contentTypeOptions', consolidate: true, title: 'X-Content-Type-Options: nosniff missing', kind: 'passive', intrusiveness: 0,
    severity: 'low', confidence: 'confirmed', cwe: [16, 693], owasp: 'A05', asvs: ['V14.4.4'],
    description: 'Without nosniff, browsers may MIME-sniff responses and execute, for example, a user-uploaded file as script or style.',
    remediation: { summary: 'Send `X-Content-Type-Options: nosniff` on every response and set accurate Content-Type headers.', references: [REFS.headers], fixId: 'fix.headersMiddleware' },
    observe: (page) => (page.kind !== 'probe' && page.status >= 200 && page.status < 400 && String(page.headers['x-content-type-options'] || '').toLowerCase() !== 'nosniff' ? [{ url: page.finalUrl, key: page.kind, evidence: { headers: pickHeaders(page.headers) } }] : []),
  },
  {
    id: 'headers.frameOptions', consolidate: true, title: 'Clickjacking protection missing (no X-Frame-Options or frame-ancestors)', kind: 'passive', intrusiveness: 0,
    severity: 'medium', confidence: 'confirmed', cwe: [1021], owasp: 'A05', asvs: ['V14.4.7'],
    description: 'The page can be embedded in a frame on any other site, enabling clickjacking: an attacker overlays the framed page with decoys so visitors click controls they cannot see.',
    remediation: { summary: "Send `Content-Security-Policy: frame-ancestors 'self'` (or 'none') and, for older browsers, `X-Frame-Options: SAMEORIGIN`.", references: ['https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html'], fixId: 'fix.headersMiddleware' },
    observe: (page) => {
      if (!htmlOk(page)) return [];
      const xfo = String(page.headers['x-frame-options'] || '').toUpperCase();
      const csp = parseCsp(page.headers['content-security-policy'] || '');
      if (csp['frame-ancestors'] || /^(DENY|SAMEORIGIN)$/.test(xfo)) return [];
      return [{ url: page.finalUrl, key: 'missing', description: xfo ? `X-Frame-Options has the unsupported value "${xfo}" and CSP has no frame-ancestors directive.` : undefined, evidence: { headers: pickHeaders(page.headers) } }];
    },
  },
  {
    id: 'headers.referrerPolicy', consolidate: true, title: 'Referrer-Policy missing or leaky', kind: 'passive', intrusiveness: 0,
    severity: 'low', confidence: 'confirmed', cwe: [200], owasp: 'A05', asvs: ['V14.4.6'],
    description: 'Without a Referrer-Policy, browsers may send the full URL of this page — including query strings and path segments that can carry tokens or personal data — to every third-party site a visitor navigates to.',
    remediation: { summary: 'Send `Referrer-Policy: strict-origin-when-cross-origin` (or `no-referrer`).', references: ['https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy'], fixId: 'fix.headersMiddleware' },
    observe: (page) => {
      if (!htmlOk(page)) return [];
      const v = String(page.headers['referrer-policy'] || page.dom?.meta?.referrer || '').toLowerCase();
      if (!v) return [{ url: page.finalUrl, key: 'missing', evidence: { headers: pickHeaders(page.headers) } }];
      if (/\b(unsafe-url|no-referrer-when-downgrade|origin-when-cross-origin)\b/.test(v) && !/\b(strict-origin-when-cross-origin|no-referrer|same-origin|strict-origin)\b/.test(v)) return [{ url: page.finalUrl, key: 'leaky', severity: 'informational', description: `Referrer-Policy "${v}" sends the full URL to other origins.`, evidence: { headers: { 'referrer-policy': v } } }];
      return [];
    },
  },
  {
    id: 'headers.permissionsPolicy', consolidate: true, title: 'Permissions-Policy not set', kind: 'passive', intrusiveness: 0,
    severity: 'informational', confidence: 'confirmed', cwe: [16], owasp: 'A05', asvs: ['V14.4'],
    description: 'Permissions-Policy lets a site switch off browser features it does not use (camera, microphone, geolocation, payment, …) so an injected script or a framed third party cannot request them.',
    remediation: { summary: 'Send `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()` adjusted to the features the site actually uses.', references: ['https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy'], fixId: 'fix.headersMiddleware' },
    observe: (page) => (htmlOk(page) && !page.headers['permissions-policy'] ? [{ url: page.finalUrl, key: 'missing' }] : []),
  },
  {
    id: 'headers.crossOriginIsolation', consolidate: true, title: 'Cross-origin isolation headers not set (COOP / CORP)', kind: 'passive', intrusiveness: 0,
    severity: 'informational', confidence: 'confirmed', cwe: [16], owasp: 'A05', asvs: ['V14.4'],
    description: 'Cross-Origin-Opener-Policy and Cross-Origin-Resource-Policy isolate the page from other origins\' windows and resources, blunting side-channel (Spectre-class) and cross-site leak attacks.',
    remediation: { summary: 'Where compatible, send `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Resource-Policy: same-origin` (or same-site); add COEP once embedded resources support it.', references: ['https://web.dev/articles/coop-coep'], fixId: 'fix.headersMiddleware' },
    observe: (page) => {
      if (!htmlOk(page)) return [];
      const missing = ['cross-origin-opener-policy', 'cross-origin-resource-policy'].filter((h) => !page.headers[h]);
      return missing.length ? [{ url: page.finalUrl, key: missing.join('+'), description: `Missing: ${missing.join(', ')}.` }] : [];
    },
  },
  {
    id: 'headers.cacheControlSensitive', title: 'Response that sets a cookie is cacheable', kind: 'passive', intrusiveness: 0,
    severity: 'low', confidence: 'firm', cwe: [525], owasp: 'A05', asvs: ['V8.1.1'],
    description: 'A response that sets a cookie (so it is personalised) carries no Cache-Control preventing shared caches or the browser from storing it, so another user of the same machine or proxy may see it.',
    remediation: { summary: 'Send `Cache-Control: no-store` on authenticated/personalised responses.', references: ['https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html'], fixId: 'fix.headersMiddleware' },
    observe: (page) => {
      if (!htmlOk(page) || !page.cookies.length) return [];
      const cc = String(page.headers['cache-control'] || '').toLowerCase();
      if (/no-store|private/.test(cc)) return [];
      return [{ url: page.finalUrl, key: 'cacheable', evidence: { headers: { 'cache-control': cc || '(absent)', 'set-cookie': page.headers['set-cookie'] } } }];
    },
  },
]);
