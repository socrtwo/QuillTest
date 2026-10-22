/*
 * QuillTest — request-smuggling-adjacent header and method checks (active, detection-only)
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 *   injection.hostHeader: send a benign marker in forwarding headers
 *     (X-Forwarded-Host and friends) and report when the server reflects it
 *     into an absolute URL or a redirect. The marker host is a .invalid name
 *     that resolves nowhere; nothing is poisoned, cached, or followed.
 *   methods.enabled: ask the server with OPTIONS which methods it advertises
 *     and flag TRACE (cross-site tracing) and the write methods. QuillTest
 *     never sends TRACE, PUT, DELETE or any state-changing method — it reports
 *     what the Allow header advertises, for you to confirm are authenticated.
 */
import { defineCheck } from '../registry.mjs';

const HOST_PROBE = 'quilltest-hosthdr-probe.invalid';
const FWD_HEADERS = { 'x-forwarded-host': HOST_PROBE, 'x-host': HOST_PROBE, 'x-forwarded-server': HOST_PROBE, forwarded: `host=${HOST_PROBE}` };

function reflectsHost(res) {
  const loc = res.headers?.location;
  if (loc && String(loc).includes(HOST_PROBE)) return { via: 'Location header', value: String(loc) };
  const body = res.body || '';
  // Only an absolute reference to the probe host matters (a bare mention in text is harmless).
  const m = new RegExp(`(?:https?:)?//${HOST_PROBE.replace(/\\./g, '\\\\.')}[\\\\w/?#:-]*`).exec(body);
  if (m) return { via: 'absolute URL in the body', value: m[0] };
  return null;
}

defineCheck([
  {
    id: 'injection.hostHeader', title: 'Host / forwarding header reflected into the response', kind: 'active', intrusiveness: 2,
    requests: 'one request per sampled page carrying benign X-Forwarded-Host / X-Host / Forwarded headers pointing at a .invalid host; the response is inspected for reflection',
    severity: 'medium', confidence: 'firm', cwe: [644, 601], owasp: 'A03', asvs: ['V5.1.1'],
    description: 'The server builds an absolute URL (a link, a canonical tag, a redirect, or a password-reset link) from a client-supplied Host or X-Forwarded-Host header without validation. An attacker can set that header to their own host — the basis of host-header poisoning, cache poisoning and reset-link hijacking.',
    remediation: { summary: 'Build absolute URLs from a configured canonical host, not from the request Host / X-Forwarded-* headers; validate the Host against an allowlist of expected names and reject anything else at the edge.', references: ['https://portswigger.net/web-security/host-header'], fixId: 'fix.headersMiddleware' },
    active: async (site) => {
      const urls = [site.origin + '/', ...site.pages.filter((p) => p.kind === 'page' && p.status === 200).map((p) => p.finalUrl)].filter((v, i, a) => a.indexOf(v) === i).slice(0, Math.min(8, site.maxPointsPerCheck));
      const out = [];
      for (const url of urls) {
        const res = site.sendUrl(url, { headers: FWD_HEADERS });
        if (!res) break;
        const awaited = await res;
        if (!awaited || awaited.status === 0) continue;
        const hit = reflectsHost(awaited);
        if (hit) { out.push({ url, key: 'forwarded-host', description: `A forwarding header value was reflected into ${hit.via}.`, evidence: { request: { url, headers: Object.keys(FWD_HEADERS) }, detail: { via: hit.via, reflected: hit.value, status: awaited.status } } }); break; }
      }
      return out;
    },
  },
  {
    id: 'methods.enabled', title: 'Unsafe HTTP methods advertised', kind: 'active', intrusiveness: 2,
    requests: 'one OPTIONS request to the origin root and a sample page; the Allow header is read. QuillTest never sends TRACE or any write method.',
    severity: 'low', confidence: 'tentative', cwe: [650, 16], owasp: 'A05', asvs: ['V14.4.1'],
    description: 'An OPTIONS request shows the server advertising methods beyond the safe set. TRACE enables cross-site tracing (reading headers a browser would not otherwise expose); PUT, DELETE and PATCH are state-changing and must be authenticated and intended. QuillTest only reads what Allow advertises; it does not invoke these methods.',
    remediation: { summary: 'Disable TRACE/TRACK at the web server; allow only the methods each endpoint needs; ensure PUT/DELETE/PATCH require authentication and authorization, or remove them where unused.', references: ['https://owasp.org/www-community/attacks/Cross_Site_Tracing', 'https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html'] },
    active: async (site) => {
      const urls = [site.origin + '/', ...site.pages.filter((p) => p.kind === 'page' && p.status === 200).map((p) => p.finalUrl)].filter((v, i, a) => a.indexOf(v) === i).slice(0, 3);
      const out = [];
      const seen = new Set();
      for (const url of urls) {
        const res = site.sendUrl(url, { method: 'OPTIONS' });
        if (!res) break;
        const awaited = await res;
        if (!awaited || awaited.status === 0) continue;
        const allow = String(awaited.headers?.allow || awaited.headers?.['access-control-allow-methods'] || '').toUpperCase();
        if (!allow) continue;
        const methods = allow.split(',').map((m) => m.trim()).filter(Boolean);
        const risky = methods.filter((m) => ['TRACE', 'TRACK', 'PUT', 'DELETE', 'PATCH', 'CONNECT'].includes(m));
        for (const m of risky) {
          if (seen.has(m)) continue;
          seen.add(m);
          const xst = m === 'TRACE' || m === 'TRACK';
          out.push({ url, key: m, severity: xst ? 'medium' : 'low', description: `The server advertises the ${m} method in Allow${xst ? ' (cross-site tracing / XST risk)' : ' (a write method — confirm it is authenticated and intended)'}.`, evidence: { request: { url, method: 'OPTIONS' }, detail: { allow, method: m } } });
        }
      }
      return out;
    },
  },
]);
