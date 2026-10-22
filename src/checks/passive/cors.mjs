/** CORS misconfiguration — benign GETs of the start page with an Origin header. */
import { defineCheck } from '../registry.mjs';

export const PROBE_ORIGIN = 'https://quilltest-cors-probe.invalid';

defineCheck([
  {
    id: 'cors.permissive', title: 'CORS policy trusts arbitrary origins', kind: 'passive', intrusiveness: 1, requests: 'two GETs of the start page (and up to two JSON/XML pages) with Origin headers: a .invalid origin, and "null"',
    severity: 'medium', confidence: 'confirmed', cwe: [942], owasp: 'A05', asvs: ['V14.5.3'],
    description: 'The server reflects the request\'s Origin (or sends a wildcard) in Access-Control-Allow-Origin. Any website can then read responses from this origin in a visitor\'s browser; with Access-Control-Allow-Credentials: true it can read them as the logged-in visitor.',
    remediation: { summary: 'Allow-list the exact origins that need cross-origin access; never echo the request Origin unchecked; never combine a wildcard or reflected origin with Allow-Credentials: true; do not trust the "null" origin.', references: ['https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing'], fixId: 'fix.cors' },
    probe: async (site) => {
      const out = [];
      const targets = [site.origin + '/', ...site.pages.filter((p) => p.kind === 'page' && p.status === 200 && /json|xml/.test(p.contentType)).map((p) => p.finalUrl)].slice(0, 3);
      for (const url of targets) {
        for (const origin of [PROBE_ORIGIN, 'null']) {
          const res = await site.request(url, { kind: 'probe', headers: { origin } });
          if (!res || res.status === 0) continue;
          const acao = String(res.headers['access-control-allow-origin'] || '');
          const acac = String(res.headers['access-control-allow-credentials'] || '').toLowerCase() === 'true';
          if (!acao) continue;
          const headers = { 'access-control-allow-origin': acao, ...(res.headers['access-control-allow-credentials'] ? { 'access-control-allow-credentials': res.headers['access-control-allow-credentials'] } : {}) };
          if (acao === origin && origin === 'null') out.push({ url, key: 'null', severity: acac ? 'high' : 'medium', description: `The "null" origin is accepted${acac ? ' with credentials' : ''}; sandboxed iframes and some redirects produce it.`, evidence: { headers, request: { url, headers: { origin } } } });
          else if (acao === origin) out.push({ url, key: 'reflected', severity: acac ? 'high' : 'medium', description: `The request Origin (${origin}) was reflected in Access-Control-Allow-Origin${acac ? ' together with Allow-Credentials: true' : ''}.`, evidence: { headers, request: { url, headers: { origin } } } });
          else if (acao === '*' && acac && origin === PROBE_ORIGIN) out.push({ url, key: 'wildcardCredentials', severity: 'medium', description: 'Access-Control-Allow-Origin: * combined with Allow-Credentials: true (browsers refuse this combination, which suggests a misconfigured policy).', evidence: { headers } });
          else if (acao === '*' && origin === PROBE_ORIGIN) out.push({ url, key: 'wildcard', severity: 'informational', description: 'Access-Control-Allow-Origin: * — fine for public, non-personalised data; review if this endpoint ever returns user-specific content.', evidence: { headers } });
        }
      }
      return out;
    },
  },
]);
