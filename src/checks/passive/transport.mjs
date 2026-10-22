/** Transport: HTTPS, HSTS, mixed content, TLS protocol and certificate. */
import { defineCheck } from '../registry.mjs';
import { parseOrigin } from '../../verify/origin.mjs';

const isHtml = (p) => p.kind === 'page' && p.status === 200 && p.dom;

defineCheck([
  {
    id: 'transport.https', title: 'Site served over plain HTTP', kind: 'passive', intrusiveness: 0,
    severity: 'medium', confidence: 'confirmed', cwe: [319, 311], owasp: 'A02', asvs: ['V9.1.1'],
    description: 'The target origin uses http://. Everything a visitor sends or receives — including cookies and form data — crosses the network unencrypted and can be read or altered in transit.',
    remediation: { summary: 'Serve the site over HTTPS with a valid certificate, redirect http:// to https:// with a 301, then add Strict-Transport-Security.', references: ['https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html'], fixId: 'fix.tls' },
    observe: (page, site) => {
      if (page.kind !== 'page' || page.depth !== 0 || !site.origin.startsWith('http:')) return [];
      const hasPasswordForm = site.pages.some((p) => p.dom?.forms.some((f) => f.inputs.some((i) => i.type === 'password')));
      return [{ url: site.origin + '/', key: 'origin', severity: hasPasswordForm ? 'high' : 'medium', description: hasPasswordForm ? 'The site is served over plain HTTP and contains a password form, so credentials are sent in cleartext.' : undefined, evidence: { detail: { origin: site.origin, passwordFormOverHttp: hasPasswordForm } } }];
    },
  },
  {
    id: 'transport.hsts', consolidate: true, title: 'Strict-Transport-Security missing or weak', kind: 'passive', intrusiveness: 0,
    severity: 'low', confidence: 'confirmed', cwe: [319, 693], owasp: 'A05', asvs: ['V9.1.3'],
    description: 'Without HSTS a browser will still make its first request to the site over HTTP (or follow an http:// link), where it can be intercepted and never upgraded. HSTS tells browsers to use HTTPS for the host for max-age seconds.',
    remediation: { summary: 'Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` (add `preload` once every subdomain is HTTPS). Serve it on every HTTPS response.', references: ['https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security', 'https://hstspreload.org/'], fixId: 'fix.headersMiddleware' },
    observe: (page, site) => {
      if (!site.origin.startsWith('https:') || page.kind !== 'page' || page.status < 200 || page.status >= 400) return [];
      const h = page.headers['strict-transport-security'];
      if (!h) return [{ url: page.finalUrl, key: 'missing', description: 'No Strict-Transport-Security header on an HTTPS response.', evidence: { headers: pick(page.headers, ['strict-transport-security', 'server']) } }];
      const m = /max-age\s*=\s*(\d+)/i.exec(h);
      const maxAge = m ? Number(m[1]) : 0;
      if (maxAge < 15_552_000) return [{ url: page.finalUrl, key: 'short', severity: maxAge === 0 ? 'low' : 'informational', description: `HSTS max-age is ${maxAge} seconds; at least 180 days (15552000) is recommended, one year for preloading.`, evidence: { headers: { 'strict-transport-security': h } } }];
      if (!/includesubdomains/i.test(h)) return [{ url: page.finalUrl, key: 'subdomains', severity: 'informational', description: 'HSTS is set without includeSubDomains; subdomains remain reachable over HTTP on first visit.', evidence: { headers: { 'strict-transport-security': h } } }];
      return [];
    },
  },
  {
    id: 'transport.mixedContent', title: 'Mixed content on an HTTPS page', kind: 'passive', intrusiveness: 0,
    severity: 'medium', confidence: 'confirmed', cwe: [319], owasp: 'A02', asvs: ['V9.1.1'],
    description: 'An HTTPS page loads a resource over plain HTTP. Scripts, styles and frames loaded this way can be replaced by anyone on the network path and run with the page\'s privileges (active mixed content); images and media leak what the visitor is viewing (passive mixed content).',
    remediation: { summary: 'Reference every resource with https:// or a scheme-relative/relative URL. Add `Content-Security-Policy: upgrade-insecure-requests` as a safety net and `block-all-mixed-content` once clean.', references: ['https://developer.mozilla.org/docs/Web/Security/Mixed_content'], fixId: 'fix.csp' },
    observe: (page, site) => {
      if (!site.origin.startsWith('https:') || !isHtml(page)) return [];
      const d = page.dom;
      const active = [...d.scripts.map((s) => s.url), ...d.styles.map((s) => s.url), ...d.frames].filter((u) => u && u.startsWith('http://'));
      const passive = d.images.filter((u) => u.startsWith('http://'));
      const out = [];
      if (active.length) out.push({ url: page.finalUrl, key: 'active', severity: 'high', description: `${active.length} active resource(s) (script/style/frame) loaded over HTTP.`, evidence: { detail: { resources: active.slice(0, 20) } } });
      if (passive.length) out.push({ url: page.finalUrl, key: 'passive', severity: 'low', description: `${passive.length} image/media resource(s) loaded over HTTP.`, evidence: { detail: { resources: passive.slice(0, 20) } } });
      return out;
    },
  },
  {
    id: 'transport.tls', title: 'TLS configuration or certificate problem', kind: 'passive', intrusiveness: 1, requests: 'one TLS handshake to the origin (no HTTP request)',
    severity: 'medium', confidence: 'confirmed', cwe: [326, 295], owasp: 'A02', asvs: ['V9.1.2', 'V9.1.3'],
    description: 'Inspects the TLS handshake: the negotiated protocol version, whether the certificate chain validates, whether it is self-signed, and how long it remains valid.',
    remediation: { summary: 'Allow only TLS 1.2 and 1.3; deploy a certificate from a trusted CA that covers the host name; automate renewal (ACME) so it never comes within two weeks of expiry.', references: ['https://ssl-config.mozilla.org/', 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html'], fixId: 'fix.tls' },
    probe: async (site) => {
      if (!site.origin.startsWith('https:') || !site.inspectTls) return [];
      const { host, port } = parseOrigin(site.origin);
      const t = await site.inspectTls(host, port);
      const out = [];
      const url = site.origin + '/';
      if (!t.ok) return [{ url, key: 'handshake', severity: 'informational', confidence: 'tentative', description: `TLS handshake could not be completed: ${t.error}.`, evidence: { detail: t } }];
      if (t.protocol && /^TLSv1(\.0|\.1)?$/.test(t.protocol)) out.push({ url, key: 'protocol', severity: 'medium', description: `The server negotiated ${t.protocol}; TLS 1.0 and 1.1 are deprecated (RFC 8996).`, evidence: { detail: { protocol: t.protocol, cipher: t.cipher } } });
      if (!t.authorized) out.push({ url, key: 'chain', severity: 'high', description: `The certificate does not validate: ${t.authorizationError}${t.cert?.selfSigned ? ' (self-signed)' : ''}. Browsers will warn visitors, and visitors who click through can be intercepted.`, evidence: { detail: { authorizationError: t.authorizationError, cert: t.cert } } });
      if (t.cert?.daysLeft !== null && t.cert?.daysLeft !== undefined) {
        if (t.cert.daysLeft < 0) out.push({ url, key: 'expired', severity: 'high', description: `The certificate expired ${-t.cert.daysLeft} day(s) ago (${t.cert.validTo}).`, evidence: { detail: t.cert } });
        else if (t.cert.daysLeft <= 14) out.push({ url, key: 'expiring', severity: 'low', description: `The certificate expires in ${t.cert.daysLeft} day(s) (${t.cert.validTo}).`, evidence: { detail: t.cert } });
      }
      return out;
    },
  },
]);

export function pick(headers, names) {
  const out = {};
  for (const n of names) if (headers[n] !== undefined) out[n] = headers[n];
  return out;
}
