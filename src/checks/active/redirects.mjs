/*
 * QuillTest — open redirect detection (active, detection-only)
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Detection method: for a parameter that looks like it carries a destination,
 * supply a benign absolute URL on a host QuillTest controls the name of (a
 * .invalid host that resolves nowhere) and observe whether the server answers
 * with a 3xx whose Location points off-origin to that host, or emits a
 * meta-refresh to it. It confirms the redirect is attacker-controllable; it
 * does not follow the redirect and sends no payload.
 */
import { defineCheck } from '../registry.mjs';

const PROBE_HOST = 'quilltest-openredirect-probe.invalid';
const PROBE_URL = `https://${PROBE_HOST}/qt`;
const HINT = /^(url|uri|link|next|dest|destination|redirect|redir|return|returnurl|return_to|returnto|continue|goto|go|target|to|out|r|u|forward|callback|redirect_uri|redirect_url|image_url|file)$/i;

function locatesProbe(res) {
  const loc = res.headers?.location;
  if (loc) { try { if (new URL(String(loc), res.finalUrl || res.url).hostname === PROBE_HOST) return { via: 'Location', value: String(loc) }; } catch { /* ignore */ } }
  if (res.dom?.metaRefresh) { try { if (new URL(res.dom.metaRefresh).hostname === PROBE_HOST) return { via: 'meta refresh', value: res.dom.metaRefresh }; } catch { /* ignore */ } }
  return null;
}

defineCheck({
  id: 'redirects.open', title: 'Open redirect', kind: 'active', intrusiveness: 2,
  requests: 'one request per redirect-like parameter, carrying a benign off-origin marker URL; the redirect is observed, never followed',
  severity: 'medium', confidence: 'firm', cwe: [601], owasp: 'A01', asvs: ['V5.1.5'],
  description: 'A parameter sets the destination of a redirect without validating it, so a link to this site can bounce a visitor to an attacker-chosen site — used for phishing and to slip past URL allowlists.',
  remediation: { summary: 'Do not redirect to a location taken from the request. Redirect to a fixed path, or map an opaque key to an allow-listed URL; if an absolute URL must be accepted, verify its host against an allowlist.', references: ['https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html'], fixId: 'fix.redirects' },
  active: async (site) => {
    const points = site.points.filter((p) => p.where === 'query' && (HINT.test(p.name) || /^https?:\/\//i.test(p.original) || p.original.startsWith('/'))).slice(0, site.maxPointsPerCheck);
    const out = [];
    for (const point of points) {
      const res = site.send(point, PROBE_URL);
      if (!res) break;
      const awaited = await res;
      if (!awaited || awaited.status === 0) continue;
      const hit = locatesProbe(awaited);
      if (hit) out.push({ url: point.url, key: point.name, description: `The "${point.name}" parameter controls a redirect destination (${hit.via} → ${PROBE_HOST}).`, evidence: { request: { url: point.action, param: point.name }, detail: { status: awaited.status, via: hit.via, location: hit.value } } });
    }
    return out;
  },
});
