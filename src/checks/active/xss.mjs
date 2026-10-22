/*
 * QuillTest — reflected cross-site scripting (active, detection-only via a safe canary)
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Detection method: send a unique, non-executing canary — a random token
 * followed by the four HTML metacharacters ' " < > — and look for the token in
 * the response. If the metacharacters come back unencoded next to the token,
 * the parameter's value is reflected without output encoding, which is the
 * precondition for reflected XSS. QuillTest reports that precondition and the
 * context it saw; it never sends a <script>, an event handler, or any markup
 * that would execute, and it does not try to run anything.
 */
import { randomBytes } from 'node:crypto';
import { defineCheck } from '../registry.mjs';

const METACHARS = ["'", '"', '<', '>'];

function reflectionContext(body, index) {
  const before = body.slice(Math.max(0, index - 600), index);
  const lastOpen = before.lastIndexOf('<');
  const lastClose = before.lastIndexOf('>');
  if (/<script\b[^>]*>[^]*$/i.test(before) && !/<\/script>/i.test(before.slice(before.search(/<script\b/i)))) return 'script';
  if (lastOpen > lastClose) return 'tag';                       // inside a tag's attributes
  return 'html';                                                // element text content
}

defineCheck({
  id: 'xss.reflected', title: 'Reflected input without output encoding (reflected XSS)', kind: 'active', intrusiveness: 2,
  requests: 'one request per parameter carrying a unique non-executing canary token plus the characters \' " < >; the response is inspected for unencoded reflection',
  severity: 'high', confidence: 'firm', cwe: [79], owasp: 'A03', asvs: ['V5.3.3'],
  description: 'A parameter\'s value is written into the response without HTML output encoding: a unique marker came back with its \', ", < and > characters intact, in a context where that lets an attacker inject active content. Detected with a safe canary, not a working payload.',
  remediation: { summary: 'Output-encode untrusted data for the context it lands in (HTML body, attribute, JavaScript, URL), using the framework\'s contextual escaping; add a Content-Security-Policy as defence in depth. Prefer templating that auto-escapes by default.', references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html'], fixId: 'fix.csp' },
  active: async (site) => {
    const points = site.points.slice(0, site.maxPointsPerCheck);
    const out = [];
    for (const point of points) {
      const token = 'qt' + randomBytes(5).toString('hex');
      const canary = `${token}${METACHARS.join('')}`;          // e.g. qtab12cd34'"<>
      const res = site.send(point, canary);
      if (!res) break;
      const awaited = await res;
      if (!awaited || !awaited.body || !/text\/html|application\/xhtml/.test(awaited.contentType || 'text/html')) continue;
      const at = awaited.body.indexOf(token);
      if (at < 0) continue;
      const after = awaited.body.slice(at + token.length, at + token.length + 8);
      const unencoded = METACHARS.filter((ch) => after.includes(ch));
      if (!unencoded.length) continue;                          // reflected but encoded → safe
      const context = reflectionContext(awaited.body, at);
      const dangerous = (context === 'html' && unencoded.includes('<')) || (context === 'tag' && (unencoded.includes('"') || unencoded.includes("'"))) || context === 'script';
      out.push({
        url: point.url, key: `${point.name}`,
        severity: dangerous ? 'high' : 'medium',
        confidence: dangerous ? 'firm' : 'tentative',
        description: `The "${point.name}" parameter is reflected in the response with ${unencoded.map((c) => `"${c}"`).join(' ')} unencoded, in ${context} context.`,
        evidence: { request: { url: point.action, param: point.name }, detail: { context, unencoded, where: point.where }, snippet: awaited.body.slice(Math.max(0, at - 40), at + token.length + 20) },
      });
    }
    return out;
  },
});
