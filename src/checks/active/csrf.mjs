/*
 * QuillTest — anti-CSRF token presence (active category, read-only form inspection)
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Reads the forms the crawl observed; sends nothing. A state-changing form
 * (POST, or a form with a password/sensitive field) with no apparent anti-CSRF
 * token and no SameSite protection on the session cookie is flagged for review.
 * Confidence is tentative: a site may carry the token in a header the crawl
 * cannot see, which is why this reports a candidate rather than asserting a bug.
 */
import { defineCheck } from '../registry.mjs';
import { looksLikeSession } from '../../crawl/cookies.mjs';

const TOKEN_FIELD = /csrf|xsrf|_token|authenticity_token|nonce|__requestverificationtoken|anti.?forgery|form.?key|verify.?token/i;
const STATE_CHANGING_PATH = /(login|logout|signin|signout|register|signup|password|account|profile|settings|delete|remove|create|update|edit|add|transfer|pay|checkout|order|subscribe|admin|upload|import|comment|post|submit)/i;

defineCheck({
  id: 'csrf.formToken', title: 'State-changing form without an anti-CSRF token', kind: 'active', intrusiveness: 1,
  requests: 'none — reads the forms already seen during the crawl',
  severity: 'medium', confidence: 'tentative', cwe: [352], owasp: 'A01', asvs: ['V4.2.2'],
  description: 'A form that changes server state has no visible anti-CSRF token field, and the session cookie is not SameSite Lax/Strict. Another site could then submit the form on a logged-in visitor\'s behalf. Reported for review because a token may travel in a header the scan cannot observe.',
  remediation: { summary: 'Add a per-session (or per-request) anti-CSRF token to every state-changing form and verify it server-side; set SameSite=Lax or Strict on the session cookie as defence in depth.', references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'], fixId: 'fix.cookies' },
  finalize: (site) => {
    const sessionProtected = site.pages.some((p) => p.cookies?.some((c) => looksLikeSession(c) && c.sameSite && c.sameSite !== 'None'));
    if (sessionProtected) return [];
    const out = [];
    const seen = new Set();
    for (const page of site.pages) {
      for (const form of page.dom?.forms || []) {
        const method = (form.method || 'get').toLowerCase();
        const hasPassword = form.inputs.some((i) => i.type === 'password');
        const stateChanging = method === 'post' || hasPassword || (form.action && STATE_CHANGING_PATH.test(form.action));
        if (!stateChanging) continue;
        const hasToken = form.inputs.some((i) => i.type === 'hidden' && TOKEN_FIELD.test(i.name || '')) || form.inputs.some((i) => TOKEN_FIELD.test(i.name || ''));
        if (hasToken) continue;
        const action = form.action || page.finalUrl;
        if (seen.has(action)) continue;
        seen.add(action);
        out.push({ url: page.finalUrl, key: action, description: `A ${method.toUpperCase()} form posting to ${action} has no visible anti-CSRF token field.`, evidence: { detail: { action, method, fields: form.inputs.map((i) => i.name || i.type) } } });
      }
    }
    return out;
  },
});
