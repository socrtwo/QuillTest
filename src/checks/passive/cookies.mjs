/** Cookie attributes. */
import { defineCheck } from '../registry.mjs';
import { looksLikeSession } from '../../crawl/cookies.mjs';
import { parseOrigin } from '../../verify/origin.mjs';

const REF = 'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies';

defineCheck([
  {
    id: 'cookies.secure', title: 'Cookie set without the Secure attribute', kind: 'passive', intrusiveness: 0,
    severity: 'medium', confidence: 'confirmed', cwe: [614], owasp: 'A05', asvs: ['V3.4.1'],
    description: 'A cookie without Secure is also sent over plain HTTP, where it can be read on the network. For a session cookie that is session hijacking.',
    remediation: { summary: 'Add `Secure` to every cookie (and serve the site over HTTPS only). Consider the `__Host-` prefix for session cookies.', references: [REF], fixId: 'fix.cookies' },
    observe: (page, site) => page.cookies.filter((c) => !c.secure).map((c) => ({ url: page.finalUrl, key: c.name, severity: looksLikeSession(c) ? (site.origin.startsWith('https:') ? 'high' : 'medium') : 'low', description: `Cookie "${c.name}"${looksLikeSession(c) ? ' (looks like a session cookie)' : ''} is set without Secure.`, evidence: { headers: { 'set-cookie': c.raw } } })),
  },
  {
    id: 'cookies.httpOnly', title: 'Cookie set without HttpOnly', kind: 'passive', intrusiveness: 0,
    severity: 'low', confidence: 'confirmed', cwe: [1004], owasp: 'A05', asvs: ['V3.4.2'],
    description: 'A cookie without HttpOnly can be read by JavaScript, so any cross-site scripting bug on the site can steal it.',
    remediation: { summary: 'Add `HttpOnly` to cookies that scripts do not need to read — always to session cookies.', references: [REF], fixId: 'fix.cookies' },
    observe: (page) => page.cookies.filter((c) => !c.httpOnly).map((c) => ({ url: page.finalUrl, key: c.name, severity: looksLikeSession(c) ? 'medium' : 'low', description: `Cookie "${c.name}"${looksLikeSession(c) ? ' (looks like a session cookie)' : ''} is readable by JavaScript.`, evidence: { headers: { 'set-cookie': c.raw } } })),
  },
  {
    id: 'cookies.sameSite', title: 'Cookie without a SameSite attribute, or SameSite=None without Secure', kind: 'passive', intrusiveness: 0,
    severity: 'low', confidence: 'confirmed', cwe: [1275, 352], owasp: 'A05', asvs: ['V3.4.3'],
    description: 'SameSite controls whether the cookie accompanies cross-site requests. Without it (or with None) the cookie is attached to requests initiated from other sites, which is what cross-site request forgery relies on.',
    remediation: { summary: 'Set `SameSite=Lax` (or Strict) on session cookies. If a cookie must be cross-site (`SameSite=None`), it must also be `Secure`.', references: [REF], fixId: 'fix.cookies' },
    observe: (page) => page.cookies.flatMap((c) => {
      if (!c.sameSite) return [{ url: page.finalUrl, key: c.name, severity: looksLikeSession(c) ? 'low' : 'informational', description: `Cookie "${c.name}" has no SameSite attribute (browsers default to Lax, but explicit is portable).`, evidence: { headers: { 'set-cookie': c.raw } } }];
      if (c.sameSite === 'None' && !c.secure) return [{ url: page.finalUrl, key: c.name + ':none', severity: 'medium', description: `Cookie "${c.name}" is SameSite=None without Secure; browsers reject it, and where accepted it is sent cross-site in the clear.`, evidence: { headers: { 'set-cookie': c.raw } } }];
      return [];
    }),
  },
  {
    id: 'cookies.scope', title: 'Cookie scoped more broadly than the host', kind: 'passive', intrusiveness: 0,
    severity: 'low', confidence: 'firm', cwe: [16], owasp: 'A05', asvs: ['V3.4.4', 'V3.4.5'],
    description: 'A Domain attribute set to a parent domain sends the cookie to every subdomain, so a weaker sibling site (or a subdomain takeover) can read or overwrite it.',
    remediation: { summary: 'Omit the Domain attribute so the cookie is host-only, and set Path to the narrowest prefix that works. Use the `__Host-` prefix to enforce both.', references: [REF], fixId: 'fix.cookies' },
    observe: (page, site) => {
      const host = parseOrigin(site.origin).host;
      return page.cookies.filter((c) => c.domain && c.domain !== host && host.endsWith('.' + c.domain)).map((c) => ({ url: page.finalUrl, key: c.name, severity: looksLikeSession(c) ? 'low' : 'informational', description: `Cookie "${c.name}" is scoped to Domain=${c.domain}, which includes every subdomain of it.`, evidence: { headers: { 'set-cookie': c.raw } } }));
    },
  },
]);
