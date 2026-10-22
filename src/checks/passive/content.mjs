/** Page content: forms over HTTP, autocomplete on sensitive fields, external scripts without SRI. */
import { defineCheck } from '../registry.mjs';

const SENSITIVE_FIELD = /(card|cc[-_]?(num|number|csc|cvv|cvc)|cvv|cvc|security[-_]?code|ssn|social[-_]?security|passport|iban|routing|account[-_]?number|secret|otp|one[-_]?time)/i;
const sameOrigin = (u, origin) => { try { return new URL(u).origin.toLowerCase() === origin; } catch { return false; } };

defineCheck([
  {
    id: 'content.formsOverHttp', title: 'Form submits to a plain-HTTP URL', kind: 'passive', intrusiveness: 0,
    severity: 'high', confidence: 'confirmed', cwe: [319, 523], owasp: 'A02', asvs: ['V9.1.1'],
    description: 'A form posts its fields to an http:// URL (or a password form is served over HTTP). Whatever the visitor types — passwords, card numbers — is sent in cleartext.',
    remediation: { summary: 'Point every form action at an https:// URL (relative actions inherit the page scheme) and serve pages with forms over HTTPS only.', references: ['https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html'], fixId: 'fix.tls' },
    observe: (page, site) => {
      if (!page.dom) return [];
      const out = [];
      page.dom.forms.forEach((f, i) => {
        const hasPassword = f.inputs.some((x) => x.type === 'password');
        if (f.action && f.action.startsWith('http://') && site.origin.startsWith('https:')) out.push({ url: page.finalUrl, key: `action:${f.action}`, severity: hasPassword ? 'high' : 'medium', description: `Form #${i + 1} on an HTTPS page submits to ${f.action}.`, evidence: { detail: { action: f.action, method: f.method, fields: f.inputs.map((x) => x.name || x.type) } } });
        else if (hasPassword && (site.origin.startsWith('http:') || (f.action && f.action.startsWith('http://')))) out.push({ url: page.finalUrl, key: `password:${i}`, severity: 'high', description: `Form #${i + 1} contains a password field and is ${site.origin.startsWith('http:') ? 'served' : 'submitted'} over plain HTTP.`, evidence: { detail: { action: f.action, method: f.method } } });
      });
      return out;
    },
  },
  {
    id: 'content.autocompleteSensitive', title: 'Sensitive form field allows browser autocomplete', kind: 'passive', intrusiveness: 0,
    severity: 'low', confidence: 'firm', cwe: [359, 525], owasp: 'A04', asvs: ['V8.2.1'],
    description: 'A field that looks like it takes a card security code, social-security number, one-time code or similar secret does not set autocomplete="off", so browsers may store and later suggest the value on a shared device.',
    remediation: { summary: 'Add `autocomplete="off"` (or the specific token, e.g. `autocomplete="one-time-code"`) to fields holding card security codes, government identifiers and one-time secrets. Do not disable autocomplete on password fields; password managers need it.', references: ['https://developer.mozilla.org/docs/Web/HTML/Attributes/autocomplete'] },
    observe: (page) => {
      if (!page.dom) return [];
      const out = [];
      for (const f of page.dom.forms) {
        if ((f.autocomplete || '').toLowerCase() === 'off') continue;
        for (const x of f.inputs) {
          if (x.type === 'password' || x.type === 'hidden' || x.type === 'submit') continue;
          if (SENSITIVE_FIELD.test(x.name) && (x.autocomplete || '').toLowerCase() !== 'off' && !/one-time-code|cc-csc/.test(x.autocomplete || '')) out.push({ url: page.finalUrl, key: x.name, description: `Field "${x.name}" (type ${x.type}) looks sensitive and allows autocomplete.`, evidence: { detail: { field: x } } });
        }
      }
      return out;
    },
  },
  {
    id: 'content.subresourceIntegrity', title: 'Third-party script or stylesheet without Subresource Integrity', kind: 'passive', intrusiveness: 0,
    severity: 'low', confidence: 'confirmed', cwe: [353, 345], owasp: 'A08', asvs: ['V14.2.3'],
    description: 'A script or stylesheet is loaded from another origin without an integrity attribute. If that origin (a CDN, an analytics vendor) is compromised or its content changes, the altered file runs on this site with full page privileges.',
    remediation: { summary: 'Add `integrity="sha384-…"` and `crossorigin="anonymous"` to cross-origin <script> and <link rel="stylesheet"> tags, pinning the exact file; or self-host the asset.', references: ['https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity'] },
    observe: (page, site) => {
      if (!page.dom) return [];
      const out = [];
      for (const s of page.dom.scripts) if (s.url && !sameOrigin(s.url, site.origin) && !s.integrity) out.push({ url: page.finalUrl, key: `script:${s.url}`, severity: 'low', description: `External script without integrity: ${s.url}`, evidence: { detail: { src: s.url } } });
      for (const s of page.dom.styles) if (!sameOrigin(s.url, site.origin) && !s.integrity) out.push({ url: page.finalUrl, key: `style:${s.url}`, severity: 'informational', description: `External stylesheet without integrity: ${s.url}`, evidence: { detail: { href: s.url } } });
      return out;
    },
  },
  {
    id: 'content.targetBlankOpener', title: 'External link opens in a new window without rel="noopener"', kind: 'passive', intrusiveness: 0,
    severity: 'informational', confidence: 'firm', cwe: [1021], owasp: 'A05', asvs: [],
    description: 'Links with target="_blank" and no rel="noopener" give the opened page a window.opener reference; in older browsers the destination could redirect this tab. Modern browsers imply noopener, so this is informational.',
    remediation: { summary: 'Add rel="noopener noreferrer" to target="_blank" links to third-party sites.', references: ['https://developer.mozilla.org/docs/Web/HTML/Attributes/rel/noopener'] },
    observe: (page, site) => {
      if (!page.body || !page.dom) return [];
      const re = /<a\b[^>]*\btarget\s*=\s*["']?_blank["']?[^>]*>/gi;
      let count = 0;
      for (const m of page.body.matchAll(re)) {
        const tag = m[0];
        const href = /\bhref\s*=\s*["']?([^"'\s>]+)/i.exec(tag)?.[1];
        if (!href || sameOrigin(href, site.origin) || !/^https?:/i.test(href)) continue;
        if (!/\brel\s*=\s*["'][^"']*\bnoopener\b/i.test(tag)) count++;
      }
      return count ? [{ url: page.finalUrl, key: 'blank', description: `${count} external link(s) with target="_blank" lack rel="noopener".` }] : [];
    },
  },
]);
