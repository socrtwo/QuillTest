/** Component fingerprinting and known-vulnerable version matching. */
import { readFileSync } from 'node:fs';
import { defineCheck } from '../registry.mjs';
import { parseVersion, versionBelow, versionInRange } from '../version.mjs';
import { inlineScripts } from '../../crawl/html.mjs';

export const KNOWN_VULNERABLE = JSON.parse(readFileSync(new URL('../data/known-vulnerable.json', import.meta.url), 'utf8')).components;

const V = '(\\d+(?:\\.\\d+){1,3})';
/** Fingerprint sources: header or URL/body patterns → {name, version}. */
const HEADER_RULES = [
  { header: 'server', re: new RegExp(`\\bnginx(?:/${V})?`, 'i'), name: 'nginx' },
  { header: 'server', re: new RegExp(`\\bApache(?:/${V})?`, 'i'), name: 'Apache' },
  { header: 'server', re: new RegExp(`\\bOpenSSL/${V}`, 'i'), name: 'OpenSSL' },
  { header: 'server', re: new RegExp(`\\bMicrosoft-IIS/${V}`, 'i'), name: 'IIS' },
  { header: 'server', re: new RegExp(`\\bLiteSpeed`, 'i'), name: 'LiteSpeed' },
  { header: 'server', re: new RegExp(`\\bcloudflare`, 'i'), name: 'Cloudflare' },
  { header: 'server', re: new RegExp(`\\bgunicorn(?:/${V})?`, 'i'), name: 'gunicorn' },
  { header: 'x-powered-by', re: new RegExp(`\\bPHP/${V}`, 'i'), name: 'PHP' },
  { header: 'x-powered-by', re: /\bExpress\b/i, name: 'Express' },
  { header: 'x-powered-by', re: new RegExp(`\\bASP\\.NET`, 'i'), name: 'ASP.NET' },
  { header: 'x-aspnet-version', re: new RegExp(V), name: 'ASP.NET' },
  { header: 'x-powered-by', re: new RegExp(`\\bNext\\.js(?:\\s*${V})?`, 'i'), name: 'Next.js' },
  { header: 'x-generator', re: new RegExp(`\\bDrupal\\s*${V}?`, 'i'), name: 'Drupal' },
  { header: 'x-drupal-cache', re: /./, name: 'Drupal' },
  { header: 'x-shopify-stage', re: /./, name: 'Shopify' },
];
const URL_RULES = [
  { re: new RegExp(`jquery[-.]${V}(?:\\.min|\\.slim)?\\.js`, 'i'), name: 'jQuery' },
  { re: new RegExp(`jquery-ui[-.]${V}(?:\\.min)?\\.js`, 'i'), name: 'jQuery UI' },
  { re: new RegExp(`bootstrap[-.]${V}(?:\\.min)?\\.(js|css)`, 'i'), name: 'Bootstrap' },
  { re: new RegExp(`/bootstrap@${V}/`, 'i'), name: 'Bootstrap' },
  { re: new RegExp(`/jquery@${V}/`, 'i'), name: 'jQuery' },
  { re: new RegExp(`angular(?:\\.min)?\\.js|/angular(?:js)?/${V}/`, 'i'), name: 'AngularJS', versionGroup: 1 },
  { re: new RegExp(`/angular\\.js/${V}/`, 'i'), name: 'AngularJS' },
  { re: new RegExp(`lodash(?:\\.min)?\\.js|/lodash(?:\\.js)?@${V}/|/lodash\\.js/${V}/`, 'i'), name: 'Lodash' },
  { re: new RegExp(`moment(?:\\.min)?\\.js|/moment(?:\\.js)?@${V}/|/moment\\.js/${V}/`, 'i'), name: 'Moment.js' },
  { re: new RegExp(`/vue@${V}/|vue(?:\\.min)?\\.js`, 'i'), name: 'Vue' },
  { re: new RegExp(`/react(?:-dom)?@${V}/`, 'i'), name: 'React' },
  { re: /\/wp-content\/|\/wp-includes\//i, name: 'WordPress' },
];
const BODY_RULES = [
  { re: new RegExp(`/\\*!?\\s*jQuery (?:JavaScript Library )?v${V}`, 'i'), name: 'jQuery' },
  { re: new RegExp(`jQuery JavaScript Library v${V}`, 'i'), name: 'jQuery' },
  { re: new RegExp(`/\\*!?\\s*jQuery UI - v${V}`, 'i'), name: 'jQuery UI' },
  { re: new RegExp(`Bootstrap\\s+v${V}`, 'i'), name: 'Bootstrap' },
  { re: new RegExp(`@license AngularJS v${V}`, 'i'), name: 'AngularJS' },
  { re: new RegExp(`\\*\\s*@license\\s*\\n?\\s*\\*\\s*Lodash|lodash\\.com/license|var VERSION = '${V}'`, 'i'), name: 'Lodash', versionGroup: 1 },
  { re: new RegExp(`//! moment\\.js\\s*\\n?//! version : ${V}`, 'i'), name: 'Moment.js' },
  { re: new RegExp(`\\*\\s*Vue\\.js v${V}|/\\*\\*\\s*\\* vue v${V}`, 'i'), name: 'Vue', versionGroup: 1 },
  { re: new RegExp(`React v${V}|@license React\\s*\\n?\\s*\\*\\s*react(?:-dom)?\\.\\w+\\.js`, 'i'), name: 'React' },
];
const META_GENERATOR = new RegExp(`^\\s*(WordPress|Drupal|Joomla!?|TYPO3(?: CMS)?|Wix\\.com|Hugo|Gatsby|Jekyll|Ghost|Squarespace|Shopify|Webflow|Astro|Docusaurus|MediaWiki|phpBB|vBulletin|Magento|PrestaShop|OpenCart|Next\\.js)\\s*v?${V}?`, 'i');

/** Collect components from one page into site.fingerprint (a Map name → {name, version, evidence}). */
export function fingerprintPage(page, fingerprint) {
  const add = (name, version, where) => {
    const cur = fingerprint.get(name);
    if (!cur || (!cur.version && version)) fingerprint.set(name, { name, version: version || cur?.version || null, evidence: cur?.evidence || where });
  };
  for (const r of HEADER_RULES) {
    const v = page.headers[r.header];
    if (!v) continue;
    const m = r.re.exec(String(v));
    if (m) add(r.name, m[1] || null, `${r.header}: ${v}`);
  }
  if (page.dom) {
    const gen = page.dom.meta.generator;
    if (gen) { const m = META_GENERATOR.exec(gen); if (m) add(m[1].replace(/!$/, ''), m[2] || null, `meta generator: ${gen}`); }
    const urls = [...page.dom.scripts.map((s) => s.url), ...page.dom.styles.map((s) => s.url)].filter(Boolean);
    for (const u of urls) for (const r of URL_RULES) { const m = r.re.exec(u); if (m) add(r.name, m[1] || m[2] || null, u); }
    for (const s of inlineScripts(page.body).slice(0, 20)) for (const r of BODY_RULES) { const m = r.re.exec(s.slice(0, 4000)); if (m) add(r.name, m[1] || m[2] || null, 'inline script banner'); }
  } else if (page.kind === 'asset') {
    const head = page.body.slice(0, 4000);
    for (const r of BODY_RULES) { const m = r.re.exec(head); if (m) add(r.name, m[1] || m[2] || null, page.finalUrl); }
    for (const r of URL_RULES) { const m = r.re.exec(page.finalUrl); if (m && m[1]) add(r.name, m[1], page.finalUrl); }
  }
}

export function matchKnownVulnerable(name, version) {
  if (!version) return [];
  const v = parseVersion(version);
  if (!v) return [];
  return KNOWN_VULNERABLE.filter((k) => k.name.toLowerCase() === name.toLowerCase() && (k.below ? versionBelow(v, k.below) : k.range ? versionInRange(v, k.range) : false));
}

defineCheck([
  {
    id: 'components.fingerprint', title: 'Component detected', kind: 'passive', intrusiveness: 0,
    severity: 'informational', confidence: 'firm', cwe: [200], owasp: 'A06', asvs: ['V14.2.1'],
    description: 'Software identified from headers, generator tags, asset URLs and library banners. Informational on its own; the version check below flags known problems. The stack fingerprint also selects the matching remediation snippets.',
    remediation: { summary: 'Keep an inventory of the components in use and their versions; subscribe to their security advisories; hide version strings where they serve no purpose.', references: ['https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/'] },
    observe: (page, site) => {
      fingerprintPage(page, site.fingerprint);
      return [];
    },
    finalize: (site) => [...site.fingerprint.values()].map((c) => ({ url: site.origin + '/', key: c.name, description: `${c.name}${c.version ? ' ' + c.version : ''} detected (${c.evidence}).`, evidence: { detail: c } })),
  },
  {
    id: 'components.knownVulnerable', title: 'Component version with known vulnerabilities or end of life', kind: 'passive', intrusiveness: 0,
    severity: 'medium', confidence: 'firm', cwe: [1395, 1104], owasp: 'A06', asvs: ['V14.2.1'],
    description: 'A detected component version falls in a range with published vulnerabilities or no longer receives security fixes. Version detection from file names and banners is firm, not confirmed: a patched fork or a vendor backport can carry an old version string.',
    remediation: { summary: 'Upgrade the component to a supported, fixed release; where that is not immediately possible, check whether the advisories apply to how the site uses it and mitigate (CSP, input handling).', references: ['https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/'], fixId: 'fix.dependencyBump' },
    finalize: (site) => {
      const out = [];
      for (const c of site.fingerprint.values()) {
        for (const k of matchKnownVulnerable(c.name, c.version)) {
          out.push({ url: site.origin + '/', key: `${c.name}@${c.version}:${k.advisories[0] || k.below || k.range?.join('-')}`, severity: k.severity, description: `${c.name} ${c.version} — ${k.note}. ${k.advisories.length ? 'Advisories: ' + k.advisories.join(', ') + '.' : ''} Detected via ${c.evidence}.`, evidence: { detail: { component: c, rule: k } } });
        }
      }
      return out;
    },
  },
]);
