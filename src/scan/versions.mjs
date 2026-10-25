/*
 * Anne's Test — component version assessment (EOL and known advisories)
 * Part of the Anne's Office suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Turns a fingerprinted version ("nginx/1.18.0", "jQuery 1.12.4") into a
 * finding when that version is end-of-life or falls in a range with
 * well-known, widely documented advisories.
 *
 * Two sources:
 *   1. An offline table below — deliberately small, conservative, and dated
 *      (KNOWN_DATA_AS_OF). It covers the components the fingerprinter can see
 *      and only ranges that are unambiguous. Offline-first is a project
 *      principle, so this works with no network at all.
 *   2. Optional online enrichment through OSV.dev (https://osv.dev), a free,
 *      keyless vulnerability database, for components that map cleanly to a
 *      package ecosystem (jQuery and Bootstrap on npm, Drupal on Packagist).
 *      Off by default; the CLI enables it with --online-cve. fetch is
 *      injectable so it is tested offline.
 *
 * Honesty about banners: Linux distributions backport security fixes without
 * changing the advertised version (Debian's nginx 1.18.0 may be fully
 * patched). Banner-derived advisory matches are therefore reported with
 * confidence "firm", not "confirmed", and the remediation says to confirm
 * against the vendor's own advisory before acting. EOL status, by contrast,
 * is a fact about the version line itself.
 */

export const KNOWN_DATA_AS_OF = '2026-10';

// ---------------------------------------------------------------------------
// Version comparison (numeric dotted versions; tolerant of suffixes like "-beta")
// ---------------------------------------------------------------------------

export function parseVersion(v) {
  const m = String(v ?? '').trim().match(/^v?(\d+(?:\.\d+)*)/);
  if (!m) return null;
  return m[1].split('.').map((n) => Number.parseInt(n, 10));
}

/** Returns -1, 0, 1, or null when either side is unparseable. */
export function compareVersions(a, b) {
  const pa = parseVersion(a), pb = parseVersion(b);
  if (!pa || !pb) return null;
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const x = pa[i] ?? 0, y = pb[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

const lt = (v, bound) => compareVersions(v, bound) === -1;
const gte = (v, bound) => { const c = compareVersions(v, bound); return c === 0 || c === 1; };

/** v in [from, below) ; from may be null (= any) */
export function inRange(v, { from = null, below = null } = {}) {
  if (from && !gte(v, from)) return false;
  if (below && !lt(v, below)) return false;
  return compareVersions(v, '0') !== null;
}

// ---------------------------------------------------------------------------
// Offline knowledge
// ---------------------------------------------------------------------------

/**
 * Keyed by the fingerprint name. Each entry:
 *   eol:        [{ below, note }]                      — version lines no longer maintained
 *   advisories: [{ from?, below, ids[], severity, summary, fixedIn, conditional? }]
 *   upgrade:    one-line upgrade guidance
 *   osv:        { ecosystem, name }                    — for optional online enrichment
 */
export const KNOWN = {
  'jQuery': {
    upgrade: 'Upgrade to the current jQuery 3.x release and test; most 1.x/2.x code runs unchanged with jquery-migrate.',
    osv: { ecosystem: 'npm', name: 'jquery' },
    eol: [{ below: '3.0.0', note: 'jQuery 1.x and 2.x are no longer maintained.' }],
    advisories: [
      { below: '3.5.0', ids: ['CVE-2020-11022', 'CVE-2020-11023'], severity: 'medium', summary: 'Cross-site scripting via HTML passed to jQuery DOM manipulation methods even after sanitization.', fixedIn: '3.5.0' },
      { below: '3.4.0', ids: ['CVE-2019-11358'], severity: 'medium', summary: 'Prototype pollution in jQuery.extend.', fixedIn: '3.4.0' },
      { below: '3.0.0', ids: ['CVE-2015-9251'], severity: 'medium', summary: 'Cross-site scripting via cross-domain Ajax responses executed as script.', fixedIn: '3.0.0' },
    ],
  },
  'Bootstrap': {
    upgrade: 'Upgrade to a current Bootstrap 5.x (or at least 4.3.1 / 3.4.1 on the older lines).',
    osv: { ecosystem: 'npm', name: 'bootstrap' },
    eol: [{ below: '4.0.0', note: 'Bootstrap 3.x reached end of life in 2019.' }],
    advisories: [
      { from: '4.0.0', below: '4.3.1', ids: ['CVE-2019-8331'], severity: 'medium', summary: 'XSS in tooltip/popover data-template.', fixedIn: '4.3.1' },
      { below: '3.4.1', ids: ['CVE-2019-8331'], severity: 'medium', summary: 'XSS in tooltip/popover data-template.', fixedIn: '3.4.1' },
      { from: '4.0.0', below: '4.1.2', ids: ['CVE-2018-14040', 'CVE-2018-14041', 'CVE-2018-14042'], severity: 'medium', summary: 'XSS in collapse data-parent, scrollspy data-target, and tooltip data-container attributes.', fixedIn: '4.1.2' },
    ],
  },
  'PHP': {
    upgrade: 'Move to a supported PHP release (8.2 or newer at the time of this data) and re-test the application.',
    eol: [
      { below: '7.0', note: 'PHP 5.x has been end-of-life since 2018 and receives no security fixes.' },
      { below: '8.2', note: 'PHP releases before 8.2 no longer receive security fixes (8.1 ended December 2025).' },
    ],
    advisories: [],
  },
  'nginx': {
    upgrade: 'Upgrade to a current nginx stable release from nginx.org or your distribution; if your distribution backports fixes, confirm the CVE is listed as fixed in its changelog.',
    eol: [],
    advisories: [
      { from: '0.6.18', below: '1.20.1', ids: ['CVE-2021-23017'], severity: 'high', summary: 'One-byte memory overwrite in the DNS resolver (only when a "resolver" directive is configured).', fixedIn: '1.20.1 / 1.21.0', conditional: 'resolver directive in use' },
    ],
  },
  'Apache': {
    upgrade: 'Upgrade to the current Apache httpd 2.4.x release; confirm distribution backports where applicable.',
    eol: [{ below: '2.4', note: 'Apache httpd 2.2 and earlier are end-of-life.' }],
    advisories: [
      { from: '2.4.49', below: '2.4.51', ids: ['CVE-2021-41773', 'CVE-2021-42013'], severity: 'critical', summary: 'Path traversal and remote code execution via path normalization (2.4.49 and 2.4.50 only).', fixedIn: '2.4.51' },
      { from: '2.4', below: '2.4.56', ids: ['CVE-2023-25690'], severity: 'critical', summary: 'HTTP request splitting in mod_proxy with certain RewriteRule/ProxyPassMatch configurations.', fixedIn: '2.4.56', conditional: 'mod_proxy with user-controlled rewrite targets' },
    ],
  },
  'Microsoft-IIS': {
    upgrade: 'Move to a supported Windows Server release (IIS 10 or newer).',
    eol: [{ below: '10.0', note: 'IIS 8.5 and earlier ship with Windows Server versions that are out of support.' }],
    advisories: [],
  },
  'Drupal': {
    upgrade: 'Upgrade to a supported Drupal release (10.x or newer) following the official migration guide.',
    osv: { ecosystem: 'Packagist', name: 'drupal/core' },
    eol: [
      { below: '8.0', note: 'Drupal 7 reached end of life on 5 January 2025.' },
      { below: '10.0', note: 'Drupal 8 (November 2021) and Drupal 9 (November 2023) are end-of-life.' },
    ],
    advisories: [],
  },
  'WordPress': {
    upgrade: 'Update WordPress core to the current release (Dashboard → Updates) and enable automatic updates.',
    eol: [{ below: '6.0', note: 'WordPress releases before 6.0 are well behind current security fixes; only the latest release is fully supported.' }],
    advisories: [],
  },
  'Joomla': {
    upgrade: 'Upgrade to a supported Joomla release (5.x, or 4.4 LTS at minimum).',
    eol: [{ below: '4.0', note: 'Joomla 3.x reached end of life in August 2023.' }],
    advisories: [],
  },
  'Angular': {
    upgrade: 'Upgrade along the supported Angular LTS path.',
    eol: [{ below: '17.0.0', note: 'Angular versions before 17 are out of long-term support as of this data.' }],
    advisories: [],
  },
};

// ---------------------------------------------------------------------------
// Assessment
// ---------------------------------------------------------------------------

function severityRank(s) { return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[s] || 0; }

/**
 * Assess every fingerprinted component that has a version.
 * @param {{signals?:object[]}} fp  result of fingerprint()
 * @returns {object[]} partial findings ({title, severity, confidence, cwe, owasp, location, evidence, remediation, component})
 */
export function assessVersions(fp, { location } = {}) {
  const out = [];
  for (const comp of fp?.signals || []) {
    if (!comp.version || !KNOWN[comp.name]) continue;
    const k = KNOWN[comp.name];
    const v = comp.version;
    if (compareVersions(v, '0') === null) continue;
    const base = { component: comp.name, version: v, location: location || null };
    const evidenceBase = { snippet: `${comp.name} ${v} — detected from: ${comp.evidence.join('; ')}` };

    const eol = k.eol.find((e) => lt(v, e.below));
    if (eol) {
      out.push({
        ...base,
        title: `${comp.name} ${v} is end-of-life`,
        severity: 'high', confidence: 'firm',
        cwe: 'CWE-1104', owasp: 'A06:2021 Vulnerable and Outdated Components',
        evidence: { ...evidenceBase, note: eol.note, dataAsOf: KNOWN_DATA_AS_OF },
        remediation: `${eol.note} ${k.upgrade}`,
      });
    }

    const hits = k.advisories.filter((a) => inRange(v, { from: a.from, below: a.below }));
    if (hits.length) {
      const worst = hits.reduce((m, a) => (severityRank(a.severity) > severityRank(m.severity) ? a : m), hits[0]);
      const ids = [...new Set(hits.flatMap((a) => a.ids))];
      out.push({
        ...base,
        title: `${comp.name} ${v} has known vulnerabilities (${ids.slice(0, 3).join(', ')}${ids.length > 3 ? ', …' : ''})`,
        severity: worst.severity, confidence: 'firm',
        cwe: 'CWE-1395', owasp: 'A06:2021 Vulnerable and Outdated Components',
        evidence: {
          ...evidenceBase,
          advisories: hits.map((a) => ({ ids: a.ids, severity: a.severity, summary: a.summary, fixedIn: a.fixedIn, conditional: a.conditional || null })),
          dataAsOf: KNOWN_DATA_AS_OF,
          caveat: 'Version taken from a banner or asset path. Distributions may backport fixes without changing the version; confirm against the vendor advisory or your package changelog.',
        },
        remediation: `${k.upgrade} Fixed in: ${[...new Set(hits.map((a) => a.fixedIn))].join('; ')}.${hits.some((a) => a.conditional) ? ' Some of these apply only under specific configurations (see evidence).' : ''}`,
      });
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Optional online enrichment via OSV.dev
// ---------------------------------------------------------------------------

export const OSV_QUERY_URL = 'https://api.osv.dev/v1/query';

/** Components from a fingerprint that have an OSV mapping and a version.
 *  `component` is the fingerprint display name; `name`/`ecosystem` are the OSV package coordinates. */
export function osvCandidates(fp) {
  return (fp?.signals || [])
    .filter((c) => c.version && KNOWN[c.name]?.osv)
    .map((c) => ({ component: c.name, version: c.version, ecosystem: KNOWN[c.name].osv.ecosystem, name: KNOWN[c.name].osv.name }));
}

/**
 * Query OSV for each candidate. Never throws; per-component errors are returned.
 * @returns {Promise<Array<{name, version, ecosystem, vulns:Array<{id, summary, severity}>, error?:string}>>}
 */
export async function enrichWithOsv(fp, { fetchImpl = globalThis.fetch, timeoutMs = 15_000 } = {}) {
  const results = [];
  for (const cand of osvCandidates(fp)) {
    try {
      const res = await fetchImpl(OSV_QUERY_URL, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'user-agent': 'QuillTest-Scan/0.1 (+osv lookup)' },
        body: JSON.stringify({ version: cand.version, package: { name: cand.name, ecosystem: cand.ecosystem } }),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!res.ok) { results.push({ ...cand, vulns: [], error: `HTTP ${res.status}` }); continue; }
      const json = await res.json();
      const vulns = (json.vulns || []).map((v) => ({
        id: v.id,
        aliases: v.aliases || [],
        summary: v.summary || v.details?.slice(0, 200) || '',
        severity: (v.database_specific?.severity || v.severity?.[0]?.type || '').toString().toLowerCase() || null,
      }));
      results.push({ ...cand, vulns });
    } catch (e) {
      results.push({ ...cand, vulns: [], error: e?.name === 'TimeoutError' ? 'timeout' : (e?.cause?.message || e.message) });
    }
  }
  return results;
}

/** Turn OSV results into partial findings (one per component with ≥1 vuln). */
export function osvFindings(osvResults, { location } = {}) {
  const out = [];
  for (const r of osvResults) {
    if (!r.vulns?.length) continue;
    const ids = r.vulns.map((v) => v.aliases?.find((a) => a.startsWith('CVE-')) || v.id);
    const sev = r.vulns.some((v) => /critical/.test(v.severity || '')) ? 'critical' : r.vulns.some((v) => /high/.test(v.severity || '')) ? 'high' : 'medium';
    const display = r.component || r.name;
    out.push({
      component: display, version: r.version, location: location || null,
      title: `${display} ${r.version}: ${r.vulns.length} advisory(ies) in OSV (${ids.slice(0, 3).join(', ')}${ids.length > 3 ? ', …' : ''})`,
      severity: sev, confidence: 'firm',
      cwe: 'CWE-1395', owasp: 'A06:2021 Vulnerable and Outdated Components',
      evidence: { snippet: `OSV.dev query for ${r.ecosystem}:${r.name}@${r.version}`, advisories: r.vulns.slice(0, 10), source: 'https://osv.dev' },
      remediation: `${KNOWN[display]?.upgrade || 'Upgrade to a release that is not affected.'} See the linked OSV entries for fixed versions.`,
    });
  }
  return out;
}
