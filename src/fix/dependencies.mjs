/*
 * Anne's Test — dependency-bump artifacts for fingerprinted components
 * Part of the Anne's Office suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Turns the component findings of a scan report (components.eol,
 * components.known-vulnerable, components.osv) into things you can act on:
 *
 *   - a package.json fragment for npm-hosted libraries (jQuery, Bootstrap),
 *   - a composer.json fragment for Composer-managed CMSs (Drupal),
 *   - replacement <script>/<link> tags for libraries loaded from a CDN or
 *     served as static files,
 *   - a shell script of the package-manager commands, with the runtime and
 *     server upgrades (PHP, nginx, Apache, IIS) spelled out as commented
 *     steps because those depend on the distribution,
 *   - a Markdown summary: detected version, smallest safe step, recommended
 *     target, and the findings/CVEs that motivated each bump.
 *
 * The "minimum" for each component is computed from the same offline table
 * the scanner used (src/scan/versions.mjs): the lowest version that clears
 * every matched EOL line and advisory. The "recommended" target comes from
 * BUMPS below and is dated (BUMP_DATA_AS_OF); npm/Composer caret ranges mean
 * the installer picks the newest compatible release anyway.
 *
 * Same principles as artifacts.mjs: generate, never apply; derive from
 * evidence (only components with a finding get a bump).
 */
import { KNOWN, compareVersions, parseVersion } from '../scan/versions.mjs';

export const BUMP_DATA_AS_OF = '2026-10';

/**
 * Keyed by the fingerprint name (same keys as KNOWN).
 *   ecosystem:   npm | composer | wp-cli | runtime | server | manual
 *   pkg / pkgs:  package coordinates for manifest fragments
 *   recommended: target version (a floor; caret ranges float above it)
 *   lines:       last patched release of older major lines, for the smallest safe step
 *   cdn:         { script?, style? } URL templates with {v} for the version
 *   commands:    shell lines; lines starting with '#' are distribution-dependent guidance
 *   notes:       caveats shown in the summary
 */
export const BUMPS = {
  'jQuery': {
    ecosystem: 'npm', pkg: 'jquery', recommended: '3.7.1',
    cdn: { script: 'https://code.jquery.com/jquery-{v}.min.js' },
    commands: ['npm install jquery@^{rec}'],
    notes: ['Load jquery-migrate once during the upgrade to surface removed APIs, then drop it.', 'If a newer major (4.x) is current when you read this, prefer it; 3.7.1 is the floor in this table.'],
  },
  'Bootstrap': {
    ecosystem: 'npm', pkg: 'bootstrap', recommended: '5.3.3', lines: { 3: '3.4.1', 4: '4.6.2' },
    cdn: { script: 'https://cdn.jsdelivr.net/npm/bootstrap@{v}/dist/js/bootstrap.bundle.min.js', style: 'https://cdn.jsdelivr.net/npm/bootstrap@{v}/dist/css/bootstrap.min.css' },
    commands: ['npm install bootstrap@^{rec}'],
    notes: ['Bootstrap 5 dropped jQuery and renamed data attributes (data-toggle → data-bs-toggle); a 3.x/4.x site needs markup changes. The same-line patch release closes the known XSS issues without that work.'],
  },
  'Angular': {
    ecosystem: 'npm', pkgs: ['@angular/core', '@angular/cli'], recommended: '19.0.0',
    commands: ['# Angular upgrades go one major at a time; repeat until current (see https://angular.dev/update-guide):', 'npx @angular/cli@latest update @angular/core @angular/cli'],
    notes: ['ng update rewrites package.json and applies migrations; do not hand-edit the Angular versions in the manifest.'],
  },
  'Drupal': {
    ecosystem: 'composer', pkg: 'drupal/core-recommended', recommended: '11.0.0', lines: { 10: '10.3.0' },
    commands: ['composer require drupal/core-recommended:^{recMajor} drupal/core-composer-scaffold:^{recMajor} drupal/core-project-message:^{recMajor} --update-with-all-dependencies', 'vendor/bin/drush updatedb && vendor/bin/drush cache:rebuild'],
    notes: ['Drupal 7 has no in-place upgrade path; migrate with the Migrate Drupal modules. Drupal 10.x remains supported alongside 11 as of this data.'],
  },
  'WordPress': {
    ecosystem: 'wp-cli', recommended: 'latest',
    commands: ['wp core update && wp core update-db', 'wp plugin update --all && wp theme update --all', 'wp config set WP_AUTO_UPDATE_CORE true --raw'],
    notes: ['Only the current WordPress release is fully supported; enable automatic core updates. Plugins and themes are the more common entry point — update them in the same pass.'],
  },
  'Joomla': {
    ecosystem: 'manual', recommended: '5.0.0', lines: { 4: '4.4.0' },
    commands: ['# Joomla: System → Update → Joomla (or Components → Joomla! Update). From 3.x, first update to the last 3.10.x, then use the Pre-Update Checker to move to 4.4, then 5.'],
    notes: ['Third-party extensions must be 4/5-compatible before the core upgrade.'],
  },
  'PHP': {
    ecosystem: 'runtime', recommended: '8.3',
    commands: [
      '# PHP — pick the line your platform ships:',
      '#   Docker:          FROM php:{rec}-fpm   (or php:{rec}-apache)',
      '#   Debian/Ubuntu:   apt-get install php{rec}-fpm php{rec}-{extensions}   (packages.sury.org / ppa:ondrej/php)',
      '#   RHEL/Alma/Rocky: dnf module reset php && dnf module enable php:remi-{rec} && dnf install php-fpm',
      '#   cPanel/Plesk:    MultiPHP Manager / PHP Settings → select {rec}',
      '# Then switch the web server or pool to the new binary and re-test the application.',
    ],
    notes: ['Run the application test suite on the new PHP line before switching production; removed features between majors break code silently.'],
  },
  'nginx': {
    ecosystem: 'server', recommended: '1.26.0',
    commands: [
      '# nginx — use the vendor repository for current stable rather than the distribution default:',
      '#   Debian/Ubuntu: https://nginx.org/en/linux_packages.html#Debian  then  apt-get install nginx',
      '#   RHEL family:   https://nginx.org/en/linux_packages.html#RHEL    then  dnf install nginx',
      '#   Docker:        FROM nginx:stable',
      '#   then: nginx -t && systemctl reload nginx',
    ],
    notes: ['If you stay on the distribution package, confirm the CVE is listed as fixed in its changelog (apt changelog nginx / rpm -q --changelog nginx) — banners do not reflect backports.'],
  },
  'Apache': {
    ecosystem: 'server', recommended: '2.4.62',
    commands: [
      '# Apache httpd — update from the distribution or vendor packages:',
      '#   Debian/Ubuntu: apt-get update && apt-get install --only-upgrade apache2',
      '#   RHEL family:   dnf update httpd',
      '#   Docker:        FROM httpd:2.4',
      '#   then: apachectl configtest && systemctl reload apache2   (or httpd)',
    ],
    notes: ['Distribution packages backport fixes without changing the banner; check the package changelog before concluding a CVE applies.'],
  },
  'Microsoft-IIS': {
    ecosystem: 'server', recommended: '10.0',
    commands: ['# IIS versions track Windows Server. Move the site to a supported Windows Server release (IIS 10), then apply Windows Update.'],
    notes: [],
  },
};

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

const firstVersion = (s) => (String(s ?? '').match(/\d+(?:\.\d+)*/) || [null])[0];
const maxVersion = (list) => list.filter((v) => parseVersion(v)).reduce((m, v) => (m === null || compareVersions(v, m) === 1 ? v : m), null);

/**
 * Lowest version that clears every EOL line and advisory matched for this
 * component/version in the offline table. null when the table has nothing
 * matching (e.g. an OSV-only finding).
 */
export function minimumSafeVersion(component, version) {
  const k = KNOWN[component];
  if (!k || !parseVersion(version)) return null;
  const bounds = [];
  for (const e of k.eol) if (compareVersions(version, e.below) === -1) bounds.push(e.below);
  for (const a of k.advisories) {
    const inFrom = !a.from || compareVersions(version, a.from) !== -1;
    if (inFrom && compareVersions(version, a.below) === -1) bounds.push(firstVersion(a.fixedIn) || a.below);
  }
  return maxVersion(bounds);
}

/**
 * Last patched release on the detected major line, when the table knows one
 * and it clears every matched advisory. It may still sit on an end-of-life
 * line (lineEol: true): it closes the named CVEs but not the EOL finding.
 * @returns {{version:string, lineEol:boolean}|null}
 */
export function sameLineStep(component, version) {
  const major = parseVersion(version)?.[0];
  const step = BUMPS[component]?.lines?.[major];
  const k = KNOWN[component];
  if (!step || !k || !parseVersion(version)) return null;
  for (const a of k.advisories) {
    const inFrom = !a.from || compareVersions(version, a.from) !== -1;
    if (inFrom && compareVersions(version, a.below) === -1 && compareVersions(step, firstVersion(a.fixedIn) || a.below) === -1) return null;
  }
  const lineEol = k.eol.some((e) => compareVersions(step, e.below) === -1);
  return { version: step, lineEol };
}

function fill(template, ctx) {
  return template.replace(/\{(rec|recMajor|v|extensions)\}/g, (_, k) => ctx[k] ?? `{${k}}`);
}

/**
 * Build one bump per fingerprinted component that has a component finding.
 * @param {object} report  scan report (findings[], stack)
 * @returns {{bumps: object[], coveredCheckIds: string[], skipped: object[], dataAsOf: string}}
 */
export function planDependencyBumps(report) {
  const findings = (report?.findings || []).filter((f) => String(f.checkId || '').startsWith('components.'));
  const byComponent = new Map();
  const skipped = [];
  for (const f of findings) {
    const name = f.component || f.evidence?.component;
    const version = f.version || f.evidence?.version;
    if (!name || !BUMPS[name]) { skipped.push({ id: f.id, checkId: f.checkId, title: f.title, reason: name ? 'no bump data for component' : 'finding does not name a component' }); continue; }
    const cur = byComponent.get(name) || { component: name, from: version || null, because: [], cves: [], checkIds: new Set(), osvOnly: true };
    cur.because.push(f.id || f.checkId);
    cur.checkIds.add(f.checkId);
    if (f.checkId !== 'components.osv') cur.osvOnly = false;
    for (const a of f.evidence?.advisories || []) {
      for (const id of a.ids || []) if (!cur.cves.includes(id)) cur.cves.push(id);
      if (a.id && !cur.cves.includes(a.id)) cur.cves.push(a.aliases?.find((x) => x.startsWith('CVE-')) || a.id);
    }
    if (!cur.from && version) cur.from = version;
    byComponent.set(name, cur);
  }

  const bumps = [];
  for (const cur of byComponent.values()) {
    const b = BUMPS[cur.component];
    const minimum = cur.from ? minimumSafeVersion(cur.component, cur.from) : null;
    let recommended = b.recommended;
    if (minimum && parseVersion(recommended) && compareVersions(minimum, recommended) === 1) recommended = minimum; // table drift guard
    const recMajor = parseVersion(recommended)?.[0] ?? recommended;
    const ctx = { rec: recommended, recMajor: String(recMajor), v: recommended, extensions: 'mysql' };
    bumps.push({
      component: cur.component,
      ecosystem: b.ecosystem,
      from: cur.from,
      minimum,
      sameLine: cur.from ? sameLineStep(cur.component, cur.from) : null,
      recommended,
      pkg: b.pkg || null,
      pkgs: b.pkgs || (b.pkg ? [b.pkg] : []),
      cdn: b.cdn ? Object.fromEntries(Object.entries(b.cdn).map(([k, t]) => [k, fill(t, ctx)])) : null,
      commands: b.commands.map((c) => fill(c, ctx)),
      notes: [...b.notes, ...(cur.osvOnly ? ['Fixed versions for the OSV advisories are in the linked OSV entries; the minimum here comes from the offline table only.'] : [])],
      because: cur.because,
      cves: cur.cves,
      checkIds: [...cur.checkIds].sort(),
    });
  }
  bumps.sort((a, b) => (a.component < b.component ? -1 : a.component > b.component ? 1 : 0));

  // A check id counts as covered only when every finding under it produced a bump.
  const allIds = new Set(findings.map((f) => f.checkId));
  const skippedIds = new Set(skipped.map((s) => s.checkId));
  const coveredCheckIds = [...allIds].filter((id) => !skippedIds.has(id)).sort();

  return { bumps, coveredCheckIds, skipped, dataAsOf: BUMP_DATA_AS_OF };
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

const caret = (v) => (parseVersion(v) ? `^${v}` : v);

function renderNpm(bumps) {
  const deps = {};
  for (const b of bumps) if (b.ecosystem === 'npm' && b.component !== 'Angular') for (const p of b.pkgs) deps[p] = caret(b.recommended);
  if (!Object.keys(deps).length) return null;
  const doc = {
    '//': `Anne\'s Test ${BUMP_DATA_AS_OF} — merge "dependencies" into your package.json, then run: npm install (or npm update <pkg>). Caret ranges float to the newest compatible release.`,
    dependencies: deps,
  };
  return { filename: 'quilltest-dependencies.package.json', contents: JSON.stringify(doc, null, 2) + '\n', kind: 'dependencies', target: 'npm' };
}

function renderComposer(bumps) {
  const req = {};
  for (const b of bumps) if (b.ecosystem === 'composer') {
    req[b.pkg] = caret(b.recommended);
    if (b.component === 'Drupal') { const m = parseVersion(b.recommended)?.[0]; req['drupal/core-composer-scaffold'] = `^${m}`; req['drupal/core-project-message'] = `^${m}`; }
  }
  if (!Object.keys(req).length) return null;
  const doc = {
    _comment: `Anne\'s Test ${BUMP_DATA_AS_OF} — merge "require" into your composer.json, then run: composer update --with-all-dependencies`,
    require: req,
  };
  return { filename: 'quilltest-dependencies.composer.json', contents: JSON.stringify(doc, null, 2) + '\n', kind: 'dependencies', target: 'composer' };
}

function renderHtml(bumps) {
  const withCdn = bumps.filter((b) => b.cdn);
  if (!withCdn.length) return null;
  const lines = [
    '<!-- Anne\'s Test — replacement tags for libraries the scan found at a vulnerable version. -->',
    '<!-- Self-hosted: download the file at the URL shown and replace your copy. -->',
    '<!-- CDN: replace sha384-REPLACE with the real hash BEFORE deploying; browsers block a tag whose -->',
    '<!-- integrity does not match. Compute it from the file you deploy: openssl dgst -sha384 -binary FILE | openssl base64 -A -->',
  ];
  for (const b of withCdn) {
    lines.push(`<!-- ${b.component}: ${b.from || 'detected'} → ${b.recommended}${b.sameLine ? ` (smallest step on your line: ${b.sameLine.version}${b.sameLine.lineEol ? ', but that line is end-of-life' : ''})` : ''} -->`);
    if (b.cdn.style) lines.push(`<link rel="stylesheet" href="${b.cdn.style}" integrity="sha384-REPLACE" crossorigin="anonymous">`);
    if (b.cdn.script) lines.push(`<script src="${b.cdn.script}" integrity="sha384-REPLACE" crossorigin="anonymous"></script>`);
  }
  return { filename: 'quilltest-dependencies.html', contents: lines.join('\n') + '\n', kind: 'dependencies', target: 'html' };
}

function renderShell(bumps) {
  const lines = [
    '#!/usr/bin/env sh',
    `# Anne\'s Test ${BUMP_DATA_AS_OF} — dependency and component upgrades. REVIEW BEFORE RUNNING.`,
    '# Package-manager commands are live. Runtime and server upgrades (PHP, nginx, Apache, IIS) are distribution-dependent',
    '# and appear only as commented steps to adapt; nothing here restarts a service.',
    'set -eu',
  ];
  for (const b of bumps) {
    lines.push('', `# --- ${b.component}: ${b.from || 'detected'} → ${b.recommended}${b.minimum ? ` (minimum safe: ${b.minimum})` : ''}${b.cves.length ? `  [${b.cves.slice(0, 4).join(', ')}${b.cves.length > 4 ? ', …' : ''}]` : ''}`);
    lines.push(...b.commands);
  }
  return { filename: 'quilltest-dependencies.sh', contents: lines.join('\n') + '\n', kind: 'dependencies', target: 'shell' };
}

function renderSummary(plan) {
  const esc = (s) => String(s ?? '').replace(/\|/g, '\\|');
  const lines = [
    '# Component upgrades',
    '',
    `Generated by Anne\'s Test from the scan's component findings. Version data as of ${plan.dataAsOf}; versions read from banners and asset paths may be behind distribution backports — confirm before acting.`,
    '',
    '| Component | Detected | Smallest safe step | Recommended | Because | Advisories |',
    '|---|---|---|---|---|---|',
  ];
  for (const b of plan.bumps) {
    const step = b.sameLine ? `${b.sameLine.version}${b.sameLine.lineEol ? ' (EOL line)' : ''}` : (b.minimum || '—');
    lines.push(`| ${esc(b.component)} | ${esc(b.from || '?')} | ${esc(step)} | ${esc(b.recommended)} | ${b.because.join(', ')} | ${b.cves.length ? b.cves.join(', ') : '—'} |`);
  }
  for (const b of plan.bumps) {
    lines.push('', `## ${b.component}`, '', `- Ecosystem: ${b.ecosystem}${b.pkgs.length ? ` (${b.pkgs.join(', ')})` : ''}`);
    if (b.minimum) lines.push(`- Minimum version clearing the matched advisories/EOL lines: **${b.minimum}**`);
    if (b.sameLine) lines.push(`- Last patched release on your current line: **${b.sameLine.version}** — smallest change that closes the named advisories${b.sameLine.lineEol ? '; the line itself is end-of-life, so this does not resolve the EOL finding' : ''}.`);
    lines.push(`- Recommended: **${b.recommended}**`);
    lines.push('', '```sh', ...b.commands, '```');
    for (const n of b.notes) lines.push('', `> ${n}`);
  }
  if (plan.skipped.length) {
    lines.push('', '## Not covered', '');
    for (const s of plan.skipped) lines.push(`- ${s.id || s.checkId}: ${s.title} — ${s.reason}`);
  }
  return { filename: 'quilltest-dependencies.md', contents: lines.join('\n') + '\n', kind: 'dependencies', target: 'summary' };
}

/** Render every applicable file for a plan from planDependencyBumps(). */
export function renderDependencyFiles(plan) {
  if (!plan?.bumps?.length) return [];
  return [renderNpm(plan.bumps), renderComposer(plan.bumps), renderHtml(plan.bumps), renderShell(plan.bumps), renderSummary(plan)].filter(Boolean);
}

/** Convenience: plan + files in one call. */
export function generateDependencyFixes(report) {
  const plan = planDependencyBumps(report);
  return { ...plan, files: renderDependencyFiles(plan) };
}
