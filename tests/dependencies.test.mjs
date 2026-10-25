/*
 * QuillTest — dependency-bump artifact tests (offline)
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  BUMPS, BUMP_DATA_AS_OF, minimumSafeVersion, sameLineStep, planDependencyBumps, renderDependencyFiles, generateDependencyFixes,
} from '../src/fix/dependencies.mjs';
import { KNOWN, assessVersions } from '../src/scan/versions.mjs';
import { generateFixes } from '../src/fix/artifacts.mjs';
import { runPassiveScan } from '../src/scan/passive.mjs';

const sig = (kind, name, version) => ({ kind, name, version, evidence: ['e'], confidence: 0.8 });

/** Materialize assessVersions partials the way passive.mjs does (checkId + id). */
function componentFindings(signals) {
  return assessVersions({ signals }, { location: 'https://x/' }).map((p, i) => ({
    id: `F-${String(i + 1).padStart(3, '0')}`,
    checkId: /end-of-life/.test(p.title) ? 'components.eol' : 'components.known-vulnerable',
    ...p,
  }));
}

test('bump table is dated and covers every component the version table knows', () => {
  assert.match(BUMP_DATA_AS_OF, /^\d{4}-\d{2}$/);
  for (const name of Object.keys(KNOWN)) assert.ok(BUMPS[name], `BUMPS missing ${name}`);
  for (const [name, b] of Object.entries(BUMPS)) {
    assert.ok(['npm', 'composer', 'wp-cli', 'runtime', 'server', 'manual'].includes(b.ecosystem), `${name} ecosystem`);
    assert.ok(typeof b.recommended === 'string' && b.recommended, `${name} recommended`);
    assert.ok(Array.isArray(b.commands) && b.commands.length, `${name} commands`);
    assert.ok(Array.isArray(b.notes), `${name} notes`);
    if (b.ecosystem === 'npm' || b.ecosystem === 'composer') assert.ok(b.pkg || b.pkgs?.length, `${name} package coordinates`);
  }
});

test('minimumSafeVersion is the max over matched EOL bounds and advisory fixedIn versions', () => {
  assert.equal(minimumSafeVersion('jQuery', '1.12.4'), '3.5.0', 'EOL <3.0.0 and advisories fixed in 3.5.0 → 3.5.0');
  assert.equal(minimumSafeVersion('jQuery', '3.4.1'), '3.5.0');
  assert.equal(minimumSafeVersion('jQuery', '3.5.0'), null, 'clean version has no bound');
  assert.equal(minimumSafeVersion('Bootstrap', '4.3.0'), '4.3.1');
  assert.equal(minimumSafeVersion('Bootstrap', '3.3.7'), '4.0.0', 'EOL bound beats same-line fix');
  assert.equal(minimumSafeVersion('Apache', '2.4.49'), '2.4.56');
  assert.equal(minimumSafeVersion('nginx', '1.18.0'), '1.20.1', 'first version token of "1.20.1 / 1.21.0"');
  assert.equal(minimumSafeVersion('PHP', '7.4.3'), '8.2');
  assert.equal(minimumSafeVersion('Caddy', '2.7.6'), null, 'unknown component');
  assert.equal(minimumSafeVersion('PHP', 'latest'), null, 'unparseable version');
});

test('sameLineStep offers the last patched release on the detected major only when it is safe', () => {
  assert.deepEqual(sameLineStep('Bootstrap', '4.3.0'), { version: '4.6.2', lineEol: false });
  assert.deepEqual(sameLineStep('Bootstrap', '3.3.7'), { version: '3.4.1', lineEol: true }, 'closes CVE-2019-8331 but the 3.x line is EOL');
  assert.equal(sameLineStep('jQuery', '1.12.4'), null, 'no lines table');
  const saved = BUMPS.Bootstrap.lines[4];
  BUMPS.Bootstrap.lines[4] = '4.3.0';
  try { assert.equal(sameLineStep('Bootstrap', '4.1.0'), null, 'a line release below a matched fixedIn is not offered'); } finally { BUMPS.Bootstrap.lines[4] = saved; }
});

test('planDependencyBumps merges findings per component, collects CVEs, and skips what it cannot bump', () => {
  const findings = componentFindings([
    sig('library', 'jQuery', '1.12.4'),     // eol + vuln → one bump, two findings
    sig('server', 'Apache', '2.4.49'),
    sig('framework', 'PHP', '7.4.3'),
    sig('library', 'Bootstrap', '4.3.0'),
  ]);
  findings.push({ id: 'F-900', checkId: 'headers.csp', title: 'not a component' });
  findings.push({ id: 'F-901', checkId: 'components.osv', title: 'Mystery 1.0: 1 advisory in OSV', component: 'Mystery', version: '1.0', evidence: { advisories: [{ id: 'GHSA-x' }] } });
  const plan = planDependencyBumps({ findings });

  assert.deepEqual(plan.bumps.map((b) => b.component), ['Apache', 'Bootstrap', 'PHP', 'jQuery']);
  const jq = plan.bumps.find((b) => b.component === 'jQuery');
  assert.equal(jq.because.length, 2, 'eol and vuln findings both cited');
  assert.equal(jq.from, '1.12.4');
  assert.equal(jq.minimum, '3.5.0');
  assert.equal(jq.recommended, '3.7.1');
  assert.ok(jq.cves.includes('CVE-2020-11022') && jq.cves.includes('CVE-2015-9251'));
  assert.deepEqual(jq.checkIds, ['components.eol', 'components.known-vulnerable']);
  assert.equal(jq.cdn.script, 'https://code.jquery.com/jquery-3.7.1.min.js');
  assert.deepEqual(jq.commands, ['npm install jquery@^3.7.1']);

  const bs = plan.bumps.find((b) => b.component === 'Bootstrap');
  assert.deepEqual(bs.sameLine, { version: '4.6.2', lineEol: false });
  assert.equal(bs.cdn.style, 'https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css');

  const php = plan.bumps.find((b) => b.component === 'PHP');
  assert.ok(php.commands.some((c) => c.includes('FROM php:8.3-fpm')), 'templates filled');
  assert.ok(php.commands.every((c) => c.startsWith('#')), 'runtime steps are guidance, not live commands');

  assert.deepEqual(plan.skipped.map((s) => s.id), ['F-901']);
  assert.deepEqual(plan.coveredCheckIds, ['components.eol', 'components.known-vulnerable'], 'components.osv not covered because its only finding was skipped');
  assert.equal(plan.dataAsOf, BUMP_DATA_AS_OF);
});

test('OSV-only findings get a bump with the offline minimum and a note about fixed versions', () => {
  const plan = planDependencyBumps({ findings: [
    { id: 'F-001', checkId: 'components.osv', title: 'jQuery 3.4.1: 2 advisory(ies) in OSV', component: 'jQuery', version: '3.4.1',
      evidence: { advisories: [{ id: 'GHSA-a', aliases: ['CVE-2020-11022'] }, { id: 'GHSA-b', aliases: [] }] } },
  ] });
  assert.equal(plan.bumps.length, 1);
  assert.equal(plan.bumps[0].minimum, '3.5.0');
  assert.deepEqual(plan.bumps[0].cves, ['CVE-2020-11022', 'GHSA-b']);
  assert.ok(plan.bumps[0].notes.some((n) => /OSV entries/.test(n)));
  assert.deepEqual(plan.coveredCheckIds, ['components.osv']);
});

test('table drift guard: a minimum above the recommended floor raises the recommendation', () => {
  const saved = BUMPS.jQuery.recommended;
  BUMPS.jQuery.recommended = '3.0.0';
  try {
    const plan = planDependencyBumps({ findings: componentFindings([sig('library', 'jQuery', '1.12.4')]) });
    assert.equal(plan.bumps[0].recommended, '3.5.0');
  } finally { BUMPS.jQuery.recommended = saved; }
});

test('renderers emit valid manifests, replacement tags, a reviewable shell script, and a summary', () => {
  const findings = componentFindings([
    sig('library', 'jQuery', '1.12.4'), sig('library', 'Bootstrap', '3.3.7'), sig('cms', 'Drupal', '7.98'),
    sig('server', 'nginx', '1.18.0'), sig('cms', 'WordPress', '5.9'),
  ]);
  const { files } = generateDependencyFixes({ findings });
  const by = (name) => files.find((f) => f.filename === name);
  assert.deepEqual(files.map((f) => f.filename), [
    'quilltest-dependencies.package.json', 'quilltest-dependencies.composer.json', 'quilltest-dependencies.html', 'quilltest-dependencies.sh', 'quilltest-dependencies.md',
  ]);
  assert.ok(files.every((f) => f.kind === 'dependencies'));

  const pkg = JSON.parse(by('quilltest-dependencies.package.json').contents);
  assert.deepEqual(pkg.dependencies, { bootstrap: '^5.3.3', jquery: '^3.7.1' });

  const composer = JSON.parse(by('quilltest-dependencies.composer.json').contents);
  assert.equal(composer.require['drupal/core-recommended'], '^11.0.0');
  assert.equal(composer.require['drupal/core-composer-scaffold'], '^11');

  const html = by('quilltest-dependencies.html').contents;
  assert.match(html, /<script src="https:\/\/code\.jquery\.com\/jquery-3\.7\.1\.min\.js" integrity="sha384-REPLACE" crossorigin="anonymous"><\/script>/);
  assert.match(html, /<link rel="stylesheet" href="https:\/\/cdn\.jsdelivr\.net\/npm\/bootstrap@5\.3\.3\/dist\/css\/bootstrap\.min\.css"/);
  assert.match(html, /Bootstrap: 3\.3\.7 → 5\.3\.3 \(smallest step on your line: 3\.4\.1, but that line is end-of-life\)/);
  assert.ok(!/nginx/.test(html), 'servers have no tag');

  const sh = by('quilltest-dependencies.sh').contents;
  assert.ok(sh.startsWith('#!/usr/bin/env sh'));
  assert.match(sh, /REVIEW BEFORE RUNNING/);
  assert.match(sh, /^npm install jquery@\^3\.7\.1$/m);
  assert.match(sh, /^composer require drupal\/core-recommended:\^11 /m);
  assert.match(sh, /^wp core update && wp core update-db$/m);
  assert.match(sh, /# --- nginx: 1\.18\.0 → 1\.26\.0 \(minimum safe: 1\.20\.1\)  \[CVE-2021-23017\]/);
  assert.match(sh, /^#   then: nginx -t && systemctl reload nginx$/m, 'server steps are never live commands');
  assert.ok(!sh.split('\n').some((l) => /systemctl|apachectl|dnf|apt-get/.test(l) && !l.startsWith('#')), 'no live package or service commands for servers/runtimes');

  const md = by('quilltest-dependencies.md').contents;
  assert.match(md, /^\| jQuery \| 1\.12\.4 \| 3\.5\.0 \| 3\.7\.1 \| F-\d+, F-\d+ \| CVE-2020-11022/m);
  assert.match(md, /^\| Bootstrap \| 3\.3\.7 \| 3\.4\.1 \(EOL line\) \| 5\.3\.3 \|/m, 'same-line step shown, flagged EOL');
  assert.match(md, /the line itself is end-of-life/);
  assert.match(md, /^\| WordPress \| 5\.9 \| 6\.0 \| latest \|/m);
  assert.match(md, new RegExp(`as of ${BUMP_DATA_AS_OF}`));
  assert.ok(!/## Not covered/.test(md));
});

test('nothing to render without component findings; Angular is command-only in npm output', () => {
  assert.deepEqual(renderDependencyFiles(planDependencyBumps({ findings: [{ checkId: 'headers.csp' }] })), []);
  assert.deepEqual(generateDependencyFixes({}).files, []);
  const { files } = generateDependencyFixes({ findings: componentFindings([sig('library', 'Angular', '15.2.0')]) });
  assert.ok(!files.some((f) => f.filename.endsWith('package.json')), 'ng update owns the manifest');
  assert.match(files.find((f) => f.filename.endsWith('.sh')).contents, /npx @angular\/cli@latest update @angular\/core @angular\/cli/);
});

test('generateFixes includes dependency files, covers component findings, and lists the bumps in its notes', async () => {
  const mk = (s, h = {}, b = '', sc = []) => { const hh = new Headers(h); hh.getSetCookie = () => sc; return { status: s, headers: hh, text: async () => b }; };
  const H = { 'content-type': 'text/html', server: 'Apache/2.4.49', 'x-powered-by': 'PHP/7.4.3' };
  const body = '<html><body><script src="https://code.jquery.com/jquery-1.12.4.min.js"></script></body></html>';
  const f = async (url) => { const u = new URL(url); if (u.protocol === 'http:') return mk(301, { location: 'https://w.test/' }); return u.pathname === '/' ? mk(200, H, body, ['PHPSESSID=x; Path=/']) : mk(404, { 'content-type': 'text/html' }, 'nf'); };
  const report = await runPassiveScan('https://w.test', { fetchImpl: f });
  const fx = generateFixes(report);
  const dep = fx.files.filter((x) => x.kind === 'dependencies');
  assert.deepEqual(dep.map((x) => x.filename), ['quilltest-dependencies.package.json', 'quilltest-dependencies.html', 'quilltest-dependencies.sh', 'quilltest-dependencies.md']);
  assert.deepEqual(fx.dependencies.bumps.map((b) => `${b.component} ${b.from}`), ['Apache 2.4.49', 'PHP 7.4.3', 'jQuery 1.12.4']);
  assert.ok(fx.coverage.generated.includes('components.eol') && fx.coverage.generated.includes('components.known-vulnerable'));
  assert.ok(!fx.coverage.manual.some((m) => m.checkId.startsWith('components.')), 'component findings no longer listed as manual');
  assert.ok(fx.notes.some((n) => /Dependency bumps: Apache 2\.4\.49 → 2\.4\.62, PHP 7\.4\.3 → 8\.3, jQuery 1\.12\.4 → 3\.7\.1/.test(n)));
  assert.equal(JSON.parse(dep[0].contents).dependencies.jquery, '^3.7.1');
  const none = generateFixes({ origin: 'https://x', findings: [{ id: 'F-001', checkId: 'headers.csp' }], stack: {} });
  assert.ok(!none.files.some((x) => x.kind === 'dependencies'));
  assert.equal(none.dependencies.bumps.length, 0);
});
