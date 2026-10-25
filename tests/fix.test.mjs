/*
 * Anne's Test — version assessment and fix-artifact tests (offline)
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseVersion, compareVersions, inRange, assessVersions, osvCandidates, enrichWithOsv, osvFindings, KNOWN, KNOWN_DATA_AS_OF,
} from '../src/scan/versions.mjs';
import { generateFixes, planHeaders, buildCsp, pickTarget, TARGETS } from '../src/fix/artifacts.mjs';
import { runPassiveScan } from '../src/scan/passive.mjs';

const sig = (kind, name, version, ev = 'e') => ({ kind, name, version, evidence: [ev], confidence: 0.8 });

test('version parsing and comparison', () => {
  assert.deepEqual(parseVersion('v1.18.0'), [1, 18, 0]);
  assert.deepEqual(parseVersion('2.4.49-beta'), [2, 4, 49]);
  assert.equal(parseVersion('latest'), null);
  assert.equal(compareVersions('1.18.0', '1.20.1'), -1);
  assert.equal(compareVersions('2.4.50', '2.4.49'), 1);
  assert.equal(compareVersions('3.5', '3.5.0'), 0);
  assert.equal(compareVersions('1.10', '1.9'), 1, 'numeric, not lexical');
  assert.equal(compareVersions('x', '1'), null);
  assert.equal(inRange('2.4.49', { from: '2.4.49', below: '2.4.51' }), true);
  assert.equal(inRange('2.4.51', { from: '2.4.49', below: '2.4.51' }), false);
  assert.equal(inRange('1.0', { below: '3.0.0' }), true);
});

test('knowledge table is well-formed and dated', () => {
  assert.match(KNOWN_DATA_AS_OF, /^\d{4}-\d{2}$/);
  for (const [name, k] of Object.entries(KNOWN)) {
    assert.equal(typeof k.upgrade, 'string', name);
    for (const e of k.eol) assert.ok(parseVersion(e.below) && e.note, `${name} eol`);
    for (const a of k.advisories) {
      assert.ok(parseVersion(a.below), `${name} advisory below`);
      assert.ok(a.ids.every((id) => /^CVE-\d{4}-\d+$/.test(id)), `${name} ids`);
      assert.ok(['critical', 'high', 'medium', 'low'].includes(a.severity), `${name} severity`);
      assert.ok(a.summary && a.fixedIn, `${name} summary/fixedIn`);
    }
  }
});

test('assessVersions flags EOL and advisory ranges with exact boundaries', () => {
  const out = assessVersions({ signals: [
    sig('library', 'jQuery', '1.12.4'), sig('library', 'jQuery', '3.5.0'),
    sig('server', 'nginx', '1.18.0'), sig('server', 'nginx', '1.20.1'),
    sig('server', 'Apache', '2.4.49'), sig('server', 'Apache', '2.4.51'), sig('server', 'Apache', '2.4.58'),
    sig('framework', 'PHP', '7.4.3'), sig('framework', 'PHP', '8.2.0'),
    sig('library', 'Bootstrap', '4.3.0'), sig('library', 'Bootstrap', '4.3.1'), sig('library', 'Bootstrap', '3.3.7'),
    sig('cms', 'WordPress', '6.4.2'), sig('cms', 'Drupal', '7.98'),
    sig('server', 'Caddy', '2.7.6'), // not in the table
    sig('framework', 'PHP', null),    // no version
  ] }, { location: 'https://x/' });
  const titles = out.map((f) => f.title);
  const has = (re) => titles.some((t) => re.test(t));
  assert.ok(has(/jQuery 1\.12\.4 is end-of-life/));
  assert.ok(has(/jQuery 1\.12\.4 has known vulnerabilities \(CVE-2020-11022, CVE-2020-11023, CVE-2019-11358/));
  assert.ok(!has(/jQuery 3\.5\.0/), '3.5.0 is clean');
  assert.ok(has(/nginx 1\.18\.0 has known vulnerabilities \(CVE-2021-23017\)/));
  assert.ok(!has(/nginx 1\.20\.1/), 'fixed version is clean');
  assert.ok(has(/Apache 2\.4\.49 has known vulnerabilities \(CVE-2021-41773/));
  assert.ok(!has(/Apache 2\.4\.58/), 'recent Apache is clean');
  const a51 = out.find((f) => /Apache 2\.4\.51/.test(f.title));
  assert.ok(a51 && !a51.title.includes('41773'), '2.4.51 is outside the traversal range but inside the mod_proxy range');
  assert.ok(has(/PHP 7\.4\.3 is end-of-life/)); assert.ok(!has(/PHP 8\.2\.0/));
  assert.ok(has(/Bootstrap 4\.3\.0 has known vulnerabilities \(CVE-2019-8331\)/)); assert.ok(!has(/Bootstrap 4\.3\.1/));
  assert.ok(has(/Bootstrap 3\.3\.7 is end-of-life/) && has(/Bootstrap 3\.3\.7 has known vulnerabilities/));
  assert.ok(!has(/WordPress 6\.4\.2/));
  assert.ok(has(/Drupal 7\.98 is end-of-life/));
  assert.ok(!has(/Caddy/), 'unknown components are skipped, not guessed');
  const nginx = out.find((f) => /nginx/.test(f.title));
  assert.equal(nginx.severity, 'high'); assert.equal(nginx.confidence, 'firm', 'banner matches are firm, not confirmed');
  assert.match(nginx.evidence.caveat, /backport/);
  assert.equal(nginx.evidence.advisories[0].conditional, 'resolver directive in use');
  assert.match(nginx.remediation, /specific configurations/);
  assert.ok(out.every((f) => f.owasp === 'A06:2021 Vulnerable and Outdated Components' && f.location === 'https://x/'));
});

test('OSV enrichment maps to package coordinates, tolerates errors, and yields findings', async () => {
  const fp = { signals: [sig('library', 'jQuery', '1.12.4'), sig('library', 'Bootstrap', '4.0.0'), sig('server', 'nginx', '1.18.0'), sig('cms', 'Drupal', '9.5.0')] };
  const cands = osvCandidates(fp);
  assert.deepEqual(cands.map((c) => `${c.ecosystem}:${c.name}@${c.version}`), ['npm:jquery@1.12.4', 'npm:bootstrap@4.0.0', 'Packagist:drupal/core@9.5.0']);
  const seen = [];
  const fetchImpl = async (url, init) => {
    const body = JSON.parse(init.body); seen.push(body);
    assert.equal(url, 'https://api.osv.dev/v1/query');
    if (body.package.name === 'bootstrap') return { ok: false, status: 500 };
    if (body.package.name === 'drupal/core') throw Object.assign(new Error('x'), { name: 'TimeoutError' });
    return { ok: true, status: 200, json: async () => ({ vulns: [{ id: 'GHSA-1', aliases: ['CVE-2020-11022'], summary: 'XSS', database_specific: { severity: 'MODERATE' } }, { id: 'GHSA-2', aliases: ['CVE-2019-11358'], summary: 'proto', database_specific: { severity: 'HIGH' } }] }) };
  };
  const res = await enrichWithOsv(fp, { fetchImpl });
  assert.equal(seen.length, 3);
  assert.deepEqual(seen[0], { version: '1.12.4', package: { name: 'jquery', ecosystem: 'npm' } });
  assert.equal(res[0].vulns.length, 2); assert.equal(res[0].component, 'jQuery');
  assert.equal(res[1].error, 'HTTP 500'); assert.equal(res[2].error, 'timeout');
  const f = osvFindings(res, { location: 'https://x/' });
  assert.equal(f.length, 1);
  assert.match(f[0].title, /jQuery 1\.12\.4: 2 advisory\(ies\) in OSV \(CVE-2020-11022, CVE-2019-11358\)/);
  assert.equal(f[0].severity, 'high');
  assert.match(f[0].remediation, /jQuery 3\.x/);
});

// ----- fix artifacts -----

function fakeReport(over = {}) {
  return {
    origin: 'https://w.test',
    stack: { server: { name: 'nginx', version: '1.18.0' }, framework: [{ name: 'PHP', version: '7.4' }], cms: [] },
    assets: { scriptOrigins: ['https://cdn.test'], styleOrigins: ['https://fonts.test'], frameOrigins: [], inlineScripts: false, inlineStyles: true, eventHandlers: false, scriptsWithoutSri: 1 },
    findings: [
      { id: 'F-001', checkId: 'transport.hsts', title: 'HSTS', remediation: 'r' },
      { id: 'F-002', checkId: 'headers.csp', title: 'CSP', remediation: 'r' },
      { id: 'F-003', checkId: 'headers.frame', title: 'frame', remediation: 'r' },
      { id: 'F-004', checkId: 'headers.x-content-type-options', title: 'nosniff', remediation: 'r' },
      { id: 'F-005', checkId: 'cookies.flags', title: 'cookie', remediation: 'r' },
      { id: 'F-006', checkId: 'disclosure.server-banner', title: 'banner', remediation: 'r' },
      { id: 'F-007', checkId: 'content.sri-missing', title: 'sri', remediation: 'add integrity' },
    ],
    ...over,
  };
}

test('planHeaders emits only headers the findings call for, with provenance', () => {
  const plan = planHeaders(fakeReport());
  const names = plan.headers.map((h) => h.name);
  assert.deepEqual(names, ['Strict-Transport-Security', 'X-Content-Type-Options', 'X-Frame-Options']);
  assert.deepEqual(plan.headers[0].because, ['transport.hsts']);
  assert.ok(plan.csp, 'CSP planned because headers.csp is present');
  const noHsts = planHeaders(fakeReport({ origin: 'http://w.test' }));
  assert.ok(!noHsts.headers.some((h) => h.name === 'Strict-Transport-Security'), 'no HSTS on a plaintext origin');
  const none = planHeaders(fakeReport({ findings: [] }));
  assert.deepEqual(none.headers, []); assert.equal(none.csp, null);
});

test('buildCsp derives the allow-list from observed assets and explains every concession', () => {
  const csp = buildCsp(fakeReport());
  assert.match(csp.enforced, /script-src 'self' https:\/\/cdn\.test;/);
  assert.match(csp.enforced, /style-src 'self' https:\/\/fonts\.test 'unsafe-inline';/);
  assert.match(csp.enforced, /frame-src 'none';/);
  assert.match(csp.enforced, /object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'/);
  assert.ok(!csp.enforced.includes("script-src 'self' https://cdn.test 'unsafe-inline'"), 'no script unsafe-inline without inline scripts');
  assert.equal(csp.concessions.length, 1); assert.match(csp.concessions[0], /style-src 'unsafe-inline'/);
  assert.ok(!csp.enforced.includes('upgrade-insecure-requests'));
  const mixed = buildCsp(fakeReport({ findings: [{ checkId: 'content.mixed' }], assets: { scriptOrigins: [], styleOrigins: [], frameOrigins: ['https://yt.test'], inlineScripts: true, inlineStyles: false, eventHandlers: true } }));
  assert.match(mixed.enforced, /upgrade-insecure-requests/);
  assert.match(mixed.enforced, /frame-src https:\/\/yt\.test/);
  assert.match(mixed.concessions[0], /inline <script> blocks and inline event handlers/);
});

test('pickTarget follows the fingerprint; every renderer produces a file that names the CSP twice (report-only + enforced)', () => {
  assert.equal(pickTarget(fakeReport()), 'nginx');
  assert.equal(pickTarget(fakeReport({ stack: { server: { name: 'Apache' }, framework: [] } })), 'apache');
  assert.equal(pickTarget(fakeReport({ stack: { server: { name: 'Caddy' }, framework: [] } })), 'caddy');
  assert.equal(pickTarget(fakeReport({ stack: { server: { name: 'Microsoft-IIS' }, framework: [] } })), 'iis');
  assert.equal(pickTarget(fakeReport({ stack: { server: null, framework: [{ name: 'Express' }] } })), 'express');
  assert.equal(pickTarget(fakeReport({ stack: { server: { name: 'Vercel' }, framework: [] } })), 'netlify');
  assert.equal(pickTarget(fakeReport({ stack: { server: null, framework: [] } })), 'generic');
  const all = generateFixes(fakeReport(), { all: true });
  const headerFiles = all.files.filter((f) => f.kind === 'headers');
  assert.deepEqual(headerFiles.map((f) => f.target), TARGETS);
  for (const f of headerFiles) {
    assert.ok(!f.contents.includes('undefined'), f.target);
    if (f.target === 'express') {
      // helmet is configured by option name, not by literal header strings.
      assert.match(f.contents, /contentSecurityPolicy: \{[\s\S]*reportOnly: true/, 'express CSP starts report-only');
      assert.match(f.contents, /nosniff/, 'express snippet states helmet sets nosniff');
      continue;
    }
    assert.ok(f.contents.includes('Content-Security-Policy-Report-Only'), f.target);
    assert.ok(/Content-Security-Policy[^-]/.test(f.contents), `${f.target} should show the enforced header too`);
    assert.ok(f.contents.includes('nosniff'), f.target);
  }
});

test('renderers quote and escape correctly for their syntax', () => {
  const r = generateFixes(fakeReport(), { all: true });
  const by = (t) => r.files.find((f) => f.kind === 'headers' && f.target === t).contents;
  assert.match(by('nginx'), /add_header X-Frame-Options "SAMEORIGIN" always;/);
  assert.match(by('nginx'), /server_tokens off;/);
  assert.match(by('apache'), /<IfModule mod_headers\.c>[\s\S]*Header always set X-Content-Type-Options "nosniff"[\s\S]*<\/IfModule>/);
  assert.match(by('apache'), /Options -Indexes/);
  assert.match(by('caddy'), /header \{[\s\S]*-Server[\s\S]*\}/);
  assert.match(by('iis'), /<add name="X-Frame-Options" value="SAMEORIGIN" \/>/);
  // XML attribute values must not contain raw double quotes; CSP uses single quotes so none are expected, and any would be escaped.
  for (const line of by('iis').split('\n').filter((l) => l.includes('value="'))) {
    const val = line.match(/value="([^"]*)"/)?.[1] ?? '';
    assert.ok(!val.includes('"'), 'raw quote inside IIS attribute');
  }
  assert.match(by('express'), /helmet\(\{[\s\S]*contentSecurityPolicy: \{[\s\S]*reportOnly: true/);
  assert.match(by('express'), /"script-src": \["'self'","https:\/\/cdn\.test"\]/);
  assert.match(by('netlify'), /^\/\*\n  Strict-Transport-Security: /m);
});

test('cookie fixes follow the detected framework; coverage separates generated from manual', () => {
  const r = generateFixes(fakeReport());
  assert.ok(r.files.some((f) => f.kind === 'cookies' && f.filename.endsWith('.php.ini')), 'PHP cookie settings');
  assert.ok(r.coverage.generated.includes('cookies.flags'));
  assert.ok(r.coverage.generated.includes('disclosure.server-banner'), 'nginx file includes server_tokens off');
  assert.deepEqual(r.coverage.manual.map((m) => m.checkId), ['content.sri-missing']);
  const dj = generateFixes(fakeReport({ stack: { server: { name: 'nginx' }, framework: [{ name: 'Django' }], cms: [] } }));
  assert.ok(dj.files.some((f) => f.filename.endsWith('.django.py') && f.contents.includes('SESSION_COOKIE_SECURE = True')));
  const unknown = generateFixes(fakeReport({ stack: { server: null, framework: [], cms: [] } }));
  assert.ok(unknown.files.some((f) => f.kind === 'cookies' && f.target === 'generic'));
  const noCookie = generateFixes(fakeReport({ findings: [{ checkId: 'headers.csp' }] }));
  assert.ok(!noCookie.files.some((f) => f.kind === 'cookies'));
});

test('end to end: a scanned site yields component findings and a CSP built from its real script origins', async () => {
  const mk = (s, h = {}, b = '', sc = []) => { const hh = new Headers(h); hh.getSetCookie = () => sc; return { status: s, headers: hh, text: async () => b }; };
  const H = { 'content-type': 'text/html', server: 'Apache/2.4.49', 'x-powered-by': 'PHP/7.4.3' };
  const body = '<html><body><script src="https://code.jquery.com/jquery-1.12.4.min.js"></script><script src="/app.js"></script></body></html>';
  const f = async (url) => { const u = new URL(url); if (u.protocol === 'http:') return mk(301, { location: 'https://w.test/' }); return u.pathname === '/' ? mk(200, H, body, ['PHPSESSID=x; Path=/']) : mk(404, { 'content-type': 'text/html' }, 'nf'); };
  const report = await runPassiveScan('https://w.test', { fetchImpl: f });
  const comps = report.findings.filter((x) => x.checkId.startsWith('components.'));
  assert.ok(comps.some((x) => /Apache 2\.4\.49 has known vulnerabilities/.test(x.title)));
  assert.ok(comps.some((x) => /PHP 7\.4\.3 is end-of-life/.test(x.title)));
  assert.ok(comps.some((x) => /jQuery 1\.12\.4/.test(x.title)), 'jQuery version read from the CDN path');
  assert.deepEqual(report.assets.scriptOrigins, ['https://code.jquery.com']);
  assert.equal(report.stack.osv, null, 'OSV is off by default');
  const fx = generateFixes(report);
  assert.equal(fx.target, 'apache');
  assert.match(fx.files.find((x) => x.kind === 'headers').contents, /script-src 'self' https:\/\/code\.jquery\.com/);
  assert.ok(fx.files.some((x) => x.filename.endsWith('.php.ini')));
});
