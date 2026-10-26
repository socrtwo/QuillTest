/*
 * Anne's Test — fix/report layer regression tests
 * Each test pins a defect found in review so it cannot come back.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, existsSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFileSync, spawnSync } from 'node:child_process';
import { buildReviewPackage, verifyManifest, renderCsv, safeArtifactName, isSafePackagePath } from '../src/report/render.mjs';
import { buildCsp, generateFixes } from '../src/fix/artifacts.mjs';
import { generatePatchForFile } from '../src/fix/patch.mjs';
import { planDependencyBumps } from '../src/fix/dependencies.mjs';

const ROOT = resolve(new URL('..', import.meta.url).pathname);
const report = (extra = {}) => ({ origin: 'https://x.test', stack: { server: { name: 'nginx' }, framework: [], cms: [] }, assets: { scriptOrigins: [], styleOrigins: [], frameOrigins: [], inlineScripts: false, inlineStyles: false, eventHandlers: false }, findings: [{ id: 'F-001', checkId: 'headers.csp', title: 't', severity: 'medium', confidence: 'firm', location: 'https://x.test/', remediation: 'r' }], ...extra });

test('review package: fix file names from the report cannot escape the package directory', () => {
  const evil = report({ fixes: { target: 'nginx', files: [{ filename: '../../pwned.txt', kind: 'headers', target: 'nginx', contents: 'x' }], notes: [], coverage: { manual: [] } } });
  assert.throws(() => buildReviewPackage(evil), /unsafe artifact file name/);
  for (const bad of ['../x', 'a/b', 'a\\b', '.hidden', '..', '']) assert.throws(() => safeArtifactName(bad), bad);
  assert.equal(safeArtifactName('quilltest-security-headers.nginx.conf'), 'quilltest-security-headers.nginx.conf');
});

test('review package: --verify refuses manifest paths that leave the package directory', () => {
  const dir = mkdtempSync(join(tmpdir(), 'qt-pkg-'));
  mkdirSync(join(dir, 'pkg'));
  writeFileSync(join(dir, 'secret.txt'), 'hello');
  const manifest = { files: [{ path: '../secret.txt', sha256: '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824' }] };
  const res = verifyManifest(manifest, (rel) => readFileSync(join(dir, 'pkg', rel)));
  assert.equal(res.ok, false);
  assert.equal(res.results[0].reason, 'unsafe path in manifest');
  assert.deepEqual(['fixes/a.conf', 'report.json'].map(isSafePackagePath), [true, true]);
  assert.deepEqual(['../../etc/hostname', '/etc/x', 'a\\b', 'C:/x', 'a/../b', ''].map(isSafePackagePath), [false, false, false, false, false, false]);
});

test('CSV: cells that would be read as spreadsheet formulas are neutralised', () => {
  const csv = renderCsv(report({ findings: [{ id: 'F-1', checkId: 'c', title: '=HYPERLINK("http://evil")', severity: 'low', confidence: 'firm', location: 'https://x/', remediation: '+cmd|x' }] }));
  const row = csv.split('\n')[1];
  assert.match(row, /"'=HYPERLINK\(""http:\/\/evil""\)"/);
  assert.match(row, /"'\+cmd\|x"/);
  assert.match(renderCsv(report()).split('\n')[1], /^F-001,medium,firm,headers\.csp,t,/, 'ordinary cells are untouched');
});

test('derived CSP: frame-src keeps same-origin iframes working', () => {
  const none = buildCsp(report());
  assert.match(none.enforced, /frame-src 'self';/);
  const ext = buildCsp(report({ assets: { scriptOrigins: [], styleOrigins: [], frameOrigins: ['https://yt.test'], inlineScripts: false, inlineStyles: false, eventHandlers: false } }));
  assert.match(ext.enforced, /frame-src 'self' https:\/\/yt\.test;/);
});

test('Express artifact disables helmet defaults so the emitted policy equals the derived one', () => {
  const fx = generateFixes(report({ stack: { server: { name: 'nginx' }, framework: [{ name: 'Express' }], cms: [] } }), { target: 'express' });
  const js = fx.files.find((f) => f.filename.endsWith('.express.js')).contents;
  assert.match(js, /useDefaults: false/);
});

test('CDN replacement tags say the placeholder integrity must be replaced before deploying', () => {
  const plan = planDependencyBumps({ findings: [{ id: 'F-1', checkId: 'components.eol', title: 'jQuery 1.12.4', component: 'jQuery', version: '1.12.4', evidence: { component: 'jQuery', version: '1.12.4' } }] });
  const fx = generateFixes(report({ findings: [{ id: 'F-1', checkId: 'components.eol', title: 'jQuery 1.12.4', component: 'jQuery', version: '1.12.4', evidence: { component: 'jQuery', version: '1.12.4' }, remediation: 'r' }] }));
  const html = fx.files.find((f) => f.filename === 'quilltest-dependencies.html').contents;
  assert.ok(plan.bumps.length);
  assert.match(html, /replace sha384-REPLACE with the real hash BEFORE deploying/);
  assert.doesNotMatch(html, /use the tag as is/);
});

test('patch: a dependency name with regex metacharacters is matched literally', () => {
  const contents = '{\n  "dependencies": {\n    "jqueryx": "^1.0",\n    "jquery": "^1.12.4"\n  }\n}\n';
  const r = generatePatchForFile({ findings: [{ checkId: 'components.eol', component: 'jQuery', version: '1.12.4', evidence: { component: 'jQuery', version: '1.12.4' } }] }, { filename: 'package.json', path: 'package.json', contents });
  assert.equal(r.changes.length, 1);
  assert.match(r.patch, /-    "jquery": "\^1\.12\.4"\n\+    "jquery": "\^3\.7\.1"/);
  assert.doesNotMatch(r.patch, /^[-+].*jqueryx/m, "the neighbouring package appears only as context");
  // the escape itself: a dotted name must not match a different character in that position
  const escaped = 'lodash.merge'.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  assert.equal(escaped, 'lodash\\.merge');
  assert.equal(new RegExp(escaped).test('lodashXmerge'), false);
});

test('fix CLI: a bare --report and a finding without remediation text exit cleanly, and same-named manifests get distinct patches', () => {
  const dir = mkdtempSync(join(tmpdir(), 'qt-fix-'));
  const bare = spawnSync(process.execPath, [join(ROOT, 'scripts/fix.mjs'), '--report'], { encoding: 'utf8' });
  assert.equal(bare.status, 2, 'usage, not a TypeError stack');
  assert.doesNotMatch(bare.stderr, /TypeError/);

  const rep = join(dir, 'r.json');
  writeFileSync(rep, JSON.stringify({ origin: 'https://x.test', stack: { server: { name: 'nginx' } }, findings: [
    { id: 'F-1', checkId: 'components.eol', title: 'jQuery 1.12.4', component: 'jQuery', version: '1.12.4', evidence: { component: 'jQuery', version: '1.12.4' } },
    { id: 'F-2', checkId: 'cors.reflect', title: 'no remediation here' },
  ] }));
  mkdirSync(join(dir, 'a')); mkdirSync(join(dir, 'b'));
  writeFileSync(join(dir, 'a/package.json'), '{\n  "dependencies": {\n    "jquery": "^1.12.4"\n  }\n}\n');
  writeFileSync(join(dir, 'b/package.json'), '{\n  "dependencies": {\n    "jquery": "~2.2.4"\n  }\n}\n');
  const out = execFileSync(process.execPath, [join(ROOT, 'scripts/fix.mjs'), '--report', rep, '--patch', 'a/package.json', '--patch', 'b/package.json', '--out', join(dir, 'p')], { cwd: dir, encoding: 'utf8' });
  assert.match(out, /no remediation text in the report/);
  assert.ok(existsSync(join(dir, 'p/a__package.json.patch')) && existsSync(join(dir, 'p/b__package.json.patch')), out);
  assert.match(readFileSync(join(dir, 'p/a__package.json.patch'), 'utf8'), /^--- a\/a\/package\.json\n\+\+\+ b\/a\/package\.json/);
  assert.match(readFileSync(join(dir, 'p/b__package.json.patch'), 'utf8'), /~2\.2\.4/);
});
