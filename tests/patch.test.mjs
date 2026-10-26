/*
 * Anne's Test — level-3 patch generation tests (offline)
 *
 * Besides unit checks, the CLI test applies every generated patch with the
 * real `git apply`, so a diff that git would reject fails the suite.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { unifiedDiff, lineOps, patchPackageJson, patchComposerJson, patcherFor, generatePatchForFile } from '../src/fix/patch.mjs';

const componentFinding = (component, version, eol = false) => ({
  id: `F-${component}`, checkId: eol ? 'components.eol' : 'components.known-vulnerable',
  title: `${component} ${version}`, component, version,
  evidence: { component, version },
});

// ---- unified diff ----

test('unifiedDiff returns empty for identical text and a valid hunk for a one-line change', () => {
  assert.equal(unifiedDiff('a\nb\n', 'a\nb\n'), '');
  const d = unifiedDiff('a\nb\nc\n', 'a\nB\nc\n', { path: 'x.txt' });
  assert.match(d, /^--- a\/x\.txt\n\+\+\+ b\/x\.txt\n@@ -1,3 \+1,3 @@\n a\n-b\n\+B\n c\n$/);
});

test('unifiedDiff marks a missing final newline', () => {
  const d = unifiedDiff('a\nb', 'a\nB', { path: 'x' });
  assert.match(d, /-b\n\\ No newline at end of file\n\+B\n\\ No newline at end of file\n/);
});

test('lineOps produces a correct edit script', () => {
  const ops = lineOps(['a', 'b', 'c'], ['a', 'x', 'c']);
  assert.deepEqual(ops.map((o) => o.t), ['eq', 'del', 'ins', 'eq']);
});

// ---- package.json ----

const PKG = `{
  "name": "demo",
  "version": "1.0.0",
  "dependencies": {
    "jquery": "^1.12.4",
    "left-pad": "~1.3.0"
  },
  "devDependencies": {
    "bootstrap": "4.3.0"
  }
}
`;

test('patchPackageJson bumps only flagged, out-of-date deps and preserves formatting', () => {
  const { newText, changes, skipped } = patchPackageJson(PKG, [
    { component: 'jQuery', recommended: '3.7.1', ecosystem: 'npm' },
    { component: 'Bootstrap', recommended: '5.3.3', ecosystem: 'npm' },
  ]);
  assert.ok(JSON.parse(newText), 'result is still valid JSON');
  assert.equal(JSON.parse(newText).dependencies.jquery, '^3.7.1');
  assert.equal(JSON.parse(newText).devDependencies.bootstrap, '^5.3.3');
  assert.equal(JSON.parse(newText).dependencies['left-pad'], '~1.3.0', 'untouched dep preserved');
  assert.deepEqual(changes.map((c) => [c.pkg, c.from, c.to, c.block]).sort(), [
    ['bootstrap', '4.3.0', '^5.3.3', 'devDependencies'], ['jquery', '^1.12.4', '^3.7.1', 'dependencies'],
  ]);
  // original indentation (2 spaces) kept
  assert.match(newText, /\n    "jquery": "\^3\.7\.1"/);
  assert.equal(skipped.length, 0);
});

test('patchPackageJson skips a dep already at or above the target, and one not present', () => {
  const { changes, skipped } = patchPackageJson('{"dependencies":{"jquery":"^3.9.0"}}', [
    { component: 'jQuery', recommended: '3.7.1', ecosystem: 'npm' },
    { component: 'Bootstrap', recommended: '5.3.3', ecosystem: 'npm' },
  ]);
  assert.equal(changes.length, 0);
  assert.ok(skipped.some((s) => s.pkg === 'jquery' && /already at/.test(s.reason)));
  assert.ok(skipped.some((s) => s.pkg === 'bootstrap' && /not present/.test(s.reason)));
});

test('patchPackageJson does not patch Angular (ng update owns the manifest)', () => {
  const { changes } = patchPackageJson('{"dependencies":{"@angular/core":"15.0.0"}}', [{ component: 'Angular', recommended: '19.0.0', ecosystem: 'npm' }]);
  assert.equal(changes.length, 0);
});

test('patchPackageJson throws on invalid JSON', () => {
  assert.throws(() => patchPackageJson('{ not json', []), /not valid JSON/);
});

// ---- composer.json ----

test('patchComposerJson bumps the drupal core trio under require', () => {
  const COMPOSER = `{
  "require": {
    "php": ">=8.1",
    "drupal/core-recommended": "^9.5",
    "drupal/core-composer-scaffold": "^9.5"
  }
}
`;
  const { newText, changes } = patchComposerJson(COMPOSER, [{ component: 'Drupal', recommended: '11.0.0', ecosystem: 'composer' }]);
  const j = JSON.parse(newText);
  assert.equal(j.require['drupal/core-recommended'], '^11.0.0');
  assert.equal(j.require['drupal/core-composer-scaffold'], '^11');
  assert.equal(j.require.php, '>=8.1', 'php left alone');
  assert.ok(changes.some((c) => c.pkg === 'drupal/core-recommended'));
});

// ---- dispatch + end-to-end ----

test('patcherFor picks by basename then by content shape', () => {
  assert.equal(patcherFor('path/to/package.json', '{}').kind, 'package.json');
  assert.equal(patcherFor('whatever.json', '{"require":{}}').kind, 'composer.json');
  assert.equal(patcherFor('x.json', '{"dependencies":{}}').kind, 'package.json');
  assert.equal(patcherFor('notes.txt', 'hello'), null);
});

test('generatePatchForFile returns a diff scoped to the manifest ecosystem', () => {
  const report = { findings: [componentFinding('jQuery', '1.12.4', true), componentFinding('Drupal', '7.98', true)] };
  const res = generatePatchForFile(report, { filename: 'package.json', contents: PKG });
  assert.equal(res.kind, 'package.json');
  assert.match(res.patch, /^--- a\/package\.json/m);
  assert.match(res.patch, /-    "jquery": "\^1\.12\.4"/);
  assert.match(res.patch, /\+    "jquery": "\^3\.7\.1"/);
  assert.ok(!/drupal/.test(res.patch), 'composer-only bump not applied to package.json');
  const none = generatePatchForFile(report, { filename: 'notes.txt', contents: 'x' });
  assert.match(none.error, /not a supported manifest/);
});

test('CLI --patch writes a diff that git apply accepts and leaves the file unchanged', () => {
  const dir = mkdtempSync(join(tmpdir(), 'qt-patch-'));
  execFileSync('git', ['init', '-q'], { cwd: dir });
  execFileSync('git', ['config', 'user.email', 't@t'], { cwd: dir });
  execFileSync('git', ['config', 'user.name', 't'], { cwd: dir });
  const pkgPath = join(dir, 'package.json');
  writeFileSync(pkgPath, PKG);
  const report = { findings: [componentFinding('jQuery', '1.12.4', true), componentFinding('Bootstrap', '4.3.0')] };
  const reportPath = join(dir, 'scan.json');
  writeFileSync(reportPath, JSON.stringify(report));

  const repoRoot = process.cwd();
  const out = execFileSync(process.execPath, [join(repoRoot, 'scripts/fix.mjs'), '--report', reportPath, '--patch', 'package.json', '--out', join(dir, 'fixes')], { cwd: dir, encoding: 'utf8' });
  assert.match(out, /jquery \^1\.12\.4 -> \^3\.7\.1/);
  assert.match(out, /never modifies your files/);

  const patchPath = join(dir, 'fixes', 'package.json.patch');
  assert.ok(existsSync(patchPath));
  // The operator's file is untouched until they apply the patch.
  assert.equal(readFileSync(pkgPath, 'utf8'), PKG);
  // git apply --check must accept it, then applying it yields a bumped, valid manifest.
  execFileSync('git', ['apply', '--check', patchPath], { cwd: dir });
  execFileSync('git', ['apply', patchPath], { cwd: dir });
  const after = JSON.parse(readFileSync(pkgPath, 'utf8'));
  assert.equal(after.dependencies.jquery, '^3.7.1');
  assert.equal(after.devDependencies.bootstrap, '^5.3.3');
  assert.equal(after.dependencies['left-pad'], '~1.3.0');

  // A manifest with nothing flagged writes no patch.
  writeFileSync(join(dir, 'clean.json'), '{"dependencies":{"react":"^18.0.0"}}');
  const out2 = execFileSync(process.execPath, [join(repoRoot, 'scripts/fix.mjs'), '--report', reportPath, '--patch', 'clean.json', '--out', join(dir, 'fixes2')], { cwd: dir, encoding: 'utf8' });
  assert.match(out2, /clean\.json: nothing to change/);
  assert.ok(!existsSync(join(dir, 'fixes2', 'clean.json.patch')));
});
