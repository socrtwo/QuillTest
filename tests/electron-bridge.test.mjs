/*
 * QuillTest — Electron command-bridge tests (offline; no Electron needed)
 *
 * The bridge is the security boundary: the renderer may run only a known
 * command id, with string args. These tests pin that, independent of Electron.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildRunnableMap, resolveRun } from '../electron/bridge.mjs';
import { COMMANDS } from '../src/commands/registry.mjs';

test('buildRunnableMap includes only script-backed (.mjs) commands', () => {
  const m = buildRunnableMap(COMMANDS);
  assert.ok(m.has('scan.passive'));
  assert.equal(m.get('scan.passive'), 'scripts/scan.mjs');
  // help.docs points at a doc path, not a script → excluded
  assert.ok(!m.has('help.docs'));
  assert.ok(!m.has('file.help'));
  for (const [, script] of m) assert.ok(script.endsWith('.mjs'));
});

test('resolveRun accepts a known command with string args', () => {
  const m = buildRunnableMap(COMMANDS);
  const r = resolveRun(m, 'scan.active', ['scan', 'https://example.com', '--active']);
  assert.deepEqual(r, { ok: true, script: 'scripts/scan.mjs' });
  assert.deepEqual(resolveRun(m, 'scan.passive', []), { ok: true, script: 'scripts/scan.mjs' });
});

test('resolveRun rejects unknown ids, doc commands, and bad args', () => {
  const m = buildRunnableMap(COMMANDS);
  assert.equal(resolveRun(m, 'nope.nope', []).ok, false);
  assert.match(resolveRun(m, 'file.help', []).error, /Unknown or non-runnable/);
  assert.match(resolveRun(m, 'scan.passive', 'not-an-array').error, /must be an array/);
  assert.match(resolveRun(m, 'scan.passive', ['ok', 42]).error, /array of strings/);
  assert.match(resolveRun(m, 'scan.passive', ['a\u0000b']).error, /NUL/);
});

test('every runnable command maps to a real project script name', () => {
  const m = buildRunnableMap(COMMANDS);
  const known = new Set(['scripts/scan.mjs', 'scripts/mirror.mjs', 'scripts/fix.mjs', 'scripts/report.mjs', 'scripts/ai-setup-wizard.mjs', 'scripts/ai-analyze.mjs', 'scripts/targets.mjs', 'scripts/commands.mjs']);
  for (const [, script] of m) assert.ok(known.has(script), `unexpected script ${script}`);
});
