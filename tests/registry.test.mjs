/*
 * Anne's Test — command registry tests (offline)
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  COMMANDS, GROUPS, CONDITIONS, getCommand, commandsByGroup, scoreCommand, searchCommands, commandCliLine, validateRegistry,
} from '../src/commands/registry.mjs';

test('the registry is well-formed: unique group.verb ids, known groups and conditions', () => {
  const r = validateRegistry();
  assert.deepEqual(r.errors, []);
  assert.equal(r.ok, true);
  assert.ok(COMMANDS.length >= 20);
  for (const cmd of COMMANDS) {
    assert.ok(GROUPS.includes(cmd.group));
    assert.ok(CONDITIONS[cmd.when]);
  }
});

test('getCommand and commandsByGroup', () => {
  assert.equal(getCommand('scan.passive').group, 'Scan');
  assert.equal(getCommand('nope.nope'), null);
  const groups = commandsByGroup();
  assert.ok(groups.get('Scan').some((c) => c.id === 'scan.active'));
  // every command appears under exactly one group bucket
  const total = [...groups.values()].reduce((n, arr) => n + arr.length, 0);
  assert.equal(total, COMMANDS.length);
});

test('scoreCommand ranks exact id over prefix over keyword over group', () => {
  const active = getCommand('scan.active');
  assert.equal(scoreCommand(active, 'scan.active'), 100);
  assert.ok(scoreCommand(getCommand('scan.passive'), 'scan') >= 45);
  assert.ok(scoreCommand(active, 'redirect') >= 35, 'keyword hit');
  assert.equal(scoreCommand(active, 'zzz'), 0);
  assert.ok(scoreCommand(active, '') > 0, 'empty query matches all');
});

test('searchCommands returns ranked matches; palette-style queries work', () => {
  const csp = searchCommands('csp');
  assert.ok(csp.some((c) => c.id === 'fix.artifacts'), 'keyword search finds the fix command');
  const redirect = searchCommands('redirect');
  assert.ok(redirect[0].id === 'scan.active' || redirect.some((c) => c.id === 'scan.active'));
  // multi-word: all tokens must hit
  const mw = searchCommands('mirror scan');
  assert.ok(mw.some((c) => c.id === 'mirror.scan'));
  assert.deepEqual(searchCommands('qqqzzz'), []);
  assert.equal(searchCommands('').length, COMMANDS.length, 'empty query = all');
  assert.equal(searchCommands('verify', { limit: 2 }).length, 2);
});

test('commandCliLine renders a runnable example for script-backed commands only', () => {
  assert.match(commandCliLine(getCommand('scan.active')), /^node scripts\/scan\.mjs scan <origin> --active \[--profile\] \[--max-active-requests\]$/);
  assert.equal(commandCliLine(getCommand('help.docs')), 'docs/', 'doc path, not a node invocation');
});

test('CLI lists, searches and validates', () => {
  const run = (...a) => execFileSync(process.execPath, ['scripts/commands.mjs', ...a], { encoding: 'utf8' });
  assert.match(run(), /Scan[\s\S]*scan\.passive/);
  assert.match(run('redirect'), /scan\.active/);
  assert.match(run('--id', 'report.diff'), /Diff two scans/);
  assert.match(run('--validate'), /registry ok/);
  const json = JSON.parse(run('--json'));
  assert.equal(json.length, COMMANDS.length);
  assert.throws(() => run('qqqzzz'), (e) => e.status === 1);
});
