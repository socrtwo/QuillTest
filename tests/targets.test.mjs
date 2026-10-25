/*
 * Anne's Test — target management tests (offline)
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { createTargetStore, withStatus, byTag, summarizeSeverity } from '../src/targets/store.mjs';

const tmpFile = () => join(mkdtempSync(join(tmpdir(), 'qt-tgt-')), 'targets.json');

test('add normalizes the origin, dedupes, and merges on re-add', () => {
  const store = createTargetStore(tmpFile());
  const a = store.add('example.com', { label: 'Prod', tags: ['prod', 'prod', 'eu'], note: 'main', now: new Date('2026-10-25T10:00:00Z') });
  assert.equal(a.created, true);
  assert.equal(a.target.origin, 'https://example.com', 'scheme defaulted, normalized');
  assert.deepEqual(a.target.tags, ['prod', 'eu'], 'tags deduped');
  // re-add merges: new tag unioned, label updated, addedAt kept
  const b = store.add('https://example.com', { label: 'Production', tags: ['us'], now: new Date('2026-10-26T10:00:00Z') });
  assert.equal(b.created, false);
  assert.equal(b.target.label, 'Production');
  assert.deepEqual(b.target.tags, ['prod', 'eu', 'us']);
  assert.equal(b.target.addedAt, '2026-10-25T10:00:00.000Z');
  assert.equal(store.list().length, 1, 'no duplicate');
});

test('add throws on an invalid origin', () => {
  const store = createTargetStore(tmpFile());
  assert.throws(() => store.add('ftp://x'), /http\(s\)/);
  assert.throws(() => store.add(''), /required/);
});

test('get, remove and update', () => {
  const store = createTargetStore(tmpFile());
  store.add('a.test'); store.add('b.test');
  assert.equal(store.get('a.test').origin, 'https://a.test');
  assert.equal(store.get('nope.test'), null);
  assert.equal(store.remove('a.test'), true);
  assert.equal(store.remove('a.test'), false, 'already gone');
  assert.equal(store.list().length, 1);
  assert.equal(store.update('b.test', { note: 'hi' }).note, 'hi');
  assert.equal(store.update('ghost.test', { note: 'x' }), null);
});

test('recordScan stores a severity summary', () => {
  const store = createTargetStore(tmpFile());
  store.add('a.test');
  const t = store.recordScan('a.test', { findings: [{ severity: 'high' }, { severity: 'high' }, { severity: 'low' }], reportPath: 'r.json', now: new Date('2026-10-25T12:00:00Z') });
  assert.equal(t.lastScan.total, 3);
  assert.deepEqual(t.lastScan.bySeverity, { critical: 0, high: 2, medium: 0, low: 1, info: 0 });
  assert.equal(t.lastScanAt, '2026-10-25T12:00:00.000Z');
  assert.equal(t.lastScan.reportPath, 'r.json');
});

test('summarizeSeverity buckets unknown severities as info', () => {
  assert.deepEqual(summarizeSeverity([{ severity: 'bogus' }, { severity: 'critical' }]), { total: 2, bySeverity: { critical: 1, high: 0, medium: 0, low: 0, info: 1 } });
});

test('withStatus joins verification state', () => {
  const now = new Date('2026-10-25T12:00:00Z');
  const future = new Date(now.getTime() + 86400000).toISOString();
  const past = new Date(now.getTime() - 1000).toISOString();
  const targets = [{ origin: 'https://v.test' }, { origin: 'https://e.test' }, { origin: 'https://u.test' }];
  const records = [
    { origin: 'https://v.test', method: 'http-file', verifiedAt: past, expires: future },
    { origin: 'https://e.test', method: 'http-file', verifiedAt: past, expires: past },
  ];
  const joined = withStatus(targets, records, now);
  assert.equal(joined[0].verification.state, 'verified');
  assert.equal(joined[0].verification.expires, future);
  assert.equal(joined[1].verification.state, 'expired');
  assert.equal(joined[2].verification.state, 'unverified');
});

test('byTag filters', () => {
  const t = [{ origin: 'a', tags: ['prod'] }, { origin: 'b', tags: ['dev'] }, { origin: 'c', tags: ['prod', 'eu'] }];
  assert.deepEqual(byTag(t, 'prod').map((x) => x.origin), ['a', 'c']);
});

test('CLI add/list/show/remove round trip with verification status', () => {
  const dir = mkdtempSync(join(tmpdir(), 'qt-tgt-'));
  const file = join(dir, 'targets.json');
  const store = join(dir, 'verify');
  // seed a verified record
  const now = new Date();
  const future = new Date(now.getTime() + 86400000).toISOString();
  writeFileSync(join(dir, 'verified.json'), JSON.stringify([{ origin: 'https://seen.test', method: 'http-file', verifiedAt: now.toISOString(), expires: future }]));
  const run = (...a) => execFileSync(process.execPath, ['scripts/targets.mjs', ...a, '--file', file, '--store', dir], { encoding: 'utf8' });

  assert.match(run('add', 'seen.test', '--label', 'Prod', '--tag', 'prod'), /added/);
  assert.match(run('add', 'fresh.test', '--tag', 'dev'), /added/);
  const list = run('list');
  assert.match(list, /2 target\(s\)/);
  assert.match(list, /verified.*seen\.test/s);
  assert.match(list, /unverified.*fresh\.test/s);
  assert.match(run('list', '--tag', 'prod'), /seen\.test/);
  assert.ok(!/fresh\.test/.test(run('list', '--tag', 'prod')), 'tag filter excludes dev');
  assert.match(run('show', 'seen.test'), /ownership: .*verified/s);
  assert.match(run('remove', 'fresh.test'), /removed/);
  const json = JSON.parse(run('list', '--json'));
  assert.equal(json.length, 1);
  assert.equal(json[0].verification.state, 'verified');
});
