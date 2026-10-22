/*
 * QuillTest — target management
 * Run: npm test
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { TargetStore, UnknownTargetError, AuthorizationRequiredError, NoActiveTargetError, normalizePath } from '../src/targets/store.mjs';
import { InvalidOriginError } from '../src/verify/origin.mjs';

function clock(startIso) {
  let t = new Date(startIso).getTime();
  const fn = () => new Date(t);
  fn.advance = (ms) => { t += ms; };
  return fn;
}

test('add normalizes the origin, names it after the host, makes the first target active, and is idempotent', () => {
  const store = new TargetStore({ now: clock('2026-10-22T14:00:00Z') });
  const { target, created } = store.add('HTTPS://Example.com/path', { tags: ['Prod', 'prod', ' Web '] });
  assert.equal(created, true);
  assert.equal(target.origin, 'https://example.com');
  assert.equal(target.name, 'example.com');
  assert.deepEqual(target.tags, ['prod', 'web']);
  assert.equal(target.addedAt, '2026-10-22T14:00:00Z');
  assert.deepEqual(target.scope, { include: [], exclude: [] });
  assert.deepEqual(target.authorization, { confirmed: false, confirmedAt: null, statement: null });
  assert.equal(store.active().origin, 'https://example.com');

  const again = store.add('example.com', { name: 'ignored' });
  assert.equal(again.created, false);
  assert.equal(again.target.name, 'example.com', 'existing target is returned unchanged');
  assert.equal(store.list().length, 1);
  assert.throws(() => store.add('ftp://x'), InvalidOriginError);
});

test('get / require / update / remove / setActive', () => {
  const store = new TargetStore();
  store.add('https://a.example', { name: 'A' });
  store.add('https://b.example', { name: 'B' });
  assert.equal(store.get('https://B.example/').name, 'B');
  assert.equal(store.get('https://c.example'), null);
  assert.equal(store.get('not a url at all ://'), null);
  assert.throws(() => store.require('https://c.example'), UnknownTargetError);

  store.update('https://a.example', { name: '  Site A ', notes: 'staging', tags: 'x, y' });
  assert.equal(store.get('https://a.example').name, 'Site A');
  assert.equal(store.get('https://a.example').notes, 'staging');
  assert.deepEqual(store.get('https://a.example').tags, ['x', 'y']);
  store.update('https://a.example', { name: '   ' });
  assert.equal(store.get('https://a.example').name, 'Site A', 'blank name keeps the old one');

  assert.equal(store.active().origin, 'https://a.example');
  store.setActive('https://b.example');
  assert.equal(store.active().origin, 'https://b.example');
  assert.deepEqual(store.list().map((t) => t.origin), ['https://b.example', 'https://a.example'], 'active first');
  assert.throws(() => store.setActive('https://c.example'), UnknownTargetError);

  assert.equal(store.remove('https://b.example'), true);
  assert.equal(store.active().origin, 'https://a.example', 'active falls back to a remaining target');
  assert.equal(store.remove('https://b.example'), false);
  store.remove('https://a.example');
  assert.equal(store.active(), null);
});

test('authorization must be an explicit statement and can be withdrawn', () => {
  const now = clock('2026-10-22T14:00:00Z');
  const store = new TargetStore({ now });
  store.add('https://a.example');
  assert.throws(() => store.confirmAuthorization('https://a.example', '   '), RangeError);
  const t = store.confirmAuthorization('https://a.example', ' I own this site. ');
  assert.deepEqual(t.authorization, { confirmed: true, confirmedAt: '2026-10-22T14:00:00Z', statement: 'I own this site.' });
  store.revokeAuthorization('https://a.example');
  assert.deepEqual(store.get('https://a.example').authorization, { confirmed: false, confirmedAt: null, statement: null });
  assert.match(new AuthorizationRequiredError('https://a.example').message, /not confirmed that you are authorized/);
  assert.match(new NoActiveTargetError().message, /No active target/);
});

test('scope: other origins never in scope; exclude beats include; empty include means whole origin; prefix is path-segment aware', () => {
  const store = new TargetStore();
  store.add('https://a.example');
  assert.equal(store.inScope('https://a.example', 'https://a.example/anything'), true);
  assert.equal(store.inScope('https://a.example', '/relative/path'), true, 'relative URLs resolve against the origin');
  assert.equal(store.inScope('https://a.example', 'https://www.a.example/'), false);
  assert.equal(store.inScope('https://a.example', 'http://a.example/'), false);
  assert.equal(store.inScope('https://a.example', 'http://[bad'), false, 'unparseable URL');
  assert.equal(store.inScope('https://a.example', 'just a path'), true, 'a bare string resolves as a relative path on the origin');

  store.setScope('https://a.example', { include: ['/app', 'https://a.example/api/v1/?x=1', 'shop//'], exclude: ['/app/admin/danger', '/logout'] });
  assert.deepEqual(store.get('https://a.example').scope, { include: ['/app', '/api/v1/', '/shop/'], exclude: ['/app/admin/danger', '/logout'] });
  assert.equal(store.inScope('https://a.example', '/app'), true);
  assert.equal(store.inScope('https://a.example', '/app/page?x=1'), true);
  assert.equal(store.inScope('https://a.example', '/application'), false, 'prefix must end at a path segment');
  assert.equal(store.inScope('https://a.example', '/api/v1/users'), true);
  assert.equal(store.inScope('https://a.example', '/shop/cart'), true);
  assert.equal(store.inScope('https://a.example', '/other'), false);
  assert.equal(store.inScope('https://a.example', '/app/admin/danger/delete-all'), false, 'exclude wins');
  assert.equal(store.inScope('https://a.example', '/logout'), false);

  store.setScope('https://a.example', { include: [] });
  assert.equal(store.inScope('https://a.example', '/other'), true);
  assert.equal(store.inScope('https://a.example', '/logout'), false, 'exclude list kept when only include is replaced');
  assert.equal(normalizePath('admin'), '/admin');
});

test('persists and reloads, tolerating partial records; rejects unknown versions', () => {
  const dir = mkdtempSync(join(tmpdir(), 'quilltest-targets-'));
  const path = join(dir, 'quilltest.targets.json');
  const store = TargetStore.load(path, { now: clock('2026-10-22T14:00:00Z') });
  store.add('https://a.example', { name: 'A', tags: ['t'] });
  store.confirmAuthorization('https://a.example', 'owner');
  store.setScope('https://a.example', { exclude: ['/logout'] });
  store.markScanned('https://a.example');

  const again = TargetStore.load(path);
  const t = again.get('https://a.example');
  assert.equal(t.name, 'A');
  assert.equal(t.authorization.statement, 'owner');
  assert.deepEqual(t.scope.exclude, ['/logout']);
  assert.equal(t.lastScanAt, '2026-10-22T14:00:00Z');
  assert.equal(again.active().origin, 'https://a.example');
  assert.equal(JSON.parse(readFileSync(path, 'utf8')).version, 1);

  writeFileSync(path, JSON.stringify({ version: 1, active: 'https://gone.example', targets: { 'https://p.example': { name: '' }, 'https://junk.example': 42 } }));
  const partial = TargetStore.load(path);
  assert.deepEqual(Object.keys(partial.data.targets), ['https://p.example']);
  assert.equal(partial.get('https://p.example').name, 'p.example');
  assert.equal(partial.active(), null, 'active pointing at a missing target is dropped');

  writeFileSync(path, JSON.stringify({ version: 7 }));
  assert.throws(() => TargetStore.load(path), /Unsupported targets file version 7/);
});
