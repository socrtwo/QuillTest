/*
 * QuillTest — command registry, ribbon layout, executor gate, macros, catalog
 * Run: npm test
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  AREAS, ID_PATTERN, allCommands, implementedCommands, getCommand, hasCommand, searchCommands, commandsForKey, normalizeKey, def,
  createContext, exec, scanReadiness, UnknownCommandError, NotImplementedError, CommandDisabledError,
} from '../src/commands/index.mjs';
import { DEFAULT_TABS, BACKSTAGE_SECTIONS, DEFAULT_QAT, placedIds } from '../src/ui/ribbonLayout.mjs';
import { VerificationRequiredError } from '../src/verify/store.mjs';
import { AuthorizationRequiredError, NoActiveTargetError } from '../src/targets/store.mjs';
import { issueChallenge, renderVerificationFile, parseVerificationFile, matchChallenge } from '../src/verify/index.mjs';
import { catalog, CATALOG_PATH } from '../scripts/gen-catalog.mjs';

const README_TABS = ['File', 'Verify', 'Scan', 'Targets', 'Checks', 'Findings', 'Fix', 'AI', 'Report', 'Review', 'Share', 'Help'];

test('registry: every command has a valid id, label, tab, group, icon; ids are unique and areas known', () => {
  const cmds = allCommands();
  assert.ok(cmds.length >= 200, `only ${cmds.length} commands`);
  const ids = cmds.map((c) => c.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const c of cmds) {
    assert.match(c.id, ID_PATTERN, c.id);
    assert.ok(AREAS.includes(c.id.split('.')[0]), c.id);
    assert.ok(c.label && c.tab && c.group && c.icon, `${c.id} missing label/tab/group/icon`);
    assert.ok([...README_TABS, 'View', 'Developer'].includes(c.tab), `${c.id} has tab ${c.tab}`);
    assert.ok(Object.isFrozen(c), `${c.id} should be frozen`);
    if (c.requiresVerification) assert.equal(c.requiresTarget, true, `${c.id}: gated implies requiresTarget`);
  }
});

test('registry: every README tab has commands; every scan.* command that contacts the target is gated', () => {
  for (const tab of README_TABS) assert.ok(allCommands().some((c) => c.tab === tab), `no commands on tab ${tab}`);
  const ungatedScans = allCommands().filter((c) => c.id.startsWith('scan.') && !c.requiresVerification && !/pause|stop|profile|profiles|intrusiveness|crawlDepth|crawlLimits|sitemap|importUrls|schedule|history|diff|log|preview/.test(c.id));
  assert.deepEqual(ungatedScans.map((c) => c.id), [], 'scan commands that send requests must be gated');
  for (const id of ['scan.start', 'scan.passive', 'scan.active', 'scan.quick', 'scan.single', 'scan.rescan', 'findings.recheck', 'fix.recheck']) {
    assert.equal(getCommand(id).requiresVerification, true, id);
  }
});

test('registry: def() rejects bad definitions and duplicates', () => {
  assert.throws(() => def({ id: 'scan.Start', label: 'x', tab: 'Scan', group: 'g' }), /Bad command id/);
  assert.throws(() => def({ id: 'nope.thing', label: 'x', tab: 'Scan', group: 'g' }), /unknown area/);
  assert.throws(() => def({ id: 'scan.zzz', label: '', tab: 'Scan', group: 'g' }), /label is required/);
  assert.throws(() => def({ id: 'scan.zzz', label: 'x', tab: 'Scan', group: 'g', run: 42 }), /run must be a function/);
  assert.throws(() => def({ id: 'scan.zzz', label: 'x', tab: 'Scan', group: 'g', requiresVerification: true }), /implies requiresTarget/);
  assert.throws(() => def({ id: 'scan.start', label: 'x', tab: 'Scan', group: 'g' }), /Duplicate command id/);
  assert.equal(hasCommand('scan.zzz'), false);
});

test('ribbon layout: every placed id is registered, no duplicates within a group, QAT ids exist, tabs match the README', () => {
  for (const t of DEFAULT_TABS) {
    for (const g of t.groups) {
      for (const id of g.items) assert.ok(hasCommand(id), `${t.id}/${g.id}: ${id} not registered`);
      if (g.launcher) assert.ok(hasCommand(g.launcher), g.launcher);
      assert.equal(new Set(g.items).size, g.items.length, `${t.id}/${g.id} has duplicate items`);
    }
  }
  for (const s of BACKSTAGE_SECTIONS) for (const id of s.items) assert.ok(hasCommand(id) && id.startsWith('file.'), id);
  for (const id of DEFAULT_QAT) assert.ok(hasCommand(id), id);
  const visible = DEFAULT_TABS.filter((t) => !t.hidden).map((t) => t.label);
  assert.deepEqual(['File', ...visible], README_TABS);
  // Nothing is hidden: the handful of commands not placed on a tab is small and known.
  const placed = placedIds();
  const notInTabs = allCommands().filter((c) => !placed.has(c.id)).map((c) => c.id).sort();
  assert.deepEqual(notInTabs, ['ai.scrubPreview', 'findings.unmarkFalsePositive', 'target.notes']);
});

test('search and shortcuts', () => {
  const hits = searchCommands('verif');
  assert.ok(hits.length >= 5);
  assert.equal(hits[0].tab, 'Verify');
  assert.deepEqual(searchCommands('  '), []);
  assert.ok(searchCommands('start scan').some((c) => c.id === 'scan.start'));
  assert.equal(normalizeKey('Shift+Ctrl+v'), 'ctrl+shift+v');
  assert.deepEqual(commandsForKey('alt+q').map((c) => c.id), ['view.cmdSearch']);
  // No two commands share a default shortcut.
  const seen = new Map();
  for (const c of allCommands()) for (const k of c.keys || []) {
    const n = normalizeKey(k);
    if (seen.has(n) && !(n === 'ctrl+p')) assert.fail(`${k} bound to both ${seen.get(n)} and ${c.id}`);
    seen.set(n, c.id);
  }
});

function readyContext() {
  const ctx = createContext({ memory: true, now: () => new Date('2026-10-22T14:00:00Z') });
  ctx.targets.add('https://example.com', { name: 'Example' });
  return ctx;
}

test('executor: unknown, planned, disabled', async () => {
  const ctx = readyContext();
  await assert.rejects(exec(ctx, 'nope.nothing'), UnknownCommandError);
  await assert.rejects(exec(ctx, 'report.generate'), NotImplementedError);
  def({ id: 'dev.disabledTest', label: 'x', tab: 'Developer', group: 'g', internal: true, isEnabled: () => false, run: () => 1 });
  await assert.rejects(exec(ctx, 'dev.disabledTest'), CommandDisabledError);
  assert.ok(!allCommands().some((c) => c.id === 'dev.disabledTest'), 'internal commands are hidden from listings');
});

test('executor: THE GATE — scan.start needs an active target, a current verification, and confirmed authorization, in that order', async () => {
  const ctx = createContext({ memory: true, now: () => new Date('2026-10-22T14:00:00Z') });
  await assert.rejects(exec(ctx, 'scan.start'), NoActiveTargetError);

  ctx.targets.add('https://example.com');
  await assert.rejects(exec(ctx, 'scan.start'), (e) => e instanceof VerificationRequiredError && e.origin === 'https://example.com');
  assert.deepEqual(scanReadiness(ctx, 'https://example.com'), { verified: false, authorized: false, ready: false, record: null, reasons: ['no ownership verification on record for this origin', 'authorization not confirmed for this target'] });

  // Verify the origin (simulating a successful HTTP check).
  const challenge = ctx.verifications.issue('https://example.com');
  const parsed = parseVerificationFile(renderVerificationFile(challenge));
  assert.equal(matchChallenge(challenge, parsed, ctx.now()).ok, true);
  ctx.verifications.complete(challenge, { ok: true, method: 'http', origin: challenge.origin, url: 'https://example.com/x' });
  await assert.rejects(exec(ctx, 'scan.start'), (e) => e instanceof AuthorizationRequiredError && e.origin === 'https://example.com');
  assert.equal(scanReadiness(ctx, 'https://example.com').verified, true);
  assert.equal(scanReadiness(ctx, 'https://example.com').ready, false);

  await exec(ctx, 'target.confirmAuthorization', { statement: 'I own example.com' });
  const r = scanReadiness(ctx, 'https://example.com');
  assert.equal(r.ready, true);
  assert.deepEqual(r.reasons, []);
  // Gate open: the scan runs. Stub the network so the test never touches example.com.
  let requests = 0;
  ctx.fetch = async () => { requests++; return new Response('<html><body>stub</body></html>', { status: 200, headers: { 'content-type': 'text/html' } }); };
  ctx.inspectTls = async () => ({ ok: false, error: 'stubbed in test' });
  const record = await exec(ctx, 'scan.start');
  assert.equal(record.origin, 'https://example.com');
  assert.ok(requests > 0, 'the scan contacted the (stubbed) target only after the gate opened');
  assert.equal(record.authorization.statement, 'I own example.com');

  // A different origin on the same host is a different target: closed again.
  ctx.targets.add('https://www.example.com');
  ctx.targets.setActive('https://www.example.com');
  await assert.rejects(exec(ctx, 'scan.start'), VerificationRequiredError);

  // Withdrawing authorization closes the gate even while the verification is current.
  ctx.targets.setActive('https://example.com');
  await exec(ctx, 'target.revokeAuthorization');
  await assert.rejects(exec(ctx, 'scan.start'), AuthorizationRequiredError);
  await exec(ctx, 'target.confirmAuthorization', { statement: 'again' });
  await exec(ctx, 'verify.revoke');
  await assert.rejects(exec(ctx, 'scan.start'), VerificationRequiredError);
});

test('executor: verify.* and target.* commands run end to end through the registry', async () => {
  const ctx = readyContext();
  const issued = await exec(ctx, 'verify.issue', 'https://example.com');
  assert.equal(issued.challenge.origin, 'https://example.com');
  assert.match(issued.url, /^https:\/\/example\.com\/\.well-known\/quilltest-verification\/[A-Z2-7]{52}\.txt$/);
  assert.equal(issued.dns.name, '_quilltest-challenge.example.com');
  const status = await exec(ctx, 'verify.status');
  assert.equal(status.verified, false);
  assert.equal(status.pending.expires, issued.challenge.expires);
  assert.equal((await exec(ctx, 'verify.list')).pending.length, 1);
  assert.equal((await exec(ctx, 'verify.cancel')).cancelled, true);
  await assert.rejects(exec(ctx, 'verify.check'), VerificationRequiredError);

  const added = await exec(ctx, 'target.add', { origin: 'https://b.example', name: 'B', tags: ['x'] });
  assert.equal(added.created, true);
  const list = await exec(ctx, 'target.list');
  assert.equal(list.targets.length, 2);
  assert.equal(list.active, 'https://example.com');
  await exec(ctx, 'target.select', 'https://b.example');
  await exec(ctx, 'target.scope', { include: ['/app'], exclude: ['/app/logout'] });
  assert.equal((await exec(ctx, 'target.inScope', { url: '/app/x' })).inScope, true);
  assert.equal((await exec(ctx, 'target.inScope', { url: '/app/logout' })).inScope, false);
  await exec(ctx, 'target.notes', { notes: 'hello' });
  assert.equal((await exec(ctx, 'target.notes')).notes, 'hello');
  const st = await exec(ctx, 'target.status');
  assert.equal(st.target.origin, 'https://b.example');
  assert.equal(st.ready, false);
  assert.equal((await exec(ctx, 'target.remove', 'https://b.example')).removed, true);
  await assert.rejects(exec(ctx, 'target.confirmAuthorization', { statement: '' }), RangeError);
});

test('executor: macros record non-noRecord commands and replay them', async () => {
  const ctx = readyContext();
  await exec(ctx, 'dev.recordMacro');
  await exec(ctx, 'target.add', 'https://m.example');
  await exec(ctx, 'target.list');                       // noRecord → not a step
  await exec(ctx, 'target.confirmAuthorization', { origin: 'https://m.example', statement: 'mine' });
  const macro = await exec(ctx, 'dev.stopRecording', 'setup');
  assert.deepEqual(macro.steps, [
    { id: 'target.add', arg: 'https://m.example' },
    { id: 'target.confirmAuthorization', arg: { origin: 'https://m.example', statement: 'mine' } },
  ]);
  ctx.targets.remove('https://m.example');
  const run = await exec(ctx, 'dev.runMacro', 'setup');
  assert.equal(run.results[0].created, true);
  assert.equal(ctx.targets.get('https://m.example').authorization.confirmed, true);
  assert.deepEqual((await exec(ctx, 'dev.macros')).map((m) => m.name), ['setup']);
  await assert.rejects(exec(ctx, 'dev.runMacro', 'missing'), RangeError);
});

test('help and view commands return data; the about box counts match the registry', async () => {
  const ctx = readyContext();
  const about = await exec(ctx, 'help.about');
  assert.equal(about.commands, allCommands().length);
  assert.equal(about.implemented, implementedCommands().length);
  assert.ok(about.implemented >= 35);
  const ref = await exec(ctx, 'help.commandReference');
  assert.equal(ref.length, allCommands().length);
  assert.ok(ref.find((c) => c.id === 'scan.start').requiresVerification);
  const search = await exec(ctx, 'view.cmdSearch', 'authoriz');
  assert.equal(search[0].id, 'target.confirmAuthorization');
  assert.match(await exec(ctx, 'help.ethics'), /No scan without proof of ownership/);
  const shortcuts = await exec(ctx, 'help.shortcuts');
  assert.ok(shortcuts.some((s) => s.id === 'view.cmdSearch' && s.keys.includes('Alt+Q')));
});

test('ai.* setup commands cope with a missing config and describe providers', async () => {
  const ctx = readyContext();
  ctx.aiConfigPath = '/nonexistent/quilltest.ai.json';
  assert.equal((await exec(ctx, 'ai.setup')).configured, false);
  assert.deepEqual(await exec(ctx, 'ai.active'), { configured: false, active: null });
  const providers = await exec(ctx, 'ai.providers');
  assert.ok(providers.find((p) => p.id === 'anthropic' && p.configured === false));
  assert.match((await exec(ctx, 'ai.test')).error, /no valid config/);
  assert.match(await exec(ctx, 'ai.privacy'), /# /);
});

test('docs/COMMANDS.md is generated from the registry and up to date', () => {
  assert.equal(readFileSync(CATALOG_PATH, 'utf8'), catalog(), 'run: npm run catalog');
  const text = catalog();
  assert.match(text, /\*\*\d+ commands are gated\.\*\*/);
  assert.match(text, /`scan\.active` \| planned \| \*gated\*/);
  assert.match(text, /`scan\.start` \| implemented \| \*gated\*/);
  assert.match(text, /`verify\.issue` \| implemented/);
});
