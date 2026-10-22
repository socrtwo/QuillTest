/*
 * QuillTest — M3 active engine: injection points, the active phase, detection-only checks
 * Run: npm test
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { enumerate, queryPoints, formPoints, buildRequest } from '../src/scan/params.mjs';
import { allChecks, getCheck, CATEGORIES } from '../src/checks/index.mjs';
import { createContext, exec } from '../src/commands/index.mjs';
import { runScan, PROFILES, planChecks } from '../src/scan/orchestrator.mjs';
import { VerificationRequiredError } from '../src/verify/store.mjs';
import { AuthorizationRequiredError } from '../src/targets/store.mjs';
import { startServer, vulnAppHandler, safeAppHandler } from './helpers/badsite.mjs';

// ----- injection points (pure) ----------------------------------------------------------------

test('enumerate: query and form points, dedup, cross-origin and password/submit excluded', () => {
  const pages = [
    { kind: 'page', url: 'https://a.example/s?q=hi&lang=en', finalUrl: 'https://a.example/s?q=hi&lang=en', dom: { forms: [{ action: '/login', method: 'post', inputs: [{ name: 'user', type: 'text' }, { name: 'pass', type: 'password' }, { name: 'go', type: 'submit' }] }] } },
    { kind: 'page', url: 'https://a.example/s?q=other', finalUrl: 'https://a.example/s?q=other', dom: { forms: [] } },
    { kind: 'page', url: 'https://other.example/x?z=1', finalUrl: 'https://other.example/x?z=1', dom: { forms: [{ action: 'https://a.example/post', method: 'post', inputs: [{ name: 'cross', type: 'text' }] }] } },
    { kind: 'asset', url: 'https://a.example/app.js?v=2', finalUrl: 'https://a.example/app.js?v=2' },
  ];
  const pts = enumerate(pages, 'https://a.example');
  assert.deepEqual(pts.map((p) => p.id).sort(), ['form:POST https://a.example/login#user', 'query:GET https://a.example/s#lang', 'query:GET https://a.example/s#q']);
  assert.ok(!pts.some((p) => p.name === 'pass' || p.name === 'go' || p.name === 'cross' || p.name === 'z' || p.name === 'v'), 'password/submit/cross-origin/asset excluded');

  const q = buildRequest(pts.find((p) => p.name === 'q'), "MARK'");
  assert.equal(q.url, 'https://a.example/s?q=MARK%27&lang=en', 'one param replaced, others preserved and encoded');
  assert.equal(q.init.method, 'GET');
  const f = buildRequest(pts.find((p) => p.where === 'form'), 'MARK');
  assert.equal(f.url, 'https://a.example/login');
  assert.equal(f.init.method, 'POST');
  assert.equal(f.init.body, 'user=MARK');
  assert.match(f.init.headers['content-type'], /x-www-form-urlencoded/);

  // query points come from the requested URL, not a post-redirect finalUrl
  assert.deepEqual(queryPoints({ url: 'https://a.example/go?url=/x', finalUrl: 'https://a.example/x' }, 'https://a.example').map((p) => p.name), ['url']);
  assert.deepEqual(formPoints({ finalUrl: 'https://a.example/' }, { action: 'https://evil.example/p', method: 'post', inputs: [{ name: 'x', type: 'text' }] }, 'https://a.example'), [], 'never target a cross-origin form action');
});

// ----- active check registry --------------------------------------------------------------------

test('active checks are well-formed, detection-only, and carry no payload library', () => {
  const active = allChecks().filter((c) => c.kind === 'active');
  assert.ok(active.length >= 7, `only ${active.length} active checks`);
  for (const c of active) {
    assert.ok(CATEGORIES[c.id.split('.')[0]], c.id);
    assert.ok(c.requests, `${c.id} must describe its requests`);
    if (c.active) assert.ok(c.intrusiveness >= 2, `${c.id} sends input → intrusiveness ≥ 2`);
    // No weaponized payloads anywhere in an active check's source.
    const src = String(c.active) + String(c.probe) + String(c.finalize);
    assert.ok(!/<script>|onerror=|onload=|alert\(|document\.cookie|UNION\s+SELECT|SLEEP\(|WAITFOR\s+DELAY|\/etc\/passwd|;\s*rm\s|\|\s*nc\s/i.test(src), `${c.id} must not contain exploit payloads`);
  }
  for (const id of ['redirects.open', 'xss.reflected', 'injection.sqlError', 'injection.templateEval', 'injection.crlf', 'access.forcedBrowsing']) {
    assert.equal(getCheck(id).kind, 'active', id);
  }
  // CSRF form check reads only — it must not send active requests.
  assert.equal(getCheck('csrf.formToken').active, undefined);
  assert.equal(typeof getCheck('csrf.formToken').finalize, 'function');
});

test('planChecks gates active checks behind the profile', () => {
  const passive = planChecks({ profile: 'passive', origin: 'https://x.example' });
  assert.ok(passive.run.every((c) => c.kind === 'passive'));
  assert.ok(passive.skipped.some((s) => s.check.id === 'xss.reflected' && /active checks are off/.test(s.reason)));
  const standard = planChecks({ profile: 'standard', origin: 'https://x.example' });
  assert.ok(standard.run.some((c) => c.id === 'xss.reflected'));
  assert.ok(standard.run.some((c) => c.id === 'injection.sqlError'));
});

// ----- orchestrator active phase against the fixtures --------------------------------------------

let vuln; let safe;
before(async () => { vuln = await startServer(vulnAppHandler); safe = await startServer(safeAppHandler); });
after(async () => { await vuln.close(); await safe.close(); });

function readyContext(origin, opts = {}) {
  const ctx = createContext({ memory: true, ...opts });
  ctx.targets.add(origin, { name: 'fixture' });
  const ch = ctx.verifications.issue(origin);
  ctx.verifications.complete(ch, { ok: true, method: 'http', origin, url: origin + '/x' });
  ctx.targets.confirmAuthorization(origin, 'test fixture');
  return ctx;
}

test('the gate holds for active scans: no active request before both proofs', async () => {
  const ctx = createContext({ memory: true });
  const { target } = ctx.targets.add(vuln.origin);
  await assert.rejects(runScan(ctx, { target, profile: 'standard' }), VerificationRequiredError);
  const ch = ctx.verifications.issue(vuln.origin);
  ctx.verifications.complete(ch, { ok: true, method: 'http', origin: vuln.origin, url: vuln.origin + '/x' });
  await assert.rejects(runScan(ctx, { target: ctx.targets.get(vuln.origin), profile: 'standard' }), AuthorizationRequiredError);
});

test('active scan of the vulnerable app detects every planted flaw, each detection-only', async () => {
  const ctx = readyContext(vuln.origin);
  const rec = await exec(ctx, 'scan.active');
  assert.equal(rec.profile, 'standard');
  assert.deepEqual(rec.checks.errors, []);
  assert.ok(rec.crawl.injectionPoints >= 6 && rec.crawl.active > 0);
  const ids = new Set(rec.findings.map((f) => f.checkId));
  for (const id of ['redirects.open', 'xss.reflected', 'injection.sqlError', 'injection.templateEval', 'injection.crlf', 'csrf.formToken', 'access.forcedBrowsing']) {
    assert.ok(ids.has(id), `expected a ${id} finding`);
  }
  const xss = rec.findings.filter((f) => f.checkId === 'xss.reflected');
  assert.ok(xss.some((f) => f.key === 'q' && f.severity === 'high' && f.confidence === 'firm'));
  assert.equal(rec.findings.find((f) => f.checkId === 'injection.sqlError').severity, 'high');
  assert.equal(rec.findings.find((f) => f.checkId === 'redirects.open').key, 'url');
  assert.equal(rec.findings.find((f) => f.checkId === 'injection.crlf').key, 'x');
  // Evidence records the parameter and context, not an exploit string.
  const x = rec.findings.find((f) => f.checkId === 'xss.reflected');
  assert.ok(x.evidence.detail.context && Array.isArray(x.evidence.detail.unencoded));
  assert.ok(!JSON.stringify(rec.findings).includes('<script>'));
  // Active requests were logged as 'active' and are in the request log for audit.
  assert.ok(rec.requestLog.some((r) => r.kind === 'active'));
});

test('active scan of the safely-written app reports no active-category findings', async () => {
  const ctx = readyContext(safe.origin);
  const rec = await exec(ctx, 'scan.active');
  const active = rec.findings.filter((f) => ['redirects', 'xss', 'injection', 'csrf', 'access'].includes(f.checkId.split('.')[0]));
  assert.deepEqual(active.map((f) => f.checkId), [], 'a correctly-built app triggers no active detector');
  assert.deepEqual(rec.checks.errors, []);
});

test('the passive profile sends no active requests and skips active checks', async () => {
  const ctx = readyContext(vuln.origin);
  const rec = await exec(ctx, 'scan.passive');
  assert.equal(rec.crawl.active, 0);
  assert.ok(!rec.findings.some((f) => ['redirects', 'xss', 'injection', 'access'].includes(f.checkId.split('.')[0])));
  assert.ok(rec.checks.skipped.some((s) => s.id === 'xss.reflected'));
});

test('the active-request budget is enforced', async () => {
  const ctx = readyContext(vuln.origin);
  ctx.scans.updateSettings(vuln.origin, { maxActiveRequests: 5 });
  const rec = await runScan(ctx, { target: ctx.targets.get(vuln.origin), profile: 'standard' });
  assert.ok(rec.crawl.active <= 5, `active requests ${rec.crawl.active} exceeded the budget`);
  assert.ok(rec.checks.skipped.some((s) => /active request budget/.test(s.reason)) || rec.checks.run.length > 0);
});

test('per-check injection-point cap limits how many points one check probes', async () => {
  const ctx = readyContext(vuln.origin);
  ctx.scans.updateSettings(vuln.origin, { maxPointsPerCheck: 1 });
  const rec = await runScan(ctx, { target: ctx.targets.get(vuln.origin), profile: 'standard' });
  assert.deepEqual(rec.checks.errors, []);
});

test('scan.active command and scan.preview reflect the active set', async () => {
  const ctx = readyContext(vuln.origin);
  const prev = await exec(ctx, 'scan.preview', { profile: 'standard' });
  assert.ok(prev.activeChecks >= 6, `preview shows ${prev.activeChecks} active checks`);
  assert.ok(prev.checks.some((c) => c.id === 'xss.reflected' && c.intrusiveness === 2));
  assert.equal(PROFILES.standard.active, true);
  assert.equal(PROFILES.passive.active, false);
});
