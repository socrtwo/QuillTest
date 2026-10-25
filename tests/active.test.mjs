/*
 * QuillTest — active scan engine tests (offline)
 *
 * Besides behavior, these pin the safety invariants: only GET/OPTIONS are
 * ever sent, redirects are never followed, and the passive profile sends
 * nothing at all.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  runActiveScan, SCAN_PROFILES, DEFAULT_PROFILE, REDIRECT_MARKER_HOST, REDIRECT_PARAMS,
  parseAllowedMethods, checkHttpMethods, checkOpenRedirect, checkReflectedInput, dedupeTargets, sortActiveFindings, INTRUSIVENESS,
} from '../src/scan/active.mjs';

/** A fetch double that records every call and answers from a handler map. */
function fakeFetch(handler) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url, method: init.method, redirect: init.redirect });
    const r = handler(url, init) || { status: 404, headers: {}, body: '' };
    const headers = new Headers(r.headers || {});
    return { status: r.status ?? 200, headers, text: async () => r.body ?? '' };
  };
  return { fetchImpl, calls };
}
const ctxFrom = (f) => ({ budget: () => true, request: (url, o) => f(url, o) });

test('profiles and levels are coherent; passive is the default and does nothing', async () => {
  assert.equal(DEFAULT_PROFILE, 'passive');
  assert.equal(SCAN_PROFILES.passive.maxIntrusiveness, 0);
  assert.equal(SCAN_PROFILES['safe-active'].maxIntrusiveness, INTRUSIVENESS.benignActive);
  const { fetchImpl, calls } = fakeFetch(() => ({ status: 200 }));
  const r = await runActiveScan('https://w.test', { profile: 'passive', targets: ['https://w.test/?x=1'], fetchImpl });
  assert.deepEqual(r.findings, []);
  assert.equal(r.requests, 0);
  assert.equal(calls.length, 0, 'passive profile sends no requests');
  await assert.rejects(() => runActiveScan('https://w.test', { profile: 'nope' }), /Unknown scan profile/);
});

test('checkHttpMethods sends only OPTIONS and flags TRACE and state-changing methods', async () => {
  // A ctx.request double that answers OPTIONS from an Allow header.
  const ctx = ctxFrom(async (url, o) => ({ url, method: o.method, status: 204, headers: { allow: 'GET, HEAD, OPTIONS, TRACE, PUT, DELETE' }, body: '' }));
  const out = await checkHttpMethods('https://w.test', ctx);
  const ids = out.map((x) => x.checkId);
  assert.ok(ids.includes('active.http-trace'));
  assert.ok(ids.includes('active.http-methods'));
  assert.match(out.find((x) => x.checkId === 'active.http-trace').evidence.method, /not sent/);

  // End to end through runActiveScan: confirm only OPTIONS hits the origin root.
  const { fetchImpl, calls } = fakeFetch((url, init) => (init.method === 'OPTIONS' ? { status: 204, headers: { allow: 'GET, OPTIONS, TRACE' } } : { status: 200 }));
  const r = await runActiveScan('https://w.test', { profile: 'safe-active', targets: ['https://w.test/'], fetchImpl });
  assert.ok(r.findings.some((x) => x.checkId === 'active.http-trace'));
  assert.deepEqual(calls.map((x) => x.method), ['OPTIONS']);
});

test('parseAllowedMethods merges Allow and Access-Control-Allow-Methods', () => {
  const m = parseAllowedMethods({ headers: { allow: 'get, post', 'access-control-allow-methods': 'PUT, trace' } });
  assert.deepEqual([...m].sort(), ['GET', 'POST', 'PUT', 'TRACE']);
  assert.equal(parseAllowedMethods({ headers: {} }).size, 0);
});

test('checkOpenRedirect flags a redirect to the benign marker host and ignores same-site redirects', async () => {
  const redirecting = ctxFrom(async (url) => {
    const u = new URL(url); const dest = u.searchParams.get('next');
    return { url, status: 302, headers: { location: dest }, body: '' };
  });
  const hits = await checkOpenRedirect('https://w.test/login?next=/home', redirecting);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].checkId, 'active.open-redirect');
  assert.match(hits[0].evidence.snippet, new RegExp(REDIRECT_MARKER_HOST));
  assert.equal(hits[0].evidence.parameter, 'next');

  const sameSite = ctxFrom(async (url) => ({ url, status: 302, headers: { location: '/dashboard' }, body: '' }));
  assert.deepEqual(await checkOpenRedirect('https://w.test/login?next=/x', sameSite), []);

  const noParam = ctxFrom(async () => ({ status: 200, headers: {}, body: '' }));
  assert.deepEqual(await checkOpenRedirect('https://w.test/page?q=1', noParam), [], 'q is not a redirect param');
});

test('checkReflectedInput flags a canary echoed in HTML and ignores non-HTML or non-reflected', async () => {
  const reflect = ctxFrom(async (url) => {
    const u = new URL(url); const v = u.searchParams.get('q');
    return { url, status: 200, contentType: 'text/html; charset=utf-8', headers: {}, body: `<p>Results for ${v}</p>` };
  });
  const hits = await checkReflectedInput('https://w.test/search?q=hello', reflect);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].checkId, 'active.reflected-input');
  assert.equal(hits[0].cwe, 'CWE-79');
  assert.match(hits[0].evidence.marker, /^qtref/);

  const json = ctxFrom(async (url) => ({ url, status: 200, contentType: 'application/json', headers: {}, body: JSON.stringify({ q: 'qtrefabc' }) }));
  assert.deepEqual(await checkReflectedInput('https://w.test/api?q=1', json), [], 'non-HTML is not flagged');

  const encoded = ctxFrom(async (url) => ({ url, status: 200, contentType: 'text/html', headers: {}, body: '<p>nothing echoed</p>' }));
  assert.deepEqual(await checkReflectedInput('https://w.test/s?q=1', encoded), []);
});

test('runActiveScan: only GET/OPTIONS are sent, redirects are never followed, budget is capped', async () => {
  const { fetchImpl, calls } = fakeFetch((url, init) => {
    if (init.method === 'OPTIONS') return { status: 204, headers: { allow: 'GET, OPTIONS' } };
    const u = new URL(url);
    if (u.searchParams.has('next')) return { status: 302, headers: { location: u.searchParams.get('next') }, body: '' };
    return { status: 200, headers: { 'content-type': 'text/html' }, body: `echo ${u.searchParams.get('q') || ''}` };
  });
  const targets = ['https://w.test/a?next=/x', 'https://w.test/s?q=1', 'https://other.test/evil?q=1'];
  const r = await runActiveScan('https://w.test', { profile: 'safe-active', targets, fetchImpl, maxRequests: 5 });
  assert.ok(calls.every((c) => c.method === 'GET' || c.method === 'OPTIONS'), 'no state-changing methods');
  assert.ok(calls.every((c) => c.redirect === 'manual'), 'redirects never followed');
  assert.ok(calls.every((c) => new URL(c.url).origin === 'https://w.test'), 'off-origin target was dropped');
  assert.ok(r.requests <= 5, 'request budget enforced');
  assert.ok(r.findings.some((x) => x.checkId === 'active.open-redirect'));
  assert.ok(r.findings.some((x) => x.checkId === 'active.reflected-input'));
});

test('budget stops further probes once exhausted', async () => {
  const { fetchImpl, calls } = fakeFetch((url, init) => (init.method === 'OPTIONS' ? { status: 204, headers: { allow: 'GET' } } : { status: 200, headers: { 'content-type': 'text/html' }, body: 'x' }));
  const targets = Array.from({ length: 30 }, (_, i) => `https://w.test/p${i}?q=1`);
  const r = await runActiveScan('https://w.test', { profile: 'safe-active', targets, fetchImpl, maxRequests: 3 });
  assert.equal(r.requests, 3);
  assert.ok(calls.length <= 3);
});

test('dedupeTargets collapses URLs with the same path and parameter names', () => {
  const out = dedupeTargets(['https://w.test/s?q=a&p=1', 'https://w.test/s?p=2&q=b', 'https://w.test/s?q=c', 'not a url']);
  assert.equal(out.length, 2, 'same param-name shape collapses; different shape stays');
});

test('sortActiveFindings orders by severity then confidence', () => {
  const out = sortActiveFindings([
    { severity: 'low', confidence: 'tentative' }, { severity: 'medium', confidence: 'firm' }, { severity: 'low', confidence: 'firm' },
  ]).map((f) => `${f.severity}/${f.confidence}`);
  assert.deepEqual(out, ['medium/firm', 'low/firm', 'low/tentative']);
});

test('REDIRECT_PARAMS covers the common names', () => {
  for (const n of ['next', 'url', 'redirect', 'return', 'dest', 'continue', 'r', 'u']) assert.ok(REDIRECT_PARAMS.has(n));
});
