/*
 * Anne's Test — staging-mirror tests (offline; the loopback server binds 127.0.0.1)
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  buildMirrorManifest, captureMirror, loadMirror, serveMirror, mirrorFetchFromManifest, scanMirror, indexMirror, MIRROR_MANIFEST,
} from '../src/scan/mirror.mjs';

/** A tiny two-page site with a missing CSP and a jQuery on a CDN path. */
function siteFetch() {
  const H = (o) => { const h = new Headers(o); h.getSetCookie = () => (o && o['set-cookie'] ? [].concat(o['set-cookie']) : []); return h; };
  const mk = (status, headers, body) => ({ status, headers: H(headers), text: async () => body ?? '' });
  const home = '<html><head></head><body><a href="/about">about</a>' +
    '<script src="https://cdn.jsdelivr.net/npm/jquery@1.12.4/dist/jquery.min.js"></script></body></html>';
  const about = '<html><body><p>about us</p></body></html>';
  return async (url) => {
    const u = new URL(url);
    if (u.protocol === 'http:') return mk(301, { location: 'https://site.test/' });
    if (u.pathname === '/robots.txt') return mk(404, { 'content-type': 'text/plain' }, 'nope');
    if (u.pathname === '/') return mk(200, { 'content-type': 'text/html', server: 'nginx/1.18.0' }, home);
    if (u.pathname === '/about') return mk(200, { 'content-type': 'text/html', server: 'nginx/1.18.0' }, about);
    return mk(404, { 'content-type': 'text/html' }, 'nf');
  };
}

test('buildMirrorManifest records pages, captures HTML bodies and respects the byte cap', async () => {
  const { crawl } = await import('../src/scan/crawl.mjs');
  const crawlResult = await crawl('https://site.test', { fetchImpl: siteFetch(), maxPages: 5, maxDepth: 2, respectRobots: false });
  const { manifest, files } = buildMirrorManifest(crawlResult, { now: new Date('2026-10-25T12:00:00Z') });
  assert.equal(manifest.origin, 'https://site.test');
  assert.ok(manifest.pageCount >= 2);
  assert.ok(files.length >= 2, 'HTML bodies stored');
  assert.ok(manifest.pages.every((p) => p.headers && !('content-length' in p.headers)), 'hop-by-hop headers stripped');
  assert.equal(manifest.capturedAt, '2026-10-25T12:00:00.000Z');

  // Byte cap: a tiny cap captures nothing and marks truncated.
  const tiny = buildMirrorManifest(crawlResult, { maxBytes: 10 });
  assert.equal(tiny.files.length, 0);
  assert.equal(tiny.manifest.truncated, true);
});

test('captureMirror writes a manifest and body files, loadMirror reads them back', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'qt-mirror-'));
  const res = await captureMirror('https://site.test', { fetchImpl: siteFetch(), outDir: dir, maxPages: 5, maxDepth: 2, respectRobots: false });
  assert.ok(existsSync(join(dir, MIRROR_MANIFEST)));
  assert.equal(res.manifest.origin, 'https://site.test');
  const loaded = loadMirror(dir);
  const home = loaded.pages.find((p) => p.url === 'https://site.test/');
  assert.ok(home && /jquery@1\.12\.4/.test(home.body), 'body round-trips from disk');
});

test('serveMirror replays captured responses on 127.0.0.1 and 404s the rest', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'qt-mirror-'));
  await captureMirror('https://site.test', { fetchImpl: siteFetch(), outDir: dir, maxPages: 5, maxDepth: 2, respectRobots: false });
  const manifest = loadMirror(dir);
  const srv = await serveMirror(manifest);
  try {
    assert.equal(srv.host, '127.0.0.1', 'loopback only');
    const r = await fetch(`${srv.url}/`);
    assert.equal(r.status, 200);
    assert.equal(r.headers.get('server'), 'nginx/1.18.0', 'captured headers replayed');
    assert.match(await r.text(), /jquery@1\.12\.4/);
    const about = await fetch(`${srv.url}/about`);
    assert.equal(about.status, 200);
    const miss = await fetch(`${srv.url}/not-captured`);
    assert.equal(miss.status, 404);
  } finally { await srv.close(); }
});

test('mirrorFetchFromManifest answers from the snapshot and 404s unknown paths', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'qt-mirror-'));
  await captureMirror('https://site.test', { fetchImpl: siteFetch(), outDir: dir, maxPages: 5, maxDepth: 2, respectRobots: false });
  const f = mirrorFetchFromManifest(loadMirror(dir));
  const root = await f('https://site.test/');
  assert.equal(root.status, 200);
  assert.equal(root.headers.get('server'), 'nginx/1.18.0');
  const missing = await f('https://site.test/.git/HEAD');
  assert.equal(missing.status, 404, 'uncaptured probe path is absent, not invented');
});

test('scanMirror runs the passive engine on the copy; findings name the real origin', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'qt-mirror-'));
  await captureMirror('https://site.test', { fetchImpl: siteFetch(), outDir: dir, maxPages: 5, maxDepth: 2, respectRobots: false });
  const report = await scanMirror('https://site.test', { dir });
  assert.equal(report.origin, 'https://site.test');
  assert.ok(report.mirror && report.mirror.pageCount >= 2);
  assert.ok(report.findings.every((x) => !/127\.0\.0\.1|localhost/.test(x.location)), 'no loopback leaks into findings');
  assert.ok(report.findings.some((x) => x.location.startsWith('https://site.test')));
  // The captured stack and a component finding come through.
  assert.match(report.stack.summary, /nginx\/1\.18\.0/);
  assert.ok(report.findings.some((x) => /jQuery 1\.12\.4/.test(x.title)), 'component finding from the snapshot');
  // A missing-CSP style header finding is present (no CSP header was captured).
  assert.ok(report.findings.some((x) => /content-security-policy|csp/i.test(x.checkId) || /content-security-policy/i.test(x.title)));
  // The http->https redirect was never captured, so that check must not fire a false finding on the mirror.
  assert.ok(!report.findings.some((x) => x.checkId === 'transport.http-not-redirected'), 'scheme-dependent check skipped, not falsely flagged');
  assert.match(report.mirror.note, /live-scheme checks/);
});

test('indexMirror keys by url and requestedUrl', () => {
  const idx = indexMirror({ pages: [{ url: 'https://s.test/a', requestedUrl: 'https://s.test/a?ref=1', headers: {} }] });
  assert.ok(idx.has('https://s.test/a'));
  assert.ok(idx.has('https://s.test/a?ref=1'));
});
