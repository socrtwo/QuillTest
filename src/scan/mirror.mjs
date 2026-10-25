/*
 * Anne's Test — staging-mirror capture, serve, and scan
 * Part of the Anne's Office suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * A mirror is a local, sandboxed copy of the client-delivered surface of your
 * OWN verified site — the HTML, response headers, scripts and forms a browser
 * would receive. It does not reproduce server-side code or data. See
 * docs/STAGING-MIRROR.md. The ownership gate lives in the CLI (scripts/
 * mirror.mjs) and src/verify/, exactly as for a live scan; nothing here copies
 * an origin the caller has not verified.
 *
 * Three steps, each usable on its own:
 *   1. captureMirror(origin)  — a bounded, same-origin, robots-aware crawl
 *      written to ./scans/<host>/<timestamp>/ as a manifest plus body files.
 *   2. serveMirror(manifest)  — replay the snapshot on a loopback address so a
 *      browser or external tool can look at the copy. Loopback only; never
 *      re-published.
 *   3. scanMirror(origin,…)   — run the normal passive engine against the
 *      snapshot through a fetch adapter that reads the captured responses, so
 *      the scan is reproducible, runs offline, and its findings still name the
 *      real origin. The copy is tested with the SAME non-destructive set as a
 *      live scan; testing a copy never unlocks a wider one.
 */
import { createServer } from 'node:http';
import { readFileSync, writeFileSync, mkdirSync, readdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { createHash } from 'node:crypto';
import { crawl } from './crawl.mjs';
import { runPassiveScan } from './passive.mjs';

export const MIRROR_MANIFEST = 'mirror.json';
export const DEFAULT_MAX_BYTES = 8 * 1024 * 1024; // 8 MiB of captured bodies

// Response headers that describe the captured hop, not the content; not replayed/stored.
const HOP_BY_HOP = new Set(['connection', 'keep-alive', 'transfer-encoding', 'content-length', 'content-encoding', 'te', 'trailer', 'upgrade', 'proxy-authenticate', 'proxy-authorization']);

function safeName(url, i) {
  let p = '/';
  try { const u = new URL(url); p = u.pathname + (u.search || ''); } catch { /* keep default */ }
  const slug = p.replace(/[^a-z0-9._-]+/gi, '_').replace(/^_+|_+$/g, '').slice(0, 60) || 'index';
  const h = createHash('sha256').update(url).digest('hex').slice(0, 8);
  return `pages/${String(i).padStart(3, '0')}-${slug}-${h}.bin`;
}

function cleanHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) if (!HOP_BY_HOP.has(k.toLowerCase())) out[k.toLowerCase()] = v;
  return out;
}

/**
 * Build a mirror manifest and the body files from a crawl result, without
 * touching disk. Bodies are captured until maxBytes is reached; pages past the
 * cap are recorded headers-only (captured:false, truncated manifest).
 * @returns {{manifest:object, files:Array<{path:string, contents:string}>}}
 */
export function buildMirrorManifest(crawlResult, opts = {}) {
  const maxBytes = Number.isInteger(opts.maxBytes) && opts.maxBytes > 0 ? opts.maxBytes : DEFAULT_MAX_BYTES;
  const files = [];
  let total = 0;
  let truncated = false;
  const pages = [];
  let i = 0;
  for (const p of crawlResult.pages || []) {
    const headers = cleanHeaders(p.headers);
    const contentType = headers['content-type'] || '';
    const body = p.isHtml ? (p.body || '') : '';
    const bytes = Buffer.byteLength(body);
    const entry = { url: p.url, requestedUrl: p.requestedUrl, status: p.status ?? null, headers, contentType, isHtml: Boolean(p.isHtml), bytes, path: null, captured: false, error: p.error ?? null };
    if (body) {
      if (total + bytes > maxBytes) { truncated = true; }
      else { const path = safeName(p.url, i); files.push({ path, contents: body }); entry.path = path; entry.captured = true; total += bytes; }
    } else {
      entry.captured = p.error ? false : true; // a header-only (non-HTML) page is still "captured"
    }
    pages.push(entry);
    i++;
  }
  const manifest = {
    tool: 'Anne\'s Test', kind: 'staging-mirror', origin: crawlResult.origin,
    capturedAt: opts.now ? opts.now.toISOString() : new Date().toISOString(),
    pageCount: pages.length, bodyBytes: total, truncated,
    maxBytes, robots: crawlResult.robots || null, requests: crawlResult.requests ?? null,
    pages,
  };
  return { manifest, files };
}

/**
 * Capture a bounded snapshot of a verified origin into outDir.
 * @param {string} origin  already verified by the caller
 * @param {object} opts  { outDir, fetchImpl, maxPages, maxDepth, maxBytes, respectRobots, delayMs, now }
 * @returns {Promise<{dir:string, manifest:object, files:number}>}
 */
export async function captureMirror(origin, opts = {}) {
  const crawlResult = await crawl(origin, {
    fetchImpl: opts.fetchImpl,
    maxPages: opts.maxPages ?? 25,
    maxDepth: opts.maxDepth ?? 3,
    respectRobots: opts.respectRobots !== false,
    delayMs: opts.delayMs,
    timeoutMs: opts.timeoutMs,
  });
  const { manifest, files } = buildMirrorManifest(crawlResult, { maxBytes: opts.maxBytes, now: opts.now });
  const dir = opts.outDir || join('scans', new URL(origin).host.replace(/[^a-z0-9.-]/gi, '_'), manifest.capturedAt.replace(/[:.]/g, '-'));
  const abs = resolve(process.cwd(), dir);
  mkdirSync(join(abs, 'pages'), { recursive: true });
  for (const f of files) writeFileSync(join(abs, f.path), f.contents, { mode: 0o600 });
  writeFileSync(join(abs, MIRROR_MANIFEST), JSON.stringify(manifest, null, 2) + '\n', { mode: 0o600 });
  return { dir: abs, manifest, files: files.length };
}

/** Load a captured snapshot, attaching each page's body from disk. */
export function loadMirror(dir) {
  const abs = resolve(process.cwd(), dir);
  const manifest = JSON.parse(readFileSync(join(abs, MIRROR_MANIFEST), 'utf8'));
  for (const p of manifest.pages) p.body = p.path ? readFileSync(join(abs, p.path), 'utf8') : '';
  return manifest;
}

// ---------------------------------------------------------------------------
// Lookup shared by the server and the fetch adapter
// ---------------------------------------------------------------------------

function keyOf(url) { try { const u = new URL(url); return u.origin + u.pathname + (u.search || ''); } catch { return String(url); } }

/** Index a manifest's pages by exact URL and by origin+path(+search). */
export function indexMirror(manifest) {
  const byKey = new Map();
  for (const p of manifest.pages) { const k = keyOf(p.url); if (!byKey.has(k)) byKey.set(k, p); const rk = keyOf(p.requestedUrl); if (!byKey.has(rk)) byKey.set(rk, p); }
  return byKey;
}

// ---------------------------------------------------------------------------
// Serve on loopback
// ---------------------------------------------------------------------------

/**
 * Serve a loaded mirror on a loopback address. Replays each captured page's
 * status, content headers and body; anything not captured is 404. Binds to
 * 127.0.0.1 only and is never re-published.
 * @param {object} manifest  from loadMirror()
 * @param {{host?:string, port?:number}} [opts]
 * @returns {Promise<{url:string, host:string, port:number, close:()=>Promise<void>, server:import('http').Server}>}
 */
export function serveMirror(manifest, opts = {}) {
  const host = opts.host || '127.0.0.1';
  const index = indexMirror(manifest);
  const server = createServer((req, res) => {
    // Resolve the request path against the captured origin, so /page?x=1 maps to the stored page.
    let page = null;
    try { page = index.get(keyOf(new URL(req.url, manifest.origin).toString())); } catch { /* bad path */ }
    if (!page) { res.writeHead(404, { 'content-type': 'text/plain' }); res.end('Not in mirror\n'); return; }
    const headers = {};
    for (const [k, v] of Object.entries(page.headers || {})) if (!HOP_BY_HOP.has(k) && k !== 'set-cookie') headers[k] = v;
    res.writeHead(page.status || 200, headers);
    res.end(page.body || '');
  });
  return new Promise((resolveP) => {
    server.listen(opts.port || 0, host, () => {
      const addr = server.address();
      resolveP({ url: `http://${host}:${addr.port}`, host, port: addr.port, server, close: () => new Promise((r) => server.close(r)) });
    });
  });
}

// ---------------------------------------------------------------------------
// Fetch adapter: run the real scan against the snapshot, offline
// ---------------------------------------------------------------------------

/**
 * A fetch-compatible function that answers from a loaded mirror. Captured
 * responses replay their status, headers and body; anything not in the
 * snapshot returns a synthetic 404, so the passive engine treats it as absent
 * (no CORS probe echo, no exposed file, no http variant). Keeps the real
 * origin, so findings name the live site.
 */
export function mirrorFetchFromManifest(manifest) {
  const index = indexMirror(manifest);
  const originStr = (() => { try { return new URL(manifest.origin).origin; } catch { return null; } })();
  return async function mirrorFetch(url /* , init */) {
    // A request to a different origin (e.g. the http:// variant of an https
    // site) was never captured. Signal "not observed" so scheme-dependent
    // checks skip, rather than returning a 404 that reads as a served page.
    let reqOrigin; try { reqOrigin = new URL(url).origin; } catch { reqOrigin = null; }
    if (originStr && reqOrigin && reqOrigin !== originStr) throw Object.assign(new Error('not in mirror (different origin)'), { code: 'ENOTCAPTURED' });
    const page = index.get(keyOf(url));
    const headers = new Headers();
    if (page) {
      for (const [k, v] of Object.entries(page.headers || {})) {
        if (k === 'set-cookie') { for (const c of Array.isArray(v) ? v : [v]) headers.append('set-cookie', c); }
        else headers.set(k, v);
      }
      const body = page.body || '';
      return { status: page.status || 200, url: page.url, headers, text: async () => body };
    }
    return { status: 404, url, headers: new Headers({ 'content-type': 'text/plain' }), text: async () => '' };
  };
}

/**
 * Scan a captured mirror with the normal passive engine. Pass either a loaded
 * `manifest` or a `dir` to load. Findings name `origin`.
 * @returns {Promise<object>} a scan report with a `mirror` metadata block
 */
export async function scanMirror(origin, opts = {}) {
  const manifest = opts.manifest || loadMirror(opts.dir);
  const fetchImpl = mirrorFetchFromManifest(manifest);
  const report = await runPassiveScan(origin, {
    fetchImpl,
    probeSensitiveFiles: opts.probeSensitiveFiles !== false,
    crawl: opts.crawl === false ? false : { maxPages: opts.maxPages ?? manifest.pageCount ?? 25, maxDepth: opts.maxDepth ?? 3, respectRobots: false },
    onlineCve: Boolean(opts.onlineCve),
  });
  report.mirror = { capturedAt: manifest.capturedAt, pageCount: manifest.pageCount, bodyBytes: manifest.bodyBytes, truncated: manifest.truncated, source: opts.dir || 'in-memory', note: 'Client-surface snapshot: header, cookie, CORS, disclosure, fingerprint and component checks apply; live-scheme checks (http->https redirect) are not evaluated here.' };
  return report;
}

/** List the body files in a snapshot directory (for CLI info). */
export function mirrorFiles(dir) {
  const abs = resolve(process.cwd(), dir, 'pages');
  try { return readdirSync(abs); } catch { return []; }
}
