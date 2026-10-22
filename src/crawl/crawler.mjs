/*
 * QuillTest — crawler
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Breadth-first, same-origin, scope-aware, polite. Fetches HTML pages (and a
 * bounded number of same-origin scripts, for integrity/fingerprint checks),
 * records every request it makes, follows only same-origin redirects, honours
 * robots.txt by default, and never submits a form or sends test input. It
 * produces the observations the passive checks read.
 *
 * The crawler does not know about the gate; the orchestrator does. Nothing in
 * src/scan calls crawl() without assertScanPermitted() first.
 */

import { extractPage } from './html.mjs';
import { parseSetCookie } from './cookies.mjs';
import { normalizeOrigin } from '../verify/origin.mjs';

export const DEFAULT_USER_AGENT = 'QuillTest/0.1 (+https://github.com/socrtwo/QuillTest; passive security scan of a verified, authorized target)';
export const DEFAULTS = {
  maxPages: 150,
  maxDepth: 3,
  maxRequests: 400,
  maxAssets: 25,
  concurrency: 4,
  delayMs: 0,
  timeoutMs: 15_000,
  maxBodyBytes: 2 * 1024 * 1024,
  honorRobots: true,
  seedSitemap: false,
};

const ASSET_EXT = /\.(png|jpe?g|gif|webp|avif|svg|ico|bmp|tiff?|woff2?|ttf|otf|eot|mp4|webm|mp3|ogg|wav|pdf|zip|gz|tgz|rar|7z|exe|dmg|iso|docx?|xlsx?|pptx?|map)$/i;

/**
 * @typedef {Object} Page
 * @property {string} url           requested URL
 * @property {string} finalUrl      after same-origin redirects
 * @property {number} status
 * @property {Record<string,string|string[]>} headers  lower-cased; set-cookie is an array
 * @property {string} contentType
 * @property {string} body          text, capped at maxBodyBytes
 * @property {boolean} truncated
 * @property {number} bytes
 * @property {number} ms
 * @property {number} depth
 * @property {'page'|'asset'|'probe'} kind
 * @property {import('./cookies.mjs').Cookie[]} cookies
 * @property {ReturnType<typeof extractPage>|null} dom   extracted structure for HTML
 * @property {{status:number, location:string}[]} redirects
 * @property {string|null} error
 */

export class Crawler {
  /**
   * @param {string} originInput
   * @param {Partial<typeof DEFAULTS> & {scope?:(url:string)=>boolean, fetch?:typeof fetch, headers?:Record<string,string>, userAgent?:string, onPage?:(p:Page)=>void, now?:()=>Date}} [opts]
   */
  constructor(originInput, opts = {}) {
    this.origin = normalizeOrigin(originInput);
    this.opts = { ...DEFAULTS, ...opts };
    this.fetchImpl = opts.fetch || globalThis.fetch;
    this.scope = opts.scope || (() => true);
    this.userAgent = opts.userAgent || DEFAULT_USER_AGENT;
    this.extraHeaders = opts.headers || {};
    this.now = opts.now || (() => new Date());
    /** @type {Page[]} */
    this.pages = [];
    /** @type {{method:string,url:string,status:number|null,ms:number,bytes:number,kind:string,at:string,error?:string}[]} */
    this.requestLog = [];
    this.seen = new Set();
    this.external = { links: new Set(), scripts: new Set(), styles: new Set(), images: new Set(), frames: new Set() };
    this.robots = { fetched: false, disallow: [], sitemaps: [] };
    this.stopped = false;
    this.stopReason = null;
  }

  get requestCount() { return this.requestLog.length; }

  stop(reason = 'stopped') { this.stopped = true; this.stopReason = reason; }

  /** Is this URL on our origin, in scope, and not something we never crawl? */
  allowed(url) {
    let u;
    try { u = new URL(url); } catch { return false; }
    if (normalizeOrigin(u.origin) !== this.origin) return false;
    if (!this.scope(url)) return false;
    if (this.opts.honorRobots && this.robots.disallow.some((p) => u.pathname.startsWith(p))) return false;
    return true;
  }

  /**
   * One raw request with manual redirect handling, logging and a body cap.
   * Same-origin redirects are followed (≤ 5); off-origin ones are recorded
   * as external and not followed.
   */
  async request(url, { kind = 'page', method = 'GET', headers = {}, body, followRedirects = true, maxBodyBytes = this.opts.maxBodyBytes } = {}) {
    const redirects = [];
    let current = url;
    for (let hop = 0; ; hop++) {
      if (this.requestLog.length >= this.opts.maxRequests) { this.stop('request budget exhausted'); return this.errorPage(url, kind, 'request budget exhausted', redirects); }
      const t0 = Date.now();
      const entry = { method, url: current, status: null, ms: 0, bytes: 0, kind, at: this.now().toISOString().replace(/\.\d{3}Z$/, 'Z') };
      this.requestLog.push(entry);
      let res;
      try {
        res = await this.fetchImpl(current, {
          method,
          redirect: 'manual',
          headers: { 'user-agent': this.userAgent, accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', ...this.extraHeaders, ...headers },
          ...(body !== undefined && method !== 'GET' && method !== 'HEAD' ? { body } : {}),
          signal: AbortSignal.timeout(this.opts.timeoutMs),
        });
      } catch (e) {
        entry.ms = Date.now() - t0;
        entry.error = e?.name === 'TimeoutError' ? 'timeout' : (e?.cause?.code || e?.cause?.message || e?.message || String(e));
        return this.errorPage(url, kind, entry.error, redirects, current);
      }
      entry.status = res.status;
      const hdrs = headersToObject(res.headers);
      if (res.status >= 300 && res.status < 400 && hdrs.location) {
        let next = null;
        try { next = new URL(String(hdrs.location), current).toString(); } catch { /* bad location */ }
        entry.ms = Date.now() - t0;
        await drain(res);
        redirects.push({ status: res.status, location: next || String(hdrs.location) });
        if (!next || !followRedirects) return this.finishPage(url, current, res.status, hdrs, '', false, 0, entry.ms, kind, redirects);
        if (normalizeOrigin(new URL(next).origin) !== this.origin) {
          this.external.links.add(next);
          return this.finishPage(url, current, res.status, hdrs, '', false, 0, entry.ms, kind, redirects);
        }
        if (hop >= 5) return this.finishPage(url, current, res.status, hdrs, '', false, 0, entry.ms, kind, redirects, 'too many redirects');
        current = next;
        continue;
      }
      const { text, truncated, bytes } = await readCapped(res, maxBodyBytes);
      entry.ms = Date.now() - t0;
      entry.bytes = bytes;
      return this.finishPage(url, current, res.status, hdrs, text, truncated, bytes, entry.ms, kind, redirects);
    }
  }

  finishPage(url, finalUrl, status, headers, body, truncated, bytes, ms, kind, redirects, error = null) {
    const contentType = String(headers['content-type'] || '').toLowerCase();
    const isHtml = /text\/html|application\/xhtml/.test(contentType) || (!contentType && /^\s*<(!doctype|html)/i.test(body));
    const cookies = (Array.isArray(headers['set-cookie']) ? headers['set-cookie'] : headers['set-cookie'] ? [headers['set-cookie']] : []).map(parseSetCookie);
    const page = { url, finalUrl, status, headers, contentType, body, truncated, bytes, ms, depth: 0, kind, cookies, dom: isHtml && body ? extractPage(body, finalUrl) : null, redirects, error };
    return page;
  }

  errorPage(url, kind, error, redirects, finalUrl = url) {
    return { url, finalUrl, status: 0, headers: {}, contentType: '', body: '', truncated: false, bytes: 0, ms: 0, depth: 0, kind, cookies: [], dom: null, redirects, error };
  }

  async fetchRobots() {
    this.robots.fetched = true;
    const page = await this.request(`${this.origin}/robots.txt`, { kind: 'probe' });
    if (page.status !== 200 || !page.body) return;
    let applies = false;
    for (const raw of page.body.split(/\r?\n/)) {
      const line = raw.replace(/#.*/, '').trim();
      if (!line) continue;
      const m = /^([A-Za-z-]+)\s*:\s*(.*)$/.exec(line);
      if (!m) continue;
      const key = m[1].toLowerCase(); const val = m[2].trim();
      if (key === 'user-agent') applies = val === '*' || /quilltest/i.test(val);
      else if (key === 'disallow' && applies && val) this.robots.disallow.push(val.replace(/\*.*$/, ''));
      else if (key === 'sitemap' && val) this.robots.sitemaps.push(val);
    }
  }

  /** Run the crawl. Resolves with the pages (also kept on this.pages). */
  async run() {
    if (this.opts.honorRobots || this.opts.seedSitemap) await this.fetchRobots();

    const queue = [{ url: `${this.origin}/`, depth: 0 }];
    this.seen.add(`${this.origin}/`);
    if (this.opts.seedSitemap) for (const sm of this.robots.sitemaps.slice(0, 3)) await this.seedFromSitemap(sm, queue);

    const assetQueue = [];
    const inFlight = new Set();
    const pageCount = () => this.pages.filter((p) => p.kind === 'page').length;

    const visit = async (item) => {
      if (this.stopped) return;
      const page = await this.request(item.url, { kind: 'page' });
      page.depth = item.depth;
      this.pages.push(page);
      this.opts.onPage?.(page);
      if (!page.dom) return;
      const d = page.dom;
      for (const u of [...d.links, ...d.frames]) this.enqueue(u, item.depth + 1, queue);
      for (const s of d.scripts) if (s.url) { if (this.allowed(s.url)) { if (!this.seen.has(s.url)) { this.seen.add(s.url); assetQueue.push(s.url); } } else if (!isSameOrigin(s.url, this.origin)) this.external.scripts.add(s.url); }
      for (const s of d.styles) if (!isSameOrigin(s.url, this.origin)) this.external.styles.add(s.url);
      for (const u of d.images) if (!isSameOrigin(u, this.origin)) this.external.images.add(u);
      for (const u of d.frames) if (!isSameOrigin(u, this.origin)) this.external.frames.add(u);
      for (const u of d.links) if (!isSameOrigin(u, this.origin)) this.external.links.add(u);
    };

    while (!this.stopped && (queue.length || inFlight.size)) {
      while (!this.stopped && queue.length && inFlight.size < this.opts.concurrency && pageCount() + inFlight.size < this.opts.maxPages) {
        const item = queue.shift();
        const p = visit(item).finally(() => inFlight.delete(p));
        inFlight.add(p);
        if (this.opts.delayMs) await sleep(this.opts.delayMs);
      }
      if (!queue.length || inFlight.size >= this.opts.concurrency || pageCount() + inFlight.size >= this.opts.maxPages) {
        if (inFlight.size) await Promise.race(inFlight);
        else break;
      }
    }
    if (!this.stopped && queue.length && pageCount() >= this.opts.maxPages) this.stopReason = 'page limit reached';

    // Same-origin scripts, bounded, for SRI/source-map/fingerprint checks.
    for (const url of assetQueue.slice(0, this.opts.maxAssets)) {
      if (this.stopped) break;
      const page = await this.request(url, { kind: 'asset', maxBodyBytes: Math.min(this.opts.maxBodyBytes, 512 * 1024) });
      this.pages.push(page);
    }
    return this.pages;
  }

  enqueue(url, depth, queue) {
    if (depth > this.opts.maxDepth) return;
    if (this.seen.has(url)) return;
    if (!this.allowed(url)) return;
    if (ASSET_EXT.test(new URL(url).pathname)) return;
    this.seen.add(url);
    queue.push({ url, depth });
  }

  async seedFromSitemap(url, queue) {
    if (!this.allowed(url)) return;
    const page = await this.request(url, { kind: 'probe' });
    if (page.status !== 200) return;
    for (const m of page.body.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)) this.enqueue(m[1].trim(), 1, queue);
  }

  /** Observations the checks consume. */
  result() {
    return {
      origin: this.origin,
      pages: this.pages,
      requestLog: this.requestLog,
      external: Object.fromEntries(Object.entries(this.external).map(([k, v]) => [k, [...v]])),
      robots: this.robots,
      stopReason: this.stopReason,
    };
  }
}

export function headersToObject(headers) {
  const out = {};
  const setCookies = typeof headers.getSetCookie === 'function' ? headers.getSetCookie() : null;
  for (const [k, v] of headers) {
    const key = k.toLowerCase();
    if (key === 'set-cookie') continue;
    out[key] = v;
  }
  if (setCookies?.length) out['set-cookie'] = setCookies;
  else if (headers.get('set-cookie')) out['set-cookie'] = [headers.get('set-cookie')];
  return out;
}

async function readCapped(res, maxBytes) {
  if (!res.body) { const b = Buffer.from(await res.arrayBuffer().catch(() => new ArrayBuffer(0))); return { text: b.subarray(0, maxBytes).toString('utf8'), truncated: b.length > maxBytes, bytes: b.length }; }
  const reader = res.body.getReader();
  const chunks = []; let total = 0; let truncated = false;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) { truncated = true; chunks.push(Buffer.from(value.subarray(0, Math.max(0, value.byteLength - (total - maxBytes))))); await reader.cancel().catch(() => {}); break; }
      chunks.push(Buffer.from(value));
    }
  } finally { reader.releaseLock?.(); }
  return { text: Buffer.concat(chunks).toString('utf8'), truncated, bytes: total };
}

async function drain(res) { try { await res.arrayBuffer(); } catch { /* ignore */ } }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
function isSameOrigin(url, origin) { try { return normalizeOrigin(new URL(url).origin) === origin; } catch { return false; } }
