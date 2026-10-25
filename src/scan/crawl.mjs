/*
 * Anne's Test — same-origin crawler
 * Part of the Anne's Office suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * A bounded, polite spider for an origin the operator has verified they own.
 * It exists so the passive checks can see the whole site rather than only the
 * root page, and so later layers (fix generation, active detection) know which
 * pages, forms and scripts exist.
 *
 * Properties, all enforced in code:
 *   - Same-origin only. Links to any other origin are counted, never fetched.
 *   - Bounded: maxPages, maxDepth, a cap on query-string variants per path,
 *     and a per-page body cap. It cannot run away on a large site.
 *   - Polite: honors robots.txt Disallow rules for "*" and for our user agent
 *     (default on; the operator can turn it off for their own site), reads
 *     sitemap.xml for seeds, sends an identifying User-Agent, and supports a
 *     delay between requests.
 *   - Read-only: GET only, never submits forms, never follows logout-like
 *     links (logout|signout|delete|remove) to avoid changing state by accident.
 *   - HTML only: skips obvious binary/asset extensions and non-HTML responses.
 */

import { observe, DEFAULT_TIMEOUT_MS, USER_AGENT } from './passive.mjs';

export const DEFAULT_MAX_PAGES = 25;
export const DEFAULT_MAX_DEPTH = 3;
export const MAX_QUERY_VARIANTS_PER_PATH = 3;
export const MAX_SITEMAP_URLS = 200;

const SKIP_EXT_RE = /\.(png|jpe?g|gif|webp|svg|ico|bmp|tiff?|css|js|mjs|map|json|xml|rss|atom|pdf|zip|gz|tgz|rar|7z|tar|mp3|mp4|m4a|webm|ogg|wav|avi|mov|woff2?|ttf|otf|eot|exe|dmg|msi|apk|iso|doc|docx|xls|xlsx|ppt|pptx|csv)(\?|#|$)/i;
const STATE_CHANGING_RE = /(^|[/?&#_-])(logout|log-out|signout|sign-out|delete|remove|destroy|unsubscribe)([/?&#_-]|$)/i;

// ---------------------------------------------------------------------------
// URL handling
// ---------------------------------------------------------------------------

/** Normalize a candidate link against a base; returns null if it should not be crawled. */
export function normalizeLink(href, baseUrl, origin) {
  if (!href) return null;
  const h = String(href).trim();
  if (!h || /^(javascript|mailto|tel|sms|data|blob|ftp|file):/i.test(h) || h.startsWith('#')) return null;
  let u;
  try { u = new URL(h, baseUrl); } catch { return null; }
  if (u.origin !== origin) return null;
  u.hash = '';
  // Drop common tracking params; keep the rest (they may select distinct pages).
  for (const k of [...u.searchParams.keys()]) if (/^(utm_|fbclid|gclid|mc_|_ga|ref$)/i.test(k)) u.searchParams.delete(k);
  u.searchParams.sort();
  // Keep trailing slashes as-is: "/admin/" and "/admin" are distinct URLs to a
  // server and to robots.txt; rewriting one into the other would let a link
  // slip past a Disallow rule.
  const s = u.toString();
  if (SKIP_EXT_RE.test(u.pathname)) return null;
  if (STATE_CHANGING_RE.test(u.pathname + u.search)) return null;
  return s;
}

export function pathKey(url) {
  const u = new URL(url);
  return u.pathname;
}

// ---------------------------------------------------------------------------
// HTML extraction (regex-based on purpose: no DOM dependency, bounded input)
// ---------------------------------------------------------------------------

function attr(tag, name) {
  const m = tag.match(new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i'));
  return m ? (m[1] ?? m[2] ?? m[3] ?? '') : null;
}

export function extractLinks(html) {
  const out = [];
  for (const m of String(html).matchAll(/<a\b[^>]*>/gi)) { const h = attr(m[0], 'href'); if (h) out.push(h); }
  for (const m of String(html).matchAll(/<(?:area|link)\b[^>]*>/gi)) {
    const t = m[0];
    const rel = (attr(t, 'rel') || '').toLowerCase();
    const h = attr(t, 'href');
    if (h && (/^area/i.test(t) || /\b(canonical|alternate|next|prev)\b/.test(rel))) out.push(h);
  }
  const base = String(html).match(/<base\b[^>]*>/i);
  return { links: out, base: base ? attr(base[0], 'href') : null };
}

export function extractForms(html, pageUrl) {
  const forms = [];
  for (const m of String(html).matchAll(/<form\b[^>]*>([\s\S]*?)<\/form>/gi)) {
    const tag = m[0].match(/<form\b[^>]*>/i)[0];
    let action = attr(tag, 'action');
    try { action = action ? new URL(action, pageUrl).toString() : pageUrl; } catch { action = action || pageUrl; }
    const method = (attr(tag, 'method') || 'GET').toUpperCase();
    const inputs = [];
    for (const im of m[1].matchAll(/<(input|textarea|select)\b[^>]*>/gi)) {
      const t = im[0];
      inputs.push({ tag: im[1].toLowerCase(), name: attr(t, 'name'), type: (attr(t, 'type') || (im[1].toLowerCase() === 'input' ? 'text' : im[1].toLowerCase())).toLowerCase(), autocomplete: attr(t, 'autocomplete') });
    }
    const hasPassword = inputs.some((i) => i.type === 'password');
    const hasCsrfLike = inputs.some((i) => i.type === 'hidden' && /csrf|xsrf|token|nonce|authenticity/i.test(i.name || ''));
    forms.push({ page: pageUrl, action, method, inputs, hasPassword, hasCsrfLike });
  }
  return forms;
}

export function extractAssets(html, pageUrl) {
  const scripts = [], styles = [], frames = [];
  const abs = (h) => { try { return new URL(h, pageUrl).toString(); } catch { return h; } };
  for (const m of String(html).matchAll(/<script\b[^>]*\bsrc\s*=[^>]*>/gi)) { const s = attr(m[0], 'src'); if (s) scripts.push({ src: abs(s), integrity: attr(m[0], 'integrity'), crossorigin: attr(m[0], 'crossorigin') }); }
  for (const m of String(html).matchAll(/<link\b[^>]*\brel\s*=\s*["']?stylesheet["']?[^>]*>/gi)) { const h = attr(m[0], 'href'); if (h) styles.push({ href: abs(h), integrity: attr(m[0], 'integrity') }); }
  for (const m of String(html).matchAll(/<iframe\b[^>]*\bsrc\s*=[^>]*>/gi)) { const s = attr(m[0], 'src'); if (s) frames.push(abs(s)); }
  return { scripts, styles, frames };
}

// ---------------------------------------------------------------------------
// robots.txt and sitemap.xml
// ---------------------------------------------------------------------------

/** Minimal robots.txt parser: Disallow/Allow for "*" and for a UA token; longest-match wins. */
export function parseRobots(text, uaToken = 'quilltest') {
  const groups = []; let cur = null;
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '').trim();
    if (!line) continue;
    const m = line.match(/^([a-z-]+)\s*:\s*(.*)$/i);
    if (!m) continue;
    const k = m[1].toLowerCase(), v = m[2].trim();
    if (k === 'user-agent') { if (!cur || cur.rules.length) { cur = { agents: [], rules: [], sitemaps: [] }; groups.push(cur); } cur.agents.push(v.toLowerCase()); }
    else if ((k === 'disallow' || k === 'allow') && cur) cur.rules.push({ allow: k === 'allow', path: v });
    else if (k === 'sitemap') { (cur || (cur = { agents: ['*'], rules: [], sitemaps: [] }, groups.push(cur), cur)).sitemaps.push(v); }
  }
  const forUs = groups.find((g) => g.agents.some((a) => a !== '*' && uaToken.toLowerCase().includes(a)));
  const star = groups.find((g) => g.agents.includes('*'));
  const rules = (forUs || star || { rules: [] }).rules;
  const sitemaps = groups.flatMap((g) => g.sitemaps);
  return { rules, sitemaps };
}

export function robotsAllows(rules, pathname) {
  let best = null;
  for (const r of rules) {
    if (!r.path) { if (!r.allow) continue; }
    const pattern = r.path.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\\\$$/, '$');
    const re = new RegExp('^' + pattern);
    if (re.test(pathname) && (!best || r.path.length > best.path.length)) best = r;
  }
  return best ? best.allow : true;
}

export function parseSitemap(xml) {
  const out = [];
  for (const m of String(xml || '').matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)) out.push(m[1]);
  return out.slice(0, MAX_SITEMAP_URLS);
}

// ---------------------------------------------------------------------------
// Crawl
// ---------------------------------------------------------------------------

/**
 * @param {string} origin  normalized origin
 * @param {object} [opts]
 * @param {Function} [opts.fetchImpl]
 * @param {number}   [opts.maxPages=25]
 * @param {number}   [opts.maxDepth=3]
 * @param {boolean}  [opts.respectRobots=true]
 * @param {number}   [opts.delayMs=0]
 * @param {number}   [opts.timeoutMs]
 * @param {object}   [opts.rootObservation]  an already-fetched root (avoids a duplicate request)
 * @returns {Promise<{pages:object[], skipped:object, external:Set<string>|string[], robots:object, requests:number}>}
 */
export async function crawl(origin, opts = {}) {
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  const timeoutMs = opts.timeoutMs || DEFAULT_TIMEOUT_MS;
  const maxPages = Number.isInteger(opts.maxPages) && opts.maxPages > 0 ? opts.maxPages : DEFAULT_MAX_PAGES;
  const maxDepth = Number.isInteger(opts.maxDepth) && opts.maxDepth >= 0 ? opts.maxDepth : DEFAULT_MAX_DEPTH;
  const respectRobots = opts.respectRobots !== false;
  const delayMs = Number.isFinite(opts.delayMs) ? Math.max(0, opts.delayMs) : 0;
  const sleep = (ms) => (ms ? new Promise((r) => setTimeout(r, ms)) : Promise.resolve());

  let requests = 0;
  const get = async (url, extra) => { requests++; await sleep(delayMs); return observe(url, { fetchImpl, timeoutMs, headers: extra }); };

  // robots + sitemap
  let robots = { rules: [], sitemaps: [], fetched: false };
  const robotsObs = await get(origin + '/robots.txt');
  if (!robotsObs.error && robotsObs.status === 200) {
    const parsed = parseRobots(robotsObs.body, USER_AGENT);
    robots = { ...parsed, fetched: true };
  }
  const allowed = (url) => !respectRobots || robotsAllows(robots.rules, new URL(url).pathname);

  const seeds = [origin + '/'];
  const sitemapUrls = robots.sitemaps.length ? robots.sitemaps : [origin + '/sitemap.xml'];
  for (const sm of sitemapUrls.slice(0, 3)) {
    let smUrl; try { smUrl = new URL(sm, origin).toString(); } catch { continue; }
    if (new URL(smUrl).origin !== origin) continue;
    const obs = await get(smUrl);
    if (!obs.error && obs.status === 200) {
      for (const loc of parseSitemap(obs.body)) { const n = normalizeLink(loc, origin, origin); if (n) seeds.push(n); }
    }
  }

  const queue = [];
  const seen = new Set();
  const variantsPerPath = new Map();
  const enqueue = (url, depth, from) => {
    if (!url || seen.has(url) || depth > maxDepth) return;
    const key = pathKey(url);
    const n = variantsPerPath.get(key) || 0;
    if (new URL(url).search && n >= MAX_QUERY_VARIANTS_PER_PATH) { skipped.queryVariants++; return; }
    if (!allowed(url)) { skipped.robots++; return; }
    seen.add(url);
    if (new URL(url).search) variantsPerPath.set(key, n + 1);
    queue.push({ url, depth, from });
  };
  const skipped = { robots: 0, queryVariants: 0, nonHtml: 0, external: 0, depth: 0, cap: 0, stateChanging: 0 };
  for (const s of seeds) enqueue(s, 0, null);

  const pages = [];
  const external = new Set();
  while (queue.length) {
    if (pages.length >= maxPages) { skipped.cap += queue.length; break; }
    const { url, depth, from } = queue.shift();
    const obs = (depth === 0 && url === origin + '/' && opts.rootObservation) ? opts.rootObservation : await get(url);
    const ct = (obs.headers?.['content-type'] || '').toLowerCase();
    const isHtml = !obs.error && (ct.includes('text/html') || ct.includes('application/xhtml') || (!ct && /^\s*<(!doctype|html)/i.test(obs.body || '')));
    const page = {
      url: obs.url || url, requestedUrl: url, depth, from,
      status: obs.status ?? null, error: obs.error ?? null, crossOriginRedirectTo: obs.crossOriginRedirectTo ?? null,
      headers: obs.headers || {}, body: isHtml ? obs.body : '', isHtml,
      forms: [], scripts: [], styles: [], frames: [], linkCount: 0,
    };
    if (isHtml && obs.body) {
      const { links, base } = extractLinks(obs.body);
      const baseUrl = base ? (() => { try { return new URL(base, page.url).toString(); } catch { return page.url; } })() : page.url;
      page.linkCount = links.length;
      for (const href of links) {
        let abs; try { abs = new URL(href, baseUrl); } catch { continue; }
        if (abs.origin !== origin) { if (/^https?:/.test(abs.protocol)) { external.add(abs.origin); skipped.external++; } continue; }
        if (STATE_CHANGING_RE.test(abs.pathname + abs.search)) { skipped.stateChanging++; continue; }
        const n = normalizeLink(href, baseUrl, origin);
        if (!n) { skipped.nonHtml++; continue; }
        if (depth + 1 > maxDepth) { skipped.depth++; continue; }
        enqueue(n, depth + 1, page.url);
      }
      page.forms = extractForms(obs.body, page.url);
      Object.assign(page, extractAssets(obs.body, page.url));
    } else if (!obs.error) {
      skipped.nonHtml++;
    }
    pages.push(page);
  }

  return { origin, pages, skipped, external: [...external].sort(), robots: { fetched: robots.fetched, rules: robots.rules.length, sitemaps: robots.sitemaps }, requests };
}
