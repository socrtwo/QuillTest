/*
 * QuillTest — tolerant HTML extraction (no dependencies)
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Enough HTML understanding for a passive scanner: tags with attributes,
 * link/asset/form discovery, meta tags, inline script text. Not a DOM.
 */

const TAG_RE = /<([a-zA-Z][\w:-]*)\b([^>]*?)\/?>/g;
const ATTR_RE = /([^\s=/>"']+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g;
const COMMENT_RE = /<!--[\s\S]*?-->/g;

/** Strip comments and the contents of script/style elements (keeping the tags). */
export function stripNonMarkup(html) {
  return String(html).replace(COMMENT_RE, '').replace(/(<script\b[^>]*>)[\s\S]*?(<\/script>)/gi, '$1$2').replace(/(<style\b[^>]*>)[\s\S]*?(<\/style>)/gi, '$1$2');
}

export function parseAttributes(text) {
  const attrs = {};
  for (const m of String(text).matchAll(ATTR_RE)) {
    const name = m[1].toLowerCase();
    if (name in attrs) continue;
    attrs[name] = decodeEntities(m[2] ?? m[3] ?? m[4] ?? '');
  }
  return attrs;
}

/** All start tags as {name, attrs, index}. */
export function tags(html, names = null) {
  const out = [];
  const src = stripNonMarkup(html);
  const want = names ? new Set(names.map((n) => n.toLowerCase())) : null;
  for (const m of src.matchAll(TAG_RE)) {
    const name = m[1].toLowerCase();
    if (want && !want.has(name)) continue;
    out.push({ name, attrs: parseAttributes(m[2]), index: m.index });
  }
  return out;
}

export function decodeEntities(s) {
  return String(s).replace(/&(amp|lt|gt|quot|#39|apos|#x27|#x2F|#47);/gi, (m, e) => ({ amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'", apos: "'", '#x27': "'", '#x2f': '/', '#47': '/' })[e.toLowerCase()] ?? m);
}

/** Resolve a reference against a base URL; null when it is not an http(s) URL. */
export function resolveUrl(ref, base) {
  const r = String(ref || '').trim();
  if (!r || /^(javascript|mailto|tel|data|blob|about|sms|ftp):/i.test(r)) return null;
  try {
    const u = new URL(r, base);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    u.hash = '';
    return u.toString();
  } catch {
    return null;
  }
}

/**
 * Extract what a passive scanner wants from a page.
 * @returns {{links:string[], scripts:{url:string|null, inline:boolean, integrity?:string, crossorigin?:string}[], styles:{url:string, integrity?:string}[], images:string[], frames:string[], forms:{action:string|null, method:string, inputs:{name:string, type:string, autocomplete?:string}[]}[], meta:Record<string,string>, title:string, metaRefresh:string|null, baseHref:string|null}}
 */
export function extractPage(html, pageUrl) {
  const src = String(html);
  const baseTag = tags(src, ['base']).find((t) => t.attrs.href);
  const base = (baseTag && resolveUrl(baseTag.attrs.href, pageUrl)) || pageUrl;

  const links = new Set();
  const scripts = [];
  const styles = [];
  const images = new Set();
  const frames = new Set();
  const meta = {};
  let metaRefresh = null;

  for (const t of tags(src)) {
    const a = t.attrs;
    switch (t.name) {
      case 'a': case 'area': { const u = resolveUrl(a.href, base); if (u) links.add(u); break; }
      case 'link': {
        const rel = (a.rel || '').toLowerCase();
        const u = resolveUrl(a.href, base);
        if (!u) break;
        if (/\bstylesheet\b/.test(rel)) styles.push({ url: u, integrity: a.integrity, crossorigin: a.crossorigin });
        else if (/\b(alternate|canonical|next|prev|manifest)\b/.test(rel)) links.add(u);
        break;
      }
      case 'script': {
        const u = a.src ? resolveUrl(a.src, base) : null;
        scripts.push({ url: u, inline: !a.src, integrity: a.integrity, crossorigin: a.crossorigin, type: a.type });
        break;
      }
      case 'img': case 'source': case 'video': case 'audio': case 'embed': case 'object': {
        const u = resolveUrl(a.src || a.data || a.srcset?.split(/[\s,]+/)[0], base); if (u) images.add(u); break;
      }
      case 'iframe': case 'frame': { const u = resolveUrl(a.src, base); if (u) frames.add(u); break; }
      case 'meta': {
        if ((a['http-equiv'] || '').toLowerCase() === 'refresh' && a.content) {
          const m = /url\s*=\s*['"]?([^'";]+)/i.exec(a.content);
          if (m) { metaRefresh = resolveUrl(m[1], base); if (metaRefresh) links.add(metaRefresh); }
        }
        const key = (a.name || a.property || a['http-equiv'] || '').toLowerCase();
        if (key && a.content !== undefined && !(key in meta)) meta[key] = a.content;
        break;
      }
      default: break;
    }
  }

  const forms = [];
  const stripped = stripNonMarkup(src);
  for (const m of stripped.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const a = parseAttributes(m[1]);
    const inputs = tags(m[2], ['input', 'select', 'textarea']).map((t) => ({
      name: t.attrs.name || t.attrs.id || '',
      type: (t.attrs.type || (t.name === 'input' ? 'text' : t.name)).toLowerCase(),
      autocomplete: t.attrs.autocomplete,
    }));
    const action = a.action !== undefined ? resolveUrl(a.action || base, base) : base;
    forms.push({ action, method: (a.method || 'get').toLowerCase(), inputs, autocomplete: a.autocomplete });
    if (action) links.add(action);
  }

  const titleMatch = /<title\b[^>]*>([\s\S]*?)<\/title>/i.exec(stripped);
  return {
    links: [...links],
    scripts,
    styles,
    images: [...images],
    frames: [...frames],
    forms,
    meta,
    title: titleMatch ? decodeEntities(titleMatch[1]).replace(/\s+/g, ' ').trim() : '',
    metaRefresh,
    baseHref: baseTag ? base : null,
  };
}

/** Inline script bodies (for sourceMappingURL / library banners). */
export function inlineScripts(html) {
  return [...String(html).matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)].map((m) => m[1]).filter((s) => s.trim());
}
