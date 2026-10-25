/*
 * QuillTest — stack fingerprinting
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Infers the server, language/framework, and CMS from what the site already
 * volunteers: response headers, cookie names, and page markup. Purely passive.
 * The result lets remediations be phrased for the right stack (an nginx
 * directive vs. an Express middleware) and gives the AI layer honest context.
 *
 * Every signal is recorded with its evidence so a wrong guess can be traced.
 */

const SIGNALS = [
  // --- servers (from Server header) ---
  { kind: 'server', name: 'nginx', header: 'server', re: /^nginx(?:\/(\S+))?/i },
  { kind: 'server', name: 'Apache', header: 'server', re: /^apache(?:\/(\S+))?/i },
  { kind: 'server', name: 'Microsoft-IIS', header: 'server', re: /^microsoft-iis(?:\/(\S+))?/i },
  { kind: 'server', name: 'LiteSpeed', header: 'server', re: /litespeed/i },
  { kind: 'server', name: 'Caddy', header: 'server', re: /^caddy/i },
  { kind: 'server', name: 'cloudflare', header: 'server', re: /^cloudflare/i },
  { kind: 'server', name: 'Vercel', header: 'server', re: /^vercel/i },
  { kind: 'server', name: 'Netlify', header: 'server', re: /^netlify/i },
  { kind: 'server', name: 'GitHub Pages', header: 'server', re: /^github\.com/i },
  { kind: 'server', name: 'AmazonS3', header: 'server', re: /^amazons3/i },
  { kind: 'server', name: 'gunicorn', header: 'server', re: /^gunicorn(?:\/(\S+))?/i },
  { kind: 'server', name: 'Kestrel', header: 'server', re: /^kestrel/i },
  { kind: 'server', name: 'Cowboy', header: 'server', re: /^cowboy/i },
  // --- languages / frameworks (headers) ---
  { kind: 'framework', name: 'PHP', header: 'x-powered-by', re: /php(?:\/(\S+))?/i },
  { kind: 'framework', name: 'ASP.NET', header: 'x-powered-by', re: /asp\.net/i },
  { kind: 'framework', name: 'ASP.NET', header: 'x-aspnet-version', re: /(.+)/ },
  { kind: 'framework', name: 'Express', header: 'x-powered-by', re: /express/i },
  { kind: 'framework', name: 'Next.js', header: 'x-powered-by', re: /next\.js/i },
  { kind: 'framework', name: 'Phusion Passenger', header: 'x-powered-by', re: /phusion passenger(?:\s*\(?r?\)?\s*(\S+))?/i },
  { kind: 'framework', name: 'Servlet/JSP', header: 'x-powered-by', re: /servlet|jsp/i },
  { kind: 'cms', name: 'Drupal', header: 'x-generator', re: /drupal(?:\s+(\S+))?/i },
  { kind: 'cms', name: 'Drupal', header: 'x-drupal-cache', re: /./ },
  { kind: 'cms', name: 'Shopify', header: 'x-shopid', re: /./ },
  { kind: 'cms', name: 'Shopify', header: 'x-shopify-stage', re: /./ },
  { kind: 'cms', name: 'WordPress', header: 'link', re: /wp-json/i },
  // --- cookies ---
  { kind: 'framework', name: 'PHP', cookie: /^PHPSESSID$/i },
  { kind: 'framework', name: 'ASP.NET', cookie: /^(ASP\.NET_SessionId|\.AspNetCore\.|ARRAffinity)/i },
  { kind: 'framework', name: 'Java (Servlet)', cookie: /^JSESSIONID$/i },
  { kind: 'framework', name: 'Django', cookie: /^(csrftoken|sessionid|django_language)$/i },
  { kind: 'framework', name: 'Laravel', cookie: /^(laravel_session|XSRF-TOKEN)$/i },
  { kind: 'framework', name: 'Ruby on Rails', cookie: /_session$|^_rails/i },
  { kind: 'framework', name: 'Express (express-session)', cookie: /^connect\.sid$/i },
  { kind: 'framework', name: 'Flask', cookie: /^session$/ },
  { kind: 'cms', name: 'WordPress', cookie: /^(wordpress_|wp-settings-|wp_)/i },
  { kind: 'cms', name: 'Joomla', cookie: /^joomla_/i },
  // --- markup ---
  { kind: 'cms', name: 'WordPress', body: /<meta\s+name=["']generator["']\s+content=["']WordPress(?:\s+([\d.]+))?/i },
  { kind: 'cms', name: 'WordPress', body: /\/wp-(?:content|includes)\//i },
  { kind: 'cms', name: 'Joomla', body: /<meta\s+name=["']generator["']\s+content=["']Joomla!?(?:\s*-\s*|\s+)?([\d.]*)/i },
  { kind: 'cms', name: 'Drupal', body: /<meta\s+name=["']generator["']\s+content=["']Drupal(?:\s+([\d.]+))?/i },
  { kind: 'cms', name: 'Ghost', body: /<meta\s+name=["']generator["']\s+content=["']Ghost(?:\s+([\d.]+))?/i },
  { kind: 'cms', name: 'Hugo', body: /<meta\s+name=["']generator["']\s+content=["']Hugo(?:\s+([\d.]+))?/i },
  { kind: 'cms', name: 'Jekyll', body: /<meta\s+name=["']generator["']\s+content=["']Jekyll(?:\s+v?([\d.]+))?/i },
  { kind: 'cms', name: 'Wix', body: /<meta\s+name=["']generator["']\s+content=["']Wix\.com/i },
  { kind: 'cms', name: 'Squarespace', body: /<!-- This is Squarespace\. -->|squarespace\.com/i },
  { kind: 'cms', name: 'Shopify', body: /cdn\.shopify\.com|Shopify\.theme/i },
  { kind: 'framework', name: 'Next.js', body: /<script[^>]+id=["']__NEXT_DATA__["']|\/_next\/static\//i },
  { kind: 'framework', name: 'Nuxt', body: /window\.__NUXT__|\/_nuxt\//i },
  { kind: 'framework', name: 'React', body: /data-reactroot|__REACT_DEVTOOLS_GLOBAL_HOOK__/i },
  { kind: 'framework', name: 'Angular', body: /\bng-version=["']([\d.]+)/i },
  { kind: 'framework', name: 'Vue', body: /data-v-[0-9a-f]{8}|__vue__/i },
  { kind: 'framework', name: 'Django', body: /csrfmiddlewaretoken/i },
  { kind: 'framework', name: 'Laravel', body: /name=["']_token["'][^>]*value=|laravel/i },
  { kind: 'framework', name: 'Ruby on Rails', body: /name=["']authenticity_token["']|csrf-param/i },
  { kind: 'framework', name: 'ASP.NET WebForms', body: /name=["']__VIEWSTATE["']/i },
  { kind: 'library', name: 'jQuery', body: /jquery(?:[-.]([\d.]+))?(?:\.min)?\.js/i },
  { kind: 'library', name: 'Bootstrap', body: /bootstrap(?:[-.]([\d.]+))?(?:\.min)?\.(?:css|js)/i },
  // CDN path styles carry the version in the directory, not the filename:
  //   cdn.jsdelivr.net/npm/jquery@3.5.1/dist/jquery.min.js · unpkg.com/bootstrap@4.3.0/dist/css/bootstrap.min.css
  //   cdnjs.cloudflare.com/ajax/libs/jquery/3.5.1/jquery.min.js · ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js
  //   cdnjs.cloudflare.com/ajax/libs/twitter-bootstrap/4.3.0/css/bootstrap.min.css · stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css
  { kind: 'library', name: 'jQuery', body: /(?:jquery@|\/jquery\/)v?(\d+\.\d+(?:\.\d+)?)\/[^"'\s>]*jquery(?:\.slim)?(?:\.min)?\.js/i },
  { kind: 'library', name: 'Bootstrap', body: /(?:bootstrap@|\/(?:twitter-)?bootstrap\/)v?(\d+\.\d+(?:\.\d+)?)\/[^"'\s>]*bootstrap(?:\.bundle)?(?:\.min)?\.(?:css|js)/i },
];

function cookieNames(headers) {
  const sc = headers?.['set-cookie'];
  const list = Array.isArray(sc) ? sc : sc ? [sc] : [];
  return list.map((c) => String(c).split('=')[0].trim()).filter(Boolean);
}

/**
 * @param {Array<{headers?:object, body?:string, url?:string}>} observations  pages/root observations
 * @returns {{server:object|null, framework:object[], cms:object[], library:object[], signals:object[]}}
 */
export function fingerprint(observations) {
  const found = new Map(); // key kind:name → {kind,name,version,evidence[],confidence}
  const add = (kind, name, version, evidence) => {
    const key = `${kind}:${name}`;
    const cur = found.get(key) || { kind, name, version: null, evidence: [], confidence: 0 };
    if (version && !cur.version) cur.version = version;
    if (cur.evidence.length < 5 && !cur.evidence.includes(evidence)) cur.evidence.push(evidence);
    cur.confidence = Math.min(1, cur.confidence + 0.4);
    found.set(key, cur);
  };

  for (const obs of observations || []) {
    if (!obs) continue;
    const headers = obs.headers || {};
    const names = cookieNames(headers);
    for (const s of SIGNALS) {
      if (s.header) {
        const v = headers[s.header];
        if (!v) continue;
        const m = String(v).match(s.re);
        if (m) add(s.kind, s.name, m[1] && /\d/.test(m[1]) ? m[1] : null, `${s.header}: ${String(v).slice(0, 80)}`);
      } else if (s.cookie) {
        for (const n of names) if (s.cookie.test(n)) add(s.kind, s.name, null, `cookie: ${n}`);
      } else if (s.body && obs.body) {
        const m = obs.body.match(s.body);
        if (m) add(s.kind, s.name, m[1] && /\d/.test(m[1]) ? m[1] : null, `markup: ${m[0].slice(0, 80)}${obs.url ? ` (${obs.url})` : ''}`);
      }
    }
  }

  const all = [...found.values()].map((x) => ({ ...x, confidence: Number(x.confidence.toFixed(1)) }));
  const by = (k) => all.filter((x) => x.kind === k).sort((a, b) => b.confidence - a.confidence);
  return { server: by('server')[0] || null, framework: by('framework'), cms: by('cms'), library: by('library'), signals: all };
}

/** One-line human summary, e.g. "nginx/1.18.0 · PHP 7.4 · WordPress 6.4". */
export function describeStack(fp) {
  const parts = [];
  if (fp?.server) parts.push(fp.server.version ? `${fp.server.name}/${fp.server.version}` : fp.server.name);
  for (const f of fp?.framework || []) parts.push(f.version ? `${f.name} ${f.version}` : f.name);
  for (const c of fp?.cms || []) parts.push(c.version ? `${c.name} ${c.version}` : c.name);
  return parts.join(' · ') || 'unknown';
}
