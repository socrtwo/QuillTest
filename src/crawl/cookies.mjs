/*
 * QuillTest — Set-Cookie parsing
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 */

/** @typedef {{name:string, value:string, secure:boolean, httpOnly:boolean, sameSite:string|null, domain:string|null, path:string|null, expires:string|null, maxAge:number|null, raw:string}} Cookie */

export function parseSetCookie(header) {
  const parts = String(header).split(';').map((p) => p.trim());
  const [first, ...attrs] = parts;
  const eq = first.indexOf('=');
  const name = eq >= 0 ? first.slice(0, eq).trim() : first.trim();
  const value = eq >= 0 ? first.slice(eq + 1).trim() : '';
  const c = { name, value, secure: false, httpOnly: false, sameSite: null, domain: null, path: null, expires: null, maxAge: null, raw: String(header), partitioned: false };
  for (const a of attrs) {
    const i = a.indexOf('=');
    const k = (i >= 0 ? a.slice(0, i) : a).trim().toLowerCase();
    const v = i >= 0 ? a.slice(i + 1).trim() : '';
    switch (k) {
      case 'secure': c.secure = true; break;
      case 'httponly': c.httpOnly = true; break;
      case 'partitioned': c.partitioned = true; break;
      case 'samesite': c.sameSite = v ? v[0].toUpperCase() + v.slice(1).toLowerCase() : 'None'; break;
      case 'domain': c.domain = v.replace(/^\./, '').toLowerCase() || null; break;
      case 'path': c.path = v || null; break;
      case 'expires': c.expires = v || null; break;
      case 'max-age': c.maxAge = Number.isFinite(Number(v)) ? Number(v) : null; break;
      default: break;
    }
  }
  return c;
}

const SESSION_NAMES = /^(phpsessid|jsessionid|asp\.net_sessionid|aspsessionid\w*|connect\.sid|sessionid|session|sess(ion)?_?id|sid|_session|rack\.session|laravel_session|ci_session|csrftoken|xsrf-token|__host-|__secure-|auth|token|jwt|remember_?me|_ga_sess)/i;

/** A cookie that looks like it carries a session or credential. */
export function looksLikeSession(cookie) {
  if (SESSION_NAMES.test(cookie.name)) return true;
  // Opaque high-entropy value with no expiry (a session cookie) is a reasonable hint.
  return !cookie.expires && cookie.maxAge === null && /^[A-Za-z0-9%+/=_-]{20,}$/.test(cookie.value) && /\d/.test(cookie.value) && /[A-Za-z]/.test(cookie.value);
}
