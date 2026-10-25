/*
 * Anne's Test — fix-artifact generators
 * Part of the Anne's Office suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Turns a scan report into things you can paste: a security-header block for
 * the server the fingerprint detected (nginx, Apache, Caddy, IIS, Express/
 * helmet, Netlify/Vercel), a Content-Security-Policy derived from the script,
 * style and frame origins the crawler actually observed, and cookie-attribute
 * settings for the detected framework.
 *
 * Principles:
 *   - Generate, never apply. Output is files for the operator to review.
 *   - Derive from evidence. Only headers that a finding calls for are
 *     emitted; the CSP allow-list is exactly the origins seen on the site.
 *   - Start safe. The CSP is emitted as Report-Only with an enforced twin,
 *     and every 'unsafe-*' concession is called out so it can be removed.
 */

export const TARGETS = ['nginx', 'apache', 'caddy', 'iis', 'express', 'netlify', 'generic'];

// ---------------------------------------------------------------------------
// Decide what to emit from the findings
// ---------------------------------------------------------------------------

const HAS = (findings, id) => findings.some((f) => f.checkId === id);

/**
 * Build the header plan: which headers, with which values, and why.
 * @param {object} report  scan report (findings, assets, origin)
 * @returns {{headers: Array<{name, value, because:string[]}>, csp: object|null, notes: string[]}}
 */
export function planHeaders(report) {
  const findings = report.findings || [];
  const isHttps = String(report.origin || '').startsWith('https://');
  const headers = [];
  const notes = [];
  const add = (name, value, because) => headers.push({ name, value, because: [because].flat() });

  if (isHttps && HAS(findings, 'transport.hsts')) {
    add('Strict-Transport-Security', 'max-age=31536000; includeSubDomains', 'transport.hsts');
    notes.push('HSTS: start with a shorter max-age (e.g. 300) if you are unsure every subdomain serves HTTPS, then raise it. Add "; preload" only when ready to submit to hstspreload.org.');
  }
  if (HAS(findings, 'headers.x-content-type-options')) add('X-Content-Type-Options', 'nosniff', 'headers.x-content-type-options');
  if (HAS(findings, 'headers.frame')) add('X-Frame-Options', 'SAMEORIGIN', 'headers.frame');
  if (HAS(findings, 'headers.referrer-policy')) add('Referrer-Policy', 'strict-origin-when-cross-origin', 'headers.referrer-policy');
  if (HAS(findings, 'headers.permissions-policy')) add('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()', 'headers.permissions-policy');

  let csp = null;
  if (HAS(findings, 'headers.csp') || HAS(findings, 'headers.frame') || HAS(findings, 'content.mixed')) {
    csp = buildCsp(report);
    notes.push(...csp.notes);
  }
  return { headers, csp, notes };
}

/**
 * Derive a CSP from observed assets. Returns both a report-only policy to
 * deploy first and the enforced policy it should become.
 */
export function buildCsp(report) {
  const a = report.assets || { scriptOrigins: [], styleOrigins: [], frameOrigins: [], inlineScripts: false, inlineStyles: false, eventHandlers: false };
  const findings = report.findings || [];
  const notes = [];
  const concessions = [];

  const script = ["'self'", ...a.scriptOrigins];
  if (a.inlineScripts || a.eventHandlers) {
    script.push("'unsafe-inline'");
    concessions.push(`script-src 'unsafe-inline' — the site has ${[a.inlineScripts && 'inline <script> blocks', a.eventHandlers && 'inline event handlers (onclick=…)'].filter(Boolean).join(' and ')}. Move them to external files or add nonces, then remove 'unsafe-inline'.`);
  }
  const style = ["'self'", ...a.styleOrigins];
  if (a.inlineStyles) {
    style.push("'unsafe-inline'");
    concessions.push("style-src 'unsafe-inline' — inline <style> or style= attributes were seen. Remove it once styles are external or nonced.");
  }
  const directives = [
    ['default-src', ["'self'"]],
    ['script-src', script],
    ['style-src', style],
    ['img-src', ["'self'", 'data:', 'https:']],
    ['font-src', ["'self'", 'https:', 'data:']],
    ['connect-src', ["'self'"]],
    ['frame-src', a.frameOrigins.length ? a.frameOrigins : ["'none'"]],
    ['object-src', ["'none'"]],
    ['base-uri', ["'self'"]],
    ['form-action', ["'self'"]],
    ['frame-ancestors', ["'self'"]],
  ];
  if (HAS(findings, 'content.mixed')) directives.push(['upgrade-insecure-requests', []]);

  const render = (dirs) => dirs.map(([k, v]) => (v.length ? `${k} ${v.join(' ')}` : k)).join('; ');
  const enforced = render(directives);
  notes.push('CSP: deploy the Report-Only header first, watch for violation reports (add "report-to"/"report-uri" to collect them), fix what breaks, then switch to the enforced header.');
  if (a.scriptOrigins.length) notes.push(`CSP allow-list was derived from scripts actually loaded on crawled pages: ${a.scriptOrigins.join(', ')}. Remove any you do not recognize.`);
  notes.push('connect-src is set to \'self\'; add the API/analytics origins your JavaScript calls (the crawler cannot see fetch/XHR targets).');
  return { reportOnly: enforced, enforced, concessions, notes, directives: Object.fromEntries(directives) };
}

// ---------------------------------------------------------------------------
// Renderers
// ---------------------------------------------------------------------------

function esc(s, q = '"') { return String(s).split(q).join('\\' + q); }

const renderers = {
  nginx(plan) {
    const lines = ['# Anne\'s Test — add inside the server { } block (or a shared snippet included from it)', '# "always" makes the header apply to error responses too.'];
    for (const h of plan.headers) lines.push(`add_header ${h.name} "${esc(h.value)}" always;`);
    if (plan.csp) {
      lines.push(`add_header Content-Security-Policy-Report-Only "${esc(plan.csp.reportOnly)}" always;`);
      lines.push(`# When clean, replace the line above with:`);
      lines.push(`# add_header Content-Security-Policy "${esc(plan.csp.enforced)}" always;`);
    }
    lines.push('', '# Hide the version in the Server header:', 'server_tokens off;');
    return { filename: 'quilltest-security-headers.nginx.conf', contents: lines.join('\n') + '\n' };
  },
  apache(plan) {
    const lines = ['# Anne\'s Test — add to the <VirtualHost> (or .htaccess if AllowOverride permits)', '<IfModule mod_headers.c>'];
    for (const h of plan.headers) lines.push(`  Header always set ${h.name} "${esc(h.value)}"`);
    if (plan.csp) {
      lines.push(`  Header always set Content-Security-Policy-Report-Only "${esc(plan.csp.reportOnly)}"`);
      lines.push(`  # When clean, replace with:`);
      lines.push(`  # Header always set Content-Security-Policy "${esc(plan.csp.enforced)}"`);
    }
    lines.push('</IfModule>', '', '# Hide version details:', 'ServerTokens Prod', 'ServerSignature Off', '', '# Disable directory listings:', 'Options -Indexes');
    return { filename: 'quilltest-security-headers.apache.conf', contents: lines.join('\n') + '\n' };
  },
  caddy(plan) {
    const lines = ['# Anne\'s Test — add inside the site block of your Caddyfile', 'header {'];
    for (const h of plan.headers) lines.push(`  ${h.name} "${esc(h.value)}"`);
    if (plan.csp) {
      lines.push(`  Content-Security-Policy-Report-Only "${esc(plan.csp.reportOnly)}"`);
      lines.push(`  # When clean, replace with:`);
      lines.push(`  # Content-Security-Policy "${esc(plan.csp.enforced)}"`);
    }
    lines.push('  -Server', '}');
    return { filename: 'quilltest-security-headers.Caddyfile', contents: lines.join('\n') + '\n' };
  },
  iis(plan) {
    const x = (s) => String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
    const lines = ['<!-- Anne\'s Test — merge into web.config under <system.webServer> -->', '<httpProtocol>', '  <customHeaders>'];
    for (const h of plan.headers) lines.push(`    <remove name="${h.name}" />`, `    <add name="${h.name}" value="${x(h.value)}" />`);
    if (plan.csp) {
      lines.push(`    <add name="Content-Security-Policy-Report-Only" value="${x(plan.csp.reportOnly)}" />`);
      lines.push(`    <!-- When clean, replace with: <add name="Content-Security-Policy" value="${x(plan.csp.enforced)}" /> -->`);
    }
    lines.push('    <remove name="X-Powered-By" />', '  </customHeaders>', '</httpProtocol>', '<security>', '  <requestFiltering removeServerHeader="true" />', '</security>');
    return { filename: 'quilltest-security-headers.web.config.xml', contents: lines.join('\n') + '\n' };
  },
  express(plan) {
    const lines = [
      '// Anne\'s Test — Express: npm i helmet, then early in your app:',
      '// helmet() already sets X-Content-Type-Options: nosniff, X-DNS-Prefetch-Control, and removes X-Powered-By;',
      '// the options below add/adjust the headers this scan called for.',
      "const helmet = require('helmet');",
      "app.disable('x-powered-by');",
    ];
    const opts = [];
    const byName = Object.fromEntries(plan.headers.map((h) => [h.name, h.value]));
    if (byName['Strict-Transport-Security']) opts.push('  strictTransportSecurity: { maxAge: 31536000, includeSubDomains: true },');
    if (byName['X-Frame-Options']) opts.push("  frameguard: { action: 'sameorigin' },");
    if (byName['Referrer-Policy']) opts.push("  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },");
    if (plan.csp) {
      const d = plan.csp.directives;
      const obj = Object.entries(d).map(([k, v]) => `      "${k}": ${JSON.stringify(v)},`).join('\n');
      opts.push('  contentSecurityPolicy: {', '    reportOnly: true, // flip to false when clean', '    directives: {', obj, '    },', '  },');
    }
    lines.push('app.use(helmet({', ...opts, '}));');
    if (byName['Permissions-Policy']) lines.push('', `app.use((req, res, next) => { res.setHeader('Permissions-Policy', '${byName['Permissions-Policy']}'); next(); });`);
    return { filename: 'quilltest-security-headers.express.js', contents: lines.join('\n') + '\n' };
  },
  netlify(plan) {
    const lines = ['# Anne\'s Test — Netlify _headers file (Vercel: translate to vercel.json "headers")', '/*'];
    for (const h of plan.headers) lines.push(`  ${h.name}: ${h.value}`);
    if (plan.csp) lines.push(`  Content-Security-Policy-Report-Only: ${plan.csp.reportOnly}`, `  # When clean: Content-Security-Policy: ${plan.csp.enforced}`);
    return { filename: '_headers', contents: lines.join('\n') + '\n' };
  },
  generic(plan) {
    const lines = ['# Anne\'s Test — response headers to add (any server/CDN)'];
    for (const h of plan.headers) lines.push(`${h.name}: ${h.value}`);
    if (plan.csp) lines.push(`Content-Security-Policy-Report-Only: ${plan.csp.reportOnly}`, `# when clean → Content-Security-Policy: ${plan.csp.enforced}`);
    return { filename: 'quilltest-security-headers.txt', contents: lines.join('\n') + '\n' };
  },
};

// ---------------------------------------------------------------------------
// Cookie fixes per framework
// ---------------------------------------------------------------------------

const COOKIE_FIXES = {
  'PHP': { filename: 'quilltest-cookies.php.ini', contents: '; Anne\'s Test — php.ini (or ini_set before session_start)\nsession.cookie_secure = 1\nsession.cookie_httponly = 1\nsession.cookie_samesite = "Lax"\nsession.use_strict_mode = 1\n' },
  'Express (express-session)': { filename: 'quilltest-cookies.express.js', contents: "// Anne's Test — express-session options\napp.set('trust proxy', 1); // if behind a TLS-terminating proxy\napp.use(session({\n  name: '__Host-sid',\n  cookie: { secure: true, httpOnly: true, sameSite: 'lax', path: '/' },\n  // ...your existing options\n}));\n" },
  'Django': { filename: 'quilltest-cookies.django.py', contents: '# Anne\'s Test — settings.py\nSESSION_COOKIE_SECURE = True\nSESSION_COOKIE_HTTPONLY = True\nSESSION_COOKIE_SAMESITE = "Lax"\nCSRF_COOKIE_SECURE = True\nCSRF_COOKIE_SAMESITE = "Lax"\nSECURE_HSTS_SECONDS = 31536000\nSECURE_HSTS_INCLUDE_SUBDOMAINS = True\n' },
  'Ruby on Rails': { filename: 'quilltest-cookies.rails.rb', contents: '# Anne\'s Test — config/initializers/session_store.rb\nRails.application.config.session_store :cookie_store, key: "_app_session", secure: Rails.env.production?, httponly: true, same_site: :lax\n# and in config/environments/production.rb:\n# config.force_ssl = true\n' },
  'Laravel': { filename: 'quilltest-cookies.laravel.env', contents: '# Anne\'s Test — .env (see config/session.php)\nSESSION_SECURE_COOKIE=true\nSESSION_HTTP_ONLY=true\nSESSION_SAME_SITE=lax\n' },
  'ASP.NET': { filename: 'quilltest-cookies.aspnet.xml', contents: '<!-- Anne\'s Test — web.config -->\n<system.web>\n  <httpCookies requireSSL="true" httpOnlyCookies="true" sameSite="Lax" />\n  <sessionState cookieSameSite="Lax" />\n</system.web>\n' },
  'Flask': { filename: 'quilltest-cookies.flask.py', contents: '# Anne\'s Test — Flask config\napp.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")\n' },
  'WordPress': { filename: 'quilltest-cookies.wp-config.php', contents: "<?php\n// Anne's Test — wp-config.php: force HTTPS for admin/login so auth cookies are Secure\ndefine('FORCE_SSL_ADMIN', true);\n// Then ensure the site URL uses https:// (Settings → General).\n" },
};

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/** Pick a render target from the fingerprint; falls back to generic. */
export function pickTarget(report) {
  const server = (report.stack?.server?.name || '').toLowerCase();
  const fw = (report.stack?.framework || []).map((f) => f.name.toLowerCase());
  if (server.includes('nginx')) return 'nginx';
  if (server.includes('apache') || server.includes('litespeed')) return 'apache';
  if (server.includes('caddy')) return 'caddy';
  if (server.includes('iis')) return 'iis';
  if (server.includes('netlify') || server.includes('vercel')) return 'netlify';
  if (fw.some((f) => f.includes('express') || f.includes('next.js'))) return 'express';
  return 'generic';
}

/**
 * @param {object} report  a scan report from runPassiveScan (findings, assets, stack, origin)
 * @param {{target?:string, all?:boolean}} [opts]
 * @returns {{target:string, files:Array<{filename, contents, kind}>, plan:object, notes:string[], coverage:object}}
 */
export function generateFixes(report, opts = {}) {
  const plan = planHeaders(report);
  const target = opts.target && TARGETS.includes(opts.target) ? opts.target : pickTarget(report);
  const files = [];
  const covered = new Set();

  if (plan.headers.length || plan.csp) {
    const targets = opts.all ? TARGETS : [target];
    for (const t of targets) files.push({ ...renderers[t](plan), kind: 'headers', target: t });
    for (const h of plan.headers) for (const b of h.because) covered.add(b);
    if (plan.csp) { covered.add('headers.csp'); covered.add('headers.frame'); }
    // The server configs also switch off version banners (server_tokens / ServerTokens / removeServerHeader / -Server / x-powered-by).
    if (['nginx', 'apache', 'iis', 'caddy', 'express'].includes(target) && (report.findings || []).some((f) => f.checkId === 'disclosure.server-banner')) covered.add('disclosure.server-banner');
    if (target === 'apache' && (report.findings || []).some((f) => f.checkId === 'content.directory-listing')) covered.add('content.directory-listing');
    if (plan.csp && (report.findings || []).some((f) => f.checkId === 'content.mixed')) covered.add('content.mixed');
  }

  // Cookie fixes for detected frameworks when a cookie finding exists.
  const cookieFinding = (report.findings || []).some((f) => f.checkId === 'cookies.flags');
  if (cookieFinding) {
    const names = [...(report.stack?.framework || []), ...(report.stack?.cms || [])].map((f) => f.name);
    let any = false;
    for (const n of names) if (COOKIE_FIXES[n]) { files.push({ ...COOKIE_FIXES[n], kind: 'cookies', target: n }); any = true; }
    if (!any) files.push({ filename: 'quilltest-cookies.txt', contents: '# Anne\'s Test — set on every cookie, especially sessions:\nSet-Cookie: <name>=<value>; Path=/; Secure; HttpOnly; SameSite=Lax\n# Prefer the __Host- prefix for session cookies.\n', kind: 'cookies', target: 'generic' });
    covered.add('cookies.flags');
  }

  // Findings without a generated artifact still carry their textual remediation.
  const manual = (report.findings || []).filter((f) => !covered.has(f.checkId)).map((f) => ({ id: f.id, checkId: f.checkId, title: f.title, remediation: f.remediation }));

  return {
    target,
    files,
    plan,
    notes: plan.notes.concat(plan.csp?.concessions?.map((c) => 'CSP concession: ' + c) || []),
    coverage: { generated: [...covered].sort(), manual },
  };
}
