/** Information disclosure: banners, verbose errors, source maps, exposed files, directory listings. */
import { defineCheck } from '../registry.mjs';

const ERROR_PATTERNS = [
  { re: /Traceback \(most recent call last\)/, stack: 'Python' },
  { re: /\bat [\w$.<>]+\([\w$]+\.java:\d+\)/, stack: 'Java' },
  { re: /Server Error in '[^']*' Application|\[HttpException\]|ASP\.NET is configured to show verbose error/, stack: 'ASP.NET' },
  { re: /<b>(Warning|Fatal error|Notice|Parse error)<\/b>:\s.+ on line <b>\d+<\/b>|PHP (Warning|Fatal error|Notice|Parse error):/, stack: 'PHP' },
  { re: /You have an error in your SQL syntax|ORA-\d{5}|PG::SyntaxError|SQLSTATE\[\w+\]|Unclosed quotation mark after the character string|Microsoft OLE DB Provider for SQL Server/, stack: 'SQL' },
  { re: /\bat .+ \(.+\.(js|mjs|ts):\d+:\d+\)\n\s+at /, stack: 'Node.js' },
  { re: /ActionController::RoutingError|ActiveRecord::\w+Error|\(RuntimeError\)|<h1>\s*Template is missing/, stack: 'Rails' },
  { re: /Whitelabel Error Page|org\.springframework\.\w+\.\w+Exception/, stack: 'Spring' },
  { re: /Django Version:|DEBUG = True|You're seeing this error because you have/, stack: 'Django' },
];

/** Well-known files whose exposure is a problem. Each has a content signature so a catch-all 200 page cannot cause a false positive. */
export const SENSITIVE_PATHS = [
  { path: '/.git/HEAD', signature: /^ref: refs\/|^[0-9a-f]{40}\s*$/m, severity: 'high', cwe: [527], what: 'Git repository metadata; the full source history can usually be reconstructed from an exposed .git directory' },
  { path: '/.git/config', signature: /^\[core\]/m, severity: 'high', cwe: [527], what: 'Git repository configuration, often including remote URLs with embedded credentials' },
  { path: '/.svn/entries', signature: /^\d+\s*$|^dir\s*$/m, severity: 'high', cwe: [527], what: 'Subversion metadata' },
  { path: '/.hg/requires', signature: /^(revlogv1|dotencode|fncache|store|generaldelta)/m, severity: 'high', cwe: [527], what: 'Mercurial repository metadata' },
  { path: '/.env', signature: /^[A-Z][A-Z0-9_]{2,}=.+/m, severity: 'critical', cwe: [538, 200], what: 'Environment file; typically holds database passwords and API keys' },
  { path: '/.env.local', signature: /^[A-Z][A-Z0-9_]{2,}=.+/m, severity: 'critical', cwe: [538, 200], what: 'Environment file' },
  { path: '/.env.production', signature: /^[A-Z][A-Z0-9_]{2,}=.+/m, severity: 'critical', cwe: [538, 200], what: 'Environment file' },
  { path: '/.DS_Store', signature: /^\x00\x00\x00\x01Bud1/, severity: 'low', cwe: [538], what: 'macOS folder metadata; reveals file names in the directory' },
  { path: '/.htaccess', signature: /^\s*(RewriteEngine|RewriteRule|AuthType|Deny from|Require |Options )/m, severity: 'medium', cwe: [538], what: 'Apache per-directory configuration, including protected paths and rewrite logic' },
  { path: '/.htpasswd', signature: /^[^:\s]+:\$?[\w$./]{10,}/m, severity: 'critical', cwe: [538, 200], what: 'Password hashes for HTTP basic authentication' },
  { path: '/wp-config.php.bak', signature: /DB_PASSWORD|DB_NAME/, severity: 'critical', cwe: [538, 200], what: 'WordPress configuration backup with database credentials' },
  { path: '/wp-config.php~', signature: /DB_PASSWORD|DB_NAME/, severity: 'critical', cwe: [538, 200], what: 'WordPress configuration backup with database credentials' },
  { path: '/config.php.bak', signature: /<\?php/, severity: 'high', cwe: [538], what: 'PHP configuration backup served as text' },
  { path: '/phpinfo.php', signature: /<title>PHP \d|phpinfo\(\)|PHP Version/, severity: 'medium', cwe: [497], what: 'phpinfo() output: paths, loaded modules, environment variables' },
  { path: '/server-status', signature: /Apache Server Status|Server Version:/, severity: 'medium', cwe: [497], what: 'Apache mod_status page: active requests including client IPs and URLs' },
  { path: '/server-info', signature: /Apache Server Information/, severity: 'medium', cwe: [497], what: 'Apache mod_info page: full server configuration' },
  { path: '/elmah.axd', signature: /Error Log for|ELMAH/, severity: 'high', cwe: [497, 200], what: 'ASP.NET ELMAH error log with request details and cookies' },
  { path: '/trace.axd', signature: /Application Trace|Request Details/, severity: 'high', cwe: [497, 200], what: 'ASP.NET request tracing' },
  { path: '/composer.json', signature: /"require"\s*:/, severity: 'low', cwe: [200], what: 'PHP dependency manifest; reveals exact library versions' },
  { path: '/package.json', signature: /"(dependencies|devDependencies|name)"\s*:/, severity: 'low', cwe: [200], what: 'Node dependency manifest; reveals exact library versions' },
  { path: '/web.config', signature: /<configuration>|<system\.web>/i, severity: 'high', cwe: [538], what: 'IIS/ASP.NET configuration, often with connection strings' },
  { path: '/WEB-INF/web.xml', signature: /<web-app|<servlet>/i, severity: 'high', cwe: [538], what: 'Java web application descriptor' },
  { path: '/backup.zip', signature: /^PK\x03\x04/, severity: 'high', cwe: [538], what: 'Archive at a guessable name' },
  { path: '/backup.sql', signature: /CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump/i, severity: 'critical', cwe: [538, 200], what: 'Database dump' },
  { path: '/dump.sql', signature: /CREATE TABLE|INSERT INTO|-- MySQL dump|PostgreSQL database dump/i, severity: 'critical', cwe: [538, 200], what: 'Database dump' },
  { path: '/.aws/credentials', signature: /aws_access_key_id|aws_secret_access_key/i, severity: 'critical', cwe: [538, 200], what: 'AWS credentials file' },
  { path: '/id_rsa', signature: /-----BEGIN (RSA |OPENSSH )?PRIVATE KEY-----/, severity: 'critical', cwe: [538, 200], what: 'SSH private key' },
  { path: '/.well-known/security.txt', signature: /^Contact:/m, severity: 'informational', cwe: [200], what: 'security.txt present (good practice) — informational, lists the security contact', positive: true },
];

const DIR_LISTING = /<title>\s*(Index of|Directory listing for|Directory Listing For|Listing of)\b|<h1>\s*(Index of|Directory listing for)\b|\[To Parent Directory\]/i;

defineCheck([
  {
    id: 'disclosure.serverBanner', title: 'Server software and version disclosed in headers', kind: 'passive', intrusiveness: 0,
    severity: 'low', confidence: 'confirmed', cwe: [200], owasp: 'A05', asvs: ['V14.3.3'],
    description: 'Server, X-Powered-By, X-AspNet-Version and similar headers tell an attacker exactly which software and version to look up exploits for.',
    remediation: { summary: 'Remove or genericise the headers: nginx `server_tokens off;`, Apache `ServerTokens Prod` + `Header unset X-Powered-By`, PHP `expose_php = Off`, Express `app.disable("x-powered-by")`, ASP.NET `<httpRuntime enableVersionHeader="false" />`.', references: ['https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html#server'], fixId: 'fix.hideVersions' },
    observe: (page) => {
      if (page.depth !== 0 || page.kind !== 'page') return [];
      const out = [];
      for (const h of ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator', 'x-drupal-cache', 'x-runtime']) {
        const v = page.headers[h];
        if (!v) continue;
        const hasVersion = /\d+\.\d+/.test(String(v));
        if (h === 'server' && !hasVersion) continue;
        out.push({ url: page.finalUrl, key: h, severity: hasVersion ? 'low' : 'informational', description: `${h}: ${v}`, evidence: { headers: { [h]: v } } });
      }
      return out;
    },
  },
  {
    id: 'disclosure.verboseErrors', title: 'Verbose error message or stack trace in response', kind: 'passive', intrusiveness: 0,
    severity: 'medium', confidence: 'firm', cwe: [209, 497], owasp: 'A05', asvs: ['V7.4.1'],
    description: 'The response contains a stack trace or framework debug page. These reveal file paths, library versions, SQL fragments and sometimes configuration values, and indicate debug mode is on in production.',
    remediation: { summary: 'Turn off debug mode in production (Django DEBUG=False, PHP display_errors=Off, ASP.NET customErrors=On, Rails consider_all_requests_local=false); return generic error pages and log details server-side.', references: ['https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html'] },
    observe: (page) => {
      if (page.kind === 'asset' || !page.body) return [];
      for (const p of ERROR_PATTERNS) {
        const m = p.re.exec(page.body);
        if (m) return [{ url: page.finalUrl, key: p.stack, description: `${p.stack} error details are visible in the response (HTTP ${page.status}).`, evidence: { snippet: excerpt(page.body, m.index), detail: { stack: p.stack, status: page.status } } }];
      }
      return [];
    },
  },
  {
    id: 'disclosure.sourceMaps', title: 'JavaScript source map exposed', kind: 'passive', intrusiveness: 1, requests: 'one GET per referenced .map file (bounded)',
    severity: 'low', confidence: 'confirmed', cwe: [200, 538], owasp: 'A05', asvs: ['V14.3.2'],
    description: 'A production script references a source map that is publicly reachable, exposing the original (unminified) source, comments and file layout.',
    remediation: { summary: 'Do not publish .map files to production (or protect them), and strip `//# sourceMappingURL` comments at build time.', references: ['https://developer.chrome.com/docs/devtools/javascript/source-maps'] },
    probe: async (site) => {
      const out = [];
      const seen = new Set();
      for (const asset of site.pages.filter((p) => p.kind === 'asset' && p.status === 200)) {
        const m = /\/\/[#@]\s*sourceMappingURL=([^\s*]+)/.exec(asset.body.slice(-4000));
        if (!m || m[1].startsWith('data:')) continue;
        let mapUrl; try { mapUrl = new URL(m[1], asset.finalUrl).toString(); } catch { continue; }
        if (seen.has(mapUrl) || seen.size >= 10) continue;
        seen.add(mapUrl);
        const res = await site.request(mapUrl, { kind: 'probe', maxBodyBytes: 64 * 1024 });
        if (res?.status === 200 && /"sources"\s*:\s*\[/.test(res.body)) out.push({ url: mapUrl, key: 'map', description: `Source map for ${asset.finalUrl} is publicly reachable.`, evidence: { detail: { script: asset.finalUrl, sourcesCount: (res.body.match(/"sources"\s*:\s*\[([^\]]*)/) || ['', ''])[1].split(',').filter(Boolean).length } } });
      }
      return out;
    },
  },
  {
    id: 'disclosure.sensitiveFiles', title: 'Sensitive file exposed at a well-known path', kind: 'passive', intrusiveness: 1, requests: `one GET per well-known path (${SENSITIVE_PATHS.length} paths), bodies capped at 16 KiB`,
    severity: 'high', confidence: 'confirmed', cwe: [538, 527, 200], owasp: 'A05', asvs: ['V14.3.2'],
    description: 'Version-control metadata, environment files, backups, server status pages or credential files are reachable. Each is confirmed by its content signature, not just an HTTP 200.',
    remediation: { summary: 'Remove the file from the web root or deny access to it in the server configuration (nginx `location ~ /\\.(git|env|svn|hg) { deny all; }`; Apache `RedirectMatch 404 /\\.(git|env|svn|hg)`), and rotate any secret it contained.', references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'] },
    probe: async (site) => {
      const out = [];
      for (const entry of SENSITIVE_PATHS) {
        const url = site.origin + entry.path;
        const res = await site.request(url, { kind: 'probe', maxBodyBytes: 16 * 1024 });
        if (!res || res.status !== 200 || !res.body) continue;
        if (res.dom && !entry.signature.test(res.body)) continue; // HTML catch-all page
        if (!entry.signature.test(res.body)) continue;
        out.push({ url, key: entry.path, severity: entry.severity, title: entry.positive ? 'security.txt published' : undefined, description: `${entry.what}. Confirmed by content signature (HTTP 200, ${res.bytes} bytes).`, evidence: { snippet: entry.positive ? res.body.slice(0, 300) : res.body.slice(0, 200), detail: { contentType: res.contentType } } });
      }
      return out;
    },
  },
  {
    id: 'disclosure.directoryListing', title: 'Directory listing enabled', kind: 'passive', intrusiveness: 1, requests: 'one GET per asset directory discovered during the crawl (bounded to 15)',
    severity: 'medium', confidence: 'confirmed', cwe: [548], owasp: 'A05', asvs: ['V14.3.2'],
    description: 'The server lists the contents of a directory with no index file, revealing every file in it — including backups, uploads and files that were never meant to be linked.',
    remediation: { summary: 'Disable automatic indexes: nginx `autoindex off;`, Apache `Options -Indexes`, IIS `<directoryBrowse enabled="false" />`; add an index file where a directory must be browsable.', references: ['https://cwe.mitre.org/data/definitions/548.html'] },
    observe: (page) => (page.kind !== 'asset' && page.status === 200 && DIR_LISTING.test(page.body) ? [{ url: page.finalUrl, key: new URL(page.finalUrl).pathname, evidence: { snippet: excerpt(page.body, page.body.search(DIR_LISTING)) } }] : []),
    probe: async (site) => {
      const dirs = new Set();
      for (const p of site.pages) {
        if (!p.dom) continue;
        for (const u of [...p.dom.scripts.map((s) => s.url), ...p.dom.styles.map((s) => s.url), ...p.dom.images]) {
          if (!u || !u.startsWith(site.origin)) continue;
          const path = new URL(u).pathname;
          const dir = path.slice(0, path.lastIndexOf('/') + 1);
          if (dir && dir !== '/') dirs.add(dir);
        }
      }
      const out = [];
      for (const dir of [...dirs].slice(0, 15)) {
        const url = site.origin + dir;
        const res = await site.request(url, { kind: 'probe', maxBodyBytes: 64 * 1024 });
        if (res?.status === 200 && DIR_LISTING.test(res.body)) out.push({ url, key: dir, evidence: { snippet: excerpt(res.body, res.body.search(DIR_LISTING)) } });
      }
      return out;
    },
  },
]);

export function excerpt(text, index, span = 240) {
  const start = Math.max(0, index - 60);
  return text.slice(start, start + span).replace(/\s+/g, ' ').trim();
}
