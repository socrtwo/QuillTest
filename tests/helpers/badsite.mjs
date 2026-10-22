/*
 * QuillTest — test fixture: a deliberately misconfigured site, and a well-configured one
 * Used by the engine tests and by `node tests/helpers/badsite.mjs` for manual runs.
 */
import { createServer } from 'node:http';

const JQUERY_OLD = '/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */\n!function(a,b){}(window);\n//# sourceMappingURL=jquery.min.map\n';

export function badSiteHandler(originRef = { current: '' }) {
  return (req, res) => {
    const url = new URL(req.url, 'http://x');
    const o = originRef.current;
    const page = (body, extra = {}) => { res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', server: 'nginx/1.18.0', 'x-powered-by': 'PHP/7.4.3', ...extra }); res.end(body); };
    switch (url.pathname) {
      case '/':
        return page(`<!doctype html><html><head><title>Bad Site</title><meta name="generator" content="WordPress 5.8">
          <script src="/js/jquery-1.12.4.min.js"></script>
          <script src="https://cdn.example.net/lib.js"></script>
          <link rel="stylesheet" href="https://cdn.example.net/lib.css">
          <script>var x = 1;</script></head>
          <body><a href="/login">Login</a> <a href="/about">About</a> <a href="/error">Error</a> <a href="/listing/">Files</a> <a href="/private/secret">Private</a> <a href="/api/data.json">API</a>
          <a href="https://external.example/x" target="_blank">ext</a> <a href="/deep/1">deep</a>
          <img src="http://img.example.net/pixel.gif"></body></html>`, {
          'set-cookie': ['PHPSESSID=abc123def456ghi789jkl012mno345; Path=/', 'prefs=dark; Path=/; Domain=.' + (o ? new URL(o).hostname : 'localhost')],
          'access-control-allow-origin': req.headers.origin || '*', 'access-control-allow-credentials': 'true',
        });
      case '/login':
        return page(`<html><body><form method="post" action="http://insecure.example/login"><input name="user"><input type="password" name="pass"><input name="cc_number"></form></body></html>`);
      case '/about':
        return page('<html><body>About <a href="/">home</a></body></html>', { 'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline'", 'x-frame-options': 'ALLOWALL' });
      case '/error':
        res.writeHead(500, { 'content-type': 'text/html' }); return res.end('<html><body><h1>Error</h1><pre>Traceback (most recent call last):\n  File "app.py", line 12, in &lt;module&gt;\nValueError: boom</pre></body></html>');
      case '/listing/':
        return page('<html><head><title>Index of /listing</title></head><body><h1>Index of /listing</h1><a href="backup.zip">backup.zip</a></body></html>');
      case '/js/':
        return page('<html><head><title>Index of /js</title></head><body><h1>Index of /js</h1></body></html>');
      case '/js/jquery-1.12.4.min.js':
        res.writeHead(200, { 'content-type': 'application/javascript' }); return res.end(JQUERY_OLD);
      case '/js/jquery.min.map':
        res.writeHead(200, { 'content-type': 'application/json' }); return res.end('{"version":3,"sources":["src/jquery.js","src/core.js"],"mappings":"AAAA"}');
      case '/api/data.json':
        res.writeHead(200, { 'content-type': 'application/json', 'access-control-allow-origin': req.headers.origin || '', 'access-control-allow-credentials': 'true' }); return res.end('{"ok":true}');
      case '/.git/HEAD':
        res.writeHead(200, { 'content-type': 'text/plain' }); return res.end('ref: refs/heads/main\n');
      case '/.env':
        res.writeHead(200, { 'content-type': 'text/plain' }); return res.end('APP_KEY=base64:abcdefghijklmnopqrstuvwxyz0123456789ABCD\nDB_PASSWORD=hunter2\n');
      case '/robots.txt':
        res.writeHead(200, { 'content-type': 'text/plain' }); return res.end('User-agent: *\nDisallow: /private/\n');
      case '/private/secret':
        return page('<html><body>should not be crawled</body></html>');
      case '/deep/1': return page('<html><body><a href="/deep/2">next</a></body></html>');
      case '/deep/2': return page('<html><body><a href="/deep/3">next</a></body></html>');
      case '/deep/3': return page('<html><body><a href="/deep/4">next</a></body></html>');
      case '/deep/4': return page('<html><body>end</body></html>');
      default:
        // Catch-all 200 HTML (SPA-style) — must not produce sensitive-file false positives.
        return page('<html><body>catch-all</body></html>');
    }
  };
}

const GOOD_HEADERS = {
  'content-type': 'text/html; charset=utf-8',
  'content-security-policy': "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
  'x-content-type-options': 'nosniff', 'referrer-policy': 'strict-origin-when-cross-origin', 'permissions-policy': 'camera=(), microphone=(), geolocation=()',
  'cross-origin-opener-policy': 'same-origin', 'cross-origin-resource-policy': 'same-origin', 'cache-control': 'no-store', server: 'nginx',
};

export function goodSiteHandler() {
  return (req, res) => {
    const url = new URL(req.url, 'http://x');
    if (url.pathname === '/') { res.writeHead(200, { ...GOOD_HEADERS, 'set-cookie': ['session=' + 'A1'.repeat(16) + '; Path=/; Secure; HttpOnly; SameSite=Lax'] }); return res.end('<html><head><title>Good</title></head><body><a href="/page">p</a><script src="https://cdn.example.net/lib.js" integrity="sha384-abc" crossorigin="anonymous"></script></body></html>'); }
    if (url.pathname === '/page') { res.writeHead(200, GOOD_HEADERS); return res.end('<html><body>fine</body></html>'); }
    if (url.pathname === '/.well-known/security.txt') { res.writeHead(200, { 'content-type': 'text/plain', 'x-content-type-options': 'nosniff' }); return res.end('Contact: mailto:security@example.com\nExpires: 2030-01-01T00:00:00.000Z\n'); }
    res.writeHead(404, { 'content-type': 'text/plain', 'x-content-type-options': 'nosniff' }); res.end('not found');
  };
}

/** Start a server on 127.0.0.1:0; returns {server, origin, close}. */
export function startServer(handlerFactory) {
  const ref = { current: '' };
  const server = createServer(handlerFactory(ref));
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => { ref.current = `http://127.0.0.1:${server.address().port}`; resolve({ server, origin: ref.current, close: () => new Promise((r) => server.close(r)) }); }));
}

if (process.argv[1] && import.meta.url.endsWith(process.argv[1].split('/').pop())) {
  const which = process.argv[2] === 'good' ? goodSiteHandler : badSiteHandler;
  startServer(which).then(({ origin }) => console.log(origin));
}
