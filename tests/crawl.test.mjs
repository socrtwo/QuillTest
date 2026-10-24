/*
 * QuillTest — crawler, fingerprint, and site-wide passive scan tests (offline)
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  crawl, normalizeLink, extractLinks, extractForms, extractAssets, parseRobots, robotsAllows, parseSitemap,
  MAX_QUERY_VARIANTS_PER_PATH,
} from '../src/scan/crawl.mjs';
import { fingerprint, describeStack } from '../src/scan/fingerprint.mjs';
import { runPassiveScan, aggregateFindings, PASSIVE_CHECKS, USER_AGENT } from '../src/scan/passive.mjs';

function mk(status, headers = {}, body = '', setCookies = []) {
  const h = new Headers(headers); h.getSetCookie = () => setCookies;
  return { status, headers: h, text: async () => body };
}
const html = (b) => mk(200, { 'content-type': 'text/html' }, b);

/** Build a fetch from a path→body map; unknown paths 404; http:// redirects to https. */
function siteOf(map, { robots, sitemap, hits } = {}) {
  return async (url) => {
    const u = new URL(url);
    if (hits) hits.push(u.pathname + u.search);
    if (u.protocol === 'http:') return mk(301, { location: `https://${u.host}/` });
    if (u.pathname === '/robots.txt') return robots ? mk(200, { 'content-type': 'text/plain' }, robots) : mk(404);
    if (u.pathname === '/sitemap.xml') return sitemap ? mk(200, { 'content-type': 'application/xml' }, sitemap) : mk(404);
    const b = map[u.pathname];
    return b === undefined ? mk(404, { 'content-type': 'text/html' }, '<html>nf</html>') : (typeof b === 'function' ? b(u) : html(b));
  };
}

test('normalizeLink: same-origin only, strips fragments/tracking, skips assets and state-changing links', () => {
  const o = 'https://s.test';
  assert.equal(normalizeLink('/a?utm_source=x&b=1#top', o + '/', o), 'https://s.test/a?b=1');
  assert.equal(normalizeLink('https://other.test/x', o + '/', o), null);
  assert.equal(normalizeLink('mailto:a@b', o + '/', o), null);
  assert.equal(normalizeLink('javascript:void(0)', o + '/', o), null);
  assert.equal(normalizeLink('/img.png', o + '/', o), null);
  assert.equal(normalizeLink('/logout', o + '/', o), null);
  assert.equal(normalizeLink('/account/delete', o + '/', o), null);
  assert.equal(normalizeLink('/admin/', o + '/', o), 'https://s.test/admin/', 'trailing slash preserved so robots rules still match');
  assert.equal(normalizeLink('/b?z=1&a=2', o + '/', o), 'https://s.test/b?a=2&z=1', 'query params sorted for de-duplication');
});

test('HTML extraction: links (incl. base href, canonical), forms with CSRF/password detection, assets', () => {
  const page = '<html><head><base href="/sub/"><link rel="canonical" href="/canon"><link rel="stylesheet" href="https://cdn.test/a.css"></head><body><a href="x">rel</a><a href=\'/abs\'>abs</a><form action="/login" method="POST"><input name="u"><input type="password" name="p"><input type="hidden" name="csrf_token" value="1"><select name="r"></select></form><form><input type="password" name="pw"></form><script src="https://cdn.test/a.js" integrity="sha384-abc" crossorigin="anonymous"></script><script src="/local.js"></script><iframe src="https://yt.test/e"></iframe></body></html>';
  const { links, base } = extractLinks(page);
  assert.equal(base, '/sub/');
  assert.deepEqual(links, ['x', '/abs', '/canon']);
  const forms = extractForms(page, 'https://s.test/p');
  assert.equal(forms.length, 2);
  assert.equal(forms[0].action, 'https://s.test/login'); assert.equal(forms[0].method, 'POST');
  assert.equal(forms[0].hasPassword, true); assert.equal(forms[0].hasCsrfLike, true);
  assert.deepEqual(forms[0].inputs.map((i) => i.type), ['text', 'password', 'hidden', 'select']);
  assert.equal(forms[1].action, 'https://s.test/p', 'missing action defaults to the page'); assert.equal(forms[1].method, 'GET'); assert.equal(forms[1].hasCsrfLike, false);
  const a = extractAssets(page, 'https://s.test/p');
  assert.equal(a.scripts.length, 2); assert.equal(a.scripts[0].integrity, 'sha384-abc'); assert.equal(a.scripts[1].src, 'https://s.test/local.js');
  assert.equal(a.styles.length, 1); assert.deepEqual(a.frames, ['https://yt.test/e']);
});

test('robots.txt: group selection, longest-match precedence, wildcards, sitemap lines', () => {
  const txt = 'User-agent: *\nDisallow: /private/\nDisallow: /tmp*\nAllow: /private/public\nSitemap: https://s.test/sm.xml\n\nUser-agent: QuillTest\nDisallow: /only-for-us\n';
  const star = parseRobots(txt, 'SomethingElse/1.0');
  assert.equal(robotsAllows(star.rules, '/private/x'), false);
  assert.equal(robotsAllows(star.rules, '/private/public/y'), true, 'longer Allow wins over shorter Disallow');
  assert.equal(robotsAllows(star.rules, '/tmpfile'), false, 'wildcard');
  assert.equal(robotsAllows(star.rules, '/open'), true);
  assert.deepEqual(star.sitemaps, ['https://s.test/sm.xml']);
  const ours = parseRobots(txt, USER_AGENT);
  assert.deepEqual(ours.rules, [{ allow: false, path: '/only-for-us' }], 'a group naming our UA replaces the * group');
  assert.deepEqual(parseRobots('', 'x').rules, []);
  assert.deepEqual(parseSitemap('<urlset><url><loc> https://s.test/a </loc></url><url><loc>https://s.test/b</loc></url></urlset>'), ['https://s.test/a', 'https://s.test/b']);
});

test('crawl is bounded, same-origin, robots-aware, sitemap-seeded, and never touches state-changing links', async () => {
  const hits = [];
  const links = (arr) => arr.map((h) => `<a href="${h}">x</a>`).join('');
  const map = {
    '/': links(['/a', '/b?p=1', '/b?p=2', '/b?p=3', '/b?p=4', '/b?p=5', '/admin/', '/logout', '/file.pdf', 'https://ext.test/']),
    '/a': links(['/a/1']), '/a/1': links(['/a/2']), '/a/2': links(['/a/3']), '/a/3': links(['/a/4']), '/a/4': 'deep',
    '/b': 'b', '/admin/': 'ADMIN', '/logout': 'BYE', '/from-sitemap': 'sm',
  };
  const r = await crawl('https://s.test', { fetchImpl: siteOf(map, { hits, robots: 'User-agent: *\nDisallow: /admin/', sitemap: '<urlset><url><loc>https://s.test/from-sitemap</loc></url></urlset>' }), maxPages: 50, maxDepth: 3 });
  const paths = r.pages.map((p) => new URL(p.url).pathname + new URL(p.url).search);
  assert.ok(paths.includes('/from-sitemap'), 'sitemap seeds are crawled');
  assert.ok(!hits.some((h) => h.startsWith('/admin')), 'robots Disallow honored');
  assert.ok(!hits.some((h) => h.startsWith('/logout')), 'state-changing links never fetched');
  assert.ok(!hits.some((h) => h.endsWith('.pdf')), 'assets never fetched');
  assert.equal(paths.filter((p) => p.startsWith('/b?')).length, MAX_QUERY_VARIANTS_PER_PATH, 'query variants capped');
  assert.ok(paths.includes('/a/2') && !paths.includes('/a/3'), 'depth cap: /a/2 is depth 3, /a/3 would be depth 4');
  assert.deepEqual(r.external, ['https://ext.test']);
  assert.equal(r.skipped.robots, 1); assert.ok(r.skipped.stateChanging >= 1); assert.ok(r.skipped.depth >= 1);
  assert.equal(r.robots.fetched, true);
});

test('crawl honors maxPages, can ignore robots on request, and reuses an already-fetched root', async () => {
  const map = { '/': '<a href="/1">1</a><a href="/2">2</a><a href="/3">3</a>', '/1': '1', '/2': '2', '/3': '3', '/admin/': 'A' };
  const capped = await crawl('https://s.test', { fetchImpl: siteOf(map), maxPages: 2 });
  assert.equal(capped.pages.length, 2); assert.ok(capped.skipped.cap > 0);
  const hits = [];
  const map2 = { '/': '<a href="/admin/">a</a>', '/admin/': 'A' };
  await crawl('https://s.test', { fetchImpl: siteOf(map2, { hits, robots: 'User-agent: *\nDisallow: /admin/' }), respectRobots: false });
  assert.ok(hits.includes('/admin/'), 'respectRobots:false crawls disallowed paths (operator owns the site)');
  const hits3 = [];
  const root = { url: 'https://s.test/', status: 200, headers: { 'content-type': 'text/html' }, body: '<a href="/x">x</a>' };
  await crawl('https://s.test', { fetchImpl: siteOf({ '/x': 'x' }, { hits: hits3 }), rootObservation: root });
  assert.ok(!hits3.includes('/'), 'root is not re-fetched when an observation is supplied');
  assert.ok(hits3.includes('/x'));
});

test('crawl identifies itself and does not follow a root that redirects off-origin', async () => {
  const hits = [];
  await crawl('https://s.test', { fetchImpl: async (url, init) => { hits.push(init.headers['user-agent']); return mk(404); } });
  assert.ok(hits.every((ua) => ua === USER_AGENT));
  const r = await crawl('https://s.test', { fetchImpl: async (url) => (new URL(url).pathname === '/' ? mk(301, { location: 'https://www.s.test/' }) : mk(404)) });
  assert.equal(r.pages.length, 1); assert.equal(r.pages[0].crossOriginRedirectTo, 'https://www.s.test/');
});

test('fingerprint infers server, framework and CMS with evidence; describeStack summarizes', () => {
  const fp = fingerprint([
    { url: 'https://s.test/', headers: { server: 'nginx/1.18.0', 'x-powered-by': 'PHP/8.1.2', 'set-cookie': ['PHPSESSID=x; Path=/', 'wordpress_logged_in_1=y'] }, body: '<meta name="generator" content="WordPress 6.4.2"><script src="/wp-includes/js/jquery/jquery.min.js"></script>' },
  ]);
  assert.equal(fp.server.name, 'nginx'); assert.equal(fp.server.version, '1.18.0');
  assert.ok(fp.framework.some((f) => f.name === 'PHP' && f.version === '8.1.2'));
  const wp = fp.cms.find((c) => c.name === 'WordPress');
  assert.equal(wp.version, '6.4.2'); assert.ok(wp.evidence.length >= 2, 'multiple corroborating signals'); assert.ok(wp.confidence > 0.5);
  assert.ok(fp.library.some((l) => l.name === 'jQuery'));
  assert.equal(describeStack(fp), 'nginx/1.18.0 · PHP 8.1.2 · WordPress 6.4.2');
  assert.equal(describeStack(fingerprint([{ headers: {}, body: '' }])), 'unknown');
  const dj = fingerprint([{ headers: { 'set-cookie': ['csrftoken=a', 'sessionid=b'] }, body: '<input name="csrfmiddlewaretoken">' }]);
  assert.ok(dj.framework.some((f) => f.name === 'Django' && f.confidence >= 0.8));
  const next = fingerprint([{ headers: {}, body: '<script id="__NEXT_DATA__"></script><div data-reactroot></div>' }]);
  assert.deepEqual(next.framework.map((f) => f.name).sort(), ['Next.js', 'React']);
});

test('aggregateFindings collapses identical findings across pages and records affected pages', () => {
  const f = (checkId, title, location) => ({ checkId, title, severity: 'low', confidence: 'confirmed', cwe: null, owasp: null, location, evidence: { snippet: 's' }, remediation: 'r' });
  const out = aggregateFindings([
    f('headers.csp', 'CSP missing', 'https://s/1'), f('headers.csp', 'CSP missing', 'https://s/2'), f('headers.csp', 'CSP missing', 'https://s/2'),
    f('cookies.flags', "Cookie 'a' missing X", 'https://s/1'), f('cookies.flags', "Cookie 'b' missing X", 'https://s/1'),
  ]);
  assert.equal(out.length, 3);
  const csp = out.find((x) => x.checkId === 'headers.csp');
  assert.equal(csp.location, 'https://s/1'); assert.equal(csp.evidence.affectedPages, 2); assert.deepEqual(csp.evidence.pages, ['https://s/1', 'https://s/2']);
  assert.equal(out.find((x) => x.title.includes("'a'")).evidence.affectedPages, undefined, 'single-page findings get no page count');
  assert.deepEqual(out.map((x) => x.id), ['F-001', 'F-002', 'F-003']);
});

test('every check declares a scope and page checks never hard-code the root as location', () => {
  for (const c of PASSIVE_CHECKS) assert.ok(['origin', 'page'].includes(c.scope), c.id);
  for (const c of PASSIVE_CHECKS.filter((x) => x.scope === 'page')) assert.ok(!c.run.toString().includes("origin + '/'"), `${c.id} must use pageUrl`);
});

test('site-wide scan finds inner-page weaknesses, aggregates site-wide gaps, and reports the stack', async () => {
  const H = { 'content-type': 'text/html', server: 'nginx/1.18.0' };
  const page = (b, sc = []) => () => mk(200, H, b, sc);
  const map = {
    '/': page('<html><body><a href="/about">a</a><a href="/login">l</a><a href="/search">s</a><script src="https://cdn.test/lib.js"></script></body></html>', ['PHPSESSID=abc; Path=/']),
    '/about': page('<html><body>about <script src="https://cdn.test/lib.js"></script></body></html>'),
    '/login': page('<html><body><form method="post" action="/login"><input name="u"><input type="password" name="p"></form></body></html>'),
    '/search': page('<html><body><form method="get" action="/do"><input type="password" name="pin"></form></body></html>'),
  };
  const r = await runPassiveScan('https://w.test', { fetchImpl: siteOf(map), crawl: { maxPages: 10 } });
  assert.equal(r.crawl.pages, 4);
  assert.match(r.stack.summary, /nginx\/1\.18\.0/);
  assert.ok(r.stack.framework.some((f) => f.name === 'PHP'), 'PHPSESSID cookie fingerprints PHP');
  const by = (id) => r.findings.filter((f) => f.checkId === id);
  assert.equal(by('forms.login-no-csrf').length, 1); assert.equal(by('forms.login-no-csrf')[0].location, 'https://w.test/login');
  assert.equal(by('forms.password-via-get').length, 1); assert.equal(by('forms.password-via-get')[0].severity, 'high');
  assert.equal(by('headers.csp').length, 1, 'site-wide gap collapses to one finding'); assert.equal(by('headers.csp')[0].evidence.affectedPages, 4);
  assert.equal(by('content.sri-missing').length, 1); assert.equal(by('content.sri-missing')[0].evidence.affectedPages, 2);
  assert.equal(by('cookies.flags').length, 1);
  assert.ok(!JSON.stringify(r).includes('PHPSESSID=abc'), 'cookie value masked');
  assert.ok(r.pages.every((p) => !('body' in p)), 'report pages carry no bodies');
  // root-only mode (crawl:false) still works and sees only the root
  const rootOnly = await runPassiveScan('https://w.test', { fetchImpl: siteOf(map) });
  assert.equal(rootOnly.crawl.pages, 1);
  assert.equal(rootOnly.findings.filter((f) => f.checkId === 'forms.login-no-csrf').length, 0);
});

test('a login form that carries a CSRF token, or uses a header, is not flagged', async () => {
  const map = {
    '/': () => mk(200, { 'content-type': 'text/html' }, '<form method="post" action="/l"><input type="password" name="p"><input type="hidden" name="authenticity_token" value="x"></form>'),
  };
  const r = await runPassiveScan('https://w.test', { fetchImpl: siteOf(map) });
  assert.equal(r.findings.filter((f) => f.checkId === 'forms.login-no-csrf').length, 0);
});
