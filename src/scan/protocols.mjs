/*
 * Anne's Test — protocol configuration checks beyond HTTP (TLS, FTP, mail, DNS)
 * Part of the Anne's Office suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Detection-only configuration review of the other services a verified host
 * exposes. The contract is docs/PROTOCOLS.md; the rules enforced here:
 *
 *   - Host-gated. The caller (scripts/scan.mjs) invokes this only for a host
 *     that has a valid ownership record. This module never widens the target.
 *   - Standard ports only. No port scanning: each service is tried on its
 *     well-known port(s); a refused connection just means "not present".
 *   - Observe what the service advertises — nothing more. The only commands
 *     sent are the capability handshakes every ordinary client issues on
 *     every connection: FTP FEAT, SMTP EHLO, IMAP CAPABILITY, POP3 CAPA,
 *     each followed by a clean QUIT/LOGOUT. Anne's Test never sends credentials,
 *     never attempts a login, never issues MAIL/RCPT/DATA, never requests a
 *     zone transfer, never writes or deletes anything.
 *   - Weaknesses that can only be confirmed by an action (anonymous FTP
 *     access, open relay, AXFR) are reported as MANUAL verification items,
 *     not performed.
 *
 * All network access is injectable (dial, tlsConnect, dns resolvers) so the
 * module is tested entirely offline against scripted fake servers.
 */

import net from 'node:net';
import tls from 'node:tls';

export const DEFAULT_TIMEOUT_MS = 6_000;
export const CAP_HELO = 'quilltest-scan.invalid'; // RFC 2606 reserved; never resolvable
export const CERT_EXPIRY_WARN_DAYS = 21;
export const MIN_RSA_BITS = 2048;

export const DEFAULT_PORTS = {
  ftp: 21, ftps: 990, smtp: [25, 587], smtps: 465,
  imap: 143, imaps: 993, pop3: 110, pop3s: 995, https: 443,
};

const isRefused = (e) => /ECONNREFUSED|EHOSTUNREACH|ENETUNREACH|ENOTFOUND|EAI_AGAIN|ETIMEDOUT|timeout|closed/i.test(e?.code || e?.message || '');

// ---------------------------------------------------------------------------
// Minimal line session over a socket (used only to read capability replies)
// ---------------------------------------------------------------------------

function makeSession(socket, timeoutMs) {
  let buffer = '';
  const waiters = [];
  let done = null;
  const flush = () => {
    while (waiters.length) {
      const nl = buffer.indexOf('\n');
      if (nl >= 0) { const line = buffer.slice(0, nl).replace(/\r$/, ''); buffer = buffer.slice(nl + 1); waiters.shift().res(line); continue; }
      if (done) { waiters.shift().rej(done); continue; }
      break;
    }
  };
  socket.setEncoding('utf8');
  socket.on('data', (d) => { buffer += d; flush(); });
  socket.on('error', (e) => { done = e; flush(); });
  socket.on('close', () => { done = done || new Error('closed'); flush(); });
  return {
    readLine: () => new Promise((res, rej) => {
      const t = setTimeout(() => { const i = waiters.findIndex((w) => w.res === res); if (i >= 0) waiters.splice(i, 1); rej(new Error('timeout')); }, timeoutMs);
      waiters.push({ res: (l) => { clearTimeout(t); res(l); }, rej: (e) => { clearTimeout(t); rej(e); } });
      flush();
    }),
    send: (s) => new Promise((res) => { try { socket.write(s.replace(/\r?\n?$/, '') + '\r\n', () => res()); } catch { res(); } }),
    close: () => { try { socket.end(); } catch { /* ignore */ } setTimeout(() => { try { socket.destroy(); } catch { /* ignore */ } }, 150).unref?.(); },
  };
}

export async function defaultDial({ host, port, useTls = false, servername, timeoutMs = DEFAULT_TIMEOUT_MS }) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { try { sock.destroy(); } catch { /* ignore */ } reject(Object.assign(new Error('connect timeout'), { code: 'ETIMEDOUT' })); }, timeoutMs);
    const sock = useTls
      ? tls.connect({ host, port, servername: servername || host, rejectUnauthorized: false }, () => { clearTimeout(timer); resolve(makeSession(sock, timeoutMs)); })
      : net.connect({ host, port }, () => { clearTimeout(timer); resolve(makeSession(sock, timeoutMs)); });
    sock.once('error', (e) => { clearTimeout(timer); reject(e); });
  });
}

/** Read a possibly multi-line coded reply (FTP/SMTP: "250-line" continues, "250 line" ends). */
async function readCodedReply(session, max = 40) {
  const lines = [];
  for (let i = 0; i < max; i++) {
    const line = await session.readLine();
    lines.push(line);
    if (/^\d{3}(?: |$)/.test(line)) break;        // final line
    if (!/^\d{3}-/.test(line) && lines.length === 1) break; // not a coded reply
  }
  const code = Number.parseInt((lines[lines.length - 1].match(/^(\d{3})/) || [])[1], 10);
  return { code: Number.isFinite(code) ? code : null, text: lines.join('\n') };
}

function sanitizeBanner(s) {
  // Keep it short and strip control chars before it becomes evidence.
  return String(s || '').replace(/[\x00-\x1f\x7f]/g, ' ').trim().slice(0, 200);
}

// ---------------------------------------------------------------------------
// TLS inspection
// ---------------------------------------------------------------------------

/**
 * Inspect a TLS endpoint: protocol, cipher, certificate validity/name/chain/key,
 * and (optionally) whether a legacy protocol version is still accepted.
 * `tlsConnect(opts)` is injectable and resolves to a socket exposing
 * getProtocol/getCipher/getPeerCertificate/authorized/authorizationError/end.
 */
export async function inspectTls(host, port, { tlsConnect, timeoutMs = DEFAULT_TIMEOUT_MS, now = new Date(), probeLegacy = true } = {}) {
  const connect = tlsConnect || ((opts) => new Promise((resolve, reject) => {
    const s = tls.connect({ host, port, servername: host, rejectUnauthorized: false, ...opts }, () => resolve(s));
    s.once('error', reject);
    s.setTimeout(timeoutMs, () => { try { s.destroy(); } catch { /* ignore */ } reject(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' })); });
  }));

  let s;
  try { s = await connect({}); } catch (e) { return { ok: false, refused: isRefused(e), error: e?.code || e.message }; }
  const cert = (s.getPeerCertificate && s.getPeerCertificate(true)) || {};
  const result = {
    ok: true,
    protocol: s.getProtocol ? s.getProtocol() : null,
    cipher: (s.getCipher && s.getCipher().name) || null,
    authorized: Boolean(s.authorized),
    authError: s.authorizationError ? String(s.authorizationError) : null,
    subject: cert.subject || null,
    issuer: cert.issuer || null,
    altNames: cert.subjectaltname || null,
    validFrom: cert.valid_from || null,
    validTo: cert.valid_to || null,
    keyBits: cert.bits || null,
    // EC certificates expose the curve name; RSA (and DSA) ones do not. Used by the weak-key check.
    keyType: cert.asn1Curve || cert.nistCurve ? 'ec' : (cert.bits ? 'rsa' : null),
    selfSigned: Boolean(cert.subject && cert.issuer && JSON.stringify(cert.subject) === JSON.stringify(cert.issuer)),
    daysToExpiry: null,
    nameMatches: null,
    legacyProtocol: null,
  };
  if (result.validTo) { const ms = Date.parse(result.validTo) - now.getTime(); result.daysToExpiry = Number.isFinite(ms) ? Math.floor(ms / 86400_000) : null; }
  result.nameMatches = certMatchesHost(cert, host);
  try { s.end(); } catch { /* ignore */ }

  if (probeLegacy) {
    try {
      // OpenSSL 3 (Node 18+) refuses TLS 1.0/1.1 at its default security level, so the
      // probe must lower it or it fails for every server and the check never fires.
      const legacy = await connect({ maxVersion: 'TLSv1.1', minVersion: 'TLSv1', ciphers: 'DEFAULT:@SECLEVEL=0' });
      result.legacyProtocol = (legacy.getProtocol && legacy.getProtocol()) || 'accepted';
      try { legacy.end(); } catch { /* ignore */ }
    } catch { result.legacyProtocol = null; }
  }
  return result;
}

/** Does the certificate's CN or any SAN DNS entry cover `host` (incl. a single wildcard label)? */
export function certMatchesHost(cert, host) {
  const names = [];
  if (cert?.subject?.CN) names.push(cert.subject.CN);
  if (cert?.subjectaltname) for (const m of String(cert.subjectaltname).matchAll(/DNS:([^,\s]+)/g)) names.push(m[1]);
  const h = String(host).toLowerCase();
  return names.some((n) => {
    n = String(n).toLowerCase();
    if (n === h) return true;
    if (n.startsWith('*.')) { const base = n.slice(2); const dot = h.indexOf('.'); return dot > 0 && h.slice(dot + 1) === base; }
    return false;
  });
}

function tlsFindings(label, location, tlsInfo) {
  if (!tlsInfo.ok) return [];
  const out = [];
  const F = (checkId, severity, confidence, title, cwe, remediation, extra = {}) => out.push({ checkId, severity, confidence, cwe, owasp: 'A02:2021 Cryptographic Failures', title: `${label}: ${title}`, location, evidence: { protocol: tlsInfo.protocol, cipher: tlsInfo.cipher, validTo: tlsInfo.validTo, ...extra }, remediation });
  if (tlsInfo.daysToExpiry !== null && tlsInfo.daysToExpiry < 0) F('tls.cert-expired', 'critical', 'confirmed', `TLS certificate expired ${-tlsInfo.daysToExpiry} day(s) ago`, 'CWE-295', 'Renew the certificate immediately and automate renewal (e.g. ACME/Let\'s Encrypt with auto-reload).');
  else if (tlsInfo.daysToExpiry !== null && tlsInfo.daysToExpiry <= CERT_EXPIRY_WARN_DAYS) F('tls.cert-expiring', 'medium', 'confirmed', `TLS certificate expires in ${tlsInfo.daysToExpiry} day(s)`, 'CWE-295', 'Renew now and automate renewal so this cannot lapse.');
  if (tlsInfo.selfSigned) F('tls.self-signed', 'high', 'firm', 'TLS certificate is self-signed', 'CWE-295', 'Install a certificate from a publicly trusted CA for this service.', { issuer: tlsInfo.issuer });
  else if (!tlsInfo.authorized && tlsInfo.authError) F('tls.untrusted-chain', 'high', 'firm', `TLS certificate chain is not trusted (${tlsInfo.authError})`, 'CWE-295', 'Serve the full certificate chain (leaf + intermediates) from a trusted CA.', { authError: tlsInfo.authError });
  if (tlsInfo.nameMatches === false) F('tls.name-mismatch', 'high', 'firm', 'TLS certificate does not cover this hostname', 'CWE-295', 'Issue a certificate whose CN/SAN includes this exact hostname.', { altNames: tlsInfo.altNames });
  if (tlsInfo.legacyProtocol && /TLSv1(?:\.1)?$|SSLv3/.test(tlsInfo.legacyProtocol)) F('tls.legacy-protocol', 'medium', 'confirmed', `Legacy TLS accepted (${tlsInfo.legacyProtocol})`, 'CWE-327', 'Disable TLS 1.0/1.1 and SSLv3; require TLS 1.2 or newer.', { legacyProtocol: tlsInfo.legacyProtocol });
  if (tlsInfo.keyBits && tlsInfo.keyType === 'rsa' && tlsInfo.keyBits < MIN_RSA_BITS) F('tls.weak-key', 'medium', 'firm', `Weak certificate key (${tlsInfo.keyBits}-bit)`, 'CWE-326', `Reissue with at least a ${MIN_RSA_BITS}-bit RSA key or an ECDSA P-256 key.`, { keyBits: tlsInfo.keyBits });
  return out;
}

// ---------------------------------------------------------------------------
// Per-service capability reads (no credentials, no state-changing commands)
// ---------------------------------------------------------------------------

/** FTP: read the 220 greeting and the FEAT capability list on the control port. */
export async function probeFtp(host, port, { dial, timeoutMs } = {}) {
  const connect = dial || defaultDial;
  let s;
  try { s = await connect({ host, port, timeoutMs }); } catch (e) { return { present: false, refused: isRefused(e), error: e?.code || e.message }; }
  try {
    const greeting = await readCodedReply(s);
    await s.send('FEAT');
    const feat = await readCodedReply(s);
    await s.send('QUIT');
    return { present: true, banner: sanitizeBanner(greeting.text), feat: sanitizeBanner(feat.text), authTls: /\bAUTH\s+TLS\b|\bAUTH\s+SSL\b/i.test(feat.text) };
  } catch (e) { return { present: true, error: e.message }; } finally { s.close(); }
}

/** SMTP: read the 220 greeting and the EHLO capability list. */
export async function probeSmtp(host, port, { dial, timeoutMs } = {}) {
  const connect = dial || defaultDial;
  let s;
  try { s = await connect({ host, port, timeoutMs }); } catch (e) { return { present: false, refused: isRefused(e), error: e?.code || e.message }; }
  try {
    const greeting = await readCodedReply(s);
    await s.send(`EHLO ${CAP_HELO}`);
    const ehlo = await readCodedReply(s);
    await s.send('QUIT');
    const caps = ehlo.text.toUpperCase();
    return { present: true, banner: sanitizeBanner(greeting.text), starttls: /\bSTARTTLS\b/.test(caps), authOffered: /\bAUTH\b/.test(caps), ehlo: sanitizeBanner(ehlo.text) };
  } catch (e) { return { present: true, error: e.message }; } finally { s.close(); }
}

/** IMAP: read the greeting and the CAPABILITY list. */
export async function probeImap(host, port, { dial, timeoutMs } = {}) {
  const connect = dial || defaultDial;
  let s;
  try { s = await connect({ host, port, timeoutMs }); } catch (e) { return { present: false, refused: isRefused(e), error: e?.code || e.message }; }
  try {
    const greeting = await s.readLine();
    await s.send('a1 CAPABILITY');
    let caps = '';
    for (let i = 0; i < 20; i++) { const l = await s.readLine(); caps += ' ' + l; if (/^a1 /i.test(l)) break; }
    await s.send('a2 LOGOUT');
    const up = (greeting + caps).toUpperCase();
    return { present: true, banner: sanitizeBanner(greeting), starttls: /\bSTARTTLS\b/.test(up), loginDisabled: /\bLOGINDISABLED\b/.test(up), caps: sanitizeBanner(caps) };
  } catch (e) { return { present: true, error: e.message }; } finally { s.close(); }
}

/** POP3: read the greeting and the CAPA list. */
export async function probePop3(host, port, { dial, timeoutMs } = {}) {
  const connect = dial || defaultDial;
  let s;
  try { s = await connect({ host, port, timeoutMs }); } catch (e) { return { present: false, refused: isRefused(e), error: e?.code || e.message }; }
  try {
    const greeting = await s.readLine();
    await s.send('CAPA');
    // CAPA is optional (RFC 2449): a server may answer -ERR, in which case no "." terminator ever comes.
    let caps = '';
    const first = await s.readLine();
    if (/^\+OK/i.test(first)) {
      for (let i = 0; i < 20; i++) { const l = await s.readLine(); if (/^\./.test(l)) break; caps += ' ' + l; }
    }
    await s.send('QUIT');
    const up = (greeting + caps).toUpperCase();
    return { present: true, banner: sanitizeBanner(greeting), stls: /\bSTLS\b/.test(up), capa: /^\+OK/i.test(first), caps: sanitizeBanner(caps) };
  } catch (e) { return { present: true, error: e.message }; } finally { s.close(); }
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

function svcFindings(service, location, info, extra = {}) {
  const out = [];
  const add = (f) => out.push({ owasp: 'A05:2021 Security Misconfiguration', confidence: 'confirmed', location, ...f });
  if (info.banner && /\d+\.\d+/.test(info.banner)) add({ checkId: `${service}.banner`, severity: 'low', cwe: 'CWE-200', title: `${service.toUpperCase()} server version disclosed in banner`, evidence: { banner: info.banner }, remediation: `Suppress or genericize the ${service.toUpperCase()} greeting banner so it does not reveal the exact software version.` });
  return out.concat(extra.findings || []);
}

/**
 * Run protocol configuration checks against a verified host.
 * @param {string} host  bare hostname (no scheme/port)
 * @param {object} [opts]
 *   fetch-free network injectables: dial, tlsConnect, resolveTxt, resolveCaa, resolveDs
 *   ports: override DEFAULT_PORTS; which: subset of ['tls','ftp','smtp','imap','pop3','dns']
 */
export async function runProtocolScan(host, opts = {}) {
  const ports = { ...DEFAULT_PORTS, ...(opts.ports || {}) };
  const which = opts.which || ['tls', 'ftp', 'smtp', 'imap', 'pop3', 'dns'];
  const timeoutMs = opts.timeoutMs || DEFAULT_TIMEOUT_MS;
  const now = opts.now || new Date();
  const startedAt = now.toISOString();
  const services = [];
  const findings = [];
  const want = (k) => which.includes(k);

  // --- TLS on implicit-TLS ports ---
  if (want('tls')) {
    for (const [name, port] of [['https', ports.https], ['smtps', ports.smtps], ['imaps', ports.imaps], ['pop3s', ports.pop3s], ['ftps', ports.ftps]]) {
      const info = await inspectTls(host, port, { tlsConnect: opts.tlsConnect, timeoutMs, now, probeLegacy: opts.probeLegacy !== false });
      if (!info.ok) { services.push({ service: name, port, present: false }); continue; }
      services.push({ service: name, port, present: true, protocol: info.protocol, cipher: info.cipher, daysToExpiry: info.daysToExpiry, authorized: info.authorized });
      findings.push(...tlsFindings(`${name.toUpperCase()} :${port}`, `tls://${host}:${port}`, info));
    }
  }

  // --- FTP ---
  if (want('ftp')) {
    const info = await probeFtp(host, ports.ftp, { dial: opts.dial, timeoutMs });
    services.push({ service: 'ftp', port: ports.ftp, present: info.present });
    if (info.present && !info.error) {
      const loc = `ftp://${host}:${ports.ftp}`;
      if (!info.authTls) findings.push({ checkId: 'ftp.plaintext', severity: 'high', confidence: 'firm', cwe: 'CWE-319', owasp: 'A02:2021 Cryptographic Failures', title: 'FTP does not advertise AUTH TLS (logins and data in cleartext)', location: loc, evidence: { banner: info.banner, feat: info.feat }, remediation: 'Require explicit FTPS (AUTH TLS) or move to SFTP (SSH). Disable plaintext FTP so credentials and file contents are never sent in the clear.' });
      findings.push({ checkId: 'ftp.anonymous-manual', severity: 'info', confidence: 'tentative', cwe: 'CWE-287', owasp: 'A05:2021 Security Misconfiguration', title: 'FTP is reachable — verify anonymous access is disabled', location: loc, evidence: { banner: info.banner, note: 'Anne\'s Test does not attempt any login. Confirm manually that the anonymous account is disabled or restricted.' }, remediation: 'Disable the anonymous FTP account unless it is deliberately required; if required, confine it to a read-only public directory.' });
      findings.push(...svcFindings('ftp', loc, info));
    }
  }

  // --- SMTP ---
  if (want('smtp')) {
    for (const port of [].concat(ports.smtp)) {
      const info = await probeSmtp(host, port, { dial: opts.dial, timeoutMs });
      services.push({ service: 'smtp', port, present: info.present });
      if (!info.present || info.error) continue;
      const loc = `smtp://${host}:${port}`;
      if (!info.starttls) findings.push({ checkId: 'smtp.no-starttls', severity: 'medium', confidence: 'firm', cwe: 'CWE-319', owasp: 'A02:2021 Cryptographic Failures', title: 'SMTP does not offer STARTTLS (mail can travel in cleartext)', location: loc, evidence: { banner: info.banner }, remediation: 'Enable STARTTLS on this SMTP listener (and offer implicit TLS on 465 for submission). Require TLS for authenticated submission.' });
      if (info.authOffered && !info.starttls) findings.push({ checkId: 'smtp.auth-before-tls', severity: 'high', confidence: 'firm', cwe: 'CWE-319', owasp: 'A07:2021 Identification and Authentication Failures', title: 'SMTP offers AUTH without STARTTLS (credentials in cleartext)', location: loc, evidence: { banner: info.banner, ehlo: info.ehlo }, remediation: 'Only advertise AUTH after STARTTLS (or on an implicit-TLS port). Set the MTA to refuse AUTH on a plaintext connection.' });
      findings.push({ checkId: 'smtp.open-relay-manual', severity: 'info', confidence: 'tentative', cwe: 'CWE-269', owasp: 'A05:2021 Security Misconfiguration', title: 'SMTP is reachable — verify it is not an open relay', location: loc, evidence: { note: 'Anne\'s Test does not send test mail or issue MAIL/RCPT. Confirm with your MTA\'s own tooling that relaying is restricted to authenticated or local senders.' }, remediation: 'Restrict relaying to authenticated users and your own networks; reject mail to external domains from unauthenticated senders.' });
      findings.push(...svcFindings('smtp', loc, info));
    }
  }

  // --- IMAP ---
  if (want('imap')) {
    const info = await probeImap(host, ports.imap, { dial: opts.dial, timeoutMs });
    services.push({ service: 'imap', port: ports.imap, present: info.present });
    if (info.present && !info.error) {
      const loc = `imap://${host}:${ports.imap}`;
      if (!info.starttls) findings.push({ checkId: 'imap.no-starttls', severity: 'medium', confidence: 'firm', cwe: 'CWE-319', owasp: 'A02:2021 Cryptographic Failures', title: 'IMAP does not offer STARTTLS', location: loc, evidence: { banner: info.banner }, remediation: 'Offer STARTTLS on 143 and implicit TLS on 993; prefer requiring TLS before login.' });
      if (!info.loginDisabled && !info.starttls) findings.push({ checkId: 'imap.plaintext-login', severity: 'medium', confidence: 'firm', cwe: 'CWE-319', owasp: 'A07:2021 Identification and Authentication Failures', title: 'IMAP allows plaintext LOGIN without TLS', location: loc, evidence: { caps: info.caps }, remediation: 'Advertise LOGINDISABLED until STARTTLS is negotiated, so passwords are never sent on a cleartext connection.' });
      findings.push(...svcFindings('imap', loc, info));
    }
  }

  // --- POP3 ---
  if (want('pop3')) {
    const info = await probePop3(host, ports.pop3, { dial: opts.dial, timeoutMs });
    services.push({ service: 'pop3', port: ports.pop3, present: info.present });
    if (info.present && !info.error) {
      const loc = `pop3://${host}:${ports.pop3}`;
      if (!info.stls) findings.push({ checkId: 'pop3.no-stls', severity: 'medium', confidence: 'firm', cwe: 'CWE-319', owasp: 'A02:2021 Cryptographic Failures', title: 'POP3 does not offer STLS (plaintext logins)', location: loc, evidence: { banner: info.banner }, remediation: 'Offer STLS on 110 and implicit TLS on 995; require TLS before USER/PASS.' });
      findings.push(...svcFindings('pop3', loc, info));
    }
  }

  // --- DNS (record lookups only) ---
  if (want('dns')) findings.push(...await dnsFindings(host, opts, now));

  return { host, startedAt, finishedAt: new Date().toISOString(), services, findings };
}

// ---------------------------------------------------------------------------
// DNS: email-auth and CA-authorization records (ordinary resolver lookups)
// ---------------------------------------------------------------------------

async function loadResolvers(opts) {
  if (opts.resolveTxt && opts.resolveCaa && opts.resolveDs) return opts;
  const dns = await import('node:dns/promises');
  return {
    resolveTxt: opts.resolveTxt || ((n) => dns.resolveTxt(n)),
    resolveCaa: opts.resolveCaa || ((n) => dns.resolveCaa(n).catch(() => [])),
    // Node's resolver cannot query DS records (dns.resolve rejects the rrtype), so without an
    // injected resolver the DNSSEC check is "not checked" (null), never "missing".
    resolveDs: opts.resolveDs || (async () => null),
  };
}

/** The host and each parent zone down to two labels: www.example.com → [www.example.com, example.com]. */
export function zoneCandidates(host) {
  const labels = String(host).split('.').filter(Boolean);
  const out = [];
  for (let i = 0; i < labels.length - 1; i++) out.push(labels.slice(i).join('.'));
  return out.length ? out : [String(host)];
}

export async function dnsFindings(host, opts = {}, now = new Date()) {
  const r = await loadResolvers(opts);
  const out = [];
  const flat = (recs) => (recs || []).map((x) => (Array.isArray(x) ? x.join('') : String(x)));
  const loc = `dns://${host}`;
  // A verified host is often www.<zone>; SPF/DMARC/CAA live at the organizational domain
  // (DMARC's org-domain fallback, RFC 7489 §6.6.3; CAA climbs the tree, RFC 8659 §3), so
  // look at the host first and then each parent, reporting where the record was found.
  const names = zoneCandidates(host);
  const firstHit = async (lookup, pick) => {
    const queried = [];
    for (const name of names) {
      let recs = null;
      try { recs = await lookup(name); } catch { recs = null; }
      queried.push(name);
      const hit = recs ? pick(recs, name) : null;
      if (hit) return { hit, foundAt: name, queried };
    }
    return { hit: null, foundAt: null, queried };
  };

  const spfRes = await firstHit((n) => r.resolveTxt(n).then(flat), (txt) => txt.find((t) => /^v=spf1/i.test(t)));
  const spf = spfRes.hit;
  if (!spf) out.push({ checkId: 'dns.spf-missing', severity: 'low', confidence: 'confirmed', cwe: 'CWE-290', owasp: 'A05:2021 Security Misconfiguration', title: 'No SPF record', location: loc, evidence: { note: `No v=spf1 TXT record at ${spfRes.queried.join(' or ')}.`, queried: spfRes.queried }, remediation: 'Publish an SPF record listing the hosts allowed to send mail for this domain, ending in "-all" (hard fail) or "~all" (soft fail).' });
  else if (/[\s]\+all\b/i.test(spf) || /^v=spf1\s+\+all/i.test(spf)) out.push({ checkId: 'dns.spf-weak', severity: 'medium', confidence: 'confirmed', cwe: 'CWE-290', owasp: 'A05:2021 Security Misconfiguration', title: 'SPF record ends in +all (permits any sender)', location: loc, evidence: { spf, foundAt: spfRes.foundAt }, remediation: 'Replace "+all" with "-all" or "~all"; "+all" authorizes the whole internet to send as your domain.' });

  const dmRes = await firstHit((n) => r.resolveTxt('_dmarc.' + n).then(flat), (txt) => txt.find((t) => /^v=DMARC1/i.test(t)));
  const dm = dmRes.hit;
  if (!dm) out.push({ checkId: 'dns.dmarc-missing', severity: 'low', confidence: 'confirmed', cwe: 'CWE-290', owasp: 'A05:2021 Security Misconfiguration', title: 'No DMARC record', location: loc, evidence: { note: `No v=DMARC1 TXT record at ${dmRes.queried.map((n) => '_dmarc.' + n).join(' or ')}`, queried: dmRes.queried.map((n) => '_dmarc.' + n) }, remediation: `Publish a DMARC record at _dmarc.${names[names.length - 1]} (start with p=none to monitor, then move to quarantine/reject).` });
  else if (/\bp=none\b/i.test(dm)) out.push({ checkId: 'dns.dmarc-weak', severity: 'low', confidence: 'confirmed', cwe: 'CWE-290', owasp: 'A05:2021 Security Misconfiguration', title: 'DMARC policy is p=none (monitor only)', location: loc, evidence: { dmarc: dm, foundAt: '_dmarc.' + dmRes.foundAt }, remediation: 'Once your SPF/DKIM alignment is clean, move the DMARC policy to p=quarantine then p=reject.' });

  const caaRes = await firstHit((n) => r.resolveCaa(n), (recs) => (Array.isArray(recs) && recs.length ? recs : null));
  if (!caaRes.hit) out.push({ checkId: 'dns.caa-missing', severity: 'info', confidence: 'confirmed', cwe: 'CWE-295', owasp: 'A05:2021 Security Misconfiguration', title: 'No CAA record', location: loc, evidence: { note: `No CAA record at ${caaRes.queried.join(' or ')} restricts which CAs may issue certificates for this domain.`, queried: caaRes.queried }, remediation: 'Publish a CAA record naming only the CA(s) you use (e.g. 0 issue "letsencrypt.org"), to limit mis-issuance.' });

  let ds = null;
  try { ds = await r.resolveDs(host); } catch { ds = null; }
  if (Array.isArray(ds) && !ds.length) out.push({ checkId: 'dns.dnssec-missing', severity: 'info', confidence: 'tentative', cwe: 'CWE-345', owasp: 'A05:2021 Security Misconfiguration', title: 'No DNSSEC delegation (DS record) found', location: loc, evidence: { note: 'No DS record at the parent; the zone may be unsigned.' }, remediation: 'Consider signing the zone with DNSSEC and publishing a DS record at the registrar, so resolvers can detect tampered DNS answers.' });

  return out;
}

/** Order findings by severity then confidence (same ranking the passive engine uses). */
export function sortFindings(findings) {
  const sev = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  const conf = { confirmed: 3, firm: 2, tentative: 1 };
  return [...findings].sort((a, b) => (sev[b.severity] || 0) - (sev[a.severity] || 0) || (conf[b.confidence] || 0) - (conf[a.confidence] || 0));
}
