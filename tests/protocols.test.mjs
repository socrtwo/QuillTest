/*
 * Anne's Test — protocol-check tests (offline; dial/tls/dns are injected)
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  runProtocolScan, inspectTls, certMatchesHost, dnsFindings, sortFindings,
  probeFtp, probeSmtp, probeImap, probePop3, CAP_HELO,
} from '../src/scan/protocols.mjs';
import { isHostVerified } from '../src/verify/ownership.mjs';

/**
 * A scripted line server. `script[port]` is { greeting, replies } where replies
 * maps an uppercased command prefix to the lines returned. Absent port → refused.
 * Records every command the client sends so tests can assert what was NOT sent.
 */
function dialer(script, sent = []) {
  return async ({ host, port }) => {
    const spec = script[port];
    if (!spec) { const e = new Error('refused'); e.code = 'ECONNREFUSED'; throw e; }
    const queue = [spec.greeting];
    return {
      readLine: async () => { if (!queue.length) { const e = new Error('closed'); e.code = 'closed'; throw e; } return queue.shift(); },
      send: async (s) => {
        sent.push({ port, cmd: s });
        const key = Object.keys(spec.replies || {}).find((k) => s.toUpperCase().startsWith(k));
        if (key) queue.push(...spec.replies[key]);
      },
      close() {},
    };
  };
}

// ----- FTP -----

test('probeFtp reads greeting and FEAT, detects AUTH TLS, and never sends USER/PASS', async () => {
  const sent = [];
  const dial = dialer({ 21: { greeting: '220 (vsFTPd 3.0.3)', replies: { FEAT: ['211-Features:', ' UTF8', ' PASV', '211 End'] } } }, sent);
  const info = await probeFtp('h', 21, { dial });
  assert.equal(info.present, true); assert.equal(info.authTls, false);
  assert.match(info.banner, /vsFTPd 3\.0\.3/);
  assert.deepEqual(sent.map((s) => s.cmd.split(' ')[0].toUpperCase()).sort(), ['FEAT', 'QUIT']);
  assert.ok(!sent.some((s) => /^(USER|PASS)/i.test(s.cmd)), 'no credentials ever sent');
  const secure = await probeFtp('h', 21, { dial: dialer({ 21: { greeting: '220 ok', replies: { FEAT: ['211-Features:', ' AUTH TLS', '211 End'] } } }) });
  assert.equal(secure.authTls, true);
  const absent = await probeFtp('h', 21, { dial: dialer({}) });
  assert.equal(absent.present, false); assert.equal(absent.refused, true);
});

// ----- SMTP -----

test('probeSmtp reads EHLO capabilities and never sends MAIL/RCPT/DATA/AUTH', async () => {
  const sent = [];
  const dial = dialer({ 25: { greeting: '220 mail ESMTP Postfix', replies: { EHLO: ['250-mail', '250-PIPELINING', '250-AUTH PLAIN LOGIN', '250 8BITMIME'] } } }, sent);
  const info = await probeSmtp('h', 25, { dial });
  assert.equal(info.starttls, false); assert.equal(info.authOffered, true);
  assert.equal(sent[0].cmd, `EHLO ${CAP_HELO}`);
  assert.ok(!sent.some((s) => /^(MAIL|RCPT|DATA|AUTH)/i.test(s.cmd)), 'no relay/auth commands');
  assert.deepEqual(sent.map((s) => s.cmd.split(' ')[0].toUpperCase()).sort(), ['EHLO', 'QUIT']);
  const tls = await probeSmtp('h', 25, { dial: dialer({ 25: { greeting: '220 mail', replies: { EHLO: ['250-mail', '250-STARTTLS', '250 OK'] } } }) });
  assert.equal(tls.starttls, true);
});

// ----- IMAP / POP3 -----

test('probeImap reads CAPABILITY, detects STARTTLS and LOGINDISABLED, only sends CAPABILITY/LOGOUT', async () => {
  const sent = [];
  const dial = dialer({ 143: { greeting: '* OK [CAPABILITY IMAP4rev1] ready', replies: { 'A1 CAPABILITY': ['* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED', 'a1 OK done'] } } }, sent);
  const info = await probeImap('h', 143, { dial });
  assert.equal(info.starttls, true); assert.equal(info.loginDisabled, true);
  assert.ok(!sent.some((s) => /LOGIN(?!DISABLED)/i.test(s.cmd) && !/CAPABILITY/i.test(s.cmd)), 'never attempts LOGIN');
  assert.ok(sent.some((s) => /LOGOUT/i.test(s.cmd)));
});

test('probePop3 reads CAPA and detects STLS, only sends CAPA/QUIT', async () => {
  const sent = [];
  const dial = dialer({ 110: { greeting: '+OK POP3 ready', replies: { CAPA: ['+OK', 'STLS', 'USER', '.'] } } }, sent);
  const info = await probePop3('h', 110, { dial });
  assert.equal(info.stls, true);
  assert.ok(!sent.some((s) => /^(USER|PASS|RETR)/i.test(s.cmd)));
});

// ----- TLS -----

function tlsConn(info) {
  return (opts) => new Promise((resolve, reject) => {
    if (info.refused) { const e = new Error('refused'); e.code = 'ECONNREFUSED'; return reject(e); }
    if (opts.maxVersion) { // legacy probe
      if (info.legacy) return resolve({ getProtocol: () => 'TLSv1.1', getCipher: () => ({ name: 'x' }), getPeerCertificate: () => ({}), authorized: true, end() {} });
      const e = new Error('no'); return reject(e);
    }
    resolve({ getProtocol: () => info.protocol || 'TLSv1.3', getCipher: () => ({ name: 'TLS_AES_128_GCM_SHA256' }), getPeerCertificate: () => info.cert || {}, authorized: info.authorized !== false, authorizationError: info.authError || null, end() {} });
  });
}
const cert = (o = {}) => ({ subject: { CN: 'ok.test' }, issuer: { CN: 'R3', O: 'Lets Encrypt' }, subjectaltname: 'DNS:ok.test, DNS:www.ok.test', valid_from: 'Jan 1 2026 GMT', valid_to: 'Dec 31 2030 GMT', bits: 2048, ...o });

test('certMatchesHost handles exact, SAN, and single-label wildcard', () => {
  assert.equal(certMatchesHost({ subject: { CN: 'ok.test' } }, 'ok.test'), true);
  assert.equal(certMatchesHost({ subjectaltname: 'DNS:a.test, DNS:ok.test' }, 'ok.test'), true);
  assert.equal(certMatchesHost({ subjectaltname: 'DNS:*.ok.test' }, 'www.ok.test'), true);
  assert.equal(certMatchesHost({ subjectaltname: 'DNS:*.ok.test' }, 'a.b.ok.test'), false);
  assert.equal(certMatchesHost({ subject: { CN: 'ok.test' } }, 'evil.test'), false);
});

test('inspectTls flags expiry, self-signed, untrusted chain, name mismatch, legacy protocol, weak key', async () => {
  const exp = await inspectTls('ok.test', 443, { tlsConnect: tlsConn({ cert: cert({ valid_to: 'Jan 1 2025 GMT' }) }), now: new Date('2026-06-01'), probeLegacy: false });
  assert.ok(exp.daysToExpiry < 0);
  const self = await inspectTls('ok.test', 443, { tlsConnect: tlsConn({ cert: cert({ issuer: { CN: 'ok.test' }, subject: { CN: 'ok.test' } }), authorized: false, authError: 'DEPTH_ZERO_SELF_SIGNED_CERT' }), probeLegacy: false });
  assert.equal(self.selfSigned, true);
  const mism = await inspectTls('evil.test', 443, { tlsConnect: tlsConn({ cert: cert() }), probeLegacy: false });
  assert.equal(mism.nameMatches, false);
  const legacy = await inspectTls('ok.test', 443, { tlsConnect: tlsConn({ cert: cert(), legacy: true }), probeLegacy: true });
  assert.equal(legacy.legacyProtocol, 'TLSv1.1');
  const refused = await inspectTls('ok.test', 443, { tlsConnect: tlsConn({ refused: true }) });
  assert.equal(refused.ok, false); assert.equal(refused.refused, true);
});

// ----- DNS -----

test('dnsFindings flags missing/weak SPF & DMARC, missing CAA, missing DNSSEC', async () => {
  const bad = await dnsFindings('ex.test', { resolveTxt: async () => [], resolveCaa: async () => [], resolveDs: async () => [] });
  const ids = bad.map((f) => f.checkId);
  assert.ok(ids.includes('dns.spf-missing') && ids.includes('dns.dmarc-missing') && ids.includes('dns.caa-missing') && ids.includes('dns.dnssec-missing'));
  const weak = await dnsFindings('ex.test', {
    resolveTxt: async (n) => (n.startsWith('_dmarc') ? [['v=DMARC1; p=none; rua=mailto:x@ex.test']] : [['v=spf1 include:_spf.google.com +all']]),
    resolveCaa: async () => [{ critical: 0, issue: 'letsencrypt.org' }],
    resolveDs: async () => [{ keyTag: 1 }],
  });
  const wids = weak.map((f) => f.checkId);
  assert.ok(wids.includes('dns.spf-weak') && wids.includes('dns.dmarc-weak'));
  assert.ok(!wids.includes('dns.caa-missing') && !wids.includes('dns.dnssec-missing'), 'present CAA/DS clear those');
  const clean = await dnsFindings('ex.test', {
    resolveTxt: async (n) => (n.startsWith('_dmarc') ? [['v=DMARC1; p=reject']] : [['v=spf1 -all']]),
    resolveCaa: async () => [{ issue: 'letsencrypt.org' }], resolveDs: async () => [{ keyTag: 1 }],
  });
  assert.deepEqual(clean, []);
});

// ----- orchestration + gate -----

test('runProtocolScan: refused services produce no findings; present weak services do', async () => {
  const dial = dialer({
    21: { greeting: '220 (ProFTPD 1.3.5)', replies: { FEAT: ['211-Features', ' UTF8', '211 End'] } }, // no AUTH TLS
    25: { greeting: '220 mail', replies: { EHLO: ['250-mail', '250-AUTH LOGIN', '250 OK'] } },         // no STARTTLS, AUTH offered
  });
  const r = await runProtocolScan('weak.test', { dial, which: ['ftp', 'smtp', 'imap', 'pop3'], tlsConnect: tlsConn({ refused: true }) });
  const ids = r.findings.map((f) => f.checkId);
  assert.ok(ids.includes('ftp.plaintext') && ids.includes('ftp.anonymous-manual') && ids.includes('ftp.banner'));
  assert.ok(ids.includes('smtp.no-starttls') && ids.includes('smtp.auth-before-tls') && ids.includes('smtp.open-relay-manual'));
  assert.ok(!ids.some((i) => i.startsWith('imap.') || i.startsWith('pop3.')), 'absent services yield nothing');
  assert.equal(r.services.find((s) => s.service === 'imap').present, false);
  // manual-verification findings are clearly marked tentative/info and state nothing was attempted
  const anon = r.findings.find((f) => f.checkId === 'ftp.anonymous-manual');
  assert.equal(anon.severity, 'info'); assert.equal(anon.confidence, 'tentative');
  assert.match(anon.evidence.note, /does not attempt any login/);
  assert.match(r.findings.find((f) => f.checkId === 'smtp.open-relay-manual').evidence.note, /does not send test mail/);
});

test('runProtocolScan honors the which-subset and includes DNS when asked', async () => {
  const r = await runProtocolScan('ex.test', {
    which: ['dns'], dial: dialer({}),
    resolveTxt: async () => [], resolveCaa: async () => [], resolveDs: async () => [],
  });
  assert.ok(r.findings.every((f) => f.checkId.startsWith('dns.')));
  assert.equal(r.services.length, 0, 'no socket services probed when only dns is requested');
});

test('every protocol finding has the analyze.mjs shape and a remediation', async () => {
  const dial = dialer({ 21: { greeting: '220 (vsFTPd 2.3.4)', replies: { FEAT: ['211 none'] } } });
  const r = await runProtocolScan('h.test', { dial, which: ['ftp'], tlsConnect: tlsConn({ refused: true }) });
  for (const f of r.findings) {
    for (const k of ['checkId', 'title', 'severity', 'confidence', 'location', 'evidence', 'remediation', 'owasp']) assert.ok(k in f, `${f.checkId} missing ${k}`);
    assert.ok(['critical', 'high', 'medium', 'low', 'info'].includes(f.severity));
    assert.match(f.location, /^(ftp|smtp|imap|pop3|tls|dns):\/\//);
  }
  assert.doesNotThrow(() => sortFindings(r.findings));
});

test('isHostVerified authorizes by hostname across any origin/port, respects expiry', () => {
  const now = new Date();
  const recs = [
    { origin: 'https://ex.test', expires: new Date(now.getTime() + 3600e3).toISOString() },
    { origin: 'http://svc.test:8080', expires: new Date(now.getTime() + 3600e3).toISOString() },
    { origin: 'https://old.test', expires: new Date(now.getTime() - 1).toISOString() },
  ];
  assert.equal(isHostVerified(recs, 'ex.test').ok, true);
  assert.equal(isHostVerified(recs, 'EX.TEST').ok, true, 'case-insensitive');
  assert.equal(isHostVerified(recs, 'svc.test').ok, true, 'a non-standard-port origin still proves host control');
  assert.equal(isHostVerified(recs, 'unknown.test').ok, false);
  assert.equal(isHostVerified(recs, 'old.test').ok, false);
  assert.match(isHostVerified(recs, 'old.test').error, /expired/);
  assert.equal(isHostVerified(recs, 'ex.test/path').ok, false, 'rejects anything that is not a bare host');
  assert.equal(isHostVerified(recs, '').ok, false);
});
