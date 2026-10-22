/*
 * QuillTest — TLS inspection (one handshake, no data sent)
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 */
import { connect } from 'node:tls';

/**
 * @param {string} host
 * @param {number} port
 * @param {{timeoutMs?:number, servername?:string}} [opts]
 * @returns {Promise<{ok:boolean, protocol:string|null, cipher:string|null, authorized:boolean, authorizationError:string|null, cert:{subject:string, issuer:string, validFrom:string|null, validTo:string|null, daysLeft:number|null, altNames:string[], selfSigned:boolean}|null, error:string|null}>}
 */
export function inspectTls(host, port = 443, { timeoutMs = 10_000, servername = host, now = new Date() } = {}) {
  return new Promise((resolve) => {
    const result = { ok: false, protocol: null, cipher: null, authorized: false, authorizationError: null, cert: null, error: null };
    let settled = false;
    const done = () => { if (!settled) { settled = true; try { socket.destroy(); } catch { /* ignore */ } resolve(result); } };
    const socket = connect({ host, port, servername, rejectUnauthorized: false, minVersion: 'TLSv1', ALPNProtocols: ['http/1.1'] }, () => {
      result.ok = true;
      result.protocol = socket.getProtocol();
      result.cipher = socket.getCipher()?.name || null;
      result.authorized = socket.authorized;
      result.authorizationError = socket.authorized ? null : String(socket.authorizationError || '');
      const c = socket.getPeerCertificate(false);
      if (c && Object.keys(c).length) {
        const validTo = c.valid_to ? new Date(c.valid_to) : null;
        result.cert = {
          subject: fmtName(c.subject), issuer: fmtName(c.issuer),
          validFrom: c.valid_from ? new Date(c.valid_from).toISOString() : null,
          validTo: validTo ? validTo.toISOString() : null,
          daysLeft: validTo ? Math.floor((validTo.getTime() - now.getTime()) / 86_400_000) : null,
          altNames: String(c.subjectaltname || '').split(',').map((s) => s.trim().replace(/^DNS:/, '')).filter(Boolean),
          selfSigned: Boolean(c.subject && c.issuer && fmtName(c.subject) === fmtName(c.issuer)),
        };
      }
      done();
    });
    socket.setTimeout(timeoutMs, () => { result.error = 'timeout'; done(); });
    socket.on('error', (e) => { result.error = e.code || e.message; done(); });
  });
}

function fmtName(n) { return n ? Object.entries(n).map(([k, v]) => `${k}=${v}`).join(', ') : ''; }
