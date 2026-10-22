/*
 * QuillTest — findings model
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * A finding is one normalized record: which check fired, where, how sure we
 * are, the evidence that proves it, and the standards it maps to (CWE, OWASP
 * Top 10 2021, ASVS). Evidence is secret-scrubbed before it is stored, so a
 * findings file can be shared or sent to an AI provider without leaking
 * cookies or tokens (docs/AI.md).
 *
 * `signature` identifies "the same finding" across scans: check + origin +
 * path (query stripped) + the check's own key (e.g. the cookie or header
 * name). It drives deduplication, the findings diff, and the false-positive
 * learning loop.
 */

import { createHash } from 'node:crypto';

export const SEVERITIES = ['informational', 'low', 'medium', 'high', 'critical'];
export const CONFIDENCES = ['tentative', 'firm', 'confirmed'];
export const STATUSES = ['open', 'false-positive', 'fixed', 'accepted'];

export const OWASP_2021 = {
  A01: 'A01:2021 Broken Access Control',
  A02: 'A02:2021 Cryptographic Failures',
  A03: 'A03:2021 Injection',
  A04: 'A04:2021 Insecure Design',
  A05: 'A05:2021 Security Misconfiguration',
  A06: 'A06:2021 Vulnerable and Outdated Components',
  A07: 'A07:2021 Identification and Authentication Failures',
  A08: 'A08:2021 Software and Data Integrity Failures',
  A09: 'A09:2021 Security Logging and Monitoring Failures',
  A10: 'A10:2021 Server-Side Request Forgery',
};

/** The CWE entries QuillTest's checks reference. Extend as checks are added. */
export const CWE = {
  16: 'Configuration',
  200: 'Exposure of Sensitive Information to an Unauthorized Actor',
  209: 'Generation of Error Message Containing Sensitive Information',
  295: 'Improper Certificate Validation',
  311: 'Missing Encryption of Sensitive Data',
  319: 'Cleartext Transmission of Sensitive Information',
  326: 'Inadequate Encryption Strength',
  345: 'Insufficient Verification of Data Authenticity',
  352: 'Cross-Site Request Forgery (CSRF)',
  353: 'Missing Support for Integrity Check',
  359: 'Exposure of Private Personal Information to an Unauthorized Actor',
  497: 'Exposure of Sensitive System Information to an Unauthorized Control Sphere',
  523: 'Unprotected Transport of Credentials',
  525: 'Use of Web Browser Cache Containing Sensitive Information',
  527: 'Exposure of Version-Control Repository to an Unauthorized Control Sphere',
  538: 'Insertion of Sensitive Information into Externally-Accessible File or Directory',
  548: 'Exposure of Information Through Directory Listing',
  614: 'Sensitive Cookie in HTTPS Session Without "Secure" Attribute',
  693: 'Protection Mechanism Failure',
  942: 'Permissive Cross-domain Policy with Untrusted Domains',
  1004: 'Sensitive Cookie Without "HttpOnly" Flag',
  1021: 'Improper Restriction of Rendered UI Layers or Frames',
  1104: 'Use of Unmaintained Third Party Components',
  1275: 'Sensitive Cookie with Improper SameSite Attribute',
  1395: 'Dependency on Vulnerable Third-Party Component',
};

export function severityRank(s) {
  const i = SEVERITIES.indexOf(s);
  if (i < 0) throw new RangeError(`Unknown severity ${JSON.stringify(s)}`);
  return i;
}
export function confidenceRank(c) {
  const i = CONFIDENCES.indexOf(c);
  if (i < 0) throw new RangeError(`Unknown confidence ${JSON.stringify(c)}`);
  return i;
}

// ----- secret scrubbing -----------------------------------------------------------

const SECRET_HEADERS = new Set(['authorization', 'proxy-authorization', 'cookie', 'x-api-key', 'x-auth-token', 'x-csrf-token', 'x-xsrf-token', 'api-key']);
const SECRET_PARAMS = /^(token|access_token|id_token|refresh_token|api[_-]?key|apikey|key|secret|password|passwd|pwd|session|sessionid|sid|auth|code|signature|sig)$/i;
const BEARER = /\b(bearer|basic|token)\s+[A-Za-z0-9\-._~+/]+=*/gi;
const LONG_HEX_OR_B64 = /\b(?=[A-Za-z0-9+/_-]*\d)(?=[A-Za-z0-9+/_-]*[A-Za-z])[A-Za-z0-9+/_-]{32,}={0,2}\b/g;

/** Redact a header value for storage. Set-Cookie keeps its attributes, loses its value. */
export function redactHeader(name, value) {
  const n = String(name).toLowerCase();
  const v = String(value);
  if (n === 'set-cookie') {
    return v.replace(/^(\s*[^=;\s]+)=([^;]*)/, (_, k) => `${k}=<redacted>`);
  }
  if (SECRET_HEADERS.has(n)) return '<redacted>';
  return v;
}

/** Redact sensitive query parameters in a URL. */
export function redactUrl(url) {
  try {
    const u = new URL(url);
    let changed = false;
    for (const [k, v] of [...u.searchParams]) {
      if (SECRET_PARAMS.test(k) && v) { u.searchParams.set(k, '<redacted>'); changed = true; }
    }
    if (u.username || u.password) { u.username = ''; u.password = ''; changed = true; }
    return changed ? u.toString() : url;
  } catch {
    return url;
  }
}

/** Redact bearer tokens and long opaque secrets in free text (body excerpts). */
export function redactText(text) {
  return String(text).replace(BEARER, (m, kind) => `${kind} <redacted>`).replace(LONG_HEX_OR_B64, '<redacted>');
}

export function redactHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    out[k.toLowerCase()] = Array.isArray(v) ? v.map((x) => redactHeader(k, x)) : redactHeader(k, v);
  }
  return out;
}

// ----- finding ---------------------------------------------------------------------

/**
 * @typedef {Object} Finding
 * @property {string} id            short hash, unique within a scan
 * @property {string} signature     stable identity across scans
 * @property {string} checkId
 * @property {string} title
 * @property {string} severity
 * @property {string} confidence
 * @property {string} origin
 * @property {string} url           where it was observed (query secrets redacted)
 * @property {string} [key]         the check's own discriminator (header, cookie, path…)
 * @property {string} description
 * @property {{summary:string, references:string[], fixId?:string}} remediation
 * @property {{cwe:number[], owasp:string|null, asvs:string[]}} standards
 * @property {{snippet?:string, headers?:Record<string,string|string[]>, request?:object, detail?:object}} evidence
 * @property {string} status        'open' | 'false-positive' | 'fixed' | 'accepted'
 * @property {string} foundAt       ISO-8601 UTC
 * @property {string[]} notes
 */

export function createFinding(input, { now = new Date() } = {}) {
  const required = ['checkId', 'title', 'severity', 'confidence', 'origin', 'url'];
  for (const f of required) if (!input[f]) throw new TypeError(`finding.${f} is required`);
  severityRank(input.severity);
  confidenceRank(input.confidence);
  const url = redactUrl(input.url);
  const key = input.key === undefined || input.key === null ? '' : String(input.key);
  const signature = computeSignature(input.checkId, input.origin, url, key);
  const evidence = {};
  if (input.evidence?.snippet !== undefined) evidence.snippet = clip(redactText(input.evidence.snippet), 2000);
  if (input.evidence?.headers) evidence.headers = redactHeaders(input.evidence.headers);
  if (input.evidence?.request) evidence.request = { ...input.evidence.request, url: input.evidence.request.url ? redactUrl(input.evidence.request.url) : undefined, headers: input.evidence.request.headers ? redactHeaders(input.evidence.request.headers) : undefined };
  if (input.evidence?.detail !== undefined) evidence.detail = input.evidence.detail;
  const standards = {
    cwe: [...new Set((input.cwe || []).map(Number))],
    owasp: input.owasp ? (OWASP_2021[input.owasp] ? input.owasp : (() => { throw new RangeError(`Unknown OWASP category ${input.owasp}`); })()) : null,
    asvs: [...(input.asvs || [])],
  };
  return {
    id: signature.slice(0, 12),
    signature,
    checkId: input.checkId,
    title: input.title,
    severity: input.severity,
    confidence: input.confidence,
    origin: input.origin,
    url,
    key: key || undefined,
    description: input.description || '',
    remediation: { summary: input.remediation?.summary || '', references: [...(input.remediation?.references || [])], ...(input.remediation?.fixId ? { fixId: input.remediation.fixId } : {}) },
    standards,
    evidence,
    status: 'open',
    foundAt: now.toISOString().replace(/\.\d{3}Z$/, 'Z'),
    notes: [],
  };
}

export function computeSignature(checkId, origin, url, key = '') {
  let path = '';
  try { path = new URL(url).pathname; } catch { path = String(url); }
  return createHash('sha256').update(`${checkId}\n${origin}\n${path}\n${key}`).digest('hex').slice(0, 24);
}

function clip(s, n) {
  return s.length > n ? s.slice(0, n) + `… [${s.length - n} more chars]` : s;
}

// ----- finding set -------------------------------------------------------------------

export class FindingSet {
  constructor(findings = []) {
    /** @type {Map<string, Finding>} */
    this.bySignature = new Map();
    for (const f of findings) this.add(f);
  }

  /** Add, deduplicating by signature: keeps the higher severity/confidence and the first URL seen. */
  add(f) {
    const existing = this.bySignature.get(f.signature);
    if (!existing) { this.bySignature.set(f.signature, f); return f; }
    if (severityRank(f.severity) > severityRank(existing.severity)) existing.severity = f.severity;
    if (confidenceRank(f.confidence) > confidenceRank(existing.confidence)) existing.confidence = f.confidence;
    existing.occurrences = (existing.occurrences || 1) + 1;
    const a = existing.evidence?.detail?.affectedUrls; const b = f.evidence?.detail?.affectedUrls;
    if (a && b) existing.evidence.detail.affectedUrls = [...new Set([...a, ...b])].slice(0, 50);
    return existing;
  }

  get(id) {
    for (const f of this.bySignature.values()) if (f.id === id || f.signature === id) return f;
    return null;
  }

  /** Sorted: severity desc, confidence desc, then check id and URL. */
  list({ severity, minSeverity, status, checkId, owasp, url, includeSuppressed = true } = {}) {
    let out = [...this.bySignature.values()];
    if (severity) out = out.filter((f) => f.severity === severity);
    if (minSeverity) out = out.filter((f) => severityRank(f.severity) >= severityRank(minSeverity));
    if (status) out = out.filter((f) => f.status === status);
    else if (!includeSuppressed) out = out.filter((f) => f.status === 'open');
    if (checkId) out = out.filter((f) => f.checkId === checkId || f.checkId.startsWith(checkId + '.'));
    if (owasp) out = out.filter((f) => f.standards.owasp === owasp);
    if (url) out = out.filter((f) => f.url.includes(url));
    return out.sort((a, b) => severityRank(b.severity) - severityRank(a.severity) || confidenceRank(b.confidence) - confidenceRank(a.confidence) || a.checkId.localeCompare(b.checkId) || a.url.localeCompare(b.url));
  }

  get size() { return this.bySignature.size; }

  /** Counts by severity for open findings. */
  summary() {
    const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
    let suppressed = 0;
    for (const f of this.bySignature.values()) {
      if (f.status === 'open') counts[f.severity]++;
      else suppressed++;
    }
    return { total: this.size, open: this.size - suppressed, suppressed, ...counts };
  }

  setStatus(id, status, note) {
    if (!STATUSES.includes(status)) throw new RangeError(`Unknown status ${JSON.stringify(status)}`);
    const f = this.get(id);
    if (!f) throw new RangeError(`No finding ${id}`);
    f.status = status;
    if (note) f.notes.push(note);
    return f;
  }

  toJSON() { return [...this.bySignature.values()]; }

  static fromJSON(arr) { return new FindingSet(arr || []); }
}

/**
 * Compare two finding sets by signature.
 * @returns {{added:Finding[], fixed:Finding[], persisting:Finding[]}}
 */
export function diffFindings(before, after) {
  const a = before instanceof FindingSet ? before : new FindingSet(before);
  const b = after instanceof FindingSet ? after : new FindingSet(after);
  const added = []; const fixed = []; const persisting = [];
  for (const f of b.bySignature.values()) (a.bySignature.has(f.signature) ? persisting : added).push(f);
  for (const f of a.bySignature.values()) if (!b.bySignature.has(f.signature)) fixed.push(f);
  const sortFn = (x, y) => severityRank(y.severity) - severityRank(x.severity) || x.checkId.localeCompare(y.checkId);
  return { added: added.sort(sortFn), fixed: fixed.sort(sortFn), persisting: persisting.sort(sortFn) };
}
