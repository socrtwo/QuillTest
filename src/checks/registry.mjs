/*
 * QuillTest — check registry
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Checks are data registered against ids, like commands. Each declares what
 * it detects, how intrusive it is, and the standards and remediation it maps
 * to. Three kinds of run function:
 *
 *   observe(page, site)  → findings[]   runs on every crawled page; reads only
 *   finalize(site)       → findings[]   runs once after the crawl; reads only
 *   probe(site)          → findings[]   runs once per scan; may send a bounded
 *                                       number of extra benign requests via site.request()
 *   active(site)         → findings[]   runs once per scan on an active profile only; sends
 *                                       non-destructive detection requests (intrusiveness 2)
 *                                       to the injection points the crawl observed, via
 *                                       site.send(). Detection only: safe markers and error
 *                                       signatures, never a working exploit, never a write.
 *
 * Intrusiveness: 0 = reads crawled responses only; 1 = extra benign GET/HEAD
 * requests to well-known paths or with a harmless header; 2 = sends test input
 * (reflective probes); 3 = may change server state. Passive checks are 0–1.
 * There is no payload library anywhere in this directory.
 */

import { SEVERITIES, CONFIDENCES, OWASP_2021, CWE } from '../findings/model.mjs';

export const CATEGORIES = {
  transport: 'Transport security',
  headers: 'Security headers',
  cookies: 'Cookies',
  cors: 'Cross-origin resource sharing',
  disclosure: 'Information disclosure',
  components: 'Components and versions',
  content: 'Page content',
  injection: 'Injection',
  xss: 'Cross-site scripting',
  csrf: 'Cross-site request forgery',
  redirects: 'Open redirects',
  access: 'Access control',
  methods: 'HTTP methods',
};

export const ID_PATTERN = /^[a-z]+\.[a-z][A-Za-z0-9]*$/;

/**
 * @typedef {Object} Check
 * @property {string} id            `category.name`
 * @property {string} title
 * @property {'passive'|'active'} kind
 * @property {0|1|2|3} intrusiveness
 * @property {string} severity      default severity
 * @property {string} confidence    default confidence
 * @property {number[]} cwe
 * @property {string} owasp         'A01'…'A10'
 * @property {string[]} [asvs]
 * @property {string} description
 * @property {{summary:string, references:string[], fixId?:string}} remediation
 * @property {(page:object, site:object)=>object[]|Promise<object[]>} [observe]
 * @property {(site:object)=>object[]|Promise<object[]>} [finalize]
 * @property {(site:object)=>Promise<object[]>} [probe]
 * @property {(site:object)=>Promise<object[]>} [active]
 * @property {string} [requests]    human description of extra requests a probe sends
 * @property {boolean} [consolidate] site-wide finding: one record per key for the whole origin, with the affected URLs listed, instead of one per page
 */

const registry = new Map();

export function defineCheck(c) {
  const list = Array.isArray(c) ? c : [c];
  for (const chk of list) {
    validate(chk);
    if (registry.has(chk.id)) throw new Error(`Duplicate check id ${chk.id}`);
    registry.set(chk.id, Object.freeze({ asvs: [], ...chk }));
  }
}

function validate(c) {
  if (!ID_PATTERN.test(c.id || '')) throw new Error(`Bad check id ${JSON.stringify(c.id)}`);
  const cat = c.id.split('.')[0];
  if (!CATEGORIES[cat]) throw new Error(`${c.id}: unknown category ${cat}`);
  if (!c.title) throw new Error(`${c.id}: title required`);
  if (!['passive', 'active'].includes(c.kind)) throw new Error(`${c.id}: kind must be passive or active`);
  if (![0, 1, 2, 3].includes(c.intrusiveness)) throw new Error(`${c.id}: intrusiveness must be 0..3`);
  if (c.kind === 'passive' && c.intrusiveness > 1) throw new Error(`${c.id}: a passive check cannot have intrusiveness > 1`);
  if (!SEVERITIES.includes(c.severity)) throw new Error(`${c.id}: bad severity`);
  if (!CONFIDENCES.includes(c.confidence)) throw new Error(`${c.id}: bad confidence`);
  if (!Array.isArray(c.cwe) || !c.cwe.length || c.cwe.some((n) => !CWE[n])) throw new Error(`${c.id}: cwe must list known CWE ids (add new ones to findings/model.mjs)`);
  if (!OWASP_2021[c.owasp]) throw new Error(`${c.id}: bad owasp category`);
  if (!c.description || !c.remediation?.summary) throw new Error(`${c.id}: description and remediation.summary required`);
  if (typeof c.observe !== 'function' && typeof c.finalize !== 'function' && typeof c.probe !== 'function' && typeof c.active !== 'function') throw new Error(`${c.id}: observe, finalize, probe or active required`);
  if (typeof c.active === 'function') {
    if (c.kind !== 'active') throw new Error(`${c.id}: an active() hook requires kind: 'active'`);
    if (c.intrusiveness < 2) throw new Error(`${c.id}: an active() hook sends test input, so intrusiveness must be ≥ 2`);
    if (!c.requests) throw new Error(`${c.id}: an active check must describe its requests`);
  }
  if (c.probe && c.intrusiveness < 1) throw new Error(`${c.id}: a probe sends requests, so intrusiveness must be ≥ 1`);
}

export function getCheck(id) { return registry.get(id); }
export function allChecks() { return [...registry.values()]; }
export function checksByCategory(cat) { return allChecks().filter((c) => c.id.startsWith(cat + '.')); }
export function searchChecks(q) {
  const terms = String(q || '').toLowerCase().split(/\s+/).filter(Boolean);
  if (!terms.length) return [];
  return allChecks().filter((c) => { const hay = `${c.id} ${c.title} ${c.description} ${c.owasp} ${OWASP_2021[c.owasp]} ${c.cwe.map((n) => 'cwe-' + n).join(' ')}`.toLowerCase(); return terms.every((t) => hay.includes(t)); });
}
export function _resetChecks() { registry.clear(); }

/** Public, serializable description of a check (no functions). */
export function describeCheck(c) {
  return {
    id: c.id, title: c.title, category: c.id.split('.')[0], categoryLabel: CATEGORIES[c.id.split('.')[0]], kind: c.kind, intrusiveness: c.intrusiveness,
    severity: c.severity, confidence: c.confidence, cwe: c.cwe.map((n) => ({ id: n, name: CWE[n] })), owasp: { id: c.owasp, name: OWASP_2021[c.owasp] }, asvs: c.asvs,
    description: c.description, remediation: c.remediation, requests: c.requests || (c.probe ? 'extra requests' : 'none'),
  };
}
