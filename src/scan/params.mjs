/*
 * QuillTest — injection points derived from the crawl (no requests)
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * An active check does not guess URLs: it works from the inputs the crawl
 * actually observed. An injection point is one place a value can be supplied —
 * a query parameter on a visited URL, or a field in an observed form. Each
 * carries enough to rebuild one request with a single parameter changed, and
 * nothing else. Enumeration is pure; it sends nothing.
 */

import { normalizeOrigin } from '../verify/origin.mjs';

/**
 * @typedef {Object} InjectionPoint
 * @property {string} id          stable key: `${where}:${method} ${path}#${name}`
 * @property {'query'|'form'} where
 * @property {string} url         the page the point lives on (query points: the URL itself)
 * @property {string} method      'GET' or 'POST'
 * @property {string} name        parameter / field name
 * @property {string} type        for form fields: input type; for query: 'query'
 * @property {string} original    the value observed in the crawl ('' when none)
 * @property {string} action      where the request goes (query: the URL; form: the form action)
 * @property {Record<string,string>} baseParams  the other parameters, to resend unchanged
 */

const SKIP_FIELD_TYPES = new Set(['submit', 'button', 'image', 'reset', 'file', 'password']);

/** Query-string parameters on one crawled, same-origin page.
 *  Uses the requested URL (page.url), not the post-redirect URL, so a parameter
 *  that drives a redirect is not lost when the crawl follows it. */
export function queryPoints(page, origin) {
  let u;
  try { u = new URL(page.url || page.finalUrl); } catch { return []; }
  if (normalizeOrigin(u.origin) !== origin) return [];
  const params = [...u.searchParams.keys()];
  if (!params.length) return [];
  const base = Object.fromEntries(u.searchParams);
  return [...new Set(params)].map((name) => ({
    id: `query:GET ${u.origin}${u.pathname}#${name}`,
    where: 'query', url: u.toString(), method: 'GET', name, type: 'query',
    original: u.searchParams.get(name) ?? '',
    action: `${u.origin}${u.pathname}`,
    baseParams: { ...base },
  }));
}

/** Writable fields of one observed form. */
export function formPoints(page, form, origin) {
  if (!form.action) return [];
  let action;
  try { action = new URL(form.action, page.finalUrl || page.url); } catch { return []; }
  if (normalizeOrigin(action.origin) !== origin) return [];       // never submit cross-origin
  const method = (form.method || 'get').toUpperCase() === 'POST' ? 'POST' : 'GET';
  const base = {};
  for (const f of form.inputs) if (f.name && !SKIP_FIELD_TYPES.has(f.type)) base[f.name] = '';
  const points = [];
  for (const f of form.inputs) {
    if (!f.name || SKIP_FIELD_TYPES.has(f.type)) continue;
    points.push({
      id: `form:${method} ${action.origin}${action.pathname}#${f.name}`,
      where: 'form', url: page.finalUrl || page.url, method, name: f.name, type: f.type,
      original: '', action: `${action.origin}${action.pathname}`, baseParams: { ...base },
    });
  }
  return points;
}

/**
 * Every injection point across a crawl, de-duplicated by id so the same
 * parameter on many pages is tested once.
 * @returns {InjectionPoint[]}
 */
export function enumerate(pages, origin) {
  const seen = new Map();
  for (const page of pages) {
    if (page.kind && page.kind !== 'page') continue;
    try { if (normalizeOrigin(new URL(page.url || page.finalUrl).origin) !== origin) continue; } catch { continue; }
    for (const p of queryPoints(page, origin)) if (!seen.has(p.id)) seen.set(p.id, p);
    for (const form of page.dom?.forms || []) for (const p of formPoints(page, form, origin)) if (!seen.has(p.id)) seen.set(p.id, p);
  }
  return [...seen.values()];
}

/**
 * Build the URL and fetch init that resends an injection point's request with
 * exactly one parameter replaced. GET points carry the value in the query;
 * POST points carry it in a urlencoded body. No other field is changed.
 */
export function buildRequest(point, value) {
  const params = { ...point.baseParams, [point.name]: value };
  if (point.method === 'POST') {
    const body = new URLSearchParams(params).toString();
    return { url: point.action, init: { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body } };
  }
  const u = new URL(point.action);
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
  return { url: u.toString(), init: { method: 'GET' } };
}
