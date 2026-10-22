/*
 * QuillTest — target management
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * A target is one origin (scheme + host + port) plus the user's bookkeeping
 * for it: a name, notes, tags, an in-scope path policy, and the explicit
 * authorization confirmation the README requires alongside the technical
 * ownership check ("you also confirm authorization for each target, and
 * QuillTest records both in the scan report").
 *
 * Targets are keyed by normalized origin, so https://example.com and
 * https://www.example.com are two targets, as they are two verifications.
 * Persisted as JSON (quilltest.targets.json, git-ignored); in-memory for tests.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { normalizeOrigin } from '../verify/origin.mjs';

export const TARGETS_VERSION = 1;

export class NoActiveTargetError extends Error {
  constructor() { super('No active target. Add one with target.add and select it with target.select.'); this.name = 'NoActiveTargetError'; }
}
export class UnknownTargetError extends Error {
  constructor(origin) { super(`${origin} is not in the target list`); this.name = 'UnknownTargetError'; this.origin = origin; }
}
export class AuthorizationRequiredError extends Error {
  constructor(origin) {
    super(`Scanning ${origin} is not permitted: you have not confirmed that you are authorized to test this target (target.confirmAuthorization). Ownership verification proves control; authorization is your explicit statement that testing is permitted.`);
    this.name = 'AuthorizationRequiredError';
    this.origin = origin;
  }
}

/**
 * @typedef {Object} Target
 * @property {string}   origin
 * @property {string}   name
 * @property {string}   notes
 * @property {string[]} tags
 * @property {string}   addedAt       ISO-8601 UTC
 * @property {{include:string[], exclude:string[]}} scope   path prefixes; empty include = whole origin
 * @property {{confirmed:boolean, confirmedAt:string|null, statement:string|null}} authorization
 * @property {string|null} lastScanAt
 */

export class TargetStore {
  constructor({ path = null, data = null, now = () => new Date() } = {}) {
    this.path = path;
    this.now = now;
    this.data = normalizeData(data ?? (path && existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : null));
  }

  static load(path, opts = {}) {
    return new TargetStore({ ...opts, path });
  }

  save() {
    if (!this.path) return;
    mkdirSync(dirname(this.path), { recursive: true });
    writeFileSync(this.path, JSON.stringify(this.data, null, 2) + '\n');
  }

  /**
   * Add a target (or return the existing one unchanged). The first target
   * added becomes active.
   * @returns {{target:Target, created:boolean}}
   */
  add(originInput, { name, notes = '', tags = [] } = {}) {
    const origin = normalizeOrigin(originInput);
    const existing = this.data.targets[origin];
    if (existing) return { target: existing, created: false };
    const target = {
      origin,
      name: (name || '').trim() || new URL(origin).host,
      notes: String(notes || ''),
      tags: uniqTags(tags),
      addedAt: iso(this.now()),
      scope: { include: [], exclude: [] },
      authorization: { confirmed: false, confirmedAt: null, statement: null },
      lastScanAt: null,
    };
    this.data.targets[origin] = target;
    if (!this.data.active) this.data.active = origin;
    this.save();
    return { target, created: true };
  }

  get(originInput) {
    try { return this.data.targets[normalizeOrigin(originInput)] || null; } catch { return null; }
  }

  require(originInput) {
    const origin = normalizeOrigin(originInput);
    const t = this.data.targets[origin];
    if (!t) throw new UnknownTargetError(origin);
    return t;
  }

  /** Targets, active first, then by name. */
  list() {
    const active = this.data.active;
    return Object.values(this.data.targets).sort((a, b) => (a.origin === active ? -1 : b.origin === active ? 1 : a.name.localeCompare(b.name) || a.origin.localeCompare(b.origin)));
  }

  remove(originInput) {
    const origin = normalizeOrigin(originInput);
    const had = Boolean(this.data.targets[origin]);
    delete this.data.targets[origin];
    if (this.data.active === origin) this.data.active = Object.keys(this.data.targets)[0] || null;
    this.save();
    return had;
  }

  /** Update name / notes / tags. Origin is immutable (add a new target instead). */
  update(originInput, patch = {}) {
    const t = this.require(originInput);
    if (patch.name !== undefined) t.name = String(patch.name).trim() || t.name;
    if (patch.notes !== undefined) t.notes = String(patch.notes);
    if (patch.tags !== undefined) t.tags = uniqTags(patch.tags);
    this.save();
    return t;
  }

  active() {
    return this.data.active ? this.data.targets[this.data.active] || null : null;
  }

  setActive(originInput) {
    const t = this.require(originInput);
    this.data.active = t.origin;
    this.save();
    return t;
  }

  /**
   * Record the user's explicit authorization statement for a target. The
   * statement is free text ("I own this site" / "engagement letter #123 dated …")
   * and is written into the scan report with the verification record.
   */
  confirmAuthorization(originInput, statement) {
    const t = this.require(originInput);
    const text = String(statement || '').trim();
    if (!text) throw new RangeError('An authorization statement is required (who authorized testing, and how).');
    t.authorization = { confirmed: true, confirmedAt: iso(this.now()), statement: text };
    this.save();
    return t;
  }

  revokeAuthorization(originInput) {
    const t = this.require(originInput);
    t.authorization = { confirmed: false, confirmedAt: null, statement: null };
    this.save();
    return t;
  }

  /** Replace the path scope. Prefixes are normalized to start with "/" (no origin, no query). */
  setScope(originInput, { include, exclude } = {}) {
    const t = this.require(originInput);
    if (include !== undefined) t.scope.include = uniq(include.map(normalizePath));
    if (exclude !== undefined) t.scope.exclude = uniq(exclude.map(normalizePath));
    this.save();
    return t;
  }

  /**
   * Is a URL inside the target's scope? Always false for another origin; then
   * exclude prefixes win over include prefixes; an empty include list means
   * the whole origin.
   */
  inScope(originInput, url) {
    const t = this.require(originInput);
    let u;
    try { u = new URL(url, t.origin); } catch { return false; }
    if (normalizeOrigin(u.origin) !== t.origin) return false;
    const path = u.pathname;
    if (t.scope.exclude.some((p) => startsWithPath(path, p))) return false;
    if (!t.scope.include.length) return true;
    return t.scope.include.some((p) => startsWithPath(path, p));
  }

  markScanned(originInput) {
    const t = this.require(originInput);
    t.lastScanAt = iso(this.now());
    this.save();
    return t;
  }
}

function normalizeData(raw) {
  const data = { version: TARGETS_VERSION, active: null, targets: {} };
  if (!raw || typeof raw !== 'object') return data;
  if (raw.version !== undefined && raw.version !== TARGETS_VERSION) throw new Error(`Unsupported targets file version ${raw.version} (expected ${TARGETS_VERSION})`);
  if (raw.targets && typeof raw.targets === 'object') {
    for (const [k, v] of Object.entries(raw.targets)) {
      if (!v || typeof v !== 'object') continue;
      data.targets[k] = {
        origin: k,
        name: typeof v.name === 'string' && v.name ? v.name : new URL(k).host,
        notes: typeof v.notes === 'string' ? v.notes : '',
        tags: Array.isArray(v.tags) ? uniqTags(v.tags) : [],
        addedAt: typeof v.addedAt === 'string' ? v.addedAt : iso(new Date(0)),
        scope: { include: arr(v.scope?.include), exclude: arr(v.scope?.exclude) },
        authorization: {
          confirmed: Boolean(v.authorization?.confirmed),
          confirmedAt: v.authorization?.confirmedAt ?? null,
          statement: v.authorization?.statement ?? null,
        },
        lastScanAt: v.lastScanAt ?? null,
      };
    }
  }
  if (typeof raw.active === 'string' && data.targets[raw.active]) data.active = raw.active;
  return data;
}

const arr = (x) => (Array.isArray(x) ? x.filter((s) => typeof s === 'string') : []);
const uniq = (xs) => [...new Set(xs)];
const uniqTags = (tags) => uniq((Array.isArray(tags) ? tags : String(tags).split(',')).map((t) => String(t).trim().toLowerCase()).filter(Boolean));
const iso = (d) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');

export function normalizePath(p) {
  let s = String(p || '').trim();
  if (/^https?:\/\//i.test(s)) s = new URL(s).pathname;
  s = s.split(/[?#]/)[0];
  if (!s.startsWith('/')) s = '/' + s;
  return s.replace(/\/{2,}/g, '/');
}

/** "/admin" matches "/admin" and "/admin/x" but not "/administrator". */
function startsWithPath(path, prefix) {
  if (prefix === '/') return true;
  const p = prefix.replace(/\/+$/, '');
  return path === p || path.startsWith(p + '/');
}
