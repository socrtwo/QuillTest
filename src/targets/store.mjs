/*
 * Anne's Test — target management
 * Part of the Anne's Office suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * The set of sites you work with. A target is an origin plus the bookkeeping
 * around it: a label, tags, a note, when it was added and last scanned. It is
 * deliberately separate from the verification store (src/verify/) — adding a
 * target is organizing your work; it grants nothing. withStatus() joins the
 * two so a list can show, per target, whether ownership is currently verified.
 *
 * Backed by one JSON file under ./scans/ (git-ignored), written mode 0600, the
 * same shape and conventions as the verification store.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync, renameSync } from 'node:fs';
import { resolve } from 'node:path';
import { normalizeOrigin, isOriginVerified } from '../verify/ownership.mjs';

export const DEFAULT_PATH = resolve(process.cwd(), 'scans', 'targets.json');

function readJson(path, fallback) {
  if (!existsSync(path)) return fallback;
  // A file that exists but does not parse is damage, not emptiness: say so instead of
  // returning the fallback, which the next save would then write over the damaged data.
  const text = readFileSync(path, 'utf8');
  try { return JSON.parse(text); } catch (e) { throw new Error(`${path} is not valid JSON (${e.message}). Repair or move the file; it will not be overwritten.`); }
}
function writeJson(path, data) {
  mkdirSync(resolve(path, '..'), { recursive: true });
  // Write-then-rename so a crash or full disk mid-write cannot leave a truncated file
  // (which readJson would then treat as empty and the next save would overwrite).
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(data, null, 2) + '\n', { mode: 0o600 });
  try { chmodSync(tmp, 0o600); } catch { /* best effort */ }
  renameSync(tmp, path);
}

const dedupeTags = (tags) => [...new Set((tags || []).map((t) => String(t).trim()).filter(Boolean))];

export function createTargetStore(path = DEFAULT_PATH) {
  const load = () => readJson(path, []);
  const save = (list) => writeJson(path, list);

  const api = {
    path,
    list: () => load(),
    get(originInput) {
      let origin; try { origin = normalizeOrigin(originInput); } catch { return null; }
      return load().find((t) => t.origin === origin) || null;
    },
    /**
     * Add or update a target. Re-adding an existing origin merges the new
     * label/note and unions tags, keeping addedAt. Returns { target, created }.
     */
    add(originInput, { label = null, tags = [], note = null, now = new Date() } = {}) {
      const origin = normalizeOrigin(originInput); // throws on invalid — the caller reports it
      const list = load();
      const existing = list.find((t) => t.origin === origin);
      if (existing) {
        if (label != null) existing.label = label;
        if (note != null) existing.note = note;
        existing.tags = dedupeTags([...(existing.tags || []), ...tags]);
        existing.updatedAt = now.toISOString();
        save(list);
        return { target: existing, created: false };
      }
      const target = { origin, label, tags: dedupeTags(tags), note, addedAt: now.toISOString(), updatedAt: now.toISOString(), lastScanAt: null, lastScan: null };
      list.push(target);
      save(list);
      return { target, created: true };
    },
    /** Merge arbitrary fields into a target (e.g. after a scan). Returns the target or null. */
    update(originInput, fields, { now = new Date() } = {}) {
      let origin; try { origin = normalizeOrigin(originInput); } catch { return null; }
      const list = load();
      const t = list.find((x) => x.origin === origin);
      if (!t) return null;
      Object.assign(t, fields, { updatedAt: now.toISOString() });
      save(list);
      return t;
    },
    /** Record the outcome of a scan on a target. Counts are a small summary. */
    recordScan(originInput, { findings = null, reportPath = null, now = new Date() } = {}) {
      const counts = Array.isArray(findings) ? summarizeSeverity(findings) : null;
      return api.update(originInput, { lastScanAt: now.toISOString(), lastScan: { at: now.toISOString(), total: counts ? counts.total : null, bySeverity: counts ? counts.bySeverity : null, reportPath } }, { now });
    },
    remove(originInput) {
      let origin; try { origin = normalizeOrigin(originInput); } catch { return false; }
      const list = load();
      const next = list.filter((t) => t.origin !== origin);
      if (next.length === list.length) return false;
      save(next);
      return true;
    },
    addTag(originInput, tag, { now = new Date() } = {}) {
      const t = api.get(originInput);
      if (!t) return null;
      return api.update(originInput, { tags: dedupeTags([...(t.tags || []), tag]) }, { now });
    },
  };
  return api;
}

/** Severity breakdown used in a target's stored last-scan summary. */
export function summarizeSeverity(findings) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) { const s = f.severity in bySeverity ? f.severity : 'info'; bySeverity[s]++; }
  return { total: findings.length, bySeverity };
}

/**
 * Join targets with verification status. Each result adds `verification`:
 * { state: 'verified'|'expired'|'unverified', expires?, verifiedAt? }.
 * @param {object[]} targets        from store.list()
 * @param {object[]} verifiedRecords from the verify store's loadVerified()
 */
export function withStatus(targets, verifiedRecords, now = new Date()) {
  return (targets || []).map((t) => {
    const res = isOriginVerified(verifiedRecords, t.origin, now);
    let verification;
    if (res.ok) verification = { state: 'verified', verifiedAt: res.record.verifiedAt, expires: res.record.expires };
    else if ((verifiedRecords || []).some((r) => r.origin === t.origin)) verification = { state: 'expired' };
    else verification = { state: 'unverified' };
    return { ...t, verification };
  });
}

/** Filter helper: targets carrying a given tag. */
export function byTag(targets, tag) {
  const q = String(tag).trim();
  return (targets || []).filter((t) => (t.tags || []).includes(q));
}
