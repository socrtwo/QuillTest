/*
 * QuillTest — scan records, per-target scan settings, false-positive rules
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * On disk: <cwd>/scans/index.json plus one <id>.json per scan (git-ignored).
 * In memory for tests. Findings files are sensitive; they are written 0600.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync, readdirSync, unlinkSync } from 'node:fs';
import { join } from 'node:path';
import { normalizeOrigin } from '../verify/origin.mjs';
import { FindingSet } from '../findings/model.mjs';

export const SCANS_VERSION = 1;
export const DEFAULT_SETTINGS = Object.freeze({ profile: 'passive', disabledChecks: [], honorRobots: true, maxDepth: 3, maxPages: 150, maxRequests: 400, concurrency: 4, delayMs: 0, timeoutMs: 15_000, seedSitemap: false });

export class ScanStore {
  constructor({ dir = null, now = () => new Date() } = {}) {
    this.dir = dir;
    this.now = now;
    this.records = new Map(); // id → full record (memory mode, or cache)
    this.index = { version: SCANS_VERSION, scans: [], settings: {}, falsePositives: {} };
    if (dir && existsSync(join(dir, 'index.json'))) {
      const raw = JSON.parse(readFileSync(join(dir, 'index.json'), 'utf8'));
      if (raw.version !== SCANS_VERSION) throw new Error(`Unsupported scans index version ${raw.version}`);
      this.index = { version: SCANS_VERSION, scans: raw.scans || [], settings: raw.settings || {}, falsePositives: raw.falsePositives || {} };
    }
  }

  static load(dir, opts = {}) { return new ScanStore({ ...opts, dir }); }

  saveIndex() {
    if (!this.dir) return;
    mkdirSync(this.dir, { recursive: true });
    writeFileSync(join(this.dir, 'index.json'), JSON.stringify(this.index, null, 2) + '\n', { mode: 0o600 });
    try { chmodSync(join(this.dir, 'index.json'), 0o600); } catch { /* best effort */ }
  }

  // ----- settings ---------------------------------------------------------------

  settings(originInput) {
    const origin = normalizeOrigin(originInput);
    return { ...DEFAULT_SETTINGS, ...(this.index.settings[origin] || {}), disabledChecks: [...(this.index.settings[origin]?.disabledChecks || [])] };
  }

  updateSettings(originInput, patch) {
    const origin = normalizeOrigin(originInput);
    const cur = this.settings(origin);
    const next = { ...cur };
    for (const [k, v] of Object.entries(patch || {})) {
      if (!(k in DEFAULT_SETTINGS)) throw new RangeError(`Unknown scan setting ${JSON.stringify(k)} (known: ${Object.keys(DEFAULT_SETTINGS).join(', ')})`);
      if (k === 'disabledChecks') next[k] = [...new Set(v)];
      else if (typeof DEFAULT_SETTINGS[k] === 'number') { const n = Number(v); if (!Number.isFinite(n) || n < 0) throw new RangeError(`${k} must be a non-negative number`); next[k] = n; }
      else if (typeof DEFAULT_SETTINGS[k] === 'boolean') next[k] = v === true || v === 'true' || v === 1;
      else next[k] = String(v);
    }
    this.index.settings[origin] = next;
    this.saveIndex();
    return next;
  }

  setCheckEnabled(originInput, checkId, enabled) {
    const s = this.settings(originInput);
    const set = new Set(s.disabledChecks);
    if (enabled) set.delete(checkId); else set.add(checkId);
    return this.updateSettings(originInput, { disabledChecks: [...set] });
  }

  // ----- scans -----------------------------------------------------------------------

  save(record) {
    this.records.set(record.id, record);
    const entry = { id: record.id, origin: record.origin, profile: record.profile, startedAt: record.startedAt, finishedAt: record.finishedAt, summary: record.summary, pages: record.crawl.pages, requests: record.crawl.requests };
    this.index.scans = [...this.index.scans.filter((s) => s.id !== record.id), entry].sort((a, b) => a.startedAt.localeCompare(b.startedAt));
    if (this.dir) {
      mkdirSync(this.dir, { recursive: true });
      const file = join(this.dir, `${record.id}.json`);
      writeFileSync(file, JSON.stringify(record, null, 2) + '\n', { mode: 0o600 });
      try { chmodSync(file, 0o600); } catch { /* best effort */ }
    }
    this.saveIndex();
    return entry;
  }

  list(originInput) {
    const origin = originInput ? normalizeOrigin(originInput) : null;
    return this.index.scans.filter((s) => !origin || s.origin === origin).slice().reverse();
  }

  /** Full record by id; 'last' or 'latest' = most recent (optionally for an origin). */
  get(id, originInput) {
    if (id === 'last' || id === 'latest' || !id) {
      const entry = this.list(originInput)[0];
      return entry ? this.get(entry.id) : null;
    }
    if (this.records.has(id)) return this.records.get(id);
    if (this.dir && existsSync(join(this.dir, `${id}.json`))) {
      const rec = JSON.parse(readFileSync(join(this.dir, `${id}.json`), 'utf8'));
      this.records.set(id, rec);
      return rec;
    }
    return null;
  }

  previousFor(record) {
    const list = this.list(record.origin);
    const i = list.findIndex((s) => s.id === record.id);
    const prev = i >= 0 ? list[i + 1] : list[0];
    return prev ? this.get(prev.id) : null;
  }

  remove(id) {
    const had = this.index.scans.some((s) => s.id === id);
    this.index.scans = this.index.scans.filter((s) => s.id !== id);
    this.records.delete(id);
    if (this.dir && existsSync(join(this.dir, `${id}.json`))) unlinkSync(join(this.dir, `${id}.json`));
    this.saveIndex();
    return had;
  }

  /** Change a finding's status inside a saved scan. */
  updateFinding(scanId, findingId, status, note) {
    const rec = this.get(scanId);
    if (!rec) throw new RangeError(`No scan ${scanId}`);
    const set = FindingSet.fromJSON(rec.findings);
    const f = set.setStatus(findingId, status, note);
    rec.findings = set.toJSON();
    rec.summary = set.summary();
    this.save(rec);
    return f;
  }

  // ----- false-positive learning loop ---------------------------------------------------

  falsePositives(originInput) {
    return [...(this.index.falsePositives[normalizeOrigin(originInput)] || [])];
  }

  addFalsePositive(originInput, finding, note) {
    const origin = normalizeOrigin(originInput);
    const list = this.index.falsePositives[origin] || [];
    if (!list.some((r) => r.signature === finding.signature)) {
      list.push({ signature: finding.signature, checkId: finding.checkId, title: finding.title, url: finding.url, key: finding.key, note: note || '', at: this.now().toISOString().replace(/\.\d{3}Z$/, 'Z') });
    }
    this.index.falsePositives[origin] = list;
    this.saveIndex();
    return list;
  }

  removeFalsePositive(originInput, signature) {
    const origin = normalizeOrigin(originInput);
    const before = this.index.falsePositives[origin] || [];
    const after = before.filter((r) => r.signature !== signature);
    this.index.falsePositives[origin] = after;
    this.saveIndex();
    return before.length !== after.length;
  }

  /** Mark findings that match a remembered false-positive signature. */
  applyFalsePositives(originInput, findingSet) {
    const sigs = new Set(this.falsePositives(originInput).map((r) => r.signature));
    let n = 0;
    for (const f of findingSet.bySignature.values()) if (sigs.has(f.signature) && f.status === 'open') { f.status = 'false-positive'; f.notes.push('matched a remembered false-positive signature'); n++; }
    return n;
  }

  /** Scan files present on disk but not indexed (e.g. copied in). */
  orphans() {
    if (!this.dir || !existsSync(this.dir)) return [];
    const known = new Set(this.index.scans.map((s) => s.id));
    return readdirSync(this.dir).filter((f) => /^scan-.*\.json$/.test(f) && !known.has(f.replace(/\.json$/, '')));
  }
}
