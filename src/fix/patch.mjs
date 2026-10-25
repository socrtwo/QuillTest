/*
 * QuillTest — level-3 fixes: applyable patches for dependency manifests
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Level 1 is guidance, level 2 is a generated artifact to paste (see
 * artifacts.mjs / dependencies.mjs). Level 3 is a patch against a file the
 * OPERATOR provides: QuillTest reads their package.json or composer.json and
 * emits a unified diff that bumps the versions a scan flagged as vulnerable or
 * end-of-life. QuillTest generates the diff; it never applies it. The operator
 * reviews it and runs `git apply` / `patch -p1` themselves.
 *
 * Only dependency manifests are patched, because only there can the edit be
 * made correctly without seeing the rest of the system: the change is a value
 * in a known object, and the file round-trips. Server configs (nginx.conf and
 * the like) stay level 2 — a block to add, not an auto-merge — since inserting
 * into arbitrary config syntax cannot be done safely sight-unseen.
 *
 * The diff is minimal by construction: only the version string on a matched
 * line changes, and the operator's own formatting (indent, quote style,
 * key order) is preserved, so review is trivial.
 */
import { parseVersion, compareVersions } from '../scan/versions.mjs';
import { planDependencyBumps, BUMPS } from './dependencies.mjs';

// ---------------------------------------------------------------------------
// Unified diff (line-based, LCS). Produces standard `git apply`-compatible
// output with a/ b/ prefixes and 3 lines of context.
// ---------------------------------------------------------------------------

const NO_EOL = '\\ No newline at end of file';

function splitLines(text) {
  const hadFinalNewline = text.endsWith('\n');
  const body = hadFinalNewline ? text.slice(0, -1) : text;
  return { lines: body.length === 0 && !hadFinalNewline ? [] : body.split('\n'), hadFinalNewline };
}

/** Longest-common-subsequence edit script over lines. Returns ops: {t:'eq'|'del'|'ins', a, b}. */
export function lineOps(oldLines, newLines) {
  const n = oldLines.length, m = newLines.length;
  const dp = Array.from({ length: n + 1 }, () => new Int32Array(m + 1));
  for (let i = n - 1; i >= 0; i--)
    for (let j = m - 1; j >= 0; j--)
      dp[i][j] = oldLines[i] === newLines[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const ops = [];
  let i = 0, j = 0;
  while (i < n && j < m) {
    if (oldLines[i] === newLines[j]) { ops.push({ t: 'eq', a: i, b: j }); i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) { ops.push({ t: 'del', a: i }); i++; }
    else { ops.push({ t: 'ins', b: j }); j++; }
  }
  while (i < n) ops.push({ t: 'del', a: i++ });
  while (j < m) ops.push({ t: 'ins', b: j++ });
  return ops;
}

/**
 * Unified diff between two texts.
 * @param {string} oldText
 * @param {string} newText
 * @param {{path?:string, context?:number}} [opts]
 * @returns {string} empty when identical
 */
export function unifiedDiff(oldText, newText, opts = {}) {
  if (oldText === newText) return '';
  const context = opts.context ?? 3;
  const path = opts.path || 'file';
  const o = splitLines(oldText), nw = splitLines(newText);
  const ops = lineOps(o.lines, nw.lines);

  // Mark changed line indices to find hunk windows.
  const changedOld = new Set(), changedNew = new Set();
  for (const op of ops) { if (op.t === 'del') changedOld.add(op.a); if (op.t === 'ins') changedNew.add(op.b); }
  if (!changedOld.size && !changedNew.size) return '';

  // Build hunks by walking the op list, grouping ops that are within `context`
  // equal lines of a change.
  const hunks = [];
  let cur = null;
  let trailingEq = 0;
  for (let k = 0; k < ops.length; k++) {
    const op = ops[k];
    const isChange = op.t !== 'eq';
    if (isChange) {
      if (!cur) {
        // open a hunk, backfilling up to `context` equal lines
        const start = Math.max(0, k - context);
        cur = { ops: ops.slice(start, k) };
      } else if (trailingEq > context * 2) {
        // close the current hunk keeping `context` trailing eqs, open nothing yet
        cur.ops = cur.ops.slice(0, cur.ops.length - (trailingEq - context));
        hunks.push(cur);
        const start = Math.max(0, k - context);
        cur = { ops: ops.slice(start, k) };
      }
      cur.ops.push(op);
      trailingEq = 0;
    } else if (cur) {
      cur.ops.push(op);
      trailingEq++;
    }
  }
  if (cur) { if (trailingEq > context) cur.ops = cur.ops.slice(0, cur.ops.length - (trailingEq - context)); hunks.push(cur); }

  const out = [`--- a/${path}`, `+++ b/${path}`];
  for (const h of hunks) {
    const firstEqOrDel = h.ops.find((x) => x.t !== 'ins');
    const firstEqOrIns = h.ops.find((x) => x.t !== 'del');
    const oldStart = (firstEqOrDel ? firstEqOrDel.a : 0) + 1;
    const newStart = (firstEqOrIns ? firstEqOrIns.b : 0) + 1;
    const oldCount = h.ops.filter((x) => x.t === 'eq' || x.t === 'del').length;
    const newCount = h.ops.filter((x) => x.t === 'eq' || x.t === 'ins').length;
    out.push(`@@ -${oldStart},${oldCount} +${newStart},${newCount} @@`);
    for (const op of h.ops) {
      if (op.t === 'eq') { out.push(' ' + o.lines[op.a]); maybeNoEol(out, op.a, o, o.lines.length); }
      else if (op.t === 'del') { out.push('-' + o.lines[op.a]); maybeNoEol(out, op.a, o, o.lines.length); }
      else { out.push('+' + nw.lines[op.b]); maybeNoEol(out, op.b, nw, nw.lines.length); }
    }
  }
  return out.join('\n') + '\n';
}

function maybeNoEol(out, idx, side, total) {
  if (idx === total - 1 && !side.hadFinalNewline) out.push(NO_EOL);
}

// ---------------------------------------------------------------------------
// Manifest patchers
// ---------------------------------------------------------------------------

const caret = (v) => `^${v}`;
/** Pull the first dotted version out of a semver range like "^1.12.4" or ">=1.2 <2". */
const rangeFloor = (range) => (String(range).match(/\d+\.\d+(?:\.\d+)?/) || [null])[0];

/** component → npm package names we are willing to patch (Angular is excluded: ng update owns the manifest). */
function npmPackagesFor(component) {
  const b = BUMPS[component];
  if (!b || b.ecosystem !== 'npm' || component === 'Angular') return [];
  return b.pkgs || (b.pkg ? [b.pkg] : []);
}
function composerPackagesFor(component, recommended) {
  const b = BUMPS[component];
  if (!b || b.ecosystem !== 'composer') return [];
  const major = parseVersion(recommended)?.[0];
  if (component === 'Drupal') return [
    { name: 'drupal/core-recommended', to: caret(recommended) },
    { name: 'drupal/core-composer-scaffold', to: `^${major}` },
    { name: 'drupal/core-project-message', to: `^${major}` },
  ];
  return [{ name: b.pkg, to: caret(recommended) }];
}

/** Replace the version string of one key inside a specific JSON object block, preserving formatting. */
function replaceVersionInBlock(text, blockKey, depName, newRange) {
  // Find the "blockKey": { ... } span, then the "depName": "..." inside it.
  const blockRe = new RegExp(`("${blockKey}"\\s*:\\s*\\{)`, '');
  const bm = blockRe.exec(text);
  if (!bm) return { text, changed: false };
  const start = bm.index + bm[0].length;
  // find matching close brace
  let depth = 1, i = start;
  for (; i < text.length && depth > 0; i++) { if (text[i] === '{') depth++; else if (text[i] === '}') depth--; }
  const blockEnd = i - 1;
  const block = text.slice(start, blockEnd);
  const depRe = new RegExp(`("${depName.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\\\$&')}"\\s*:\\s*")([^"]*)(")`);
  const dm = depRe.exec(block);
  if (!dm) return { text, changed: false, oldRange: null };
  const oldRange = dm[2];
  if (oldRange === newRange) return { text, changed: false, oldRange };
  const newBlock = block.slice(0, dm.index) + dm[1] + newRange + dm[3] + block.slice(dm.index + dm[0].length);
  return { text: text.slice(0, start) + newBlock + text.slice(blockEnd), changed: true, oldRange };
}

/**
 * Patch a package.json text from a scan's component bumps.
 * @returns {{newText:string, changes:Array<{pkg,from,to,block}>, skipped:Array<{pkg,reason}>}}
 */
export function patchPackageJson(originalText, bumps) {
  let json; try { json = JSON.parse(originalText); } catch (e) { throw new Error(`package.json is not valid JSON: ${e.message}`); }
  let text = originalText;
  const changes = [], skipped = [];
  const blocks = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];
  for (const bump of bumps) {
    for (const pkg of npmPackagesFor(bump.component)) {
      let located = false;
      for (const blk of blocks) {
        const cur = json[blk]?.[pkg];
        if (cur === undefined) continue;
        located = true;
        const floor = rangeFloor(cur);
        if (floor && parseVersion(bump.recommended) && compareVersions(floor, bump.recommended) !== -1) { skipped.push({ pkg, reason: `already at ${cur} (>= ${bump.recommended})` }); continue; }
        const to = caret(bump.recommended);
        const r = replaceVersionInBlock(text, blk, pkg, to);
        if (r.changed) { text = r.text; changes.push({ pkg, from: r.oldRange, to, block: blk }); }
      }
      if (!located) skipped.push({ pkg, reason: 'not present in this manifest' });
    }
  }
  return { newText: text, changes, skipped };
}

/** Patch a composer.json text. Composer deps live under "require". */
export function patchComposerJson(originalText, bumps) {
  let json; try { json = JSON.parse(originalText); } catch (e) { throw new Error(`composer.json is not valid JSON: ${e.message}`); }
  let text = originalText;
  const changes = [], skipped = [];
  for (const bump of bumps) {
    for (const { name, to } of composerPackagesFor(bump.component, bump.recommended)) {
      for (const blk of ['require', 'require-dev']) {
        const cur = json[blk]?.[name];
        if (cur === undefined) continue;
        const floor = rangeFloor(cur), target = rangeFloor(to);
        if (floor && target && compareVersions(floor, target) !== -1) { skipped.push({ pkg: name, reason: `already at ${cur}` }); continue; }
        const r = replaceVersionInBlock(text, blk, name, to);
        if (r.changed) { text = r.text; changes.push({ pkg: name, from: r.oldRange, to, block: blk }); }
      }
    }
  }
  return { newText: text, changes, skipped };
}

const PATCHERS = {
  'package.json': { fn: patchPackageJson, ecosystem: 'npm' },
  'composer.json': { fn: patchComposerJson, ecosystem: 'composer' },
};

/** Choose a patcher by file basename, else by content shape. */
export function patcherFor(filename, text) {
  const base = String(filename).split(/[\\/]/).pop();
  if (PATCHERS[base]) return { kind: base, ...PATCHERS[base] };
  try { const j = JSON.parse(text); if (j.require || j['require-dev']) return { kind: 'composer.json', ...PATCHERS['composer.json'] }; if (j.dependencies || j.devDependencies) return { kind: 'package.json', ...PATCHERS['package.json'] }; } catch { /* not json */ }
  return null;
}

/**
 * Produce a unified-diff patch for one provided manifest, from a scan report's
 * component findings.
 * @param {object} report  a scan report
 * @param {{filename:string, contents:string, path?:string}} file  the operator's manifest
 * @returns {{patch:string, changes:Array, skipped:Array, kind:string}|{error:string}}
 */
export function generatePatchForFile(report, file) {
  const patcher = patcherFor(file.filename, file.contents);
  if (!patcher) return { error: `${file.filename}: not a supported manifest (package.json or composer.json).` };
  const { bumps } = planDependencyBumps(report);
  const relevant = bumps.filter((b) => b.ecosystem === patcher.ecosystem);
  const { newText, changes, skipped } = patcher.fn(file.contents, relevant);
  const diffPath = file.path || file.filename;
  const patch = unifiedDiff(file.contents, newText, { path: diffPath });
  return { kind: patcher.kind, patch, changes, skipped };
}
