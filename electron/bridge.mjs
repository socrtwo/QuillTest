/*
 * Anne's Test — Electron command bridge (pure, testable)
 * Part of the Anne's Office suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * The security boundary between the renderer and the main process. The renderer
 * may ask to run an Anne's Test command, but only a KNOWN one, by its registry id,
 * with string arguments. These helpers enforce that; main.js wires them to IPC
 * and child_process. Keeping the rule here (not inline in main.js) lets it be
 * unit-tested without launching Electron.
 */

/** Map of runnable command id → script path. Only script-backed (.mjs) commands run. */
export function buildRunnableMap(commands) {
  return new Map((commands || []).filter((c) => c?.cli?.script?.endsWith('.mjs')).map((c) => [c.id, c.cli.script]));
}

/**
 * Validate a run request. Returns { ok:true, script } or { ok:false, error }.
 * Never resolves anything but a known id, and requires an array of string args
 * (no object/number args, nothing that could become a shell token).
 */
export function resolveRun(runnable, id, args) {
  const script = runnable.get(id);
  if (!script) return { ok: false, error: `Unknown or non-runnable command: ${id}` };
  if (!Array.isArray(args)) return { ok: false, error: 'args must be an array' };
  if (!args.every((a) => typeof a === 'string')) return { ok: false, error: 'args must be an array of strings' };
  // Defense in depth: reject NUL and the arg-injection sentinel, though spawn with
  // an argv array (no shell) already prevents shell interpretation.
  if (args.some((a) => a.includes('\0'))) return { ok: false, error: 'args must not contain NUL' };
  return { ok: true, script };
}
