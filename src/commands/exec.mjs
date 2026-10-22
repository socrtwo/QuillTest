/*
 * QuillTest — command executor and the context commands run against
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * exec(ctx, id, arg) is the single path through which the shell, the CLI and
 * macros run commands. It is where the scan gate is enforced in code: a
 * command marked requiresVerification runs only when the active target's
 * origin has a current ownership verification and the user has confirmed
 * authorization for that target. The UI cannot bypass this because the UI
 * never calls run() directly.
 */

import { getCommand } from './registry.mjs';
import { VerificationStore } from '../verify/store.mjs';
import { TargetStore, AuthorizationRequiredError, NoActiveTargetError } from '../targets/store.mjs';

export class UnknownCommandError extends Error {
  constructor(id) { super(`Unknown command ${JSON.stringify(id)}`); this.name = 'UnknownCommandError'; this.id = id; }
}
export class NotImplementedError extends Error {
  constructor(cmd) { super(`${cmd.label} (${cmd.id}) is planned but not implemented yet`); this.name = 'NotImplementedError'; this.id = cmd.id; }
}
export class CommandDisabledError extends Error {
  constructor(cmd, why) { super(`${cmd.label} (${cmd.id}) is not available${why ? `: ${why}` : ''}`); this.name = 'CommandDisabledError'; this.id = cmd.id; }
}

/**
 * @typedef {Object} Context
 * @property {VerificationStore} verifications
 * @property {TargetStore} targets
 * @property {string} aiConfigPath
 * @property {string} cwd
 * @property {Record<string,string|undefined>} env
 * @property {()=>Date} now
 * @property {(line:string)=>void} out    human-readable output sink
 * @property {{id:string,arg?:any}[]|null} recording   macro recorder, when active
 * @property {(id:string,arg?:any)=>Promise<any>} exec  re-entrant executor for commands that call others
 */

/**
 * Build a context. Stores default to the git-ignored JSON files in `cwd`;
 * pass `memory: true` for an in-memory context (tests, dry runs).
 */
export function createContext({ cwd = process.cwd(), memory = false, env = process.env, now = () => new Date(), out = () => {}, verificationsPath, targetsPath, aiConfigPath } = {}) {
  const join = (f) => `${cwd.replace(/[\\/]+$/, '')}/${f}`;
  const ctx = {
    cwd,
    env,
    now,
    out,
    recording: null,
    verifications: memory ? new VerificationStore({ now }) : VerificationStore.load(verificationsPath || join('quilltest.verifications.json'), { now }),
    targets: memory ? new TargetStore({ now }) : TargetStore.load(targetsPath || join('quilltest.targets.json'), { now }),
    aiConfigPath: aiConfigPath || join('quilltest.ai.json'),
  };
  ctx.exec = (id, arg) => exec(ctx, id, arg);
  return ctx;
}

/**
 * Run a command by id.
 * Order of checks: known → enabled → target present → verified+authorized → implemented → run.
 * The gate runs before the implementation check on purpose: a planned scan
 * command on an unverified target reports the gate, not "not implemented".
 */
export async function exec(ctx, id, arg) {
  const cmd = getCommand(id);
  if (!cmd) throw new UnknownCommandError(id);
  if (cmd.isEnabled && !cmd.isEnabled(ctx)) throw new CommandDisabledError(cmd);

  let target = null;
  if (cmd.requiresTarget) {
    target = ctx.targets.active();
    if (!target) throw new NoActiveTargetError();
  }
  if (cmd.requiresVerification) {
    ctx.verifications.assertVerified(target.origin);          // throws VerificationRequiredError
    if (!target.authorization?.confirmed) throw new AuthorizationRequiredError(target.origin);
  }
  if (typeof cmd.run !== 'function') throw new NotImplementedError(cmd);

  if (ctx.recording && !cmd.noRecord) ctx.recording.push(arg === undefined ? { id } : { id, arg });
  return cmd.run(ctx, arg, target);
}

/**
 * Is the gate open for a target? Pure query used by the UI to grey out scan
 * commands and by `target status`. Never throws.
 * @returns {{verified:boolean, authorized:boolean, ready:boolean, record:object|null, reasons:string[]}}
 */
export function scanReadiness(ctx, originInput) {
  const reasons = [];
  let record = null;
  let verified = false;
  try { record = ctx.verifications.assertVerified(originInput); verified = true; } catch (e) { reasons.push(e.detail || e.message); }
  const t = ctx.targets.get(originInput);
  const authorized = Boolean(t?.authorization?.confirmed);
  if (!t) reasons.push('not in the target list');
  else if (!authorized) reasons.push('authorization not confirmed for this target');
  return { verified, authorized, ready: verified && authorized, record, reasons };
}
