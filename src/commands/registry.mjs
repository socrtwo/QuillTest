/*
 * QuillTest — command registry
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Every user-facing action in QuillTest is a Command, registered by id. The
 * ribbon tabs, the Quick Access Bar, context menus, keyboard shortcuts, command
 * search (Alt+Q), macros and the customization dialogs all reference commands
 * by id, so anything that exists can be placed anywhere the user wants — the
 * suite's "no missing commands" rule. Same shape as QuillStage's registry.
 *
 * ids are `area.name` in camelCase. Areas: file, verify, target, scan, checks,
 * findings, fix, ai, report, review, share, view, dev, help.
 *
 * A command may exist as data before it is implemented: `run` is optional and
 * the catalog (docs/COMMANDS.md) reports which commands are implemented.
 *
 * QuillTest-specific fields:
 *   requiresTarget        the command acts on the active target
 *   requiresVerification  the executor refuses to run it unless the active
 *                         target's origin has a current ownership verification
 *                         AND the user has confirmed authorization for it.
 *                         Every command that sends requests to a target sets
 *                         this; there is no bypass (docs/ETHICS.md).
 */

export const AREAS = ['file', 'verify', 'target', 'scan', 'checks', 'findings', 'fix', 'ai', 'report', 'review', 'share', 'view', 'dev', 'help'];

export const ID_PATTERN = /^[a-z]+\.[a-z][A-Za-z0-9]*(\.[a-z][A-Za-z0-9]*)?$/;

/**
 * @typedef {'button'|'toggle'|'menu'|'split'|'gallery'|'combo'} CommandKind
 *
 * @typedef {Object} Command
 * @property {string}   id         `area.name`
 * @property {string}   label      what the user sees
 * @property {string}   tab        primary tab: "File", "Verify", "Scan", "Targets", "Checks", "Findings", "Fix", "AI", "Report", "Review", "Share", "View", "Developer", "Help"
 * @property {string}   group      group within the tab
 * @property {string}   [icon]     Material Symbols name
 * @property {string[]} [keys]     default shortcuts, e.g. ["Ctrl+Shift+V"]
 * @property {string}   [tip]      tooltip / one-line description
 * @property {CommandKind} [kind]  default "button"
 * @property {(ctx:object, arg?:any)=>any} [run]  implementation; absent while planned
 * @property {(ctx:object)=>boolean} [isEnabled]
 * @property {boolean}  [requiresTarget]
 * @property {boolean}  [requiresVerification]
 * @property {boolean}  [noRecord]   not recorded into macros (navigation, UI toggles)
 * @property {boolean}  [popular]    appears in the default chooser list
 * @property {boolean}  [internal]   hidden from choosers and the catalog
 * @property {string}   [keywords]   extra search terms
 * @property {string}   [origin]     heritage note for the command reference (e.g. "inspired by ZAP's Alerts tab")
 */

const registry = new Map();

/** Register one command or a list. Throws on a malformed or duplicate id. */
export function def(c) {
  const list = Array.isArray(c) ? c : [c];
  for (const cmd of list) {
    validate(cmd);
    if (registry.has(cmd.id)) throw new Error(`Duplicate command id ${cmd.id}`);
    registry.set(cmd.id, Object.freeze({ kind: 'button', ...cmd }));
  }
}

function validate(cmd) {
  if (!cmd || typeof cmd !== 'object') throw new TypeError('command must be an object');
  if (!ID_PATTERN.test(cmd.id || '')) throw new Error(`Bad command id ${JSON.stringify(cmd.id)} (expected area.name in camelCase)`);
  const area = cmd.id.split('.')[0];
  if (!AREAS.includes(area)) throw new Error(`${cmd.id}: unknown area "${area}" (known: ${AREAS.join(', ')})`);
  for (const f of ['label', 'tab', 'group']) {
    if (typeof cmd[f] !== 'string' || !cmd[f].trim()) throw new Error(`${cmd.id}: ${f} is required`);
  }
  if (cmd.run !== undefined && typeof cmd.run !== 'function') throw new Error(`${cmd.id}: run must be a function`);
  if (cmd.requiresVerification && !cmd.requiresTarget) throw new Error(`${cmd.id}: requiresVerification implies requiresTarget`);
  if (cmd.keys && !Array.isArray(cmd.keys)) throw new Error(`${cmd.id}: keys must be an array`);
}

/** @returns {Command|undefined} */
export function getCommand(id) {
  return registry.get(id);
}

export function hasCommand(id) {
  return registry.has(id);
}

/** Every non-internal command, in registration order. */
export function allCommands() {
  return [...registry.values()].filter((c) => !c.internal);
}

export function commandCount() {
  return allCommands().length;
}

export function implementedCommands() {
  return allCommands().filter((c) => typeof c.run === 'function');
}

export function isImplemented(id) {
  return typeof registry.get(id)?.run === 'function';
}

/** Commands whose default shortcut includes `key` (case-insensitive). */
export function commandsForKey(key) {
  const k = normalizeKey(key);
  return allCommands().filter((c) => (c.keys || []).some((x) => normalizeKey(x) === k));
}

export function normalizeKey(key) {
  return String(key).split('+').map((p) => p.trim().toLowerCase()).sort((a, b) => {
    const order = ['ctrl', 'alt', 'shift', 'meta'];
    const ia = order.indexOf(a); const ib = order.indexOf(b);
    if (ia >= 0 && ib >= 0) return ia - ib;
    if (ia >= 0) return -1;
    if (ib >= 0) return 1;
    return 0;
  }).join('+');
}

/**
 * Command search (Alt+Q). Every term must match somewhere; matches at the start
 * of the label score highest. Same scoring as QuillStage so results feel familiar.
 */
export function searchCommands(q, limit = 60) {
  const terms = String(q || '').toLowerCase().split(/\s+/).filter(Boolean);
  if (!terms.length) return [];
  const scored = [];
  for (const c of allCommands()) {
    const label = c.label.toLowerCase();
    const hay = `${label} ${c.tab} ${c.group} ${c.keywords || ''} ${c.tip || ''} ${c.id}`.toLowerCase();
    let s = 0;
    let ok = true;
    for (const t of terms) {
      const i = hay.indexOf(t);
      if (i < 0) { ok = false; break; }
      s += i === 0 ? 10 : label.startsWith(t) ? 8 : label.includes(t) ? 5 : 1;
    }
    if (ok) scored.push({ c, s });
  }
  scored.sort((a, b) => b.s - a.s || a.c.label.localeCompare(b.c.label));
  return scored.slice(0, limit).map((x) => x.c);
}

/** Test helper: forget everything (modules re-register on import). */
export function _resetRegistry() {
  registry.clear();
}
