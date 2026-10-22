/** Targets tab — the list of origins you may test. Implemented against src/targets/. */
import { def } from './registry.mjs';
import { scanReadiness } from './exec.mjs';

const originOf = (ctx, arg) => (typeof arg === 'string' ? arg : arg?.origin) || ctx.targets.active()?.origin;
const need = (ctx, arg) => {
  const o = originOf(ctx, arg);
  if (!o) throw new RangeError('An origin is required (or select an active target).');
  return o;
};
const opts = (arg) => (typeof arg === 'object' && arg ? arg : {});

def([
  {
    id: 'target.add', label: 'Add Target', icon: 'add_circle', tab: 'Targets', group: 'Targets', keys: ['Ctrl+T'], popular: true,
    tip: 'Add an origin (scheme + host + port) to the target list',
    keywords: 'site host origin new',
    run: (ctx, arg) => ctx.targets.add(typeof arg === 'string' ? arg : arg.origin, opts(arg)),
  },
  { id: 'target.remove', label: 'Remove Target', icon: 'delete', tab: 'Targets', group: 'Targets', run: (ctx, arg) => ({ removed: ctx.targets.remove(need(ctx, arg)) }) },
  { id: 'target.edit', label: 'Edit Target…', icon: 'edit', tab: 'Targets', group: 'Targets', tip: 'Rename, add notes or tags', run: (ctx, arg) => ctx.targets.update(need(ctx, arg), opts(arg)) },
  { id: 'target.list', label: 'Target List', icon: 'list', tab: 'Targets', group: 'Targets', noRecord: true, run: (ctx) => ({ active: ctx.targets.active()?.origin || null, targets: ctx.targets.list() }) },
  { id: 'target.select', label: 'Select Active Target', icon: 'ads_click', tab: 'Targets', group: 'Targets', popular: true, run: (ctx, arg) => ctx.targets.setActive(need(ctx, arg)) },
  {
    id: 'target.status', label: 'Target Status', icon: 'health_and_safety', tab: 'Targets', group: 'Targets', noRecord: true, popular: true,
    tip: 'Verification, authorization and scan readiness for a target',
    run: (ctx, arg) => { const t = ctx.targets.require(need(ctx, arg)); return { target: t, ...scanReadiness(ctx, t.origin) }; },
  },
  {
    id: 'target.confirmAuthorization', label: 'Confirm Authorization…', icon: 'gavel', tab: 'Targets', group: 'Authorization', popular: true,
    tip: 'Record your statement that you are authorized to test this target; required in addition to ownership verification',
    keywords: 'permission legal consent engagement',
    run: (ctx, arg) => ctx.targets.confirmAuthorization(need(ctx, arg), opts(arg).statement),
  },
  { id: 'target.revokeAuthorization', label: 'Withdraw Authorization', icon: 'do_not_disturb_on', tab: 'Targets', group: 'Authorization', run: (ctx, arg) => ctx.targets.revokeAuthorization(need(ctx, arg)) },
  {
    id: 'target.scope', label: 'Scope…', icon: 'crop_free', tab: 'Targets', group: 'Scope',
    tip: 'Limit a scan to path prefixes within the origin, and exclude paths (logout, destructive admin pages)',
    run: (ctx, arg) => ctx.targets.setScope(need(ctx, arg), { include: opts(arg).include, exclude: opts(arg).exclude }),
  },
  {
    id: 'target.inScope', label: 'Is URL in Scope?', icon: 'rule', tab: 'Targets', group: 'Scope', noRecord: true,
    run: (ctx, arg) => ({ url: opts(arg).url, inScope: ctx.targets.inScope(need(ctx, arg), opts(arg).url) }),
  },
  { id: 'target.import', label: 'Import Targets…', icon: 'upload_file', tab: 'Targets', group: 'Exchange', tip: 'From a text file, one origin per line, or a QuillTest targets JSON' },
  { id: 'target.export', label: 'Export Targets…', icon: 'download', tab: 'Targets', group: 'Exchange' },
  { id: 'target.open', label: 'Open in Browser', icon: 'open_in_browser', tab: 'Targets', group: 'Targets', noRecord: true, requiresTarget: true },
  { id: 'target.credentials', label: 'Scan Credentials…', icon: 'password', tab: 'Targets', group: 'Authentication', requiresTarget: true, tip: 'Per-scan login for authenticated checks; never persisted' },
  { id: 'target.sessionRecord', label: 'Record Login Sequence…', icon: 'fiber_manual_record', tab: 'Targets', group: 'Authentication', requiresTarget: true, origin: 'inspired by ZAP authentication scripts and Burp session handling' },
  { id: 'target.headers', label: 'Extra Request Headers…', icon: 'view_headline', tab: 'Targets', group: 'Authentication', requiresTarget: true, tip: 'e.g. a bug-bounty identification header' },
  { id: 'target.rateLimit', label: 'Rate Limit…', icon: 'speed', tab: 'Targets', group: 'Politeness', requiresTarget: true, tip: 'Delay between requests (ms) and concurrency cap for this target', run: (ctx, arg, t) => { const o = opts(arg); const patch = {}; if (o.delayMs !== undefined) patch.delayMs = o.delayMs; if (o.concurrency !== undefined) patch.concurrency = o.concurrency; if (Object.keys(patch).length) ctx.scans.updateSettings(t.origin, patch); const s = ctx.scans.settings(t.origin); return { delayMs: s.delayMs, concurrency: s.concurrency }; } },
  { id: 'target.robots', label: 'Honor robots.txt', icon: 'smart_toy', tab: 'Targets', group: 'Politeness', kind: 'toggle', requiresTarget: true, run: (ctx, arg, t) => { const cur = ctx.scans.settings(t.origin).honorRobots; const next = arg === undefined ? !cur : (arg === true || arg === 'true' || arg === 'on' || opts(arg).on === true); return { honorRobots: ctx.scans.updateSettings(t.origin, { honorRobots: next }).honorRobots }; } },
  { id: 'target.notes', label: 'Target Notes', icon: 'sticky_note_2', tab: 'Targets', group: 'Targets', requiresTarget: true, run: (ctx, arg, t) => (opts(arg).notes !== undefined ? ctx.targets.update(t.origin, { notes: opts(arg).notes }) : { notes: t.notes }) },
]);
