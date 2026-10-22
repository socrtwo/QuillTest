/** Checks tab — the check registry is data (docs/CHECKS.md); these commands read and configure it. */
import { def } from './registry.mjs';
import { allChecks, getCheck, checksByCategory, searchChecks, describeCheck, CATEGORIES } from '../checks/index.mjs';
import { OWASP_2021, CWE } from '../findings/model.mjs';

const opts = (arg) => (typeof arg === 'object' && arg ? arg : {});
const idOf = (arg) => (typeof arg === 'string' ? arg : opts(arg).check || opts(arg).id || opts(arg).value);
const need = (arg) => { const id = idOf(arg); const c = id && getCheck(id); if (!c) throw new RangeError(`Unknown check ${JSON.stringify(id)}; see checks.list`); return c; };
const withState = (ctx, t) => { const disabled = new Set(t ? ctx.scans.settings(t.origin).disabledChecks : []); return (c) => ({ ...describeCheck(c), enabled: !(disabled.has(c.id) || disabled.has(c.id.split('.')[0])) }); };

def([
  { id: 'checks.list', label: 'All Checks', icon: 'checklist', tab: 'Checks', group: 'Checks', noRecord: true, popular: true, run: (ctx) => allChecks().map(withState(ctx, ctx.targets.active())) },
  { id: 'checks.details', label: 'Check Details', icon: 'info', tab: 'Checks', group: 'Checks', noRecord: true, tip: 'What it detects, how, intrusiveness, CWE/OWASP mapping, remediation', run: (ctx, arg) => withState(ctx, ctx.targets.active())(need(arg)) },
  { id: 'checks.enable', label: 'Enable Check', icon: 'check_box', tab: 'Checks', group: 'Checks', requiresTarget: true, run: (ctx, arg, t) => ({ check: need(arg).id, disabledChecks: ctx.scans.setCheckEnabled(t.origin, need(arg).id, true).disabledChecks }) },
  { id: 'checks.disable', label: 'Disable Check', icon: 'check_box_outline_blank', tab: 'Checks', group: 'Checks', requiresTarget: true, tip: 'Per target; a disabled check is skipped by every profile', run: (ctx, arg, t) => ({ check: need(arg).id, disabledChecks: ctx.scans.setCheckEnabled(t.origin, need(arg).id, false).disabledChecks }) },
  { id: 'checks.enableCategory', label: 'Enable Category', icon: 'library_add_check', tab: 'Checks', group: 'Categories', requiresTarget: true, run: (ctx, arg, t) => { const cat = idOf(arg); if (!CATEGORIES[cat]) throw new RangeError(`Unknown category ${cat}; one of ${Object.keys(CATEGORIES).join(', ')}`); const s = ctx.scans.settings(t.origin); return { category: cat, disabledChecks: ctx.scans.updateSettings(t.origin, { disabledChecks: s.disabledChecks.filter((x) => x !== cat && !x.startsWith(cat + '.')) }).disabledChecks }; } },
  { id: 'checks.disableCategory', label: 'Disable Category', icon: 'remove_done', tab: 'Checks', group: 'Categories', requiresTarget: true, run: (ctx, arg, t) => { const cat = idOf(arg); if (!CATEGORIES[cat]) throw new RangeError(`Unknown category ${cat}; one of ${Object.keys(CATEGORIES).join(', ')}`); return { category: cat, disabledChecks: ctx.scans.setCheckEnabled(t.origin, cat, false).disabledChecks }; } },
  { id: 'checks.passiveOnly', label: 'Passive Checks Only', icon: 'visibility', tab: 'Checks', group: 'Categories', kind: 'toggle', requiresTarget: true, tip: 'Equivalent to the Passive profile', run: (ctx, arg, t) => ({ profile: ctx.scans.updateSettings(t.origin, { profile: 'passive' }).profile }) },
  { id: 'checks.byOwasp', label: 'Group by OWASP Top 10', icon: 'category', tab: 'Checks', group: 'View', kind: 'toggle', noRecord: true, run: () => Object.entries(OWASP_2021).map(([id, name]) => ({ id, name, checks: allChecks().filter((c) => c.owasp === id).map((c) => c.id) })) },
  { id: 'checks.byCwe', label: 'Group by CWE', icon: 'account_tree', tab: 'Checks', group: 'View', kind: 'toggle', noRecord: true, run: () => Object.entries(CWE).map(([n, name]) => ({ id: `CWE-${n}`, name, checks: allChecks().filter((c) => c.cwe.includes(Number(n))).map((c) => c.id) })).filter((x) => x.checks.length) },
  { id: 'checks.byAsvs', label: 'Group by ASVS', icon: 'segment', tab: 'Checks', group: 'View', kind: 'toggle', noRecord: true, run: () => { const m = new Map(); for (const c of allChecks()) for (const a of c.asvs) { if (!m.has(a)) m.set(a, []); m.get(a).push(c.id); } return [...m].sort().map(([id, checks]) => ({ id, checks })); } },
  { id: 'checks.search', label: 'Search Checks', icon: 'search', tab: 'Checks', group: 'View', noRecord: true, run: (ctx, arg) => searchChecks(typeof arg === 'string' ? arg : opts(arg).query || opts(arg).value).map(withState(ctx, ctx.targets.active())) },
  { id: 'checks.categories', label: 'Check Categories', icon: 'folder', tab: 'Checks', group: 'View', noRecord: true, run: () => Object.entries(CATEGORIES).map(([id, label]) => ({ id, label, checks: checksByCategory(id).map((c) => c.id) })) },
  { id: 'checks.custom', label: 'New Custom Check…', icon: 'add_box', tab: 'Checks', group: 'Custom', tip: 'Pattern/response-based detection check; no payload fields by design' },
  { id: 'checks.import', label: 'Import Checks…', icon: 'upload_file', tab: 'Checks', group: 'Custom' },
  { id: 'checks.export', label: 'Export Checks…', icon: 'download', tab: 'Checks', group: 'Custom', noRecord: true, run: () => allChecks().map(describeCheck) },
  { id: 'checks.update', label: 'Update Check Signatures', icon: 'system_update_alt', tab: 'Checks', group: 'Custom', tip: 'Component fingerprints and known-vulnerable version data' },
]);
