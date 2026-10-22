/** Scan tab — every command that sends requests to the target is gated. Passive engine: implemented (M2). Active: M3. */
import { def } from './registry.mjs';
import { runScan, planChecks, PROFILES, describeProfile } from '../scan/orchestrator.mjs';
import { DEFAULT_SETTINGS } from '../scan/store.mjs';
import { diffFindings } from '../findings/model.mjs';

const gated = { requiresTarget: true, requiresVerification: true };
const opts = (arg) => (typeof arg === 'object' && arg ? arg : {});
const num = (v, name) => { if (v === undefined) return undefined; const n = Number(v); if (!Number.isFinite(n) || n < 0) throw new RangeError(`${name} must be a non-negative number`); return n; };
const progress = (ctx) => (e) => {
  if (e.type === 'page') ctx.out(`  ${String(e.status).padStart(3)}  ${e.url}`);
  else if (e.type === 'probe') ctx.out(`  probe ${e.checkId}`);
  else if (e.type === 'start') ctx.out(`Scanning ${e.origin} (${e.profile} profile) — scan ${e.id}`);
};
const run = (ctx, target, o) => runScan(ctx, { target, onProgress: progress(ctx), fetch: ctx.fetch, inspectTls: ctx.inspectTls, ...o });

def([
  { id: 'scan.start', label: 'Start Scan', icon: 'play_arrow', tab: 'Scan', group: 'Run', keys: ['F5'], popular: true, ...gated, tip: 'Run the target\'s scan profile (default Passive) against the active target', run: (ctx, arg, t) => run(ctx, t, { profile: opts(arg).profile }) },
  { id: 'scan.passive', label: 'Passive Scan', icon: 'visibility', tab: 'Scan', group: 'Run', ...gated, tip: 'Crawl and observe: headers, cookies, TLS, disclosure, components. No test inputs are sent.', run: (ctx, arg, t) => run(ctx, t, { profile: 'passive' }) },
  { id: 'scan.active', label: 'Active Scan', icon: 'bolt', tab: 'Scan', group: 'Run', ...gated, tip: 'Detection probes for injection, XSS, access control… least-intrusive probe that proves a finding, then stop (M3; not yet available)' },
  { id: 'scan.quick', label: 'Quick Scan', icon: 'timer', tab: 'Scan', group: 'Run', ...gated, tip: 'Passive checks on the entry page and its direct links', run: (ctx, arg, t) => run(ctx, t, { profile: 'quick' }) },
  { id: 'scan.single', label: 'Scan Single URL', icon: 'link', tab: 'Scan', group: 'Run', ...gated, tip: 'Passive checks on one URL within the target, no crawl', run: (ctx, arg, t) => { const url = typeof arg === 'string' ? arg : opts(arg).url || opts(arg).value; if (!url) throw new RangeError('A URL within the target is required'); return run(ctx, t, { url, profile: opts(arg).profile || 'passive' }); } },
  { id: 'scan.spiderOnly', label: 'Crawl Only (no checks)', icon: 'travel_explore', tab: 'Scan', group: 'Crawl', ...gated, run: (ctx, arg, t) => run(ctx, t, { spiderOnly: true }) },
  { id: 'scan.pause', label: 'Pause', icon: 'pause', tab: 'Scan', group: 'Control', requiresTarget: true, noRecord: true },
  { id: 'scan.resume', label: 'Resume', icon: 'resume', tab: 'Scan', group: 'Control', ...gated, noRecord: true },
  { id: 'scan.stop', label: 'Stop', icon: 'stop', tab: 'Scan', group: 'Control', keys: ['Shift+F5'], requiresTarget: true, noRecord: true },
  {
    id: 'scan.profile', label: 'Scan Profile', icon: 'tune', tab: 'Scan', group: 'Profile', kind: 'menu', requiresTarget: true, tip: 'Passive / Quick / Standard / Thorough; pass a name to set it for the active target',
    run: (ctx, arg, t) => {
      const want = typeof arg === 'string' ? arg : opts(arg).profile || opts(arg).value;
      if (want) { if (!PROFILES[want]) throw new RangeError(`Unknown profile ${want}; one of ${Object.keys(PROFILES).join(', ')}`); ctx.scans.updateSettings(t.origin, { profile: want }); }
      const s = ctx.scans.settings(t.origin);
      return { origin: t.origin, profile: describeProfile(s.profile), available: Object.keys(PROFILES) };
    },
  },
  { id: 'scan.profiles', label: 'Manage Profiles…', icon: 'settings_suggest', tab: 'Scan', group: 'Profile', noRecord: true, run: () => Object.keys(PROFILES).map(describeProfile) },
  { id: 'scan.intrusiveness', label: 'Intrusiveness Cap', icon: 'shield', tab: 'Scan', group: 'Profile', kind: 'combo', requiresTarget: true, noRecord: true, tip: 'Highest intrusiveness level the current profile permits (0 observe, 1 benign extra requests, 2 test input, 3 state-changing)', run: (ctx, arg, t) => { const p = describeProfile(ctx.scans.settings(t.origin).profile); return { profile: p.id, maxIntrusiveness: p.maxIntrusiveness, active: p.active }; } },
  { id: 'scan.crawlDepth', label: 'Crawl Depth', icon: 'account_tree', tab: 'Scan', group: 'Crawl', kind: 'combo', requiresTarget: true, run: (ctx, arg, t) => { const d = num(typeof arg === 'string' ? arg : opts(arg).depth ?? opts(arg).value, 'depth'); if (d !== undefined) ctx.scans.updateSettings(t.origin, { maxDepth: d }); return { maxDepth: ctx.scans.settings(t.origin).maxDepth }; } },
  {
    id: 'scan.crawlLimits', label: 'Crawl Limits…', icon: 'data_thresholding', tab: 'Scan', group: 'Crawl', requiresTarget: true, tip: 'Max pages, max requests, timeout, concurrency, delay between requests, sitemap seeding',
    run: (ctx, arg, t) => {
      const o = opts(arg); const patch = {};
      for (const k of ['maxPages', 'maxRequests', 'timeoutMs', 'concurrency', 'delayMs', 'maxDepth']) if (o[k] !== undefined) patch[k] = num(o[k], k);
      if (o.seedSitemap !== undefined) patch.seedSitemap = o.seedSitemap;
      if (Object.keys(patch).length) ctx.scans.updateSettings(t.origin, patch);
      return { origin: t.origin, settings: ctx.scans.settings(t.origin), defaults: DEFAULT_SETTINGS };
    },
  },
  { id: 'scan.sitemap', label: 'Seed from sitemap.xml', icon: 'map', tab: 'Scan', group: 'Crawl', kind: 'toggle', requiresTarget: true, run: (ctx, arg, t) => ({ seedSitemap: ctx.scans.updateSettings(t.origin, { seedSitemap: arg === undefined ? !ctx.scans.settings(t.origin).seedSitemap : (arg === true || arg === 'true' || opts(arg).on === true) }).seedSitemap }) },
  { id: 'scan.importUrls', label: 'Import URL List…', icon: 'playlist_add', tab: 'Scan', group: 'Crawl', requiresTarget: true, origin: 'inspired by Burp target site map import' },
  { id: 'scan.schedule', label: 'Schedule…', icon: 'schedule', tab: 'Scan', group: 'History', requiresTarget: true, tip: 'Recurring scans; each run re-checks verification first' },
  {
    id: 'scan.history', label: 'Scan History', icon: 'history', tab: 'Scan', group: 'History', requiresTarget: true, noRecord: true,
    run: (ctx, arg, t) => ({ origin: t.origin, scans: ctx.scans.list(t.origin) }),
  },
  { id: 'scan.rescan', label: 'Re-run Last Scan', icon: 'replay', tab: 'Scan', group: 'History', ...gated, run: (ctx, arg, t) => { const last = ctx.scans.get('last', t.origin); return run(ctx, t, { profile: last?.profile }); } },
  {
    id: 'scan.diff', label: 'Compare with Previous Scan', icon: 'difference', tab: 'Scan', group: 'History', requiresTarget: true, origin: 'findings diff — see INNOVATIONS.md',
    run: (ctx, arg, t) => {
      const o = opts(arg);
      const after = ctx.scans.get(o.scan || o.value || 'last', t.origin);
      if (!after) throw new RangeError(`No scans recorded for ${t.origin}`);
      const before = o.previous ? ctx.scans.get(o.previous) : ctx.scans.previousFor(after);
      if (!before) return { after: after.id, before: null, added: after.findings, fixed: [], persisting: [], note: 'Only one scan on record; everything counts as new.' };
      const d = diffFindings(before.findings, after.findings);
      return { after: after.id, before: before.id, added: d.added, fixed: d.fixed, persisting: d.persisting, counts: { added: d.added.length, fixed: d.fixed.length, persisting: d.persisting.length } };
    },
  },
  {
    id: 'scan.log', label: 'Request Log', icon: 'receipt_long', tab: 'Scan', group: 'History', requiresTarget: true, noRecord: true, tip: 'Every request QuillTest sent in a scan, for audit',
    run: (ctx, arg, t) => { const rec = ctx.scans.get(opts(arg).scan || opts(arg).value || (typeof arg === 'string' ? arg : 'last'), t.origin); if (!rec) throw new RangeError(`No scans recorded for ${t.origin}`); return { scan: rec.id, requests: rec.requestLog }; },
  },
  {
    id: 'scan.preview', label: 'Scan Preview', icon: 'preview', tab: 'Scan', group: 'Profile', requiresTarget: true, noRecord: true, tip: 'What this profile would do: checks, request budget, intrusiveness', origin: 'scan-as-you-configure preview — INNOVATIONS.md',
    run: (ctx, arg, t) => {
      const s = ctx.scans.settings(t.origin);
      const profile = describeProfile(opts(arg).profile || s.profile);
      const { run: checks, skipped } = planChecks({ profile: profile.id, disabledChecks: s.disabledChecks, origin: t.origin });
      const crawl = { maxDepth: s.maxDepth, maxPages: s.maxPages, maxRequests: s.maxRequests, honorRobots: s.honorRobots, ...(profile.crawl || {}) };
      return { origin: t.origin, profile, crawl, checks: checks.map((c) => ({ id: c.id, intrusiveness: c.intrusiveness, requests: c.requests || (c.probe ? 'extra requests' : 'none') })), skipped: skipped.map((x) => ({ id: x.check.id, reason: x.reason })), extraRequestChecks: checks.filter((c) => c.probe).length, activeChecks: checks.filter((c) => c.kind === 'active').length };
    },
  },
]);
