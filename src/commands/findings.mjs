/** Findings tab — normalized, CWE/OWASP-mapped findings from saved scans. */
import { def } from './registry.mjs';
import { FindingSet, SEVERITIES, OWASP_2021, CWE } from '../findings/model.mjs';
import { exportFindings, FORMATS } from '../findings/export.mjs';
import { getCheck } from '../checks/index.mjs';

const opts = (arg) => (typeof arg === 'object' && arg ? arg : {});
const scanOf = (ctx, arg, t) => { const rec = ctx.scans.get(opts(arg).scan || 'last', t.origin); if (!rec) throw new RangeError(`No scans recorded for ${t.origin}; run scan.start first`); return rec; };
const findingOf = (rec, arg) => { const id = typeof arg === 'string' ? arg : opts(arg).finding || opts(arg).id || opts(arg).value; const set = FindingSet.fromJSON(rec.findings); const f = id && set.get(id); if (!f) throw new RangeError(`No finding ${JSON.stringify(id)} in scan ${rec.id}`); return f; };
const setStatus = (status) => (ctx, arg, t) => { const rec = scanOf(ctx, arg, t); const f = findingOf(rec, arg); return ctx.scans.updateFinding(rec.id, f.id, status, opts(arg).note || opts(arg).reason); };

def([
  {
    id: 'findings.list', label: 'Findings', icon: 'bug_report', tab: 'Findings', group: 'Browse', noRecord: true, popular: true, keys: ['Ctrl+Shift+F'], requiresTarget: true,
    tip: 'Findings of the latest scan (or --scan <id>); filter with severity / minSeverity / status / check / owasp / url',
    run: (ctx, arg, t) => { const rec = scanOf(ctx, arg, t); const o = opts(arg); const set = FindingSet.fromJSON(rec.findings); return { scan: rec.id, origin: rec.origin, summary: set.summary(), findings: set.list({ severity: o.severity, minSeverity: o.minSeverity, status: o.status, checkId: o.check, owasp: o.owasp, url: o.url }).map(brief) }; },
  },
  {
    id: 'findings.details', label: 'Finding Details', icon: 'article', tab: 'Findings', group: 'Browse', noRecord: true, requiresTarget: true, tip: 'Evidence, mapping, remediation',
    run: (ctx, arg, t) => { const rec = scanOf(ctx, arg, t); const f = findingOf(rec, arg); const check = getCheck(f.checkId); return { ...f, standards: { ...f.standards, owaspName: f.standards.owasp ? OWASP_2021[f.standards.owasp] : null, cweNames: f.standards.cwe.map((n) => `CWE-${n}: ${CWE[n]}`) }, check: check ? { intrusiveness: check.intrusiveness, kind: check.kind } : null }; },
  },
  { id: 'findings.next', label: 'Next Finding', icon: 'arrow_downward', tab: 'Findings', group: 'Browse', keys: ['F8'], noRecord: true },
  { id: 'findings.prev', label: 'Previous Finding', icon: 'arrow_upward', tab: 'Findings', group: 'Browse', keys: ['Shift+F8'], noRecord: true },
  { id: 'findings.search', label: 'Search Findings', icon: 'search', tab: 'Findings', group: 'Browse', noRecord: true, requiresTarget: true, run: (ctx, arg, t) => { const rec = scanOf(ctx, arg, t); const q = String(typeof arg === 'string' ? arg : opts(arg).query || opts(arg).value || '').toLowerCase(); return FindingSet.fromJSON(rec.findings).list().filter((f) => `${f.title} ${f.description} ${f.url} ${f.checkId} ${f.key || ''}`.toLowerCase().includes(q)).map(brief); } },
  { id: 'findings.filter', label: 'Filter', icon: 'filter_list', tab: 'Findings', group: 'Organize', kind: 'menu', noRecord: true, tip: 'By severity, confidence, category, status, URL (use findings.list arguments)' },
  { id: 'findings.sort', label: 'Sort', icon: 'sort', tab: 'Findings', group: 'Organize', kind: 'menu', noRecord: true },
  { id: 'findings.group', label: 'Group By', icon: 'workspaces', tab: 'Findings', group: 'Organize', kind: 'menu', noRecord: true, requiresTarget: true, tip: 'severity | owasp | check | url', run: (ctx, arg, t) => { const rec = scanOf(ctx, arg, t); const by = (typeof arg === 'string' ? arg : opts(arg).by || opts(arg).value) || 'severity'; const keyOf = { severity: (f) => f.severity, owasp: (f) => f.standards.owasp || 'unmapped', check: (f) => f.checkId, url: (f) => f.url }[by]; if (!keyOf) throw new RangeError('group by one of severity, owasp, check, url'); const groups = {}; for (const f of FindingSet.fromJSON(rec.findings).list()) (groups[keyOf(f)] ||= []).push(brief(f)); return groups; } },
  { id: 'findings.dedupe', label: 'Merge Duplicates', icon: 'merge', tab: 'Findings', group: 'Organize', tip: 'Findings are deduplicated by signature as they are recorded; this re-applies it to an imported set' },
  { id: 'findings.prioritize', label: "Attacker's-Eye Priority", icon: 'crisis_alert', tab: 'Findings', group: 'Organize', requiresTarget: true, noRecord: true, tip: 'Deterministic ordering: severity, then confidence, then how many pages are affected; AI can refine it (ai.prioritize)', origin: 'INNOVATIONS.md', run: (ctx, arg, t) => { const rec = scanOf(ctx, arg, t); return FindingSet.fromJSON(rec.findings).list({ includeSuppressed: false }).sort((a, b) => SEVERITIES.indexOf(b.severity) - SEVERITIES.indexOf(a.severity) || (b.occurrences || 1) - (a.occurrences || 1)).map(brief); } },
  { id: 'findings.setSeverity', label: 'Set Severity', icon: 'priority_high', tab: 'Findings', group: 'Triage', kind: 'menu', requiresTarget: true, run: (ctx, arg, t) => { const rec = scanOf(ctx, arg, t); const f = findingOf(rec, arg); const sev = opts(arg).severity; if (!SEVERITIES.includes(sev)) throw new RangeError(`severity must be one of ${SEVERITIES.join(', ')}`); f.severity = sev; f.notes.push(`severity set to ${sev} by user`); const set = FindingSet.fromJSON(rec.findings); set.get(f.id).severity = sev; set.get(f.id).notes.push(`severity set to ${sev} by user`); rec.findings = set.toJSON(); rec.summary = set.summary(); ctx.scans.save(rec); return brief(set.get(f.id)); } },
  { id: 'findings.setConfidence', label: 'Set Confidence', icon: 'percent', tab: 'Findings', group: 'Triage', kind: 'menu' },
  {
    id: 'findings.markFalsePositive', label: 'Mark False Positive', icon: 'block', tab: 'Findings', group: 'Triage', popular: true, requiresTarget: true, tip: 'Suppresses the finding and remembers its signature for future scans of this target', origin: 'false-positive learning loop — INNOVATIONS.md',
    run: (ctx, arg, t) => { const rec = scanOf(ctx, arg, t); const f = findingOf(rec, arg); ctx.scans.addFalsePositive(t.origin, f, opts(arg).note || opts(arg).reason); return ctx.scans.updateFinding(rec.id, f.id, 'false-positive', opts(arg).note || opts(arg).reason || 'marked false positive by user'); },
  },
  {
    id: 'findings.unmarkFalsePositive', label: 'Unmark False Positive', icon: 'undo', tab: 'Findings', group: 'Triage', requiresTarget: true,
    run: (ctx, arg, t) => { const rec = scanOf(ctx, arg, t); const f = findingOf(rec, arg); ctx.scans.removeFalsePositive(t.origin, f.signature); return ctx.scans.updateFinding(rec.id, f.id, 'open', 'false-positive mark removed by user'); },
  },
  { id: 'findings.markFixed', label: 'Mark Fixed', icon: 'task_alt', tab: 'Findings', group: 'Triage', requiresTarget: true, run: setStatus('fixed') },
  { id: 'findings.markAccepted', label: 'Accept Risk…', icon: 'thumb_up', tab: 'Findings', group: 'Triage', requiresTarget: true, tip: 'Record a reason; shown in the report', run: (ctx, arg, t) => { if (!opts(arg).reason && !opts(arg).note) throw new RangeError('A reason is required to accept a risk'); return setStatus('accepted')(ctx, arg, t); } },
  { id: 'findings.reopen', label: 'Reopen Finding', icon: 'restart_alt', tab: 'Findings', group: 'Triage', requiresTarget: true, run: setStatus('open') },
  { id: 'findings.recheck', label: 'Re-check Finding', icon: 'published_with_changes', tab: 'Findings', group: 'Triage', requiresTarget: true, requiresVerification: true, tip: 'Scan just the finding\'s URL again (passive) and report whether the finding is still present', run: async (ctx, arg, t) => { const rec = scanOf(ctx, arg, t); const f = findingOf(rec, arg); const fresh = await ctx.exec('scan.single', { url: f.url }); const still = fresh.findings.find((x) => x.signature === f.signature); return { finding: brief(f), rescan: fresh.id, stillPresent: Boolean(still), current: still ? brief(still) : null }; } },
  { id: 'findings.note', label: 'Add Note', icon: 'note_add', tab: 'Findings', group: 'Annotate', requiresTarget: true, run: (ctx, arg, t) => { const rec = scanOf(ctx, arg, t); const f = findingOf(rec, arg); const note = opts(arg).note || opts(arg).text; if (!note) throw new RangeError('note text required'); return ctx.scans.updateFinding(rec.id, f.id, f.status, note); } },
  { id: 'findings.tag', label: 'Tag', icon: 'label', tab: 'Findings', group: 'Annotate' },
  { id: 'findings.assign', label: 'Assign To…', icon: 'person_add', tab: 'Findings', group: 'Annotate' },
  { id: 'findings.copy', label: 'Copy Finding', icon: 'content_copy', tab: 'Findings', group: 'Exchange', noRecord: true, requiresTarget: true, tip: 'Markdown summary', run: (ctx, arg, t) => { const rec = scanOf(ctx, arg, t); const f = findingOf(rec, arg); return `### ${f.title}\n\n- **Severity:** ${f.severity} (${f.confidence})\n- **Where:** ${f.url}${f.key ? ` (${f.key})` : ''}\n- **Standards:** ${[f.standards.owasp ? OWASP_2021[f.standards.owasp] : null, ...f.standards.cwe.map((n) => `CWE-${n}`)].filter(Boolean).join(', ')}\n\n${f.description}\n\n**Fix:** ${f.remediation.summary}\n`; } },
  { id: 'findings.export', label: 'Export Findings…', icon: 'download', tab: 'Findings', group: 'Exchange', requiresTarget: true, tip: 'json | csv | sarif', run: (ctx, arg, t) => { const rec = scanOf(ctx, arg, t); const format = (typeof arg === 'string' ? arg : opts(arg).format || opts(arg).value) || 'json'; if (!FORMATS.includes(format)) throw new RangeError(`format must be one of ${FORMATS.join(', ')}`); return exportFindings(rec, format); } },
  { id: 'findings.import', label: 'Import Findings…', icon: 'upload_file', tab: 'Findings', group: 'Exchange', tip: 'From a previous QuillTest export, for comparison' },
  { id: 'findings.falsePositives', label: 'False-Positive Rules', icon: 'rule_folder', tab: 'Findings', group: 'Triage', noRecord: true, requiresTarget: true, tip: 'Signatures remembered for this target', run: (ctx, arg, t) => ctx.scans.falsePositives(t.origin) },
]);

export function brief(f) {
  return { id: f.id, signature: f.signature, severity: f.severity, confidence: f.confidence, status: f.status, checkId: f.checkId, title: f.title, url: f.url, key: f.key, occurrences: f.occurrences || 1, owasp: f.standards.owasp, cwe: f.standards.cwe };
}
