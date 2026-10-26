/*
 * Anne's Test — report rendering, export, findings diff, review packages
 * Part of the Anne's Office suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Takes the JSON report scripts/scan.mjs writes and renders it for people:
 *   - renderHtml:      one self-contained HTML file (inline CSS, no scripts,
 *                      no external resources) that prints cleanly to PDF
 *   - renderMarkdown:  the same content for tickets, wikis and pull requests
 *   - renderCsv:       one row per finding for spreadsheets
 *   - diffReports:     new / resolved / changed / unchanged between two scans
 *   - buildReviewPackage: the report in every format plus the fix artifacts
 *                      and a manifest with SHA-256 of each file, for handing
 *                      to a reviewer or attaching to a change request
 *
 * Everything from the target (titles, evidence, headers, banners) is treated
 * as untrusted text: HTML-escaped in HTML, pipe-escaped in Markdown tables,
 * quoted in CSV. The HTML never includes a <script> tag, so a hostile banner
 * cannot execute when the report is opened.
 */
import { createHash } from 'node:crypto';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, SEVERITIES.length - i]));
const CONF_RANK = { confirmed: 3, firm: 2, tentative: 1 };

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

export function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}
const mdCell = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
// Quote on CSV metacharacters, and neutralise spreadsheet formula injection: a cell beginning
// with = + - @ or a tab/CR is prefixed with an apostrophe so Excel/Sheets treat it as text.
const csvCell = (s) => {
  let v = String(s ?? '');
  if (/^[=+\-@\t\r]/.test(v)) v = `'${v}`;
  return /[",\r\n']/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
};
const fmtDate = (iso) => (iso ? String(iso).replace('T', ' ').replace(/\.\d+Z$/, ' UTC').replace(/Z$/, ' UTC') : '—');
const pretty = (v) => JSON.stringify(v, null, 2);

export function sortFindings(findings) {
  return [...(findings || [])].sort((a, b) => (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0)
    || (CONF_RANK[b.confidence] || 0) - (CONF_RANK[a.confidence] || 0)
    || String(a.id || '').localeCompare(String(b.id || '')));
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

/** Counts and headline facts for the top of a report. */
export function summarize(report) {
  const findings = report?.findings || [];
  const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  const byConfidence = { confirmed: 0, firm: 0, tentative: 0 };
  const byCategory = {};
  for (const f of findings) {
    if (f.severity in bySeverity) bySeverity[f.severity]++; else bySeverity.info++;
    if (f.confidence in byConfidence) byConfidence[f.confidence]++;
    const cat = f.owasp || 'Uncategorized';
    byCategory[cat] = (byCategory[cat] || 0) + 1;
  }
  const consensus = report?.analysis?.consensus || {};
  const verdicts = { real: 0, 'false-positive': 0, split: 0, unreviewed: 0 };
  for (const v of Object.values(consensus)) if (v?.verdict in verdicts) verdicts[v.verdict]++;
  const services = (report?.protocols?.services || []).filter((s) => s.present).map((s) => `${s.service}:${s.port}`);
  return {
    origin: report?.origin || report?.host || null,
    startedAt: report?.startedAt || null,
    finishedAt: report?.finishedAt || null,
    requests: report?.requests ?? null,
    pages: report?.crawl?.pages ?? null,
    total: findings.length,
    bySeverity, byConfidence, byCategory,
    highest: SEVERITIES.find((s) => bySeverity[s] > 0) || null,
    stack: report?.stack?.summary || null,
    verification: report?.verification || null,
    protocolServices: services,
    activeScan: report?.active ? { profile: report.active.profile, requests: report.active.requests ?? null, targetsProbed: report.active.targetsProbed ?? null } : null,
    analysis: report?.analysis ? { providers: (report.analysis.providers || []).map((p) => ({ label: p.label || p.providerId, ok: Boolean(p.ok) })), verdicts } : null,
    fixFiles: (report?.fixes?.files || []).map((f) => f.filename),
  };
}

// ---------------------------------------------------------------------------
// Findings diff
// ---------------------------------------------------------------------------

/**
 * Stable identity for a finding across scans. Ids (F-001) are positional and
 * must not be used. Site-wide findings (seen on more than one page) drop the
 * location, since which page is listed first depends on crawl order.
 */
export function findingKey(f) {
  const loc = f.evidence?.affectedPages > 1 ? '*' : String(f.location || '').replace(/\/+$/, '');
  return `${f.checkId}|${f.title}|${loc}`;
}

/** Compare two reports of the same origin. */
export function diffReports(before, after) {
  const prev = new Map((before?.findings || []).map((f) => [findingKey(f), f]));
  const next = new Map((after?.findings || []).map((f) => [findingKey(f), f]));
  const added = [], resolved = [], unchanged = [], changed = [];
  for (const [k, f] of next) {
    const p = prev.get(k);
    if (!p) { added.push(f); continue; }
    const what = [];
    if (p.severity !== f.severity) what.push('severity');
    if (p.confidence !== f.confidence) what.push('confidence');
    if ((p.evidence?.affectedPages || 1) !== (f.evidence?.affectedPages || 1)) what.push('pages');
    if (what.length) changed.push({ before: p, after: f, what }); else unchanged.push(f);
  }
  for (const [k, f] of prev) if (!next.has(k)) resolved.push(f);
  return {
    before: { origin: before?.origin || null, startedAt: before?.startedAt || null, total: prev.size },
    after: { origin: after?.origin || null, startedAt: after?.startedAt || null, total: next.size },
    sameOrigin: Boolean(before?.origin && after?.origin && before.origin === after.origin),
    new: sortFindings(added), resolved: sortFindings(resolved), changed, unchanged: sortFindings(unchanged),
    summary: { new: added.length, resolved: resolved.length, changed: changed.length, unchanged: unchanged.length },
  };
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

export const CSV_COLUMNS = ['id', 'severity', 'confidence', 'checkId', 'title', 'location', 'affectedPages', 'cwe', 'owasp', 'remediation'];

export function renderCsv(report) {
  const rows = [CSV_COLUMNS.join(',')];
  for (const f of sortFindings(report?.findings)) {
    rows.push(CSV_COLUMNS.map((c) => csvCell(c === 'affectedPages' ? (f.evidence?.affectedPages || 1) : f[c])).join(','));
  }
  return rows.join('\r\n') + '\r\n';
}

// ---------------------------------------------------------------------------
// Markdown
// ---------------------------------------------------------------------------

function evidenceLines(f) {
  const ev = { ...(f.evidence || {}) };
  const out = [];
  if (ev.snippet) { out.push(String(ev.snippet)); delete ev.snippet; }
  if (ev.affectedPages) { out.push(`Affected pages: ${ev.affectedPages}${ev.pages ? ` (e.g. ${ev.pages.join(', ')})` : ''}`); delete ev.affectedPages; delete ev.pages; }
  return { lines: out, rest: Object.keys(ev).length ? ev : null };
}

/**
 * @param {object} report
 * @param {{diff?:object, includeEvidence?:boolean, includeFixes?:boolean, includeAnalysis?:boolean, title?:string}} [opts]
 */
export function renderMarkdown(report, opts = {}) {
  const { diff = null, includeEvidence = true, includeFixes = true, includeAnalysis = true } = opts;
  const s = summarize(report);
  const findings = sortFindings(report.findings);
  const L = [];
  L.push(`# ${opts.title || `Anne\'s Test report — ${s.origin || 'scan'}`}`, '');
  L.push(`| | |`, `|---|---|`);
  L.push(`| Target | ${mdCell(s.origin || '—')} |`);
  L.push(`| Scanned | ${mdCell(fmtDate(s.startedAt))}${s.finishedAt ? ` → ${mdCell(fmtDate(s.finishedAt))}` : ''} |`);
  if (s.verification) L.push(`| Ownership | verified via ${mdCell(s.verification.method)} on ${mdCell(fmtDate(s.verification.verifiedAt))} |`);
  if (s.stack) L.push(`| Stack | ${mdCell(s.stack)} |`);
  if (s.pages != null) L.push(`| Coverage | ${s.pages} page(s), ${s.requests ?? '?'} request(s)${s.protocolServices.length ? `; services: ${mdCell(s.protocolServices.join(', '))}` : ''}${s.activeScan ? `; active profile: ${mdCell(s.activeScan.profile)} (${s.activeScan.requests ?? '?'} probe(s))` : ''} |`);
  L.push(`| Findings | **${s.total}** — ${SEVERITIES.filter((x) => s.bySeverity[x]).map((x) => `${s.bySeverity[x]} ${x}`).join(', ') || 'none'} |`);
  L.push('');

  if (includeAnalysis && report.analysis?.providers?.length) {
    L.push('## AI review', '');
    for (const p of report.analysis.providers) {
      L.push(`- **${mdCell(p.label || p.providerId)}**: ${p.ok ? 'reviewed' : `failed (${mdCell(p.error || 'unknown error')})`}${p.ok && p.parsed?.summary ? ` — ${mdCell(p.parsed.summary)}` : ''}`);
    }
    const v = s.analysis.verdicts;
    L.push('', `Consensus: ${v.real} real, ${v['false-positive']} likely false positive, ${v.split} split, ${v.unreviewed} unreviewed.`, '');
  }

  if (diff) {
    L.push('## Changes since previous scan', '');
    L.push(`Previous: ${mdCell(fmtDate(diff.before.startedAt))} (${diff.before.total} findings) → this scan (${diff.after.total}).${diff.sameOrigin ? '' : ' **Different origins — compare with care.**'}`, '');
    L.push(`| New | Resolved | Changed | Unchanged |`, `|---|---|---|---|`, `| ${diff.summary.new} | ${diff.summary.resolved} | ${diff.summary.changed} | ${diff.summary.unchanged} |`, '');
    const list = (title, arr, fmt) => { if (!arr.length) return; L.push(`### ${title}`, ''); for (const x of arr) L.push(`- ${fmt(x)}`); L.push(''); };
    list('New', diff.new, (f) => `**${f.severity}** ${mdCell(f.title)} — ${mdCell(f.location)}`);
    list('Resolved', diff.resolved, (f) => `~~${mdCell(f.title)}~~ — ${mdCell(f.location)}`);
    list('Changed', diff.changed, (c) => `${mdCell(c.after.title)} — ${c.what.join(', ')}: ${c.what.map((w) => w === 'pages' ? `${c.before.evidence?.affectedPages || 1} → ${c.after.evidence?.affectedPages || 1}` : `${c.before[w]} → ${c.after[w]}`).join('; ')}`);
  }

  L.push('## Findings', '');
  if (!findings.length) L.push('No findings.', '');
  else {
    L.push(`| # | Severity | Confidence | Finding | Where |`, `|---|---|---|---|---|`);
    for (const f of findings) L.push(`| ${mdCell(f.id)} | ${f.severity} | ${f.confidence} | ${mdCell(f.title)} | ${mdCell(f.location)}${f.evidence?.affectedPages > 1 ? ` (+${f.evidence.affectedPages - 1})` : ''} |`);
    L.push('');
    for (const f of findings) {
      L.push(`### ${mdCell(f.id)} · ${mdCell(f.title)}`, '');
      L.push(`- Severity: **${f.severity}** · Confidence: ${f.confidence} · Check: \`${f.checkId}\`${f.cwe ? ` · ${f.cwe}` : ''}${f.owasp ? ` · ${mdCell(f.owasp)}` : ''}`);
      L.push(`- Location: ${mdCell(f.location)}`);
      const cons = report.analysis?.consensus?.[f.id];
      if (includeAnalysis && cons && cons.verdict !== 'unreviewed') L.push(`- AI consensus: ${cons.verdict} (${cons.reviewers} reviewer(s)${cons.meanAttackerPriority != null ? `, attacker priority ≈ ${cons.meanAttackerPriority.toFixed(1)}` : ''})`);
      if (includeEvidence) {
        const { lines, rest } = evidenceLines(f);
        if (lines.length || rest) {
          L.push('', '**Evidence**', '');
          for (const l of lines) L.push(`> ${l.replace(/\r?\n/g, '\n> ')}`);
          if (rest) L.push('', '```json', pretty(rest), '```');
        }
      }
      L.push('', '**Fix**', '', String(f.remediation || '—'), '');
    }
  }

  if (includeFixes && report.fixes?.files?.length) {
    L.push('## Generated fix artifacts', '', `Target: ${mdCell(report.fixes.target)}. Review before deploying; nothing was applied.`, '');
    for (const file of report.fixes.files) L.push(`- \`${mdCell(file.filename)}\` (${file.kind}${file.target && file.target !== report.fixes.target ? `, ${mdCell(file.target)}` : ''})`);
    for (const n of report.fixes.notes || []) L.push(`- Note: ${mdCell(n)}`);
    L.push('');
  }

  if (report.protocols?.services?.length) {
    L.push('## Services checked', '', `| Service | Port | Present | Notes |`, `|---|---|---|---|`);
    for (const sv of report.protocols.services) L.push(`| ${mdCell(sv.service)} | ${sv.port} | ${sv.present ? 'yes' : 'no'} | ${mdCell(sv.error || sv.banner || '')} |`);
    L.push('');
  }

  L.push('---', '', `Generated by Anne\'s Test${s.finishedAt ? ` from a scan finished ${fmtDate(s.finishedAt)}` : ''}. Detection was non-destructive and ran only against an origin whose ownership was verified. Versions read from banners may lag distribution backports; confirm before acting.`, '');
  return L.join('\n');
}

// ---------------------------------------------------------------------------
// HTML (self-contained, script-free)
// ---------------------------------------------------------------------------

const CSS = `
:root{--bg:#fff;--fg:#1b1b1b;--muted:#5f6368;--line:#e3e3e3;--card:#f7f7f8;--critical:#8b0000;--high:#c62828;--medium:#b26a00;--low:#1565c0;--info:#546e7a}
@media (prefers-color-scheme:dark){:root{--bg:#121212;--fg:#e6e6e6;--muted:#9aa0a6;--line:#2c2c2c;--card:#1c1c1e;--critical:#ff6b6b;--high:#ef5350;--medium:#ffb74d;--low:#64b5f6;--info:#90a4ae}}
*{box-sizing:border-box}body{margin:0;padding:24px 16px;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:980px;margin:0 auto}h1{font-size:1.6rem;margin:0 0 4px}h2{font-size:1.2rem;margin:32px 0 12px;padding-top:12px;border-top:1px solid var(--line)}h3{font-size:1.05rem;margin:24px 0 6px}
.muted{color:var(--muted)}table{border-collapse:collapse;width:100%;margin:8px 0 16px}th,td{text-align:left;vertical-align:top;padding:6px 8px;border-bottom:1px solid var(--line)}th{font-weight:600}td:first-child{white-space:nowrap}
.tiles{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}.tile{flex:1 1 120px;background:var(--card);border-radius:8px;padding:10px 12px}.tile b{display:block;font-size:1.5rem}
.sev{display:inline-block;padding:1px 8px;border-radius:999px;font-size:.8rem;font-weight:600;color:#fff;text-transform:uppercase;letter-spacing:.02em}
.sev-critical{background:var(--critical)}.sev-high{background:var(--high)}.sev-medium{background:var(--medium)}.sev-low{background:var(--low)}.sev-info{background:var(--info)}
.finding{background:var(--card);border-radius:8px;padding:12px 16px;margin:12px 0}.finding .meta{font-size:.85rem;color:var(--muted);word-break:break-word}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:10px;overflow:auto;font-size:.85rem;white-space:pre-wrap;word-break:break-word}
details summary{cursor:pointer;color:var(--muted)}blockquote{margin:8px 0;padding:4px 12px;border-left:3px solid var(--line);white-space:pre-wrap;word-break:break-word}
.fix{margin-top:8px}.fix b{display:block;margin-bottom:2px}a{color:inherit}.diff ul{margin:4px 0 12px}.del{text-decoration:line-through;color:var(--muted)}
@media print{body{padding:0;font-size:12px}.finding{break-inside:avoid;border:1px solid #ccc}details{open:true}details>summary{display:none}details>*{display:block}h2{break-after:avoid}}
`;

const sevBadge = (s) => `<span class="sev sev-${escapeHtml(SEVERITIES.includes(s) ? s : 'info')}">${escapeHtml(s)}</span>`;

/**
 * @param {object} report
 * @param {{diff?:object, includeEvidence?:boolean, includeFixes?:boolean, includeAnalysis?:boolean, title?:string}} [opts]
 */
export function renderHtml(report, opts = {}) {
  const { diff = null, includeEvidence = true, includeFixes = true, includeAnalysis = true } = opts;
  const s = summarize(report);
  const findings = sortFindings(report.findings);
  const title = opts.title || `Anne\'s Test report — ${s.origin || 'scan'}`;
  const H = [];
  H.push('<!doctype html>', '<html lang="en">', '<head>', '<meta charset="utf-8">', '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; img-src data:">',
    `<title>${escapeHtml(title)}</title>`, `<style>${CSS}</style>`, '</head>', '<body>', '<main>');
  H.push(`<h1>${escapeHtml(title)}</h1>`);
  H.push(`<p class="muted">Scanned ${escapeHtml(fmtDate(s.startedAt))}${s.finishedAt ? ` → ${escapeHtml(fmtDate(s.finishedAt))}` : ''}${s.verification ? ` · ownership verified via ${escapeHtml(s.verification.method)} on ${escapeHtml(fmtDate(s.verification.verifiedAt))}` : ''}</p>`);
  H.push('<div class="tiles">');
  H.push(`<div class="tile"><b>${s.total}</b>finding${s.total === 1 ? '' : 's'}</div>`);
  for (const sev of SEVERITIES) if (s.bySeverity[sev]) H.push(`<div class="tile"><b>${s.bySeverity[sev]}</b>${sevBadge(sev)}</div>`);
  if (s.pages != null) H.push(`<div class="tile"><b>${s.pages}</b>page${s.pages === 1 ? '' : 's'} crawled</div>`);
  if (s.protocolServices.length) H.push(`<div class="tile"><b>${s.protocolServices.length}</b>service${s.protocolServices.length === 1 ? '' : 's'} checked</div>`);
  H.push('</div>');
  H.push('<table>');
  H.push(`<tr><th>Target</th><td>${escapeHtml(s.origin || '—')}</td></tr>`);
  if (s.stack) H.push(`<tr><th>Stack</th><td>${escapeHtml(s.stack)}</td></tr>`);
  if (s.requests != null) H.push(`<tr><th>Requests</th><td>${escapeHtml(s.requests)}</td></tr>`);
  if (s.protocolServices.length) H.push(`<tr><th>Services</th><td>${escapeHtml(s.protocolServices.join(', '))}</td></tr>`);
  if (s.activeScan) H.push(`<tr><th>Active scan</th><td>profile ${escapeHtml(s.activeScan.profile)}, ${escapeHtml(s.activeScan.requests ?? '?')} probe(s) across ${escapeHtml(s.activeScan.targetsProbed ?? '?')} URL(s)</td></tr>`);
  if (s.fixFiles.length && includeFixes) H.push(`<tr><th>Fix artifacts</th><td>${escapeHtml(s.fixFiles.join(', '))}</td></tr>`);
  H.push('</table>');

  if (includeAnalysis && report.analysis?.providers?.length) {
    H.push('<h2>AI review</h2>', '<ul>');
    for (const p of report.analysis.providers) H.push(`<li><b>${escapeHtml(p.label || p.providerId)}</b>: ${p.ok ? 'reviewed' : `failed (${escapeHtml(p.error || 'unknown error')})`}${p.ok && p.parsed?.summary ? ` — ${escapeHtml(p.parsed.summary)}` : ''}</li>`);
    H.push('</ul>');
    const v = s.analysis.verdicts;
    H.push(`<p>Consensus across providers: ${v.real} real, ${v['false-positive']} likely false positive, ${v.split} split, ${v.unreviewed} unreviewed.</p>`);
  }

  if (diff) {
    H.push('<h2>Changes since previous scan</h2>', '<div class="diff">');
    H.push(`<p class="muted">Previous: ${escapeHtml(fmtDate(diff.before.startedAt))} (${diff.before.total} findings) → this scan (${diff.after.total}).${diff.sameOrigin ? '' : ' <b>Different origins — compare with care.</b>'}</p>`);
    H.push('<div class="tiles">', `<div class="tile"><b>${diff.summary.new}</b>new</div>`, `<div class="tile"><b>${diff.summary.resolved}</b>resolved</div>`, `<div class="tile"><b>${diff.summary.changed}</b>changed</div>`, `<div class="tile"><b>${diff.summary.unchanged}</b>unchanged</div>`, '</div>');
    const list = (t, arr, fmt) => { if (!arr.length) return; H.push(`<h3>${t}</h3>`, '<ul>'); for (const x of arr) H.push(`<li>${fmt(x)}</li>`); H.push('</ul>'); };
    list('New', diff.new, (f) => `${sevBadge(f.severity)} <a href="#${escapeHtml(f.id)}">${escapeHtml(f.title)}</a> <span class="muted">${escapeHtml(f.location)}</span>`);
    list('Resolved', diff.resolved, (f) => `<span class="del">${escapeHtml(f.title)}</span> <span class="muted">${escapeHtml(f.location)}</span>`);
    list('Changed', diff.changed, (c) => `<a href="#${escapeHtml(c.after.id)}">${escapeHtml(c.after.title)}</a> — ${escapeHtml(c.what.map((w) => w === 'pages' ? `pages ${c.before.evidence?.affectedPages || 1} → ${c.after.evidence?.affectedPages || 1}` : `${w} ${c.before[w]} → ${c.after[w]}`).join('; '))}`);
    H.push('</div>');
  }

  H.push('<h2>Findings</h2>');
  if (!findings.length) H.push('<p>No findings.</p>');
  else {
    H.push('<table>', '<tr><th>#</th><th>Severity</th><th>Confidence</th><th>Finding</th><th>Where</th></tr>');
    for (const f of findings) H.push(`<tr><td><a href="#${escapeHtml(f.id)}">${escapeHtml(f.id)}</a></td><td>${sevBadge(f.severity)}</td><td>${escapeHtml(f.confidence)}</td><td>${escapeHtml(f.title)}</td><td class="muted">${escapeHtml(f.location)}${f.evidence?.affectedPages > 1 ? ` (+${f.evidence.affectedPages - 1})` : ''}</td></tr>`);
    H.push('</table>');
    for (const f of findings) {
      H.push(`<section class="finding" id="${escapeHtml(f.id)}">`);
      H.push(`<h3>${escapeHtml(f.id)} · ${escapeHtml(f.title)}</h3>`);
      const cons = report.analysis?.consensus?.[f.id];
      H.push(`<div class="meta">${sevBadge(f.severity)} confidence ${escapeHtml(f.confidence)} · <code>${escapeHtml(f.checkId)}</code>${f.cwe ? ` · ${escapeHtml(f.cwe)}` : ''}${f.owasp ? ` · ${escapeHtml(f.owasp)}` : ''}<br>${escapeHtml(f.location)}${includeAnalysis && cons && cons.verdict !== 'unreviewed' ? `<br>AI consensus: ${escapeHtml(cons.verdict)} (${cons.reviewers} reviewer(s)${cons.meanAttackerPriority != null ? `, attacker priority ≈ ${cons.meanAttackerPriority.toFixed(1)}` : ''})` : ''}</div>`);
      if (includeEvidence) {
        const { lines, rest } = evidenceLines(f);
        for (const l of lines) H.push(`<blockquote>${escapeHtml(l)}</blockquote>`);
        if (rest) H.push(`<details><summary>Evidence detail</summary><pre>${escapeHtml(pretty(rest))}</pre></details>`);
      }
      H.push(`<div class="fix"><b>Fix</b>${escapeHtml(f.remediation || '—').replace(/\n/g, '<br>')}</div>`);
      H.push('</section>');
    }
  }

  if (includeFixes && report.fixes?.files?.length) {
    H.push('<h2>Generated fix artifacts</h2>', `<p class="muted">Target: ${escapeHtml(report.fixes.target)}. Review before deploying; nothing was applied.</p>`);
    for (const file of report.fixes.files) H.push(`<details><summary><code>${escapeHtml(file.filename)}</code> <span class="muted">(${escapeHtml(file.kind)}${file.target && file.target !== report.fixes.target ? `, ${escapeHtml(file.target)}` : ''})</span></summary><pre>${escapeHtml(file.contents)}</pre></details>`);
    if (report.fixes.notes?.length) { H.push('<ul>'); for (const n of report.fixes.notes) H.push(`<li class="muted">${escapeHtml(n)}</li>`); H.push('</ul>'); }
  }

  if (report.protocols?.services?.length) {
    H.push('<h2>Services checked</h2>', '<table>', '<tr><th>Service</th><th>Port</th><th>Present</th><th>Notes</th></tr>');
    for (const sv of report.protocols.services) H.push(`<tr><td>${escapeHtml(sv.service)}</td><td>${escapeHtml(sv.port)}</td><td>${sv.present ? 'yes' : 'no'}</td><td class="muted">${escapeHtml(sv.error || sv.banner || '')}</td></tr>`);
    H.push('</table>');
  }

  H.push(`<p class="muted" style="margin-top:32px">Generated by Anne\'s Test${s.finishedAt ? ` from a scan finished ${escapeHtml(fmtDate(s.finishedAt))}` : ''}. Detection was non-destructive and ran only against an origin whose ownership was verified. Versions read from banners may lag distribution backports; confirm before acting.</p>`);
  H.push('</main>', '</body>', '</html>');
  return H.join('\n') + '\n';
}

// ---------------------------------------------------------------------------
// Review package
// ---------------------------------------------------------------------------

export const sha256 = (s) => createHash('sha256').update(s).digest('hex');

/**
 * Everything a reviewer needs in one directory: the raw report, HTML, Markdown
 * and CSV renderings, the fix artifacts (from report.fixes, or supplied), a
 * manifest with a SHA-256 per file, and a README. Returned as in-memory files;
 * the CLI writes them.
 * @param {object} report
 * @param {{diff?:object, fixes?:{files:object[]}, previousReport?:object, now?:Date}} [opts]
 */
export function buildReviewPackage(report, opts = {}) {
  const now = opts.now || new Date();
  const fixes = opts.fixes || report.fixes || null;
  const diff = opts.diff || null;
  const files = [];
  files.push({ filename: 'report.json', contents: JSON.stringify(report, null, 2) + '\n' });
  files.push({ filename: 'report.html', contents: renderHtml(report, { diff }) });
  files.push({ filename: 'report.md', contents: renderMarkdown(report, { diff }) });
  files.push({ filename: 'findings.csv', contents: renderCsv(report) });
  if (diff) files.push({ filename: 'diff.json', contents: JSON.stringify(diff, null, 2) + '\n' });
  if (opts.previousReport) files.push({ filename: 'previous-report.json', contents: JSON.stringify(opts.previousReport, null, 2) + '\n' });
  // Fix file names come from the report (which may have been produced elsewhere): keep them to a
  // plain basename so a crafted report cannot write outside the package directory.
  for (const f of fixes?.files || []) files.push({ filename: `fixes/${safeArtifactName(f.filename)}`, contents: f.contents });
  if (fixes) files.push({ filename: 'fixes/fixes.json', contents: JSON.stringify(fixes, null, 2) + '\n' });

  const s = summarize(report);
  const readme = [
    `Anne\'s Test review package — ${s.origin || 'scan'}`,
    `Generated ${now.toISOString()} from a scan started ${s.startedAt || '?'}.`,
    '',
    'Contents:',
    '  report.html        human-readable report (self-contained; open in a browser, print to PDF)',
    '  report.md          same content as Markdown (tickets, wikis, pull requests)',
    '  findings.csv       one row per finding',
    '  report.json        the raw scan report (source of truth)',
    ...(diff ? ['  diff.json          findings diff against the previous scan'] : []),
    ...(opts.previousReport ? ['  previous-report.json  the previous scan this package was diffed against'] : []),
    ...(fixes?.files?.length ? ['  fixes/             generated configuration and dependency artifacts — review, then deploy yourself'] : []),
    '  manifest.json      SHA-256 of every file above, for integrity checks',
    '',
    `Findings: ${s.total}${s.total ? ` (${SEVERITIES.filter((x) => s.bySeverity[x]).map((x) => `${s.bySeverity[x]} ${x}`).join(', ')})` : ''}.`,
    'Scope: passive, non-destructive checks against an origin whose ownership was verified. Nothing was exploited or modified.',
    '',
  ].join('\n');
  files.push({ filename: 'README.txt', contents: readme });

  const manifest = {
    tool: 'Anne\'s Test', generatedAt: now.toISOString(), origin: s.origin, scanStartedAt: s.startedAt, findings: s.total,
    files: files.map((f) => ({ path: f.filename, bytes: Buffer.byteLength(f.contents), sha256: sha256(f.contents) })),
  };
  files.push({ filename: 'manifest.json', contents: JSON.stringify(manifest, null, 2) + '\n' });
  return { files, manifest };
}

/**
 * A file name an artifact may be written under: one path segment, no traversal, not hidden.
 * Throws on anything else so a crafted report cannot direct writes outside the output directory.
 */
export function safeArtifactName(name) {
  const s = String(name ?? '');
  if (!s || s !== s.replace(/[\\/]/g, '') || s === '.' || s === '..' || s.startsWith('.') || /[\0]/.test(s)) throw new Error(`Refusing unsafe artifact file name: ${JSON.stringify(s)}`);
  return s;
}

/** A manifest entry path is relative, uses forward slashes, and never leaves the package directory. */
export function isSafePackagePath(p) {
  const s = String(p ?? '');
  if (!s || s.startsWith('/') || /^[a-zA-Z]:/.test(s) || s.includes('\\') || /[\0]/.test(s)) return false;
  return s.split('/').every((seg) => seg && seg !== '.' && seg !== '..');
}

/** Verify a package directory's files against its manifest. Pure; the caller supplies file contents. */
export function verifyManifest(manifest, readFile) {
  const results = [];
  for (const entry of manifest.files || []) {
    let ok = false, reason = null;
    if (!isSafePackagePath(entry.path)) { results.push({ path: String(entry.path), ok: false, reason: 'unsafe path in manifest' }); continue; }
    try { const c = readFile(entry.path); ok = c != null && sha256(c) === entry.sha256; if (!ok) reason = c == null ? 'missing' : 'hash mismatch'; } catch (e) { reason = e.message; }
    results.push({ path: entry.path, ok, reason });
  }
  return { ok: results.every((r) => r.ok), results };
}
