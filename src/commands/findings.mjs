/** Findings tab — normalized, CWE/OWASP-mapped findings (src/findings/, M2). */
import { def } from './registry.mjs';

def([
  { id: 'findings.list', label: 'Findings', icon: 'bug_report', tab: 'Findings', group: 'Browse', noRecord: true, popular: true, keys: ['Ctrl+Shift+F'] },
  { id: 'findings.details', label: 'Finding Details', icon: 'article', tab: 'Findings', group: 'Browse', noRecord: true, tip: 'Evidence, request/response excerpt, mapping, remediation' },
  { id: 'findings.next', label: 'Next Finding', icon: 'arrow_downward', tab: 'Findings', group: 'Browse', keys: ['F8'], noRecord: true },
  { id: 'findings.prev', label: 'Previous Finding', icon: 'arrow_upward', tab: 'Findings', group: 'Browse', keys: ['Shift+F8'], noRecord: true },
  { id: 'findings.search', label: 'Search Findings', icon: 'search', tab: 'Findings', group: 'Browse', noRecord: true },
  { id: 'findings.filter', label: 'Filter', icon: 'filter_list', tab: 'Findings', group: 'Organize', kind: 'menu', noRecord: true, tip: 'By severity, confidence, category, status, URL' },
  { id: 'findings.sort', label: 'Sort', icon: 'sort', tab: 'Findings', group: 'Organize', kind: 'menu', noRecord: true },
  { id: 'findings.group', label: 'Group By', icon: 'workspaces', tab: 'Findings', group: 'Organize', kind: 'menu', noRecord: true, tip: 'Severity, OWASP category, CWE, URL, check' },
  { id: 'findings.dedupe', label: 'Merge Duplicates', icon: 'merge', tab: 'Findings', group: 'Organize' },
  { id: 'findings.prioritize', label: "Attacker's-Eye Priority", icon: 'crisis_alert', tab: 'Findings', group: 'Organize', tip: 'Order by what an attacker would exploit first (deterministic; AI can refine)', origin: 'INNOVATIONS.md' },
  { id: 'findings.setSeverity', label: 'Set Severity', icon: 'priority_high', tab: 'Findings', group: 'Triage', kind: 'menu' },
  { id: 'findings.setConfidence', label: 'Set Confidence', icon: 'percent', tab: 'Findings', group: 'Triage', kind: 'menu' },
  { id: 'findings.markFalsePositive', label: 'Mark False Positive', icon: 'block', tab: 'Findings', group: 'Triage', popular: true, tip: 'Remembered for future scans of this target', origin: 'false-positive learning loop — INNOVATIONS.md' },
  { id: 'findings.unmarkFalsePositive', label: 'Unmark False Positive', icon: 'undo', tab: 'Findings', group: 'Triage' },
  { id: 'findings.markFixed', label: 'Mark Fixed', icon: 'task_alt', tab: 'Findings', group: 'Triage' },
  { id: 'findings.markAccepted', label: 'Accept Risk…', icon: 'thumb_up', tab: 'Findings', group: 'Triage', tip: 'Record a reason; shown in the report' },
  { id: 'findings.recheck', label: 'Re-check Finding', icon: 'published_with_changes', tab: 'Findings', group: 'Triage', requiresTarget: true, requiresVerification: true, tip: 'Run just this check again to confirm a fix' },
  { id: 'findings.note', label: 'Add Note', icon: 'note_add', tab: 'Findings', group: 'Annotate' },
  { id: 'findings.tag', label: 'Tag', icon: 'label', tab: 'Findings', group: 'Annotate' },
  { id: 'findings.assign', label: 'Assign To…', icon: 'person_add', tab: 'Findings', group: 'Annotate' },
  { id: 'findings.copy', label: 'Copy Finding', icon: 'content_copy', tab: 'Findings', group: 'Exchange', noRecord: true, tip: 'Markdown summary to the clipboard' },
  { id: 'findings.export', label: 'Export Findings…', icon: 'download', tab: 'Findings', group: 'Exchange', tip: 'JSON, CSV, SARIF' },
  { id: 'findings.import', label: 'Import Findings…', icon: 'upload_file', tab: 'Findings', group: 'Exchange', tip: 'From a previous QuillTest export, for comparison' },
  { id: 'findings.falsePositives', label: 'False-Positive Rules', icon: 'rule_folder', tab: 'Findings', group: 'Triage', noRecord: true, tip: 'Signatures remembered for this target' },
]);
