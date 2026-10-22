/** Checks tab — the check registry is data (docs/CHECKS.md); these commands manage it. Engine: M2/M3. */
import { def } from './registry.mjs';

def([
  { id: 'checks.list', label: 'All Checks', icon: 'checklist', tab: 'Checks', group: 'Checks', noRecord: true, popular: true },
  { id: 'checks.details', label: 'Check Details', icon: 'info', tab: 'Checks', group: 'Checks', noRecord: true, tip: 'What it detects, how, intrusiveness, CWE/OWASP mapping, remediation' },
  { id: 'checks.enable', label: 'Enable Check', icon: 'check_box', tab: 'Checks', group: 'Checks' },
  { id: 'checks.disable', label: 'Disable Check', icon: 'check_box_outline_blank', tab: 'Checks', group: 'Checks' },
  { id: 'checks.enableCategory', label: 'Enable Category', icon: 'library_add_check', tab: 'Checks', group: 'Categories' },
  { id: 'checks.disableCategory', label: 'Disable Category', icon: 'remove_done', tab: 'Checks', group: 'Categories' },
  { id: 'checks.passiveOnly', label: 'Passive Checks Only', icon: 'visibility', tab: 'Checks', group: 'Categories', kind: 'toggle' },
  { id: 'checks.byOwasp', label: 'Group by OWASP Top 10', icon: 'category', tab: 'Checks', group: 'View', kind: 'toggle', noRecord: true },
  { id: 'checks.byCwe', label: 'Group by CWE', icon: 'account_tree', tab: 'Checks', group: 'View', kind: 'toggle', noRecord: true },
  { id: 'checks.byAsvs', label: 'Group by ASVS', icon: 'segment', tab: 'Checks', group: 'View', kind: 'toggle', noRecord: true },
  { id: 'checks.search', label: 'Search Checks', icon: 'search', tab: 'Checks', group: 'View', noRecord: true },
  { id: 'checks.custom', label: 'New Custom Check…', icon: 'add_box', tab: 'Checks', group: 'Custom', tip: 'Pattern/response-based detection check; no payload fields by design' },
  { id: 'checks.import', label: 'Import Checks…', icon: 'upload_file', tab: 'Checks', group: 'Custom' },
  { id: 'checks.export', label: 'Export Checks…', icon: 'download', tab: 'Checks', group: 'Custom' },
  { id: 'checks.update', label: 'Update Check Signatures', icon: 'system_update_alt', tab: 'Checks', group: 'Custom', tip: 'Component fingerprints and known-vulnerable version data' },
]);
