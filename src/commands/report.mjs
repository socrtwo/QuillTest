/** Report tab — reports, exports, review packages (src/report/, M6). */
import { def } from './registry.mjs';

def([
  { id: 'report.generate', label: 'Generate Report', icon: 'summarize', tab: 'Report', group: 'Build', popular: true, keys: ['Ctrl+Shift+R'], tip: 'Includes the verification record and your authorization statement for each target' },
  { id: 'report.executiveSummary', label: 'Executive Summary', icon: 'business_center', tab: 'Report', group: 'Build' },
  { id: 'report.technical', label: 'Technical Report', icon: 'engineering', tab: 'Report', group: 'Build' },
  { id: 'report.remediationPlan', label: 'Remediation Plan', icon: 'checklist_rtl', tab: 'Report', group: 'Build' },
  { id: 'report.preview', label: 'Preview', icon: 'preview', tab: 'Report', group: 'Build', noRecord: true },
  { id: 'report.template', label: 'Template', icon: 'dashboard_customize', tab: 'Report', group: 'Style', kind: 'gallery' },
  { id: 'report.branding', label: 'Branding…', icon: 'palette', tab: 'Report', group: 'Style', tip: 'Logo, colors, footer, classification label' },
  { id: 'report.sections', label: 'Sections…', icon: 'view_list', tab: 'Report', group: 'Style' },
  { id: 'report.redact', label: 'Redact Sensitive Values', icon: 'visibility_off', tab: 'Report', group: 'Style', kind: 'toggle', tip: 'Cookies, tokens and credentials in evidence excerpts' },
  { id: 'report.exportPdf', label: 'Export PDF', icon: 'picture_as_pdf', tab: 'Report', group: 'Export' },
  { id: 'report.exportHtml', label: 'Export HTML', icon: 'html', tab: 'Report', group: 'Export' },
  { id: 'report.exportMarkdown', label: 'Export Markdown', icon: 'description', tab: 'Report', group: 'Export' },
  { id: 'report.exportJson', label: 'Export JSON', icon: 'data_object', tab: 'Report', group: 'Export' },
  { id: 'report.exportSarif', label: 'Export SARIF', icon: 'download', tab: 'Report', group: 'Export' },
  { id: 'report.exportCsv', label: 'Export CSV', icon: 'table_view', tab: 'Report', group: 'Export' },
  { id: 'report.compare', label: 'Compare Two Scans', icon: 'compare', tab: 'Report', group: 'Compare', tip: 'New, fixed and persisting findings between scans' },
  { id: 'report.trend', label: 'Trend Over Time', icon: 'trending_down', tab: 'Report', group: 'Compare' },
  { id: 'report.schedule', label: 'Scheduled Reports…', icon: 'schedule_send', tab: 'Report', group: 'Export' },
  { id: 'report.print', label: 'Print', icon: 'print', tab: 'Report', group: 'Export', keys: ['Ctrl+P'] },
]);
