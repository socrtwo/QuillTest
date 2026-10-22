/*
 * QuillTest — default tab and group arrangement
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Groups reference command ids only, so users can rebuild any of it with
 * Customize Tabs. Tab order follows the README: File, Verify, Scan, Targets,
 * Checks, Findings, Fix, AI, Report, Review, Share, Help (View and Developer
 * are reachable from the tab list but not shown by default, as in QuillStage).
 * File is the Backstage screen, not a ribbon tab.
 */

/** @typedef {{id:string, label:string, items:string[], launcher?:string}} RibbonGroup */
/** @typedef {{id:string, label:string, groups:RibbonGroup[], hidden?:boolean}} RibbonTab */

/** @type {RibbonTab[]} */
export const DEFAULT_TABS = [
  {
    id: 'verify', label: 'Verify', groups: [
      { id: 'challenge', label: 'Challenge', items: ['verify.issue', 'verify.writeFile', 'verify.check', 'verify.checkDns'] },
      { id: 'status', label: 'Status', items: ['verify.status', 'verify.list', 'verify.reverify'] },
      { id: 'manage', label: 'Manage', items: ['verify.cancel', 'verify.revoke'] },
      { id: 'help', label: 'Help', items: ['verify.help', 'help.ethics'] },
    ],
  },
  {
    id: 'scan', label: 'Scan', groups: [
      { id: 'run', label: 'Run', items: ['scan.start', 'scan.passive', 'scan.active', 'scan.quick', 'scan.single'] },
      { id: 'control', label: 'Control', items: ['scan.pause', 'scan.resume', 'scan.stop'] },
      { id: 'profile', label: 'Profile', items: ['scan.profile', 'scan.intrusiveness', 'scan.preview'], launcher: 'scan.profiles' },
      { id: 'crawl', label: 'Crawl', items: ['scan.crawlDepth', 'scan.sitemap', 'scan.spiderOnly', 'scan.importUrls'], launcher: 'scan.crawlLimits' },
      { id: 'history', label: 'History', items: ['scan.history', 'scan.rescan', 'scan.diff', 'scan.log', 'scan.schedule'] },
    ],
  },
  {
    id: 'targets', label: 'Targets', groups: [
      { id: 'targets', label: 'Targets', items: ['target.add', 'target.select', 'target.edit', 'target.remove', 'target.list', 'target.status'] },
      { id: 'authorization', label: 'Authorization', items: ['target.confirmAuthorization', 'target.revokeAuthorization'] },
      { id: 'scope', label: 'Scope', items: ['target.scope', 'target.inScope'] },
      { id: 'authentication', label: 'Authentication', items: ['target.credentials', 'target.sessionRecord', 'target.headers'] },
      { id: 'politeness', label: 'Politeness', items: ['target.rateLimit', 'target.robots'] },
      { id: 'exchange', label: 'Exchange', items: ['target.import', 'target.export', 'target.open'] },
    ],
  },
  {
    id: 'checks', label: 'Checks', groups: [
      { id: 'checks', label: 'Checks', items: ['checks.list', 'checks.details', 'checks.enable', 'checks.disable'] },
      { id: 'categories', label: 'Categories', items: ['checks.enableCategory', 'checks.disableCategory', 'checks.passiveOnly'] },
      { id: 'view', label: 'View', items: ['checks.categories', 'checks.byOwasp', 'checks.byCwe', 'checks.byAsvs', 'checks.search'] },
      { id: 'custom', label: 'Custom', items: ['checks.custom', 'checks.import', 'checks.export', 'checks.update'] },
    ],
  },
  {
    id: 'findings', label: 'Findings', groups: [
      { id: 'browse', label: 'Browse', items: ['findings.list', 'findings.details', 'findings.prev', 'findings.next', 'findings.search'] },
      { id: 'organize', label: 'Organize', items: ['findings.filter', 'findings.sort', 'findings.group', 'findings.dedupe', 'findings.prioritize'] },
      { id: 'triage', label: 'Triage', items: ['findings.setSeverity', 'findings.setConfidence', 'findings.markFalsePositive', 'findings.markFixed', 'findings.markAccepted', 'findings.reopen', 'findings.recheck'], launcher: 'findings.falsePositives' },
      { id: 'annotate', label: 'Annotate', items: ['findings.note', 'findings.tag', 'findings.assign'] },
      { id: 'exchange', label: 'Exchange', items: ['findings.copy', 'findings.export', 'findings.import'] },
    ],
  },
  {
    id: 'fix', label: 'Fix', groups: [
      { id: 'remediate', label: 'Remediate', items: ['fix.generate', 'fix.generateAll', 'fix.preview', 'fix.explain', 'fix.copySnippet', 'fix.downloadPatch'] },
      { id: 'platform', label: 'Platform', items: ['fix.targetPlatform'] },
      { id: 'generators', label: 'Generators', items: ['fix.headersNginx', 'fix.headersApache', 'fix.headersCaddy', 'fix.headersIis', 'fix.headersMiddleware', 'fix.csp', 'fix.cookies', 'fix.cors', 'fix.tls', 'fix.redirects', 'fix.dependencyBump', 'fix.hideVersions'] },
      { id: 'track', label: 'Track', items: ['fix.plan', 'fix.markApplied', 'fix.recheck'] },
    ],
  },
  {
    id: 'ai', label: 'AI', groups: [
      { id: 'setup', label: 'Setup', items: ['ai.setup', 'ai.active', 'ai.providers', 'ai.test', 'ai.privacy', 'ai.dryRun', 'ai.stop'], launcher: 'ai.prompts' },
      { id: 'analyze', label: 'Analyze', items: ['ai.triage', 'ai.prioritize', 'ai.explain', 'ai.falsePositives', 'ai.mapCwe', 'ai.askAboutFinding'] },
      { id: 'fix', label: 'Fix', items: ['ai.draftFix', 'ai.refineFix'] },
      { id: 'report', label: 'Report', items: ['ai.summary'] },
      { id: 'several', label: 'Several AIs', items: ['ai.ensembleMode', 'ai.ensembleMembers', 'ai.showDeliberation'] },
    ],
  },
  {
    id: 'report', label: 'Report', groups: [
      { id: 'build', label: 'Build', items: ['report.generate', 'report.executiveSummary', 'report.technical', 'report.remediationPlan', 'report.preview'] },
      { id: 'style', label: 'Style', items: ['report.template', 'report.branding', 'report.sections', 'report.redact'] },
      { id: 'export', label: 'Export', items: ['report.exportPdf', 'report.exportHtml', 'report.exportMarkdown', 'report.exportJson', 'report.exportSarif', 'report.exportCsv', 'report.print', 'report.schedule'] },
      { id: 'compare', label: 'Compare', items: ['report.compare', 'report.trend'] },
    ],
  },
  {
    id: 'review', label: 'Review', groups: [
      { id: 'review', label: 'Review', items: ['review.queue', 'review.approve', 'review.reject', 'review.needsInfo'] },
      { id: 'comments', label: 'Comments', items: ['review.comment', 'review.resolveComment', 'review.comments'] },
      { id: 'workflow', label: 'Workflow', items: ['review.assign', 'review.signoff'] },
      { id: 'audit', label: 'Audit', items: ['review.history', 'review.auditLog', 'review.compareFindings', 'review.checkReport'] },
    ],
  },
  {
    id: 'share', label: 'Share', groups: [
      { id: 'package', label: 'Package', items: ['share.package', 'share.bundle', 'share.redactedCopy'] },
      { id: 'send', label: 'Send', items: ['share.email', 'share.system', 'share.copyLink'] },
      { id: 'integrate', label: 'Integrate', items: ['share.issueTracker', 'share.webhook', 'share.ci'] },
    ],
  },
  {
    id: 'view', label: 'View', hidden: true, groups: [
      { id: 'find', label: 'Find', items: ['view.cmdSearch'] },
      { id: 'views', label: 'Views', items: ['view.dashboard'] },
      { id: 'panes', label: 'Panes', items: ['view.targetsPane', 'view.findingsPane', 'view.detailsPane', 'view.logPane', 'view.requestViewer', 'view.sitemap'] },
      { id: 'zoom', label: 'Zoom', items: ['view.zoomIn', 'view.zoomOut', 'view.zoomReset'] },
      { id: 'appearance', label: 'Appearance', items: ['view.theme', 'view.touchMode'] },
      { id: 'window', label: 'Window', items: ['view.fullScreen', 'view.statusBar'] },
      { id: 'customize', label: 'Customize', items: ['view.qatAddAll', 'view.qatPosition', 'file.customizeQat', 'file.customizeRibbon', 'file.customizeKeyboard'] },
    ],
  },
  {
    id: 'developer', label: 'Developer', hidden: true, groups: [
      { id: 'macros', label: 'Macros', items: ['dev.recordMacro', 'dev.stopRecording', 'dev.runMacro', 'dev.macros'] },
      { id: 'scripting', label: 'Scripting', items: ['dev.console', 'dev.scripts', 'dev.api'] },
      { id: 'diagnostics', label: 'Diagnostics', items: ['dev.diagnostics', 'dev.logs', 'dev.resetState'] },
    ],
  },
  {
    id: 'help', label: 'Help', groups: [
      { id: 'help', label: 'Help', items: ['help.help', 'help.shortcuts', 'help.commandReference', 'help.tour', 'help.whatsNew', 'help.feedback', 'help.updates'] },
      { id: 'policy', label: 'Policy', items: ['help.ethics', 'help.legal', 'help.verification'] },
      { id: 'about', label: 'About', items: ['help.notices', 'help.about'] },
    ],
  },
];

/** Backstage (File screen) sections; also id-only. */
export const BACKSTAGE_SECTIONS = [
  { id: 'new', label: 'New', items: ['file.new'] },
  { id: 'open', label: 'Open', items: ['file.open', 'file.openRecent', 'file.clearRecent'] },
  { id: 'save', label: 'Save', items: ['file.save', 'file.saveAs', 'file.autosave'] },
  { id: 'info', label: 'Info', items: ['file.properties', 'file.encrypt'] },
  { id: 'import', label: 'Import', items: ['file.import.targets', 'file.import.findings', 'file.import.urls'] },
  { id: 'export', label: 'Export', items: ['file.export.json', 'file.export.sarif', 'file.export.csv', 'file.export.pdf', 'file.export.html', 'file.export.markdown'] },
  { id: 'print', label: 'Print', items: ['file.print'] },
  { id: 'share', label: 'Share', items: ['file.share'] },
  { id: 'options', label: 'Options', items: ['file.options', 'file.customizeQat', 'file.customizeRibbon', 'file.customizeKeyboard', 'file.exportSettings', 'file.resetCustomizations'] },
  { id: 'close', label: 'Close', items: ['file.close', 'file.exit'] },
];

/** Default Quick Access Bar. */
export const DEFAULT_QAT = ['file.save', 'verify.status', 'scan.start', 'scan.stop', 'findings.list', 'fix.generate', 'view.cmdSearch'];

/** Every command id placed somewhere by default. */
export function placedIds() {
  const ids = new Set();
  for (const t of DEFAULT_TABS) for (const g of t.groups) { for (const id of g.items) ids.add(id); if (g.launcher) ids.add(g.launcher); }
  for (const s of BACKSTAGE_SECTIONS) for (const id of s.items) ids.add(id);
  return ids;
}
