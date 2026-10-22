/** View — panes, zoom, theme, command search. */
import { def, searchCommands } from './registry.mjs';

def([
  {
    id: 'view.cmdSearch', label: 'Command Search', icon: 'search', tab: 'View', group: 'Find', keys: ['Alt+Q'], popular: true, noRecord: true,
    tip: 'Find any command by name',
    run: (_ctx, arg) => searchCommands(typeof arg === 'string' ? arg : arg?.query || '', arg?.limit).map((c) => ({ id: c.id, label: c.label, tab: c.tab, group: c.group, keys: c.keys || [], implemented: typeof c.run === 'function' })),
  },
  { id: 'view.targetsPane', label: 'Targets Pane', icon: 'dns', tab: 'View', group: 'Panes', kind: 'toggle', noRecord: true },
  { id: 'view.findingsPane', label: 'Findings Pane', icon: 'bug_report', tab: 'View', group: 'Panes', kind: 'toggle', noRecord: true },
  { id: 'view.detailsPane', label: 'Details Pane', icon: 'article', tab: 'View', group: 'Panes', kind: 'toggle', noRecord: true },
  { id: 'view.logPane', label: 'Log Pane', icon: 'terminal', tab: 'View', group: 'Panes', kind: 'toggle', noRecord: true },
  { id: 'view.requestViewer', label: 'Request / Response Viewer', icon: 'swap_vert', tab: 'View', group: 'Panes', kind: 'toggle', noRecord: true },
  { id: 'view.sitemap', label: 'Site Map', icon: 'account_tree', tab: 'View', group: 'Panes', kind: 'toggle', noRecord: true, origin: 'inspired by ZAP Sites tree and Burp Target site map' },
  { id: 'view.dashboard', label: 'Dashboard', icon: 'dashboard', tab: 'View', group: 'Views', noRecord: true, tip: 'Severity counts, scan status, verification expiry' },
  { id: 'view.zoomIn', label: 'Zoom In', icon: 'zoom_in', tab: 'View', group: 'Zoom', keys: ['Ctrl+='], noRecord: true },
  { id: 'view.zoomOut', label: 'Zoom Out', icon: 'zoom_out', tab: 'View', group: 'Zoom', keys: ['Ctrl+-'], noRecord: true },
  { id: 'view.zoomReset', label: 'Reset Zoom', icon: 'youtube_searched_for', tab: 'View', group: 'Zoom', keys: ['Ctrl+0'], noRecord: true },
  { id: 'view.theme', label: 'Theme', icon: 'dark_mode', tab: 'View', group: 'Appearance', kind: 'menu', noRecord: true, tip: 'Light, dark, system, high contrast' },
  { id: 'view.touchMode', label: 'Touch Mode', icon: 'touch_app', tab: 'View', group: 'Appearance', kind: 'toggle', noRecord: true },
  { id: 'view.fullScreen', label: 'Full Screen', icon: 'fullscreen', tab: 'View', group: 'Window', keys: ['F11'], noRecord: true },
  { id: 'view.statusBar', label: 'Status Bar', icon: 'horizontal_rule', tab: 'View', group: 'Window', kind: 'toggle', noRecord: true },
  { id: 'view.qatAddAll', label: 'Add All Commands to Quick Access Bar', icon: 'playlist_add', tab: 'View', group: 'Customize', noRecord: true },
  { id: 'view.qatPosition', label: 'Quick Access Bar Position', icon: 'swap_vert', tab: 'View', group: 'Customize', kind: 'menu', noRecord: true },
]);
