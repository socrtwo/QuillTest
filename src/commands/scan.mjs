/** Scan tab — every command here sends requests to the target, so every one is gated. Engine: M2/M3. */
import { def } from './registry.mjs';

const gated = { requiresTarget: true, requiresVerification: true };

def([
  { id: 'scan.start', label: 'Start Scan', icon: 'play_arrow', tab: 'Scan', group: 'Run', keys: ['F5'], popular: true, ...gated, tip: 'Run the active profile against the active target' },
  { id: 'scan.passive', label: 'Passive Scan', icon: 'visibility', tab: 'Scan', group: 'Run', ...gated, tip: 'Crawl and observe only: headers, cookies, TLS, disclosure. No test inputs are sent.' },
  { id: 'scan.active', label: 'Active Scan', icon: 'bolt', tab: 'Scan', group: 'Run', ...gated, tip: 'Detection probes for injection, XSS, access control… least-intrusive probe that proves a finding, then stop' },
  { id: 'scan.quick', label: 'Quick Scan', icon: 'timer', tab: 'Scan', group: 'Run', ...gated, tip: 'Passive checks plus the fastest active ones on the entry page' },
  { id: 'scan.single', label: 'Scan Single URL', icon: 'link', tab: 'Scan', group: 'Run', ...gated },
  { id: 'scan.pause', label: 'Pause', icon: 'pause', tab: 'Scan', group: 'Control', requiresTarget: true, noRecord: true },
  { id: 'scan.resume', label: 'Resume', icon: 'resume', tab: 'Scan', group: 'Control', ...gated, noRecord: true },
  { id: 'scan.stop', label: 'Stop', icon: 'stop', tab: 'Scan', group: 'Control', keys: ['Shift+F5'], requiresTarget: true, noRecord: true },
  { id: 'scan.profile', label: 'Scan Profile', icon: 'tune', tab: 'Scan', group: 'Profile', kind: 'menu', requiresTarget: true, tip: 'Passive / Standard / Thorough / Custom' },
  { id: 'scan.profiles', label: 'Manage Profiles…', icon: 'settings_suggest', tab: 'Scan', group: 'Profile' },
  { id: 'scan.intrusiveness', label: 'Intrusiveness Cap', icon: 'shield', tab: 'Scan', group: 'Profile', kind: 'combo', requiresTarget: true, tip: 'Highest intrusiveness level a check may use in this scan' },
  { id: 'scan.crawlDepth', label: 'Crawl Depth', icon: 'account_tree', tab: 'Scan', group: 'Crawl', kind: 'combo', requiresTarget: true },
  { id: 'scan.crawlLimits', label: 'Crawl Limits…', icon: 'data_thresholding', tab: 'Scan', group: 'Crawl', requiresTarget: true, tip: 'Max pages, max time, max requests' },
  { id: 'scan.sitemap', label: 'Seed from sitemap.xml', icon: 'map', tab: 'Scan', group: 'Crawl', kind: 'toggle', requiresTarget: true },
  { id: 'scan.spiderOnly', label: 'Crawl Only (no checks)', icon: 'travel_explore', tab: 'Scan', group: 'Crawl', ...gated },
  { id: 'scan.importUrls', label: 'Import URL List…', icon: 'playlist_add', tab: 'Scan', group: 'Crawl', requiresTarget: true, origin: 'inspired by Burp target site map import' },
  { id: 'scan.schedule', label: 'Schedule…', icon: 'schedule', tab: 'Scan', group: 'History', requiresTarget: true, tip: 'Recurring scans; each run re-checks verification first' },
  { id: 'scan.history', label: 'Scan History', icon: 'history', tab: 'Scan', group: 'History', requiresTarget: true, noRecord: true },
  { id: 'scan.rescan', label: 'Re-run Last Scan', icon: 'replay', tab: 'Scan', group: 'History', ...gated },
  { id: 'scan.diff', label: 'Compare with Previous Scan', icon: 'difference', tab: 'Scan', group: 'History', requiresTarget: true, origin: 'findings diff — see INNOVATIONS.md' },
  { id: 'scan.log', label: 'Request Log', icon: 'receipt_long', tab: 'Scan', group: 'History', requiresTarget: true, noRecord: true, tip: 'Every request QuillTest sent, for audit' },
  { id: 'scan.preview', label: 'Scan Preview', icon: 'preview', tab: 'Scan', group: 'Profile', requiresTarget: true, noRecord: true, tip: 'What this profile would do: checks, request budget, intrusiveness', origin: 'scan-as-you-configure preview — INNOVATIONS.md' },
]);
