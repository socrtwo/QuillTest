/** Share tab — moving results to other people without moving secrets. */
import { def } from './registry.mjs';

def([
  { id: 'share.package', label: 'Review Package…', icon: 'inventory_2', tab: 'Share', group: 'Package', popular: true, tip: 'Report + findings + fixes in one archive for a reviewer', origin: 'export-ready review packages — INNOVATIONS.md' },
  { id: 'share.bundle', label: 'Export Workspace Bundle', icon: 'archive', tab: 'Share', group: 'Package' },
  { id: 'share.redactedCopy', label: 'Redacted Copy', icon: 'visibility_off', tab: 'Share', group: 'Package', tip: 'Strips cookies, tokens, credentials and request bodies' },
  { id: 'share.email', label: 'Email Report', icon: 'mail', tab: 'Share', group: 'Send', tip: 'Uses QuillPost when installed' },
  { id: 'share.system', label: 'Share…', icon: 'share', tab: 'Share', group: 'Send', tip: 'System share sheet' },
  { id: 'share.copyLink', label: 'Copy Finding Link', icon: 'link', tab: 'Share', group: 'Send', noRecord: true },
  { id: 'share.issueTracker', label: 'Create Issue…', icon: 'bug_report', tab: 'Share', group: 'Integrate', tip: 'GitHub / GitLab / Jira issue from a finding, with the fix attached' },
  { id: 'share.webhook', label: 'Webhook…', icon: 'webhook', tab: 'Share', group: 'Integrate' },
  { id: 'share.ci', label: 'CI Snippet', icon: 'terminal', tab: 'Share', group: 'Integrate', tip: 'Run this scan from CI; verification is re-checked on every run' },
]);
