/** Review tab — human review of findings and fixes, audit trail. */
import { def } from './registry.mjs';

def([
  { id: 'review.queue', label: 'Review Queue', icon: 'pending_actions', tab: 'Review', group: 'Review', noRecord: true, popular: true, tip: 'Findings awaiting a human decision' },
  { id: 'review.approve', label: 'Approve Finding', icon: 'thumb_up', tab: 'Review', group: 'Review', tip: 'Confirmed real; goes to the report' },
  { id: 'review.reject', label: 'Reject Finding', icon: 'thumb_down', tab: 'Review', group: 'Review', tip: 'Not real or out of scope; recorded with a reason' },
  { id: 'review.needsInfo', label: 'Needs More Information', icon: 'help', tab: 'Review', group: 'Review' },
  { id: 'review.comment', label: 'Comment', icon: 'comment', tab: 'Review', group: 'Comments' },
  { id: 'review.comments', label: 'Comments Pane', icon: 'forum', tab: 'Review', group: 'Comments', kind: 'toggle', noRecord: true },
  { id: 'review.resolveComment', label: 'Resolve Comment', icon: 'check_circle', tab: 'Review', group: 'Comments' },
  { id: 'review.assign', label: 'Assign Reviewer…', icon: 'person_add', tab: 'Review', group: 'Workflow' },
  { id: 'review.signoff', label: 'Sign Off Scan', icon: 'draw', tab: 'Review', group: 'Workflow', tip: 'Locks the findings of this scan; later changes are tracked as amendments' },
  { id: 'review.history', label: 'Change History', icon: 'history', tab: 'Review', group: 'Audit', noRecord: true },
  { id: 'review.auditLog', label: 'Audit Log', icon: 'receipt_long', tab: 'Review', group: 'Audit', noRecord: true, tip: 'Who verified, authorized, scanned, changed what, when' },
  { id: 'review.compareFindings', label: 'Compare Findings', icon: 'compare_arrows', tab: 'Review', group: 'Audit' },
  { id: 'review.checkReport', label: 'Check Report', icon: 'spellcheck', tab: 'Review', group: 'Audit', tip: 'Missing remediations, unreviewed findings, unredacted secrets' },
]);
