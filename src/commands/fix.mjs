/** Fix tab — remediation registry and artifact generators (src/fixes/, M4). Nothing here touches a live site. */
import { def } from './registry.mjs';

def([
  { id: 'fix.generate', label: 'Generate Fix', icon: 'build', tab: 'Fix', group: 'Remediate', popular: true, keys: ['Ctrl+Shift+X'], tip: 'The remediation for the selected finding, matched to the detected server/framework' },
  { id: 'fix.generateAll', label: 'Generate All Fixes', icon: 'construction', tab: 'Fix', group: 'Remediate' },
  { id: 'fix.preview', label: 'Preview Fix', icon: 'preview', tab: 'Fix', group: 'Remediate', noRecord: true },
  { id: 'fix.explain', label: 'Explain Fix', icon: 'school', tab: 'Fix', group: 'Remediate', noRecord: true, tip: 'Why this change closes the finding, and what it might break' },
  { id: 'fix.copySnippet', label: 'Copy Snippet', icon: 'content_copy', tab: 'Fix', group: 'Remediate', noRecord: true },
  { id: 'fix.downloadPatch', label: 'Download Patch / Config', icon: 'download', tab: 'Fix', group: 'Remediate', tip: 'A diff or config file to review and deploy yourself; QuillTest never changes a live site' },
  { id: 'fix.targetPlatform', label: 'Target Platform', icon: 'dns', tab: 'Fix', group: 'Platform', kind: 'combo', tip: 'nginx, Apache, Caddy, IIS, Express, Django, Rails, Spring, static host… detected, overridable' },
  { id: 'fix.headersNginx', label: 'Security Headers — nginx', icon: 'code', tab: 'Fix', group: 'Generators' },
  { id: 'fix.headersApache', label: 'Security Headers — Apache', icon: 'code', tab: 'Fix', group: 'Generators' },
  { id: 'fix.headersCaddy', label: 'Security Headers — Caddy', icon: 'code', tab: 'Fix', group: 'Generators' },
  { id: 'fix.headersIis', label: 'Security Headers — IIS web.config', icon: 'code', tab: 'Fix', group: 'Generators' },
  { id: 'fix.headersMiddleware', label: 'Security Headers — Framework Middleware', icon: 'code', tab: 'Fix', group: 'Generators', tip: 'helmet, django-csp/SecurityMiddleware, Rails, Spring Security…' },
  { id: 'fix.csp', label: 'Content-Security-Policy Builder', icon: 'policy', tab: 'Fix', group: 'Generators', tip: 'Built from the sources the crawl observed; starts in report-only' },
  { id: 'fix.cookies', label: 'Cookie Flags', icon: 'cookie', tab: 'Fix', group: 'Generators', tip: 'Secure, HttpOnly, SameSite per cookie, per platform' },
  { id: 'fix.cors', label: 'CORS Policy', icon: 'swap_horiz', tab: 'Fix', group: 'Generators' },
  { id: 'fix.tls', label: 'TLS Configuration', icon: 'lock', tab: 'Fix', group: 'Generators', tip: 'Protocol/cipher recommendations per server' },
  { id: 'fix.redirects', label: 'Redirect Allow-List', icon: 'alt_route', tab: 'Fix', group: 'Generators' },
  { id: 'fix.dependencyBump', label: 'Dependency Update', icon: 'upgrade', tab: 'Fix', group: 'Generators', tip: 'Version bump for a detected vulnerable component' },
  { id: 'fix.hideVersions', label: 'Hide Version Banners', icon: 'visibility_off', tab: 'Fix', group: 'Generators' },
  { id: 'fix.markApplied', label: 'Mark Fix Applied', icon: 'done_all', tab: 'Fix', group: 'Track' },
  { id: 'fix.recheck', label: 'Re-check After Fix', icon: 'published_with_changes', tab: 'Fix', group: 'Track', requiresTarget: true, requiresVerification: true },
  { id: 'fix.plan', label: 'Remediation Plan', icon: 'list_alt', tab: 'Fix', group: 'Track', noRecord: true, tip: 'All fixes ordered by priority, with effort estimates' },
]);
