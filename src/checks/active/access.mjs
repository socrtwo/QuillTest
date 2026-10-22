/*
 * QuillTest — forced browsing to common sensitive paths (active, detection-only)
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Detection method: GET a short list of conventional administrative and
 * operational endpoints and report the ones that answer 200 with content.
 * To avoid false positives on sites that answer 200 to everything, QuillTest
 * first fetches a random path as a baseline; a candidate is only reported when
 * it behaves differently from that baseline. It requests with no credentials,
 * reads only status and whether the page looks like an app page, and performs
 * no state-changing action. IDOR and privilege checks need accounts you supply
 * and are a later, separately gated step.
 */
import { randomBytes } from 'node:crypto';
import { defineCheck } from '../registry.mjs';

const PATHS = [
  { path: '/admin', what: 'admin area' },
  { path: '/admin/', what: 'admin area' },
  { path: '/administrator', what: 'admin area' },
  { path: '/admin/login', what: 'admin login' },
  { path: '/manage', what: 'management area' },
  { path: '/dashboard', what: 'dashboard' },
  { path: '/console', what: 'console' },
  { path: '/actuator', what: 'Spring Boot Actuator' },
  { path: '/actuator/env', what: 'Spring Boot Actuator environment' },
  { path: '/metrics', what: 'metrics endpoint' },
  { path: '/debug', what: 'debug endpoint' },
  { path: '/phpmyadmin/', what: 'phpMyAdmin' },
  { path: '/api', what: 'API root' },
  { path: '/swagger-ui.html', what: 'API documentation' },
  { path: '/swagger/index.html', what: 'API documentation' },
  { path: '/.well-known/security.txt', what: 'security.txt', positive: true },
];

defineCheck({
  id: 'access.forcedBrowsing', title: 'Conventional sensitive path reachable without authentication', kind: 'active', intrusiveness: 2,
  requests: `a random baseline GET plus one GET per path in a short list (${PATHS.length} paths); no credentials, no writes`,
  severity: 'medium', confidence: 'tentative', cwe: [200, 548], owasp: 'A01', asvs: ['V4.1.1'],
  description: 'A conventional administrative or operational endpoint answered a request with no credentials, differently from a random non-existent path. It may be unprotected, or it may be a login page; QuillTest reports it as a candidate for you to confirm.',
  remediation: { summary: 'Put every administrative and operational endpoint behind authentication and authorization; return 404 (not 403) for unauthenticated requests to hide their existence; remove debug, metrics and actuator endpoints from production or bind them to an internal interface.', references: ['https://owasp.org/Top10/A01_2021-Broken_Access_Control/'] },
  active: async (site) => {
    const baselineUrl = `${site.origin}/qt-${randomBytes(6).toString('hex')}`;
    const baseline = await site.sendUrl(baselineUrl);
    const baseStatus = baseline?.status ?? 404;
    const baseLen = baseline?.body?.length ?? 0;
    if (!baseline) return [];
    const out = [];
    for (const entry of PATHS) {
      const res = await site.sendUrl(site.origin + entry.path);
      if (!res || res.status === 0) continue;
      const interesting = res.status === 200 || res.status === 401 || res.status === 403;
      if (!interesting) continue;
      // Skip when it behaves exactly like the catch-all baseline.
      if (res.status === baseStatus && baseStatus === 200 && Math.abs((res.body?.length ?? 0) - baseLen) < 32) continue;
      const protectedByAuth = res.status === 401 || res.status === 403;
      out.push({
        url: site.origin + entry.path, key: entry.path,
        title: entry.positive ? 'security.txt published' : undefined,
        severity: entry.positive ? 'informational' : protectedByAuth ? 'informational' : entry.path.includes('actuator') || entry.path.includes('phpmyadmin') ? 'medium' : 'low',
        confidence: 'tentative',
        description: entry.positive ? 'A security.txt file is published (good practice).' : protectedByAuth ? `The ${entry.what} at ${entry.path} exists but requires authentication (HTTP ${res.status}).` : `The ${entry.what} at ${entry.path} answered HTTP ${res.status} without credentials; confirm it is meant to be public.`,
        evidence: { detail: { path: entry.path, status: res.status, baselineStatus: baseStatus, bytes: res.body?.length ?? 0 } },
      });
    }
    return out;
  },
});
