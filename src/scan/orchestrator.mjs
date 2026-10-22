/*
 * QuillTest — scan orchestrator
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Runs a scan: gate → crawl → observe checks per page → finalize checks →
 * probe checks (bounded extra requests) → findings → record. The gate is
 * enforced here as well as in the command executor: nothing in this module
 * contacts a target before assertScanPermitted() has passed.
 */

import { randomBytes } from 'node:crypto';
import { Crawler } from '../crawl/crawler.mjs';
import { enumerate, buildRequest } from './params.mjs';
import { inspectTls } from '../crawl/tls.mjs';
import { allChecks, getCheck } from '../checks/index.mjs';
import { createFinding, FindingSet } from '../findings/model.mjs';
import { AuthorizationRequiredError } from '../targets/store.mjs';

export const PROFILES = Object.freeze({
  passive: { label: 'Passive', description: 'Crawl and observe. Extra requests only to well-known paths, with a harmless Origin header, and one TLS handshake. No test input is ever sent.', maxIntrusiveness: 1, active: false },
  quick: { label: 'Quick', description: 'Passive checks on the entry page and its direct links only.', maxIntrusiveness: 1, active: false, crawl: { maxDepth: 1, maxPages: 12, maxRequests: 80 } },
  standard: { label: 'Standard', description: 'Passive checks plus detection-only active checks: reflected XSS, SQL-error, template and CRLF injection, open redirect, CSRF-token and forced-browsing. Safe markers and error signatures only — no exploit, no data change.', maxIntrusiveness: 2, active: true },
  thorough: { label: 'Thorough', description: 'Everything in Standard with deeper crawl limits and a larger active-request budget.', maxIntrusiveness: 3, active: true, crawl: { maxDepth: 5, maxPages: 500, maxRequests: 1500 } },
});

/**
 * Both proofs, or no scan. Returns the verification record for the report.
 * Throws VerificationRequiredError / AuthorizationRequiredError.
 */
export function assertScanPermitted(ctx, target) {
  const record = ctx.verifications.assertVerified(target.origin);
  if (!target.authorization?.confirmed) throw new AuthorizationRequiredError(target.origin);
  return record;
}

/**
 * Which checks a scan would run, and why the others are skipped.
 * @returns {{run:object[], skipped:{check:object, reason:string}[]}}
 */
export function planChecks({ profile = 'passive', disabledChecks = [], origin = 'https://example.com' } = {}) {
  const p = PROFILES[profile];
  if (!p) throw new RangeError(`Unknown profile ${JSON.stringify(profile)}; one of ${Object.keys(PROFILES).join(', ')}`);
  const run = []; const skipped = [];
  for (const c of allChecks()) {
    if (disabledChecks.includes(c.id) || disabledChecks.includes(c.id.split('.')[0])) { skipped.push({ check: c, reason: 'disabled for this target' }); continue; }
    if (c.kind === 'active' && !p.active) { skipped.push({ check: c, reason: `active checks are off in the ${p.label} profile` }); continue; }
    if (c.intrusiveness > p.maxIntrusiveness) { skipped.push({ check: c, reason: `intrusiveness ${c.intrusiveness} exceeds the profile cap ${p.maxIntrusiveness}` }); continue; }
    if (c.id === 'transport.tls' && !origin.startsWith('https:')) { skipped.push({ check: c, reason: 'origin is not https' }); continue; }
    run.push(c);
  }
  return { run, skipped };
}

function newScanId(now) {
  return `scan-${now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z')}-${randomBytes(3).toString('hex')}`;
}

/**
 * @param {import('../commands/exec.mjs').Context} ctx
 * @param {{target:object, profile?:string, url?:string, spiderOnly?:boolean, crawl?:object, onProgress?:(e:object)=>void, fetch?:typeof fetch, inspectTls?:Function}} opts
 */
export async function runScan(ctx, { target, profile, url, spiderOnly = false, crawl: crawlOverrides = {}, onProgress = () => {}, fetch: fetchImpl, inspectTls: tlsImpl = inspectTls } = {}) {
  if (!target) throw new TypeError('runScan needs a target');
  const settings = ctx.scans.settings(target.origin);
  const profileName = profile || settings.profile || 'passive';
  const prof = PROFILES[profileName];
  if (!prof) throw new RangeError(`Unknown profile ${JSON.stringify(profileName)}`);

  // THE GATE. Both proofs are recorded into the scan.
  const verification = assertScanPermitted(ctx, target);

  const startedAt = ctx.now();
  const id = newScanId(startedAt);
  const crawlOpts = {
    maxDepth: settings.maxDepth, maxPages: settings.maxPages, maxRequests: settings.maxRequests, concurrency: settings.concurrency, delayMs: settings.delayMs, timeoutMs: settings.timeoutMs, honorRobots: settings.honorRobots, seedSitemap: settings.seedSitemap,
    ...(prof.crawl || {}), ...crawlOverrides,
    scope: (u) => ctx.targets.inScope(target.origin, u),
    fetch: fetchImpl,
    now: ctx.now,
    onPage: (p) => onProgress({ type: 'page', url: p.finalUrl, status: p.status }),
  };
  const crawler = new Crawler(target.origin, crawlOpts);
  onProgress({ type: 'start', id, origin: target.origin, profile: profileName });

  if (url) {
    // Single-URL mode: one page, no link following.
    if (!ctx.targets.inScope(target.origin, url)) throw new RangeError(`${url} is outside the target's scope`);
    const page = await crawler.request(new URL(url, target.origin).toString(), { kind: 'page' });
    crawler.pages.push(page);
    onProgress({ type: 'page', url: page.finalUrl, status: page.status });
  } else {
    await crawler.run();
  }
  const crawlResult = crawler.result();

  const findings = new FindingSet();
  const checksRun = [];
  const { run: plan, skipped } = spiderOnly ? { run: [], skipped: allChecks().map((c) => ({ check: c, reason: 'crawl-only scan' })) } : planChecks({ profile: profileName, disabledChecks: settings.disabledChecks, origin: target.origin });
  const injectionPoints = spiderOnly ? [] : enumerate(crawlResult.pages, target.origin);
  let activeSent = 0;
  const activeBudget = settings.maxActiveRequests;
  const site = {
    origin: target.origin,
    pages: crawlResult.pages,
    external: crawlResult.external,
    fingerprint: new Map(),
    inspectTls: tlsImpl,
    points: injectionPoints,
    maxPointsPerCheck: settings.maxPointsPerCheck,
    request: (u, opts = {}) => crawler.request(u, { kind: 'probe', followRedirects: false, ...opts }),
    // Active, non-destructive detection request against one injection point with
    // a single parameter replaced. Budgeted; never follows redirects; logged as 'active'.
    send: (point, value, opts = {}) => {
      if (activeSent >= activeBudget || crawler.stopped) return null;
      activeSent++;
      const { url, init } = buildRequest(point, value);
      return crawler.request(url, { kind: 'active', method: init.method, headers: init.headers, body: init.body, followRedirects: false, ...opts });
    },
    // Budgeted active request to an arbitrary same-origin URL (forced browsing, host-header
    // and method checks). Logged 'active'; counts against the active budget.
    sendUrl: (url, opts = {}) => {
      if (activeSent >= activeBudget || crawler.stopped) return null;
      activeSent++;
      return crawler.request(url, { kind: 'active', followRedirects: false, ...opts });
    },
    activeBudgetLeft: () => Math.max(0, activeBudget - activeSent),
  };
  const emit = (check, items) => {
    for (const item of items || []) {
      if (check.consolidate && item.url) {
        item.evidence = { ...(item.evidence || {}), detail: { ...(item.evidence?.detail || {}), affectedUrls: [item.url] } };
        item.url = target.origin + '/';
      }
      findings.add(createFinding({
        checkId: check.id, title: item.title || check.title, severity: item.severity || check.severity, confidence: item.confidence || check.confidence,
        origin: target.origin, url: item.url, key: item.key, description: item.description || check.description, remediation: check.remediation,
        cwe: check.cwe, owasp: check.owasp, asvs: check.asvs, evidence: item.evidence,
      }, { now: ctx.now() }));
    }
  };
  const errors = [];
  const safely = async (check, phase, fn) => { try { emit(check, await fn()); } catch (e) { errors.push({ checkId: check.id, phase, error: e?.message || String(e) }); } };

  for (const check of plan.filter((c) => c.observe)) {
    for (const page of site.pages) await safely(check, 'observe', () => check.observe(page, site));
    checksRun.push(check.id);
  }
  for (const check of plan.filter((c) => c.finalize)) { await safely(check, 'finalize', () => check.finalize(site)); if (!checksRun.includes(check.id)) checksRun.push(check.id); }
  for (const check of plan.filter((c) => c.probe)) {
    if (crawler.stopped) { skipped.push({ check, reason: `request budget exhausted before probes (${crawler.stopReason})` }); continue; }
    onProgress({ type: 'probe', checkId: check.id });
    await safely(check, 'probe', () => check.probe(site));
    if (!checksRun.includes(check.id)) checksRun.push(check.id);
  }
  for (const check of plan.filter((c) => c.active)) {
    if (crawler.stopped) { skipped.push({ check, reason: `request budget exhausted before active checks (${crawler.stopReason})` }); continue; }
    if (site.activeBudgetLeft() === 0) { skipped.push({ check, reason: `active request budget (${activeBudget}) exhausted` }); continue; }
    onProgress({ type: 'active', checkId: check.id, points: injectionPoints.length });
    await safely(check, 'active', () => check.active(site));
    if (!checksRun.includes(check.id)) checksRun.push(check.id);
  }

  const suppressed = ctx.scans.applyFalsePositives(target.origin, findings);
  const finishedAt = ctx.now();
  const pages = site.pages.filter((p) => p.kind === 'page');
  const record = {
    version: 1,
    id,
    origin: target.origin,
    target: { name: target.name, tags: target.tags, scope: target.scope },
    profile: profileName,
    startedAt: iso(startedAt),
    finishedAt: iso(finishedAt),
    durationMs: finishedAt.getTime() - startedAt.getTime(),
    verification: { method: verification.method, verifiedAt: verification.verifiedAt, validUntil: verification.validUntil, tokenHash: verification.tokenHash, targetAddress: verification.targetAddress || null },
    authorization: { ...target.authorization },
    crawl: { pages: pages.length, assets: site.pages.filter((p) => p.kind === 'asset').length, probes: crawlResult.requestLog.filter((r) => r.kind === 'probe').length, active: crawlResult.requestLog.filter((r) => r.kind === 'active').length, injectionPoints: injectionPoints.length, requests: crawlResult.requestLog.length, errors: pages.filter((p) => p.error).length, stopReason: crawlResult.stopReason, robotsDisallow: crawlResult.robots.disallow, external: Object.fromEntries(Object.entries(crawlResult.external).map(([k, v]) => [k, v.length])), urls: pages.map((p) => ({ url: p.finalUrl, status: p.status, depth: p.depth, ms: p.ms, bytes: p.bytes, ...(p.error ? { error: p.error } : {}) })) },
    checks: { run: checksRun, skipped: skipped.map((s) => ({ id: s.check.id, reason: s.reason })), errors },
    fingerprint: [...site.fingerprint.values()],
    summary: findings.summary(),
    suppressedByRules: suppressed,
    findings: findings.toJSON(),
    requestLog: crawlResult.requestLog,
  };
  ctx.scans.save(record);
  ctx.targets.markScanned(target.origin);
  onProgress({ type: 'done', id, summary: record.summary });
  return record;
}

export function describeProfile(name) {
  const p = PROFILES[name];
  if (!p) throw new RangeError(`Unknown profile ${JSON.stringify(name)}`);
  return { id: name, ...p };
}

export { getCheck };
const iso = (d) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');
