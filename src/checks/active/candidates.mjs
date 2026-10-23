/*
 * QuillTest — manual-review candidates for SSRF and IDOR (active category, read-only)
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * These two checks send nothing. They read the injection points and URLs the
 * crawl already observed and flag the ones whose shape calls for manual,
 * human-judged testing: a parameter that takes a URL (an SSRF candidate, to be
 * confirmed with out-of-band testing you set up) or a value that looks like an
 * object identifier (an IDOR candidate, to be confirmed with two accounts you
 * control). They are informational and tentative on purpose — a surfaced
 * candidate is a place to look, never an asserted finding — which is exactly
 * the "surface for review rather than auto-assert" posture docs/CHECKS.md sets
 * for SSRF, access control and business-logic classes. The automated
 * out-of-band SSRF probe and account-based IDOR testing are separate, later,
 * separately-gated steps.
 */
import { defineCheck } from '../registry.mjs';

const URL_NAME = /^(url|uri|link|href|src|dest|destination|redirect|redir|return|returnurl|continue|next|target|to|out|u|forward|callback|webhook|feed|rss|fetch|load|proxy|image_?url|img|avatar|file|path|document|doc|domain|host|site|server|endpoint|api|resource|data|xml|json|template|page|preview|open|view|window)$/i;
const ID_NAME = /^(id|.*_id|.*id|uid|uuid|guid|user|userid|account|acct|customer|member|order|orderid|invoice|txn|transaction|doc|docid|document|file|fileid|record|ref|reference|key|number|num|no|seq|pid|gid|oid|nid|item|object|entity|node|row)$/i;
const LOOKS_URL = /^(https?:)?\/\/|^\/[^/]/i;
const LOOKS_ID = /^\d{1,12}$/;
const LOOKS_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const LOOKS_HASH = /^[0-9a-f]{16,64}$/i;
const PATH_ID = /\/(\d{2,12}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?=\/|$)/i;

defineCheck([
  {
    id: 'ssrf.candidate', title: 'Parameter that takes a URL (server-side request forgery candidate)', kind: 'active', intrusiveness: 1,
    requests: 'none — reads the parameters the crawl observed',
    severity: 'informational', confidence: 'tentative', cwe: [918], owasp: 'A10', asvs: ['V12.6.1'],
    description: 'A parameter\'s name or observed value indicates it supplies a URL or host that the server may fetch. If the server requests it, an attacker can point it at internal services or cloud metadata (SSRF). QuillTest surfaces it for manual, out-of-band testing rather than probing automatically.',
    remediation: { summary: 'If the server must fetch a user-supplied URL, validate it against an allowlist of schemes and hosts, resolve and re-check the address to block internal/link-local/metadata ranges, disable redirects, and fetch from a network segment with no access to internal services.', references: ['https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'] },
    finalize: (site) => {
      const out = [];
      const seen = new Set();
      for (const p of site.points || []) {
        const byName = URL_NAME.test(p.name);
        const byValue = p.original && LOOKS_URL.test(p.original);
        if (!byName && !byValue) continue;
        const sig = `${p.action}#${p.name}`;
        if (seen.has(sig)) continue;
        seen.add(sig);
        out.push({ url: p.url, key: p.name, description: `The ${p.where === 'form' ? 'form field' : 'parameter'} "${p.name}" ${byName ? 'is named like a URL/host input' : 'was observed holding a URL'}; review it for SSRF with out-of-band testing.`, evidence: { detail: { where: p.where, method: p.method, action: p.action, observedValue: byValue ? p.original : undefined } } });
      }
      return out;
    },
  },
  {
    id: 'access.idorCandidate', title: 'Identifier-like value (insecure direct object reference candidate)', kind: 'active', intrusiveness: 1,
    requests: 'none — reads the parameters and URLs the crawl observed',
    severity: 'informational', confidence: 'tentative', cwe: [639], owasp: 'A01', asvs: ['V4.2.1'],
    description: 'A parameter or path segment carries what looks like an object identifier (a sequential number, a UUID, or a hash). If the server returns the object without checking it belongs to the caller, changing the identifier reaches another user\'s data (IDOR). QuillTest surfaces it for manual testing with accounts you supply rather than accessing anyone\'s data.',
    remediation: { summary: 'Enforce an authorization check on every object access — confirm the authenticated user may see the requested object — rather than trusting the identifier in the request. Prefer unguessable identifiers as defence in depth, never as the only control.', references: ['https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html'] },
    finalize: (site) => {
      const out = [];
      const seen = new Set();
      const flag = (url, key, where, why, detail) => { const sig = `${where}:${key}`; if (seen.has(sig)) return; seen.add(sig); out.push({ url, key, description: `${why} "${key}"; test for IDOR with two accounts you control.`, evidence: { detail } }); };
      for (const p of site.points || []) {
        const idName = ID_NAME.test(p.name);
        const idValue = p.original && (LOOKS_ID.test(p.original) || LOOKS_UUID.test(p.original) || LOOKS_HASH.test(p.original));
        if (idName || idValue) flag(p.url, p.name, `${p.where}:${p.action}`, `The ${p.where === 'form' ? 'form field' : 'parameter'} ${idName ? 'is named like an object identifier' : 'was observed holding an identifier-like value'},`, { where: p.where, method: p.method, action: p.action, observedValue: idValue ? p.original : undefined });
      }
      // Identifier-like path segments (e.g. /orders/4821, /users/<uuid>).
      for (const page of site.pages || []) {
        if (page.kind && page.kind !== 'page') continue;
        let path; try { path = new URL(page.finalUrl || page.url).pathname; } catch { continue; }
        const m = PATH_ID.exec(path);
        if (m) flag(page.finalUrl || page.url, m[1], `path:${path}`, `The path ${path} contains an identifier-like segment`, { segment: m[1], path });
      }
      return out;
    },
  },
]);
