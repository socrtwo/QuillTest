# Fixes and remediation

Anne's Test is a test-*and*-fix tool. A finding that only says "you have a problem" is half a product. Every check therefore carries a remediation, and where the fix is a concrete artifact, Anne's Test generates it.

## Three levels of fix

1. **Guidance** — always present. Plain-language explanation of the flaw, its impact, the CWE and OWASP category, and what to change. This is the minimum every finding ships with.
2. **Generated artifact** — where the fix is config or markup that does not require seeing the site's source. Examples:
   - a security-header block for nginx, Apache, Caddy, IIS, or a Cloudflare/Fastly rule,
   - a `Content-Security-Policy` derived from the resources the crawler actually observed the page loading,
   - corrected cookie attributes (`Secure`, `HttpOnly`, `SameSite`),
   - a CORS policy narrowed to the origins in use,
   - a `Strict-Transport-Security` header with sane max-age,
   - a dependency version bump when a known-vulnerable library/version is fingerprinted.
3. **Applyable patch** — where Anne's Test can see the artifact to change (a config file or dependency manifest you provide, or a file at a verified origin) and produce a diff. Anne's Test **generates** the patch; it never applies it to a live site itself. You review and apply.

## The fix is mapped, not generic

Anne's Test fingerprints the server and framework from response headers, error pages, cookie names, and asset paths, then selects the remediation that fits. A missing-CSP finding on an Express app gets a `helmet` snippet; on nginx it gets an `add_header` block; on a static host it gets the `<meta http-equiv>` fallback and a note on why a header is better. The mapping lives in `src/fix/artifacts.mjs` as data (`renderers` per server target, `COOKIE_FIXES` per framework), same as the check registry.

## Role of AI in fixes

With a provider configured, the AI layer drafts and tailors remediation prose, adapts a generated artifact to the exact stack detected, and writes the executive summary. It works from Anne's Test's findings and the observed responses only. Every AI-drafted fix is labeled as such and is reviewable; nothing is applied automatically. See [AI.md](AI.md).

## What Anne's Test will not do

- It will not modify a live target. Fixes are generated for you to review and deploy.
- It will not generate exploit code, even to "demonstrate" a fix. A finding is demonstrated by the non-destructive evidence that detected it, not by weaponizing it.

## Status

Levels 1 and 2 are implemented.

- **Guidance (level 1):** every check in `src/scan/passive.mjs` carries a concrete remediation string, and component findings name the fixed version.
- **Generated artifacts (level 2):** `src/fix/artifacts.mjs`, run with `scripts/scan.mjs scan <origin> --fixes` or `scripts/fix.mjs --report <scan.json>`. From a report it emits:
  - a **security-header block for the detected server** — nginx `add_header … always`, Apache `<IfModule mod_headers.c>` (plus `ServerTokens Prod`, `Options -Indexes`), Caddy `header { }`, IIS `web.config` `customHeaders`, Express/helmet options, Netlify `_headers`, or a generic header list; `--target` overrides the choice and `--all` emits every variant;
  - a **Content-Security-Policy derived from what the crawler observed** — the `script-src`/`style-src`/`frame-src` allow-lists are exactly the third-party origins seen on crawled pages, `upgrade-insecure-requests` is added when mixed content was found, and every `'unsafe-inline'` concession is explained so it can be removed. It is emitted as `Content-Security-Policy-Report-Only` with the enforced twin alongside, because a CSP deployed blind breaks sites;
  - **cookie-attribute settings for the detected framework** (PHP ini, express-session, Django, Rails, Laravel, ASP.NET, Flask, WordPress);
  - **dependency bumps for components found end-of-life or vulnerable** (`src/fix/dependencies.mjs`) — a `package.json` fragment for npm-hosted libraries (jQuery, Bootstrap), a `composer.json` fragment for Drupal, replacement `<script>`/`<link>` tags with an SRI placeholder for CDN or self-hosted copies, a review-before-running shell script of package-manager commands (runtime and server upgrades for PHP, nginx, Apache, IIS, Joomla appear as commented, distribution-dependent steps), and `quilltest-dependencies.md` summarizing each component's detected version, the lowest version that clears the matched advisories (computed from the same offline table the scanner used), the last patched release on the current line where one exists, the recommended target, and the finding ids and CVEs behind it. Targets are dated (`BUMP_DATA_AS_OF`); caret ranges let the installer float above them.

  Only headers that a finding calls for are emitted, each tagged with the finding it addresses; the result lists which findings were covered and which still need a manual change.
- **Applyable patch (level 3):** implemented for dependency manifests (`src/fix/patch.mjs`). Point `scripts/fix.mjs --patch <file>` at your real `package.json` or `composer.json` and Anne's Test emits a unified diff (`<file>.patch`, written under the fixes directory) that bumps exactly the packages a scan flagged as vulnerable or end-of-life, to the recommended range, preserving your formatting. A dep already at or above the target, or absent, is skipped; Angular is left to `ng update`, which owns its manifest. The diff is `git apply`-ready and minimal (only the changed version lines). Anne's Test **generates** it and never applies it — review, then `git apply <file>.patch` (or `patch -p1 < <file>.patch`) yourself. `--patch` may be repeated. Server configs stay level 2 (a block to add), since merging into arbitrary config syntax cannot be done safely without seeing the file.
