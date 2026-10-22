# Fixes and remediation

QuillTest is a test-*and*-fix tool. A finding that only says "you have a problem" is half a product. Every check therefore carries a remediation, and where the fix is a concrete artifact, QuillTest generates it.

## Three levels of fix

1. **Guidance** — always present. Plain-language explanation of the flaw, its impact, the CWE and OWASP category, and what to change. This is the minimum every finding ships with.
2. **Generated artifact** — where the fix is config or markup that does not require seeing the site's source. Examples:
   - a security-header block for nginx, Apache, Caddy, IIS, or a Cloudflare/Fastly rule,
   - a `Content-Security-Policy` derived from the resources the crawler actually observed the page loading,
   - corrected cookie attributes (`Secure`, `HttpOnly`, `SameSite`),
   - a CORS policy narrowed to the origins in use,
   - a `Strict-Transport-Security` header with sane max-age,
   - a dependency version bump when a known-vulnerable library/version is fingerprinted.
3. **Applyable patch** — where QuillTest can see the artifact to change (a config file or dependency manifest you provide, or a file at a verified origin) and produce a diff. QuillTest **generates** the patch; it never applies it to a live site itself. You review and apply.

## The fix is mapped, not generic

QuillTest fingerprints the server and framework from response headers, error pages, cookie names, and asset paths, then selects the remediation that fits. A missing-CSP finding on an Express app gets a `helmet` snippet; on nginx it gets an `add_header` block; on a static host it gets the `<meta http-equiv>` fallback and a note on why a header is better. The mapping lives in `src/fixes/` (planned) as data, same as the check and command registries.

## Role of AI in fixes

With a provider configured, the AI layer drafts and tailors remediation prose, adapts a generated artifact to the exact stack detected, and writes the executive summary. It works from QuillTest's findings and the observed responses only. Every AI-drafted fix is labeled as such and is reviewable; nothing is applied automatically. See [AI.md](AI.md).

## What QuillTest will not do

- It will not modify a live target. Fixes are generated for you to review and deploy.
- It will not generate exploit code, even to "demonstrate" a fix. A finding is demonstrated by the non-destructive evidence that detected it, not by weaponizing it.

## Status

Planning. The remediation registry and artifact generators are specified here and not yet implemented.
