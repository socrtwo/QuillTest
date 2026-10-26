# Reports, exports, diffs and review packages

The scanner's source of truth is the JSON report `scripts/scan.mjs` writes under `scans/<host>/`. The report layer (`src/report/render.mjs`, CLI `scripts/report.mjs`) turns that file into things people read, compares two of them, and bundles everything for a reviewer. Nothing in this layer touches the network.

## Formats

| Format | Command | Notes |
|---|---|---|
| HTML | `node scripts/report.mjs --report r.json` (default) or `scan … --export html` | One self-contained file: inline CSS, **no scripts, no external resources**, and a `Content-Security-Policy` meta tag that forbids them. Dark-mode aware; prints cleanly to PDF. |
| Markdown | `--format md` | Same content for tickets, wikis and pull-request descriptions. |
| CSV | `--format csv` | One row per finding (`id, severity, confidence, checkId, title, location, affectedPages, cwe, owasp, remediation`). |
| All | `--format all --out <dir>/` | Writes each of the above. |

Every report contains: the headline counts by severity, the target, stack and coverage, each finding with its evidence and remediation (evidence can be dropped with `--no-evidence`), the generated fix artifacts if the scan ran with `--fixes` (`--no-fixes` omits them), the AI review summaries and per-finding consensus if it ran with `--analyze` (`--no-analysis` omits them), and the non-HTTP services checked if it ran with `--protocols`.

Everything that came from the target — titles, banners, headers, snippets — is treated as untrusted text: HTML-escaped in HTML, pipe-escaped in Markdown tables, quoted in CSV. A hostile `Server` banner cannot execute when the report is opened.

## Findings diff

```sh
node scripts/report.mjs --report scans/example.com/2026-10-25T….json --diff scans/example.com/2026-10-18T….json
node scripts/report.mjs --report new.json --diff old.json --format json --out changes.json   # the diff alone
```

Findings are matched across scans by a stable key — `checkId`, title and location — never by their `F-001` ids, which are positional. A finding seen on more than one page is matched without its location, because which page is listed first depends on crawl order. The result is four lists: **new**, **resolved**, **changed** (severity, confidence or affected-page count moved) and **unchanged**. In HTML and Markdown the diff appears as a "Changes since previous scan" section above the findings; with `--format json` it is written on its own. Diffing reports from different origins is allowed but flagged.

## Review packages

```sh
node scripts/report.mjs --report r.json --package review/ [--diff previous.json] [--regenerate-fixes] [--title "..."]
node scripts/report.mjs --verify review/
```

A package directory holds `report.json` (raw), `report.html`, `report.md`, `findings.csv`, `fixes/` (the artifacts recorded in the report; generated on the spot when the report has none, or regenerated with `--regenerate-fixes`), `diff.json` and `previous-report.json` when `--diff` was given, a `README.txt` describing the contents and scope, and `manifest.json` with the byte size and SHA-256 of every file. `--verify` recomputes the hashes and exits non-zero (code 4) on any mismatch, so a package can be handed over, archived or attached to a change request and checked later.

Files are written with mode `0600`. Cookie values in the report were already masked by the scanner; the package adds no new secrets, but it does contain your site's response headers and page URLs, so share it as you would any internal security document.

## Programmatic use

```js
import { renderHtml, renderMarkdown, renderCsv, diffReports, buildReviewPackage, summarize } from './src/report/render.mjs';
const html = renderHtml(report, { diff: diffReports(previous, report) });
const { files, manifest } = buildReviewPackage(report, { fixes });   // in-memory; write files yourself
```
