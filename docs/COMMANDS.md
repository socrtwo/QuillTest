# QuillTest Command Reference

QuillTest defines **241 commands**. Every one can be placed on the Quick Access Bar, added to a custom tab, bound to a keyboard shortcut, recorded in a macro, run from the command line (`node scripts/quilltest.mjs <id>`) or found with command search (Alt+Q).

**40 are implemented** and **201 are planned** (defined as data, with no implementation yet; running one reports "planned but not implemented"). 3 commands are "not in tabs" — reachable through the Quick Access Bar chooser, Customize Tabs, command search and the command line — so nothing is hidden.

**10 commands are gated.** Marked *gated* below, they send requests to the target, and the executor refuses to run them unless the active target's origin has a current ownership verification **and** you have confirmed authorization for that target (see [OWNERSHIP-VERIFICATION.md](OWNERSHIP-VERIFICATION.md) and [ETHICS.md](ETHICS.md)). This is enforced in `src/commands/exec.mjs`, not in the UI.

This file is generated from the source by `npm run catalog`; a unit test fails when it is out of date.

## Default tab layout

- **File** (Backstage): New · Open · Save · Info · Import · Export · Print · Share · Options · Close
- **Verify**: Challenge · Status · Manage · Help
- **Scan**: Run · Control · Profile · Crawl · History
- **Targets**: Targets · Authorization · Scope · Authentication · Politeness · Exchange
- **Checks**: Checks · Categories · View · Custom
- **Findings**: Browse · Organize · Triage · Annotate · Exchange
- **Fix**: Remediate · Platform · Generators · Track
- **AI**: Setup · Analyze · Fix · Report · Several AIs
- **Report**: Build · Style · Export · Compare
- **Review**: Review · Comments · Workflow · Audit
- **Share**: Package · Send · Integrate
- **View** (not shown by default): Find · Views · Panes · Zoom · Appearance · Window · Customize
- **Developer** (not shown by default): Macros · Scripting · Diagnostics
- **Help**: Help · Policy · About

Default Quick Access Bar: `file.save`, `verify.status`, `scan.start`, `scan.stop`, `findings.list`, `fix.generate`, `view.cmdSearch`

## File (28)

| Command | Group | Shortcut | ID | Status | Notes |
|---|---|---|---|---|---|
| Close | Close | Ctrl+W | `file.close` | planned |  |
| Exit | Close |  | `file.exit` | planned |  |
| Export Findings as CSV | Export |  | `file.export.csv` | planned |  |
| Export Findings as SARIF | Export |  | `file.export.sarif` | planned | For code-scanning dashboards and IDEs |
| Export Report as HTML | Export |  | `file.export.html` | planned |  |
| Export Report as Markdown | Export |  | `file.export.markdown` | planned |  |
| Export Report as PDF | Export |  | `file.export.pdf` | planned |  |
| Export Workspace as JSON | Export |  | `file.export.json` | planned |  |
| Import Findings (JSON/SARIF)… | Import |  | `file.import.findings` | planned |  |
| Import Targets… | Import |  | `file.import.targets` | planned |  |
| Import URL List… | Import |  | `file.import.urls` | planned |  |
| Encrypt Workspace with Password… | Info |  | `file.encrypt` | planned | Findings and request logs are sensitive; AES-256 at rest |
| Workspace Properties… | Info |  | `file.properties` | planned |  |
| New Workspace | New | Ctrl+N | `file.new` | planned | A workspace holds targets, scans, findings and fixes |
| Clear Unpinned Recent Workspaces | Open |  | `file.clearRecent` | planned |  |
| Open Recent | Open |  | `file.openRecent` | planned | menu |
| Open… | Open | Ctrl+O | `file.open` | planned |  |
| Customize Keyboard… | Options |  | `file.customizeKeyboard` | planned |  |
| Customize Quick Access Bar… | Options |  | `file.customizeQat` | planned |  |
| Customize Tabs… | Options |  | `file.customizeRibbon` | planned |  |
| Export / Import Settings… | Options |  | `file.exportSettings` | planned |  |
| Options… | Options |  | `file.options` | planned |  |
| Reset All Customizations | Options |  | `file.resetCustomizations` | planned |  |
| Print Report | Print | Ctrl+P | `file.print` | planned |  |
| AutoSave | Save |  | `file.autosave` | planned | toggle |
| Save | Save | Ctrl+S | `file.save` | planned |  |
| Save As… | Save | F12 | `file.saveAs` | planned |  |
| Share… | Share |  | `file.share` | planned |  |

## Verify (10)

| Command | Group | Shortcut | ID | Status | Notes |
|---|---|---|---|---|---|
| Check Verification | Challenge | Ctrl+Shift+K | `verify.check` | implemented | Fetch the published file and record the origin as verified when it matches |
| Check via DNS | Challenge |  | `verify.checkDns` | implemented | Verify with the _quilltest-challenge TXT record instead of a file |
| Issue Challenge | Challenge | Ctrl+Shift+V | `verify.issue` | implemented | Generate the verification file (and DNS record) for an origin |
| Save Verification File… | Challenge |  | `verify.writeFile` | implemented | Write the verification file into a local web root (.well-known/quilltest-verification/) |
| How Verification Works | Help |  | `verify.help` | planned | Open docs/OWNERSHIP-VERIFICATION.md |
| Cancel Challenge | Manage |  | `verify.cancel` | implemented |  |
| Re-verify Before Expiry | Manage |  | `verify.reverify` | planned | Issue and check a fresh challenge while the current record is still valid |
| Revoke Verification | Manage |  | `verify.revoke` | implemented | Remove a verification record; the origin must be verified again before scanning |
| All Verifications | Status |  | `verify.list` | implemented | Pending challenges and verification records |
| Verification Status | Status |  | `verify.status` | implemented | Is scanning this origin permitted right now? |

## Scan (22)

| Command | Group | Shortcut | ID | Status | Notes |
|---|---|---|---|---|---|
| Pause | Control |  | `scan.pause` | planned | acts on the active target |
| Resume | Control |  | `scan.resume` | planned | *gated* |
| Stop | Control | Shift+F5 | `scan.stop` | planned | acts on the active target |
| Crawl Depth | Crawl |  | `scan.crawlDepth` | planned | acts on the active target; combo |
| Crawl Limits… | Crawl |  | `scan.crawlLimits` | planned | acts on the active target; Max pages, max time, max requests |
| Crawl Only (no checks) | Crawl |  | `scan.spiderOnly` | planned | *gated* |
| Import URL List… | Crawl |  | `scan.importUrls` | planned | acts on the active target; inspired by Burp target site map import |
| Seed from sitemap.xml | Crawl |  | `scan.sitemap` | planned | acts on the active target; toggle |
| Compare with Previous Scan | History |  | `scan.diff` | planned | acts on the active target; findings diff — see INNOVATIONS.md |
| Re-run Last Scan | History |  | `scan.rescan` | planned | *gated* |
| Request Log | History |  | `scan.log` | planned | acts on the active target; Every request QuillTest sent, for audit |
| Scan History | History |  | `scan.history` | planned | acts on the active target |
| Schedule… | History |  | `scan.schedule` | planned | acts on the active target; Recurring scans; each run re-checks verification first |
| Intrusiveness Cap | Profile |  | `scan.intrusiveness` | planned | acts on the active target; combo; Highest intrusiveness level a check may use in this scan |
| Manage Profiles… | Profile |  | `scan.profiles` | planned |  |
| Scan Preview | Profile |  | `scan.preview` | planned | acts on the active target; What this profile would do: checks, request budget, intrusiveness; scan-as-you-configure preview — INNOVATIONS.md |
| Scan Profile | Profile |  | `scan.profile` | planned | acts on the active target; menu; Passive / Standard / Thorough / Custom |
| Active Scan | Run |  | `scan.active` | planned | *gated*; Detection probes for injection, XSS, access control… least-intrusive probe that proves a finding, then stop |
| Passive Scan | Run |  | `scan.passive` | planned | *gated*; Crawl and observe only: headers, cookies, TLS, disclosure. No test inputs are sent. |
| Quick Scan | Run |  | `scan.quick` | planned | *gated*; Passive checks plus the fastest active ones on the entry page |
| Scan Single URL | Run |  | `scan.single` | planned | *gated* |
| Start Scan | Run | F5 | `scan.start` | planned | *gated*; Run the active profile against the active target |

## Targets (19)

| Command | Group | Shortcut | ID | Status | Notes |
|---|---|---|---|---|---|
| Extra Request Headers… | Authentication |  | `target.headers` | planned | acts on the active target; e.g. a bug-bounty identification header |
| Record Login Sequence… | Authentication |  | `target.sessionRecord` | planned | acts on the active target; inspired by ZAP authentication scripts and Burp session handling |
| Scan Credentials… | Authentication |  | `target.credentials` | planned | acts on the active target; Per-scan login for authenticated checks; never persisted |
| Confirm Authorization… | Authorization |  | `target.confirmAuthorization` | implemented | Record your statement that you are authorized to test this target; required in addition to ownership verification |
| Withdraw Authorization | Authorization |  | `target.revokeAuthorization` | implemented |  |
| Export Targets… | Exchange |  | `target.export` | planned |  |
| Import Targets… | Exchange |  | `target.import` | planned | From a text file, one origin per line, or a QuillTest targets JSON |
| Honor robots.txt | Politeness |  | `target.robots` | planned | acts on the active target; toggle |
| Rate Limit… | Politeness |  | `target.rateLimit` | planned | acts on the active target; Requests per second and concurrency cap for this target |
| Is URL in Scope? | Scope |  | `target.inScope` | implemented |  |
| Scope… | Scope |  | `target.scope` | implemented | Limit a scan to path prefixes within the origin, and exclude paths (logout, destructive admin pages) |
| Add Target | Targets | Ctrl+T | `target.add` | implemented | Add an origin (scheme + host + port) to the target list |
| Edit Target… | Targets |  | `target.edit` | implemented | Rename, add notes or tags |
| Open in Browser | Targets |  | `target.open` | planned | acts on the active target |
| Remove Target | Targets |  | `target.remove` | implemented |  |
| Select Active Target | Targets |  | `target.select` | implemented |  |
| Target List | Targets |  | `target.list` | implemented |  |
| Target Notes | Targets |  | `target.notes` | implemented | acts on the active target; not in tabs |
| Target Status | Targets |  | `target.status` | implemented | Verification, authorization and scan readiness for a target |

## Checks (15)

| Command | Group | Shortcut | ID | Status | Notes |
|---|---|---|---|---|---|
| Disable Category | Categories |  | `checks.disableCategory` | planned |  |
| Enable Category | Categories |  | `checks.enableCategory` | planned |  |
| Passive Checks Only | Categories |  | `checks.passiveOnly` | planned | toggle |
| All Checks | Checks |  | `checks.list` | planned |  |
| Check Details | Checks |  | `checks.details` | planned | What it detects, how, intrusiveness, CWE/OWASP mapping, remediation |
| Disable Check | Checks |  | `checks.disable` | planned |  |
| Enable Check | Checks |  | `checks.enable` | planned |  |
| Export Checks… | Custom |  | `checks.export` | planned |  |
| Import Checks… | Custom |  | `checks.import` | planned |  |
| New Custom Check… | Custom |  | `checks.custom` | planned | Pattern/response-based detection check; no payload fields by design |
| Update Check Signatures | Custom |  | `checks.update` | planned | Component fingerprints and known-vulnerable version data |
| Group by ASVS | View |  | `checks.byAsvs` | planned | toggle |
| Group by CWE | View |  | `checks.byCwe` | planned | toggle |
| Group by OWASP Top 10 | View |  | `checks.byOwasp` | planned | toggle |
| Search Checks | View |  | `checks.search` | planned |  |

## Findings (24)

| Command | Group | Shortcut | ID | Status | Notes |
|---|---|---|---|---|---|
| Add Note | Annotate |  | `findings.note` | planned |  |
| Assign To… | Annotate |  | `findings.assign` | planned |  |
| Tag | Annotate |  | `findings.tag` | planned |  |
| Finding Details | Browse |  | `findings.details` | planned | Evidence, request/response excerpt, mapping, remediation |
| Findings | Browse | Ctrl+Shift+F | `findings.list` | planned |  |
| Next Finding | Browse | F8 | `findings.next` | planned |  |
| Previous Finding | Browse | Shift+F8 | `findings.prev` | planned |  |
| Search Findings | Browse |  | `findings.search` | planned |  |
| Copy Finding | Exchange |  | `findings.copy` | planned | Markdown summary to the clipboard |
| Export Findings… | Exchange |  | `findings.export` | planned | JSON, CSV, SARIF |
| Import Findings… | Exchange |  | `findings.import` | planned | From a previous QuillTest export, for comparison |
| Attacker's-Eye Priority | Organize |  | `findings.prioritize` | planned | Order by what an attacker would exploit first (deterministic; AI can refine); INNOVATIONS.md |
| Filter | Organize |  | `findings.filter` | planned | menu; By severity, confidence, category, status, URL |
| Group By | Organize |  | `findings.group` | planned | menu; Severity, OWASP category, CWE, URL, check |
| Merge Duplicates | Organize |  | `findings.dedupe` | planned |  |
| Sort | Organize |  | `findings.sort` | planned | menu |
| Accept Risk… | Triage |  | `findings.markAccepted` | planned | Record a reason; shown in the report |
| False-Positive Rules | Triage |  | `findings.falsePositives` | planned | Signatures remembered for this target |
| Mark False Positive | Triage |  | `findings.markFalsePositive` | planned | Remembered for future scans of this target; false-positive learning loop — INNOVATIONS.md |
| Mark Fixed | Triage |  | `findings.markFixed` | planned |  |
| Re-check Finding | Triage |  | `findings.recheck` | planned | *gated*; Run just this check again to confirm a fix |
| Set Confidence | Triage |  | `findings.setConfidence` | planned | menu |
| Set Severity | Triage |  | `findings.setSeverity` | planned | menu |
| Unmark False Positive | Triage |  | `findings.unmarkFalsePositive` | planned | not in tabs |

## Fix (22)

| Command | Group | Shortcut | ID | Status | Notes |
|---|---|---|---|---|---|
| Content-Security-Policy Builder | Generators |  | `fix.csp` | planned | Built from the sources the crawl observed; starts in report-only |
| Cookie Flags | Generators |  | `fix.cookies` | planned | Secure, HttpOnly, SameSite per cookie, per platform |
| CORS Policy | Generators |  | `fix.cors` | planned |  |
| Dependency Update | Generators |  | `fix.dependencyBump` | planned | Version bump for a detected vulnerable component |
| Hide Version Banners | Generators |  | `fix.hideVersions` | planned |  |
| Redirect Allow-List | Generators |  | `fix.redirects` | planned |  |
| Security Headers — Apache | Generators |  | `fix.headersApache` | planned |  |
| Security Headers — Caddy | Generators |  | `fix.headersCaddy` | planned |  |
| Security Headers — Framework Middleware | Generators |  | `fix.headersMiddleware` | planned | helmet, django-csp/SecurityMiddleware, Rails, Spring Security… |
| Security Headers — IIS web.config | Generators |  | `fix.headersIis` | planned |  |
| Security Headers — nginx | Generators |  | `fix.headersNginx` | planned |  |
| TLS Configuration | Generators |  | `fix.tls` | planned | Protocol/cipher recommendations per server |
| Target Platform | Platform |  | `fix.targetPlatform` | planned | combo; nginx, Apache, Caddy, IIS, Express, Django, Rails, Spring, static host… detected, overridable |
| Copy Snippet | Remediate |  | `fix.copySnippet` | planned |  |
| Download Patch / Config | Remediate |  | `fix.downloadPatch` | planned | A diff or config file to review and deploy yourself; QuillTest never changes a live site |
| Explain Fix | Remediate |  | `fix.explain` | planned | Why this change closes the finding, and what it might break |
| Generate All Fixes | Remediate |  | `fix.generateAll` | planned |  |
| Generate Fix | Remediate | Ctrl+Shift+X | `fix.generate` | planned | The remediation for the selected finding, matched to the detected server/framework |
| Preview Fix | Remediate |  | `fix.preview` | planned |  |
| Mark Fix Applied | Track |  | `fix.markApplied` | planned |  |
| Re-check After Fix | Track |  | `fix.recheck` | planned | *gated* |
| Remediation Plan | Track |  | `fix.plan` | planned | All fixes ordered by priority, with effort estimates |

## AI (21)

| Command | Group | Shortcut | ID | Status | Notes |
|---|---|---|---|---|---|
| Ask About This Finding… | Analyze |  | `ai.askAboutFinding` | planned |  |
| Attacker's-Eye Ranking | Analyze |  | `ai.prioritize` | planned |  |
| Confirm CWE / OWASP Mapping | Analyze |  | `ai.mapCwe` | planned |  |
| Explain Finding | Analyze |  | `ai.explain` | planned | Plain-language risk explanation for the selected finding |
| Flag False Positives | Analyze |  | `ai.falsePositives` | planned |  |
| Triage Findings | Analyze |  | `ai.triage` | planned | Deduplicate, rank by exploitability, flag likely false positives |
| Draft Remediation | Fix |  | `ai.draftFix` | planned | Refine the generated fix for the detected stack |
| Refine Remediation | Fix |  | `ai.refineFix` | planned |  |
| Draft Executive Summary | Report |  | `ai.summary` | planned |  |
| Active Provider | Setup |  | `ai.active` | implemented | combo; Which configured provider analysis uses; pass a provider id to switch |
| AI Setup Wizard | Setup |  | `ai.setup` | implemented | Choose a provider and model, test the connection, save quilltest.ai.json |
| Dry Run (show prompt, send nothing) | Setup |  | `ai.dryRun` | planned | toggle |
| Preview Secret Scrubbing | Setup |  | `ai.scrubPreview` | planned | not in tabs; Exactly which fragments would leave the machine, after scrubbing |
| Prompt Library | Setup |  | `ai.prompts` | planned | The exact prompts QuillTest uses; read-only guardrails are marked |
| Providers | Setup |  | `ai.providers` | implemented | Supported providers and which are configured |
| Stop AI Request | Setup |  | `ai.stop` | planned |  |
| Test Connection | Setup |  | `ai.test` | implemented |  |
| What Is Sent to the AI | Setup |  | `ai.privacy` | implemented |  |
| Ensemble Members… | Several AIs |  | `ai.ensembleMembers` | planned |  |
| Several AIs | Several AIs |  | `ai.ensembleMode` | planned | toggle; Ask multiple configured providers and show where they agree; QuillStage ensemble mode |
| Show Deliberation | Several AIs |  | `ai.showDeliberation` | planned | toggle |

## Report (19)

| Command | Group | Shortcut | ID | Status | Notes |
|---|---|---|---|---|---|
| Executive Summary | Build |  | `report.executiveSummary` | planned |  |
| Generate Report | Build | Ctrl+Shift+R | `report.generate` | planned | Includes the verification record and your authorization statement for each target |
| Preview | Build |  | `report.preview` | planned |  |
| Remediation Plan | Build |  | `report.remediationPlan` | planned |  |
| Technical Report | Build |  | `report.technical` | planned |  |
| Compare Two Scans | Compare |  | `report.compare` | planned | New, fixed and persisting findings between scans |
| Trend Over Time | Compare |  | `report.trend` | planned |  |
| Export CSV | Export |  | `report.exportCsv` | planned |  |
| Export HTML | Export |  | `report.exportHtml` | planned |  |
| Export JSON | Export |  | `report.exportJson` | planned |  |
| Export Markdown | Export |  | `report.exportMarkdown` | planned |  |
| Export PDF | Export |  | `report.exportPdf` | planned |  |
| Export SARIF | Export |  | `report.exportSarif` | planned |  |
| Print | Export | Ctrl+P | `report.print` | planned |  |
| Scheduled Reports… | Export |  | `report.schedule` | planned |  |
| Branding… | Style |  | `report.branding` | planned | Logo, colors, footer, classification label |
| Redact Sensitive Values | Style |  | `report.redact` | planned | toggle; Cookies, tokens and credentials in evidence excerpts |
| Sections… | Style |  | `report.sections` | planned |  |
| Template | Style |  | `report.template` | planned | gallery |

## Review (13)

| Command | Group | Shortcut | ID | Status | Notes |
|---|---|---|---|---|---|
| Audit Log | Audit |  | `review.auditLog` | planned | Who verified, authorized, scanned, changed what, when |
| Change History | Audit |  | `review.history` | planned |  |
| Check Report | Audit |  | `review.checkReport` | planned | Missing remediations, unreviewed findings, unredacted secrets |
| Compare Findings | Audit |  | `review.compareFindings` | planned |  |
| Comment | Comments |  | `review.comment` | planned |  |
| Comments Pane | Comments |  | `review.comments` | planned | toggle |
| Resolve Comment | Comments |  | `review.resolveComment` | planned |  |
| Approve Finding | Review |  | `review.approve` | planned | Confirmed real; goes to the report |
| Needs More Information | Review |  | `review.needsInfo` | planned |  |
| Reject Finding | Review |  | `review.reject` | planned | Not real or out of scope; recorded with a reason |
| Review Queue | Review |  | `review.queue` | planned | Findings awaiting a human decision |
| Assign Reviewer… | Workflow |  | `review.assign` | planned |  |
| Sign Off Scan | Workflow |  | `review.signoff` | planned | Locks the findings of this scan; later changes are tracked as amendments |

## Share (9)

| Command | Group | Shortcut | ID | Status | Notes |
|---|---|---|---|---|---|
| CI Snippet | Integrate |  | `share.ci` | planned | Run this scan from CI; verification is re-checked on every run |
| Create Issue… | Integrate |  | `share.issueTracker` | planned | GitHub / GitLab / Jira issue from a finding, with the fix attached |
| Webhook… | Integrate |  | `share.webhook` | planned |  |
| Export Workspace Bundle | Package |  | `share.bundle` | planned |  |
| Redacted Copy | Package |  | `share.redactedCopy` | planned | Strips cookies, tokens, credentials and request bodies |
| Review Package… | Package |  | `share.package` | planned | Report + findings + fixes in one archive for a reviewer; export-ready review packages — INNOVATIONS.md |
| Copy Finding Link | Send |  | `share.copyLink` | planned |  |
| Email Report | Send |  | `share.email` | planned | Uses QuillPost when installed |
| Share… | Send |  | `share.system` | planned | System share sheet |

## View (17)

| Command | Group | Shortcut | ID | Status | Notes |
|---|---|---|---|---|---|
| Theme | Appearance |  | `view.theme` | planned | menu; Light, dark, system, high contrast |
| Touch Mode | Appearance |  | `view.touchMode` | planned | toggle |
| Add All Commands to Quick Access Bar | Customize |  | `view.qatAddAll` | planned |  |
| Quick Access Bar Position | Customize |  | `view.qatPosition` | planned | menu |
| Command Search | Find | Alt+Q | `view.cmdSearch` | implemented | Find any command by name |
| Details Pane | Panes |  | `view.detailsPane` | planned | toggle |
| Findings Pane | Panes |  | `view.findingsPane` | planned | toggle |
| Log Pane | Panes |  | `view.logPane` | planned | toggle |
| Request / Response Viewer | Panes |  | `view.requestViewer` | planned | toggle |
| Site Map | Panes |  | `view.sitemap` | planned | toggle; inspired by ZAP Sites tree and Burp Target site map |
| Targets Pane | Panes |  | `view.targetsPane` | planned | toggle |
| Dashboard | Views |  | `view.dashboard` | planned | Severity counts, scan status, verification expiry |
| Full Screen | Window | F11 | `view.fullScreen` | planned |  |
| Status Bar | Window |  | `view.statusBar` | planned | toggle |
| Reset Zoom | Zoom | Ctrl+0 | `view.zoomReset` | planned |  |
| Zoom In | Zoom | Ctrl+= | `view.zoomIn` | planned |  |
| Zoom Out | Zoom | Ctrl+- | `view.zoomOut` | planned |  |

## Developer (10)

| Command | Group | Shortcut | ID | Status | Notes |
|---|---|---|---|---|---|
| Application Logs | Diagnostics |  | `dev.logs` | planned |  |
| Diagnostics | Diagnostics |  | `dev.diagnostics` | planned |  |
| Reset Application State | Diagnostics |  | `dev.resetState` | planned |  |
| Macros… | Macros |  | `dev.macros` | implemented |  |
| Record Macro | Macros |  | `dev.recordMacro` | implemented | Every command run until Stop Recording becomes a step |
| Run Macro | Macros |  | `dev.runMacro` | implemented |  |
| Stop Recording | Macros |  | `dev.stopRecording` | implemented |  |
| Command API Reference | Scripting |  | `dev.api` | implemented |  |
| Command Console | Scripting |  | `dev.console` | planned | Run commands by id with JSON arguments |
| Scripts… | Scripting |  | `dev.scripts` | planned | JavaScript automation over the command API |

## Help (12)

| Command | Group | Shortcut | ID | Status | Notes |
|---|---|---|---|---|---|
| About QuillTest | Help |  | `help.about` | implemented |  |
| Check for Updates | Help |  | `help.updates` | implemented |  |
| Command Reference | Help |  | `help.commandReference` | implemented | Every command, by tab |
| Help | Help | F1 | `help.help` | implemented |  |
| Keyboard Shortcuts | Help |  | `help.shortcuts` | implemented |  |
| Report a Problem / Feedback | Help |  | `help.feedback` | implemented |  |
| Third-Party Notices | Help |  | `help.notices` | planned |  |
| Tour | Help |  | `help.tour` | planned |  |
| What's New | Help |  | `help.whatsNew` | implemented |  |
| About Ownership Verification | Policy |  | `help.verification` | implemented |  |
| Legal Notes | Policy |  | `help.legal` | implemented |  |
| Scope and Ethics | Policy |  | `help.ethics` | implemented |  |
