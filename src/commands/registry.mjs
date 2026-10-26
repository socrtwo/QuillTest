/*
 * Anne's Test — command registry (commands are data, not code)
 * Part of the Anne's Office suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * The Anne's Office suite's organizing principle is "no missing commands": every
 * operation is a registry entry with an id, a human title, the ribbon group it
 * belongs to, search keywords, and a descriptor of how it maps to the CLI
 * today. The shell (ribbon, quick-access bar, Alt+Q command palette) and the
 * CLI are both thin dispatchers over this data; adding a capability is adding
 * an entry here, not wiring a new UI.
 *
 * Nothing in this file executes anything. `cli` is a description of the command
 * line that performs the operation, so a palette can show it and a dispatcher
 * can build it; `when` names a precondition the shell can evaluate (e.g. a
 * command that needs a verified target). Keeping it declarative is what lets
 * the same list drive a CLI, a desktop shell and a web build without
 * duplicating the catalogue.
 */

/** Ribbon groups, in tab order (mirrors the office-suite layout in the README). */
export const GROUPS = ['File', 'Verify', 'Targets', 'Scan', 'Fix', 'AI', 'Report', 'Help'];

/** Preconditions a shell can evaluate before offering/enabling a command. */
export const CONDITIONS = {
  always: 'Always available.',
  hasTarget: 'A target origin must be selected or supplied.',
  targetVerified: 'The selected target must have a current ownership verification.',
  hasReport: 'A saved scan report is required.',
  aiConfigured: 'quilltest.ai.json must exist and validate.',
};

/**
 * @typedef {object} Command
 * @property {string} id            stable dotted id (group.verb)
 * @property {string} title         human label for the ribbon/palette
 * @property {string} group         one of GROUPS
 * @property {string} summary       one line shown in the palette
 * @property {string[]} keywords    extra search terms
 * @property {string} when          a key of CONDITIONS
 * @property {{script:string, args:string[], flags?:string[]}} [cli]  how it runs today
 * @property {string} [shortcut]    suggested accelerator
 */

/** @type {Command[]} */
export const COMMANDS = [
  // File
  { id: 'file.help', title: 'Help & documentation', group: 'File', summary: 'Open the docs index.', keywords: ['docs', 'about', 'readme'], when: 'always', cli: { script: 'README.md', args: [] } },

  // Verify
  { id: 'verify.issue', title: 'Issue ownership challenge', group: 'Verify', summary: 'Get the verification file (and DNS TXT alternative) to prove you own an origin.', keywords: ['prove', 'ownership', 'challenge', 'token', 'dns', 'well-known'], when: 'hasTarget', cli: { script: 'scripts/scan.mjs', args: ['verify', 'issue', '<origin>'], flags: ['--ttl-hours'] } },
  { id: 'verify.check', title: 'Check ownership challenge', group: 'Verify', summary: 'Fetch the uploaded file or TXT record and record the origin as verified.', keywords: ['confirm', 'validate', 'ownership', 'unlock'], when: 'hasTarget', cli: { script: 'scripts/scan.mjs', args: ['verify', 'check', '<origin>'] } },
  { id: 'verify.list', title: 'List verified origins', group: 'Verify', summary: 'Show which origins are verified and when each expires.', keywords: ['status', 'expiry', 'records'], when: 'always', cli: { script: 'scripts/scan.mjs', args: ['verify', 'list'] } },

  // Targets
  { id: 'target.add', title: 'Add target', group: 'Targets', summary: 'Add an origin to your target list, with optional label and tags.', keywords: ['site', 'origin', 'new', 'manage'], when: 'hasTarget', cli: { script: 'scripts/targets.mjs', args: ['add', '<origin>'], flags: ['--label', '--tag', '--note'] } },
  { id: 'target.list', title: 'List targets', group: 'Targets', summary: 'Show your targets with verification and last-scan status.', keywords: ['sites', 'origins', 'manage', 'status'], when: 'always', cli: { script: 'scripts/targets.mjs', args: ['list'] } },
  { id: 'target.show', title: 'Show target', group: 'Targets', summary: 'Show one target in detail.', keywords: ['detail', 'info'], when: 'hasTarget', cli: { script: 'scripts/targets.mjs', args: ['show', '<origin>'] } },
  { id: 'target.remove', title: 'Remove target', group: 'Targets', summary: 'Remove an origin from your target list (does not touch verification).', keywords: ['delete', 'forget'], when: 'hasTarget', cli: { script: 'scripts/targets.mjs', args: ['remove', '<origin>'] } },

  // Scan
  { id: 'scan.passive', title: 'Passive scan', group: 'Scan', summary: 'Crawl and run the observation-only check set against a verified origin.', keywords: ['crawl', 'headers', 'cookies', 'cors', 'fingerprint', 'components'], when: 'targetVerified', cli: { script: 'scripts/scan.mjs', args: ['scan', '<origin>'], flags: ['--max-pages', '--max-depth', '--online-cve', '--fixes', '--export'] } },
  { id: 'scan.active', title: 'Active scan (safe profile)', group: 'Scan', summary: 'Add benign, non-state-changing probes: HTTP methods, open redirect, input reflection.', keywords: ['redirect', 'reflection', 'trace', 'profile', 'intrusive'], when: 'targetVerified', cli: { script: 'scripts/scan.mjs', args: ['scan', '<origin>', '--active'], flags: ['--profile', '--max-active-requests'] } },
  { id: 'scan.protocols', title: 'Protocol checks', group: 'Scan', summary: 'Observation-only TLS/FTP/mail/DNS checks for a verified host.', keywords: ['tls', 'ftp', 'smtp', 'imap', 'pop3', 'dns', 'ssl'], when: 'targetVerified', cli: { script: 'scripts/scan.mjs', args: ['protocols', '<host>'], flags: ['--which'] } },
  { id: 'mirror.capture', title: 'Capture staging mirror', group: 'Scan', summary: 'Capture a bounded same-origin snapshot of your verified site.', keywords: ['mirror', 'snapshot', 'copy', 'staging'], when: 'targetVerified', cli: { script: 'scripts/mirror.mjs', args: ['capture', '<origin>'], flags: ['--max-pages', '--max-bytes'] } },
  { id: 'mirror.serve', title: 'Serve staging mirror', group: 'Scan', summary: 'Replay a captured snapshot on a loopback address.', keywords: ['mirror', 'serve', 'loopback', 'replay'], when: 'always', cli: { script: 'scripts/mirror.mjs', args: ['serve', '<dir>'], flags: ['--port'] } },
  { id: 'mirror.scan', title: 'Scan staging mirror', group: 'Scan', summary: 'Scan a captured snapshot offline; findings name the real origin.', keywords: ['mirror', 'offline', 'reproducible'], when: 'targetVerified', cli: { script: 'scripts/mirror.mjs', args: ['scan', '<origin>'], flags: ['--dir', '--analyze'] } },

  // Fix
  { id: 'fix.artifacts', title: 'Generate fix artifacts', group: 'Fix', summary: 'Server header block, derived CSP, cookie settings and dependency bumps from a report.', keywords: ['remediation', 'headers', 'csp', 'cookies', 'nginx', 'apache'], when: 'hasReport', cli: { script: 'scripts/fix.mjs', args: ['--report', '<report>'], flags: ['--target', '--all', '--print'] } },
  { id: 'fix.patch', title: 'Generate applyable patch', group: 'Fix', summary: 'Emit a git apply-ready diff that bumps flagged versions in a manifest you provide.', keywords: ['diff', 'package.json', 'composer.json', 'upgrade', 'dependency'], when: 'hasReport', cli: { script: 'scripts/fix.mjs', args: ['--report', '<report>', '--patch', '<manifest>'] } },

  // AI
  { id: 'ai.setup', title: 'AI setup wizard', group: 'AI', summary: 'Configure providers and analysis mode in quilltest.ai.json.', keywords: ['providers', 'openai', 'anthropic', 'config', 'key'], when: 'always', cli: { script: 'scripts/ai-setup-wizard.mjs', args: [], flags: ['--providers', '--mode', '--test'] } },
  { id: 'ai.validate', title: 'Validate AI config', group: 'AI', summary: 'Check quilltest.ai.json against the schema without touching the network.', keywords: ['config', 'schema', 'check', 'lint'], when: 'always', cli: { script: 'scripts/ai-setup-wizard.mjs', args: ['--validate'], flags: ['--config'] } },
  { id: 'ai.analyze', title: 'AI analysis of findings', group: 'AI', summary: 'Have the configured providers triage findings and flag false positives.', keywords: ['triage', 'consensus', 'review', 'false positive'], when: 'aiConfigured', cli: { script: 'scripts/ai-analyze.mjs', args: ['--findings', '<findings>'], flags: ['--mode', '--dry-run'] } },

  // Report
  { id: 'report.render', title: 'Render report', group: 'Report', summary: 'Render a saved scan as self-contained HTML, Markdown or CSV.', keywords: ['html', 'markdown', 'csv', 'export', 'pdf'], when: 'hasReport', cli: { script: 'scripts/report.mjs', args: ['--report', '<report>'], flags: ['--format', '--out'] } },
  { id: 'report.diff', title: 'Diff two scans', group: 'Report', summary: 'Show new / resolved / changed findings between two scans.', keywords: ['compare', 'changes', 'delta', 'regression'], when: 'hasReport', cli: { script: 'scripts/report.mjs', args: ['--report', '<report>', '--diff', '<previous>'] } },
  { id: 'report.package', title: 'Build review package', group: 'Report', summary: 'Bundle the report, fixes and a SHA-256 manifest for a reviewer.', keywords: ['bundle', 'handover', 'manifest', 'review'], when: 'hasReport', cli: { script: 'scripts/report.mjs', args: ['--report', '<report>', '--package', '<dir>'] } },
  { id: 'report.verify', title: 'Verify review package', group: 'Report', summary: 'Check a package directory against its manifest.', keywords: ['integrity', 'checksum', 'tamper'], when: 'always', cli: { script: 'scripts/report.mjs', args: ['--verify', '<dir>'] } },

  // Help
  { id: 'help.docs', title: 'Documentation index', group: 'Help', summary: 'List the docs/ guides.', keywords: ['help', 'guide', 'manual'], when: 'always', cli: { script: 'docs/', args: [] } },
];

// ---------------------------------------------------------------------------
// Access + search
// ---------------------------------------------------------------------------

const byId = new Map(COMMANDS.map((c) => [c.id, c]));

export function getCommand(id) { return byId.get(id) || null; }

export function commandsByGroup() {
  const out = new Map(GROUPS.map((g) => [g, []]));
  for (const c of COMMANDS) { if (!out.has(c.group)) out.set(c.group, []); out.get(c.group).push(c); }
  return out;
}

const norm = (s) => String(s || '').toLowerCase();

/**
 * Score a command against a query for the Alt+Q palette. Higher is better;
 * 0 means no match. Ranking: exact id, id/title prefix, word-boundary in
 * title, substring in title, keyword hit, group hit.
 */
export function scoreCommand(cmd, query) {
  const q = norm(query).trim();
  if (!q) return 1; // empty query lists everything (stable order)
  const id = norm(cmd.id), title = norm(cmd.title), group = norm(cmd.group);
  if (id === q) return 100;
  if (id.startsWith(q) || title.startsWith(q)) return 80;
  if (new RegExp(`\\b${q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`).test(title)) return 60;
  if (title.includes(q)) return 50;
  if (id.includes(q)) return 45;
  if ((cmd.keywords || []).some((k) => norm(k).includes(q))) return 35;
  if (group.includes(q)) return 20;
  // multi-word query: all tokens must hit somewhere
  const toks = q.split(/\s+/).filter(Boolean);
  if (toks.length > 1) {
    const hay = `${id} ${title} ${group} ${(cmd.keywords || []).join(' ')}`.toLowerCase();
    if (toks.every((t) => hay.includes(t))) return 30;
  }
  return 0;
}

/**
 * Rank commands for a query. Returns matches sorted by score desc, then group
 * order, then title. An empty query returns all commands in catalogue order.
 * @param {string} query
 * @param {{limit?:number}} [opts]
 */
export function searchCommands(query, opts = {}) {
  const scored = COMMANDS.map((c) => ({ cmd: c, score: scoreCommand(c, query) })).filter((x) => x.score > 0);
  scored.sort((a, b) => b.score - a.score || GROUPS.indexOf(a.cmd.group) - GROUPS.indexOf(b.cmd.group) || a.cmd.title.localeCompare(b.cmd.title));
  const list = scored.map((x) => x.cmd);
  return typeof opts.limit === 'number' ? list.slice(0, opts.limit) : list;
}

/** Render a command's CLI descriptor as a copy-pasteable example line. */
export function commandCliLine(cmd) {
  if (!cmd?.cli) return null;
  const { script, args = [], flags = [] } = cmd.cli;
  if (!script.endsWith('.mjs')) return script; // a doc path, not a runnable script
  return `node ${script}${args.length ? ' ' + args.join(' ') : ''}${flags.length ? ' [' + flags.join('] [') + ']' : ''}`;
}

/**
 * Validate the registry: unique ids, known groups, known `when`, and a cli
 * descriptor or an explicit none. Returns { ok, errors[] }. Used by a test and
 * usable as a build check.
 */
export function validateRegistry() {
  const errors = [];
  const seen = new Set();
  for (const c of COMMANDS) {
    if (seen.has(c.id)) errors.push(`duplicate id ${c.id}`); seen.add(c.id);
    if (!/^[a-z]+\.[a-z-]+$/.test(c.id)) errors.push(`id not group.verb: ${c.id}`);
    if (!GROUPS.includes(c.group)) errors.push(`${c.id}: unknown group ${c.group}`);
    if (!CONDITIONS[c.when]) errors.push(`${c.id}: unknown when ${c.when}`);
    if (!c.title || !c.summary) errors.push(`${c.id}: missing title/summary`);
    if (!Array.isArray(c.keywords)) errors.push(`${c.id}: keywords must be an array`);
  }
  return { ok: errors.length === 0, errors };
}
