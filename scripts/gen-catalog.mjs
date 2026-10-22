#!/usr/bin/env node
/*
 * QuillTest — generate docs/COMMANDS.md from the live command registry
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 *   node scripts/gen-catalog.mjs            # write docs/COMMANDS.md
 *   node scripts/gen-catalog.mjs --check    # exit 1 if out of date
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { allCommands, implementedCommands } from '../src/commands/index.mjs';
import { DEFAULT_TABS, BACKSTAGE_SECTIONS, DEFAULT_QAT, placedIds } from '../src/ui/ribbonLayout.mjs';

export const CATALOG_PATH = resolve(dirname(fileURLToPath(import.meta.url)), '../docs/COMMANDS.md');

const TAB_ORDER = ['File', 'Verify', 'Scan', 'Targets', 'Checks', 'Findings', 'Fix', 'AI', 'Report', 'Review', 'Share', 'View', 'Developer', 'Help'];

export function catalog() {
  const cmds = allCommands();
  const impl = implementedCommands().length;
  const placed = placedIds();
  const notInTabs = cmds.filter((x) => !placed.has(x.id)).length;
  const gated = cmds.filter((x) => x.requiresVerification).length;
  const lines = [];
  lines.push('# QuillTest Command Reference', '');
  lines.push(`QuillTest defines **${cmds.length} commands**. Every one can be placed on the Quick Access Bar, added to a custom tab, bound to a keyboard shortcut, recorded in a macro, run from the command line (\`node scripts/quilltest.mjs <id>\`) or found with command search (Alt+Q).`, '');
  lines.push(`**${impl} are implemented** and **${cmds.length - impl} are planned** (defined as data, with no implementation yet; running one reports "planned but not implemented"). ${notInTabs} ${notInTabs === 1 ? 'command is' : 'commands are'} "not in tabs" — reachable through the Quick Access Bar chooser, Customize Tabs, command search and the command line — so nothing is hidden.`, '');
  lines.push(`**${gated} commands are gated.** Marked *gated* below, they send requests to the target, and the executor refuses to run them unless the active target's origin has a current ownership verification **and** you have confirmed authorization for that target (see [OWNERSHIP-VERIFICATION.md](OWNERSHIP-VERIFICATION.md) and [ETHICS.md](ETHICS.md)). This is enforced in \`src/commands/exec.mjs\`, not in the UI.`, '');
  lines.push('This file is generated from the source by `npm run catalog`; a unit test fails when it is out of date.', '');
  lines.push('## Default tab layout', '');
  lines.push(`- **File** (Backstage): ${BACKSTAGE_SECTIONS.map((s) => s.label).join(' · ')}`);
  for (const t of DEFAULT_TABS) lines.push(`- **${t.label}**${t.hidden ? ' (not shown by default)' : ''}: ${t.groups.map((g) => g.label).join(' · ')}`);
  lines.push('', `Default Quick Access Bar: ${DEFAULT_QAT.map((id) => `\`${id}\``).join(', ')}`, '');

  for (const tab of TAB_ORDER) {
    const list = cmds.filter((x) => x.tab === tab).sort((a, b) => a.group.localeCompare(b.group) || a.label.localeCompare(b.label));
    if (!list.length) continue;
    lines.push(`## ${tab} (${list.length})`, '', '| Command | Group | Shortcut | ID | Status | Notes |', '|---|---|---|---|---|---|');
    for (const x of list) {
      const notes = [];
      if (x.requiresVerification) notes.push('*gated*');
      else if (x.requiresTarget) notes.push('acts on the active target');
      if (!placed.has(x.id)) notes.push('not in tabs');
      if (x.kind && x.kind !== 'button') notes.push(x.kind);
      if (x.tip) notes.push(x.tip);
      if (x.origin) notes.push(x.origin);
      lines.push(`| ${x.label} | ${x.group} | ${(x.keys || []).join(', ')} | \`${x.id}\` | ${typeof x.run === 'function' ? 'implemented' : 'planned'} | ${notes.join('; ').replace(/\|/g, '\\|')} |`);
    }
    lines.push('');
  }
  const unknownTab = cmds.filter((x) => !TAB_ORDER.includes(x.tab));
  if (unknownTab.length) throw new Error(`Commands with an unknown tab: ${unknownTab.map((x) => `${x.id} (${x.tab})`).join(', ')}`);
  return lines.join('\n');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const wanted = catalog();
  let current = '';
  try { current = readFileSync(CATALOG_PATH, 'utf8'); } catch { /* first run */ }
  if (process.argv.includes('--check')) {
    if (current !== wanted) { console.error('docs/COMMANDS.md is out of date; run: npm run catalog'); process.exit(1); }
    console.log('docs/COMMANDS.md is up to date');
  } else {
    writeFileSync(CATALOG_PATH, wanted);
    console.log(current === wanted ? 'docs/COMMANDS.md unchanged' : 'Wrote docs/COMMANDS.md');
  }
}
