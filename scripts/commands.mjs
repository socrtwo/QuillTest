#!/usr/bin/env node
/*
 * Anne's Test — command catalogue (the CLI face of the Alt+Q palette)
 * Part of the Anne's Office suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 *   node scripts/commands.mjs                 # list every command by group
 *   node scripts/commands.mjs <query>         # search (what the palette does)
 *   node scripts/commands.mjs --json          # the registry as JSON
 *   node scripts/commands.mjs --id scan.active
 *
 * The registry (src/commands/registry.mjs) is the single source of truth for
 * what Anne's Test can do; the future shell renders the same data.
 */
import { argv, exit } from 'node:process';
import { COMMANDS, GROUPS, commandsByGroup, searchCommands, getCommand, commandCliLine, validateRegistry } from '../src/commands/registry.mjs';

const c = { bold: (s) => `\x1b[1m${s}\x1b[0m`, dim: (s) => `\x1b[2m${s}\x1b[0m`, green: (s) => `\x1b[32m${s}\x1b[0m` };

function parseArgs(args) {
  const out = { _: [] };
  for (let i = 0; i < args.length; i++) { const a = args[i]; if (!a.startsWith('--')) { out._.push(a); continue; } const k = a.slice(2), n = args[i + 1]; if (n === undefined || n.startsWith('--')) out[k] = true; else { out[k] = n; i++; } }
  return out;
}
const args = parseArgs(argv.slice(2));

if (args.help) {
  console.log(`Anne\'s Test commands — list or search the command registry\n  node scripts/commands.mjs [query] [--json] [--id <command-id>] [--validate]`);
  exit(0);
}
if (args.validate) { const r = validateRegistry(); if (r.ok) console.log(c.green(`registry ok (${COMMANDS.length} commands)`)); else { for (const e of r.errors) console.error('  ' + e); } exit(r.ok ? 0 : 1); }

const printCmd = (cmd, { full = false } = {}) => {
  console.log(`  ${c.bold(cmd.id.padEnd(16))} ${cmd.title}`);
  if (full) {
    console.log(c.dim(`    ${cmd.summary}`));
    const line = commandCliLine(cmd);
    if (line) console.log(c.dim(`    ${line}`));
    if (cmd.keywords?.length) console.log(c.dim(`    keywords: ${cmd.keywords.join(', ')}`));
  }
};

if (typeof args.id === 'string') {
  const cmd = getCommand(args.id);
  if (!cmd) { console.error(`No command ${args.id}`); exit(1); }
  if (args.json) console.log(JSON.stringify(cmd, null, 2)); else printCmd(cmd, { full: true });
  exit(0);
}

const query = args._.join(' ').trim();
if (args.json) { console.log(JSON.stringify(query ? searchCommands(query) : COMMANDS, null, 2)); exit(0); }

if (query) {
  const hits = searchCommands(query);
  if (!hits.length) { console.log(`No command matches "${query}".`); exit(1); }
  console.log(c.bold(`${hits.length} match(es) for "${query}"`));
  for (const cmd of hits) printCmd(cmd, { full: true });
} else {
  for (const [group, cmds] of commandsByGroup()) {
    if (!cmds.length) continue;
    console.log(c.bold(`\n${group}`));
    for (const cmd of cmds) printCmd(cmd);
  }
  console.log(c.dim(`\n${COMMANDS.length} commands across ${GROUPS.length} groups. Search: node scripts/commands.mjs <query>`));
}
