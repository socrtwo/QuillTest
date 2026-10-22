/** Help tab. */
import { def, allCommands, implementedCommands } from './registry.mjs';
import { readFileSync } from 'node:fs';

const REPO = 'https://github.com/socrtwo/QuillTest';
const doc = (name) => () => readFileSync(new URL(`../../docs/${name}`, import.meta.url), 'utf8');
const pkg = JSON.parse(readFileSync(new URL('../../package.json', import.meta.url), 'utf8'));

def([
  { id: 'help.help', label: 'Help', icon: 'help', tab: 'Help', group: 'Help', keys: ['F1'], noRecord: true, run: () => readFileSync(new URL('../../README.md', import.meta.url), 'utf8') },
  { id: 'help.shortcuts', label: 'Keyboard Shortcuts', icon: 'keyboard', tab: 'Help', group: 'Help', noRecord: true, run: () => allCommands().filter((c) => c.keys?.length).map((c) => ({ id: c.id, label: c.label, keys: c.keys })) },
  {
    id: 'help.commandReference', label: 'Command Reference', icon: 'menu_book', tab: 'Help', group: 'Help', noRecord: true, tip: 'Every command, by tab',
    run: () => allCommands().map((c) => ({ id: c.id, label: c.label, tab: c.tab, group: c.group, keys: c.keys || [], implemented: typeof c.run === 'function', requiresVerification: Boolean(c.requiresVerification) })),
  },
  { id: 'help.ethics', label: 'Scope and Ethics', icon: 'balance', tab: 'Help', group: 'Policy', noRecord: true, run: doc('ETHICS.md') },
  { id: 'help.legal', label: 'Legal Notes', icon: 'gavel', tab: 'Help', group: 'Policy', noRecord: true, run: doc('LEGAL.md') },
  { id: 'help.verification', label: 'About Ownership Verification', icon: 'verified_user', tab: 'Help', group: 'Policy', noRecord: true, run: doc('OWNERSHIP-VERIFICATION.md') },
  { id: 'help.tour', label: 'Tour', icon: 'tour', tab: 'Help', group: 'Help', noRecord: true },
  { id: 'help.whatsNew', label: "What's New", icon: 'new_releases', tab: 'Help', group: 'Help', noRecord: true, run: () => ({ url: `${REPO}/releases` }) },
  { id: 'help.feedback', label: 'Report a Problem / Feedback', icon: 'feedback', tab: 'Help', group: 'Help', noRecord: true, run: () => ({ url: `${REPO}/issues/new/choose` }) },
  { id: 'help.updates', label: 'Check for Updates', icon: 'system_update', tab: 'Help', group: 'Help', noRecord: true, run: () => ({ url: `${REPO}/releases/latest`, version: pkg.version }) },
  { id: 'help.notices', label: 'Third-Party Notices', icon: 'gavel', tab: 'Help', group: 'Help', noRecord: true },
  {
    id: 'help.about', label: 'About QuillTest', icon: 'info', tab: 'Help', group: 'Help', noRecord: true,
    run: () => ({ name: 'QuillTest', version: pkg.version, license: 'MIT', repo: REPO, commands: allCommands().length, implemented: implementedCommands().length, suite: ['QuillPen', 'QuillGrid', 'QuillPost', 'QuillStage', 'QuillLoom', 'QuillPress', 'QuillFolio'] }),
  },
]);
