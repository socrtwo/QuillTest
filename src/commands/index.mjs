/*
 * QuillTest — all commands
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Importing this module registers every command. Import order is the default
 * catalog order.
 */
import './file.mjs';
import './verify.mjs';
import './target.mjs';
import './scan.mjs';
import './checks.mjs';
import './findings.mjs';
import './fix.mjs';
import './ai.mjs';
import './report.mjs';
import './review.mjs';
import './share.mjs';
import './view.mjs';
import './dev.mjs';
import './help.mjs';

export * from './registry.mjs';
export { exec, createContext, scanReadiness, UnknownCommandError, NotImplementedError, CommandDisabledError } from './exec.mjs';
