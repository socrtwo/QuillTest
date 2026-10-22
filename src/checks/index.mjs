/*
 * QuillTest — all checks
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 * Importing this module registers every check. Only passive checks exist yet (M2).
 */
import './passive/transport.mjs';
import './passive/headers.mjs';
import './passive/cookies.mjs';
import './passive/cors.mjs';
import './passive/disclosure.mjs';
import './passive/components.mjs';
import './passive/content.mjs';

export * from './registry.mjs';
