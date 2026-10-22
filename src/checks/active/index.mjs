/*
 * QuillTest — active checks (M3). Detection-only, run only on active profiles,
 * only against a verified and authorized target. No payload library, no writes,
 * no data extraction: each check confirms a flaw class by a benign signal.
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 */
import './redirects.mjs';
import './csrf.mjs';
import './xss.mjs';
import './injection.mjs';
import './access.mjs';
