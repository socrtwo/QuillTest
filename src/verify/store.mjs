/*
 * QuillTest — on-disk store for ownership challenges and verification records
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Two small JSON files under ./scans/ (git-ignored), written mode 0600:
 *   scans/verify/challenges.json  — pending challenges (these hold the token)
 *   scans/verify/verified.json    — verification records (token hash only)
 *
 * The directory is overridable so tests can use a temp dir.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync } from 'node:fs';
import { resolve } from 'node:path';

export const DEFAULT_DIR = resolve(process.cwd(), 'scans', 'verify');

function readJson(path, fallback) {
  if (!existsSync(path)) return fallback;
  try { return JSON.parse(readFileSync(path, 'utf8')); } catch { return fallback; }
}

function writeJson(path, data) {
  mkdirSync(resolve(path, '..'), { recursive: true });
  writeFileSync(path, JSON.stringify(data, null, 2) + '\n', { mode: 0o600 });
  try { chmodSync(path, 0o600); } catch { /* best effort */ }
}

export function createStore(dir = DEFAULT_DIR) {
  const challengesPath = resolve(dir, 'challenges.json');
  const verifiedPath = resolve(dir, 'verified.json');
  return {
    dir,
    loadChallenges: () => readJson(challengesPath, []),
    saveChallenge(challenge) {
      const list = readJson(challengesPath, []).filter((c) => c.origin !== challenge.origin);
      list.push(challenge);
      writeJson(challengesPath, list);
    },
    findChallenge: (origin) => readJson(challengesPath, []).find((c) => c.origin === origin) || null,
    removeChallenge(origin) {
      writeJson(challengesPath, readJson(challengesPath, []).filter((c) => c.origin !== origin));
    },
    loadVerified: () => readJson(verifiedPath, []),
    saveVerified(record) {
      const list = readJson(verifiedPath, []).filter((r) => r.origin !== record.origin);
      list.push(record);
      writeJson(verifiedPath, list);
    },
  };
}
