/*
 * QuillTest — config schema validation tests (offline)
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { validateConfig, formatValidation } from '../src/ai/config-schema.mjs';

const valid = () => ({
  version: 2, analysisMode: 'concurrent', activeProviders: ['anthropic', 'openai'], active: 'anthropic',
  providers: {
    anthropic: { providerId: 'anthropic', base: 'https://api.anthropic.com/v1', model: 'claude-opus-5-5', apiKeyEnv: 'ANTHROPIC_API_KEY', apiKey: null },
    openai: { providerId: 'openai', base: 'https://api.openai.com/v1', model: 'gpt-5.4-mini', apiKeyEnv: 'OPENAI_API_KEY', apiKey: null },
  },
});

test('a well-formed v2 config validates with no errors or warnings', () => {
  const r = validateConfig(valid());
  assert.equal(r.ok, true);
  assert.deepEqual(r.errors, []);
  assert.deepEqual(r.warnings, []);
  assert.equal(r.version, 2);
});

test('non-objects are rejected', () => {
  for (const bad of [null, 42, 'x', [], undefined]) {
    const r = validateConfig(bad);
    assert.equal(r.ok, false);
    assert.match(r.errors[0], /must be a JSON object/);
  }
});

test('a v1 single-provider config is accepted with a version note', () => {
  const r = validateConfig({ active: 'openai', providers: { openai: { providerId: 'openai', base: 'https://api.openai.com/v1', model: 'gpt-5.4-mini', apiKeyEnv: 'OPENAI_API_KEY' } } });
  assert.equal(r.ok, true);
  assert.equal(r.version, 1);
  assert.ok(r.warnings.some((w) => /version 1/.test(w)));
});

test('activeProviders referencing a missing entry is an error', () => {
  const c = valid(); c.activeProviders = ['anthropic', 'ghost'];
  const r = validateConfig(c);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => /references "ghost"/.test(e)));
});

test('active pointer to a missing entry is an error', () => {
  const c = valid(); c.active = 'nope';
  const r = validateConfig(c);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => /"active" points to "nope"/.test(e)));
});

test('bad analysisMode is an error, missing one on v2 is a warning', () => {
  const c = valid(); c.analysisMode = 'parallel';
  assert.ok(validateConfig(c).errors.some((e) => /analysisMode.*sequential, concurrent/.test(e)));
  const c2 = valid(); delete c2.analysisMode;
  const r2 = validateConfig(c2);
  assert.equal(r2.ok, true);
  assert.ok(r2.warnings.some((w) => /default to "sequential"/.test(w)));
});

test('provider entry: key/id mismatch and unknown id', () => {
  const c = valid();
  c.providers.anthropic.providerId = 'openai'; // mismatch with key
  const mism = validateConfig(c);
  assert.ok(mism.errors.some((e) => /they must match/.test(e)));
  const c2 = valid();
  c2.providers.myhost = { providerId: 'myhost', base: 'https://gw.internal/v1', model: 'local-1', apiKeyEnv: 'GW_KEY' };
  c2.activeProviders.push('myhost');
  const unk = validateConfig(c2);
  assert.equal(unk.ok, true, 'unknown id is only a warning');
  assert.ok(unk.warnings.some((w) => /not a built-in provider/.test(w)));
});

test('base validation reuses the endpoint rule: plaintext remote is an error, loopback ok', () => {
  const c = valid(); c.providers.openai.base = 'http://api.openai.com/v1';
  assert.ok(validateConfig(c).errors.some((e) => /cleartext|https/.test(e)));
  const c2 = valid(); c2.providers.openai.base = 'http://localhost:1234/v1';
  assert.equal(validateConfig(c2).ok, true, 'loopback http is allowed');
  const c3 = valid(); c3.providers.openai.base = 'ftp://x/y';
  assert.ok(validateConfig(c3).errors.some((e) => /http\(s\)/.test(e)));
  const c4 = valid(); delete c4.providers.openai.base;
  assert.ok(validateConfig(c4).errors.some((e) => /base.*required/.test(e)));
  const c5 = valid(); c5.providers.openai.base = 'http://api.openai.com/v1';
  assert.ok(validateConfig(c5, { allowInsecureBase: true }).ok, 'allowInsecureBase downgrades to warning');
});

test('missing model is an error; missing key material and stored key are warnings', () => {
  const c = valid(); delete c.providers.openai.model;
  assert.ok(validateConfig(c).errors.some((e) => /model.*required/.test(e)));
  const c2 = valid(); c2.providers.openai.apiKey = 'sk-secret'; c2.providers.openai.apiKeyEnv = null;
  const r2 = validateConfig(c2);
  assert.equal(r2.ok, true);
  assert.ok(r2.warnings.some((w) => /stores a key in plaintext/.test(w)));
  const c3 = valid(); c3.providers.openai.apiKey = null; c3.providers.openai.apiKeyEnv = null;
  assert.ok(validateConfig(c3).warnings.some((w) => /neither "apiKey" nor "apiKeyEnv"/.test(w)));
});

test('defined-but-not-enabled provider is a warning', () => {
  const c = valid(); c.activeProviders = ['anthropic'];
  const r = validateConfig(c);
  assert.equal(r.ok, true);
  assert.ok(r.warnings.some((w) => /"openai" is defined but not in "activeProviders"/.test(w)));
});

test('formatValidation renders errors and warnings; empty when clean', () => {
  assert.equal(formatValidation(validateConfig(valid())), '');
  const txt = formatValidation(validateConfig({ version: 2, providers: 'x' }));
  assert.match(txt, /error:/);
});

test('CLI --validate exits 0 on a good file, 1 on a bad one', () => {
  const dir = mkdtempSync(join(tmpdir(), 'qt-cfg-'));
  const good = join(dir, 'good.json'), bad = join(dir, 'bad.json'), broken = join(dir, 'broken.json');
  writeFileSync(good, JSON.stringify(valid()));
  const c = valid(); c.activeProviders = ['ghost']; writeFileSync(bad, JSON.stringify(c));
  writeFileSync(broken, '{ not json');
  const run = (f) => execFileSync(process.execPath, ['scripts/ai-setup-wizard.mjs', '--validate', '--config', f], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  assert.match(run(good), /is valid/);
  assert.throws(() => run(bad), (e) => e.status === 1 && /references "ghost"/.test(e.stdout));
  assert.throws(() => run(broken), (e) => e.status === 1 && /not valid JSON/.test(e.stderr));
});
