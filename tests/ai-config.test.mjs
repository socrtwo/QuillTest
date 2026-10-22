/*
 * QuillTest — quilltest.ai.json validation
 * Run: npm test
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { validateAiConfig, assertAiConfig, loadAiConfig, activeProvider, resolveApiKey, AiConfigError } from '../src/ai/config.mjs';

const valid = () => ({
  version: 1,
  active: 'anthropic',
  providers: {
    anthropic: { providerId: 'anthropic', base: 'https://api.anthropic.com/v1', model: 'claude-opus-5-5', apiKeyEnv: 'ANTHROPIC_API_KEY', apiKey: null },
    local: { providerId: 'local', base: 'http://localhost:11434/v1', model: 'llama3.1', apiKeyEnv: null, apiKey: null },
  },
});

test('the shipped example config is valid', () => {
  const example = JSON.parse(readFileSync(new URL('../quilltest.ai.example.json', import.meta.url), 'utf8'));
  assert.deepEqual(validateAiConfig(example), []);
});

test('a well-formed config passes; local needs no credential', () => {
  assert.deepEqual(validateAiConfig(valid()), []);
  assert.equal(assertAiConfig(valid()).active, 'anthropic');
});

test('each schema rule reports a specific problem', () => {
  const cases = [
    [(c) => { c.version = 2; }, /version must be 1/],
    [(c) => { c.active = 'openai'; }, /active "openai" is not one of providers/],
    [(c) => { delete c.active; }, /active must name a provider id/],
    [(c) => { c.providers = []; }, /providers must be an object/],
    [(c) => { c.providers = {}; }, /providers is empty/],
    [(c) => { c.providers.nope = { providerId: 'nope', base: 'https://x', model: 'm', apiKeyEnv: 'K' }; }, /unknown provider id/],
    [(c) => { c.providers.anthropic.providerId = 'openai'; }, /providerId must equal the key "anthropic"/],
    [(c) => { c.providers.anthropic.base = 'api.anthropic.com'; }, /base must start with http/],
    [(c) => { c.providers.anthropic.base = 'https://api.anthropic.com/v1/'; }, /must not end with a slash/],
    [(c) => { c.providers.anthropic.model = ''; }, /model must be a non-empty string/],
    [(c) => { c.providers.anthropic.apiKeyEnv = 'not an env'; }, /apiKeyEnv must be null or an environment variable name/],
    [(c) => { c.providers.anthropic.apiKeyEnv = null; }, /needs apiKeyEnv or apiKey/],
    [(c) => { c.providers.anthropic.apiKey = 42; }, /apiKey must be null or a string/],
    [(c) => { c.providers.anthropic.extra = 1; }, /extra: unknown field/],
    [(c) => { c.bogus = true; }, /bogus: unknown top-level field/],
  ];
  for (const [mutate, re] of cases) {
    const c = valid();
    mutate(c);
    const problems = validateAiConfig(c);
    assert.ok(problems.some((p) => re.test(p)), `${re} not reported; got: ${JSON.stringify(problems)}`);
  }
  assert.deepEqual(validateAiConfig(null), ['config must be a JSON object']);
  assert.deepEqual(validateAiConfig([]), ['config must be a JSON object']);
});

test('loadAiConfig reports missing files, bad JSON and schema problems as AiConfigError', () => {
  const dir = mkdtempSync(join(tmpdir(), 'quilltest-cfg-'));
  assert.throws(() => loadAiConfig(join(dir, 'missing.json')), (e) => e instanceof AiConfigError && /file not found/.test(e.message));
  const bad = join(dir, 'bad.json');
  writeFileSync(bad, '{ nope');
  assert.throws(() => loadAiConfig(bad), /not valid JSON/);
  const schema = join(dir, 'schema.json');
  writeFileSync(schema, JSON.stringify({ version: 1, active: 'x', providers: {} }));
  assert.throws(() => loadAiConfig(schema), (e) => e instanceof AiConfigError && e.problems.length >= 2 && e.path === schema);
  const good = join(dir, 'good.json');
  writeFileSync(good, JSON.stringify(valid()));
  const { config } = loadAiConfig(good);
  assert.equal(activeProvider(config).model, 'claude-opus-5-5');
});

test('resolveApiKey prefers a literal key, then the env var, else empty', () => {
  assert.equal(resolveApiKey({ apiKey: 'lit', apiKeyEnv: 'X' }, { X: 'env' }), 'lit');
  assert.equal(resolveApiKey({ apiKey: null, apiKeyEnv: 'X' }, { X: 'env' }), 'env');
  assert.equal(resolveApiKey({ apiKey: null, apiKeyEnv: 'X' }, {}), '');
  assert.equal(resolveApiKey({ apiKey: null, apiKeyEnv: null }, { X: 'env' }), '');
});
