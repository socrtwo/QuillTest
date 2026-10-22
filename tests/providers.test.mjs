/*
 * QuillTest — provider registry + request-builder tests
 * Run: node --test tests/   (Node 18+)
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  PROVIDERS,
  getProvider,
  buildTestRequest,
  extractText,
  API_STYLES,
} from '../src/ai/providers.mjs';

test('all requested providers are present', () => {
  const ids = PROVIDERS.map((p) => p.id);
  for (const id of ['openai', 'anthropic', 'google', 'xai', 'meta', 'deepseek', 'qwen', 'mistral', 'local', 'custom']) {
    assert.ok(ids.includes(id), `missing provider: ${id}`);
  }
});

test('every provider has the fields the wizard relies on', () => {
  for (const p of PROVIDERS) {
    assert.equal(typeof p.id, 'string');
    assert.equal(typeof p.label, 'string');
    assert.ok(Object.values(API_STYLES).includes(p.apiStyle), `${p.id} bad apiStyle`);
    assert.equal(typeof p.keyEnv, 'string');
    assert.ok(Array.isArray(p.models));
  }
});

test('getProvider resolves and rejects correctly', () => {
  assert.equal(getProvider('xai').label, 'xAI (Grok)');
  assert.equal(getProvider('nope'), null);
});

test('OpenAI-style request targets chat/completions with Bearer auth', () => {
  const { url, init } = buildTestRequest({ providerId: 'openai', base: 'https://api.openai.com/v1', apiKey: 'sk-test', model: 'gpt-4o-mini' });
  assert.equal(url, 'https://api.openai.com/v1/chat/completions');
  assert.equal(init.headers.authorization, 'Bearer sk-test');
  assert.match(init.body, /gpt-4o-mini/);
});

test('Anthropic request uses /messages and x-api-key', () => {
  const { url, init } = buildTestRequest({ providerId: 'anthropic', base: 'https://api.anthropic.com/v1', apiKey: 'k', model: 'claude-sonnet-4-5' });
  assert.equal(url, 'https://api.anthropic.com/v1/messages');
  assert.equal(init.headers['x-api-key'], 'k');
  assert.equal(init.headers['anthropic-version'], '2023-06-01');
});

test('Gemini request puts key in query and model in path', () => {
  const { url } = buildTestRequest({ providerId: 'google', base: 'https://generativelanguage.googleapis.com/v1beta', apiKey: 'K', model: 'gemini-2.5-flash' });
  assert.match(url, /\/models\/gemini-2\.5-flash:generateContent\?key=K$/);
});

test('trailing slashes in base are normalized', () => {
  const { url } = buildTestRequest({ providerId: 'xai', base: 'https://api.x.ai/v1///', apiKey: 'x', model: 'grok-4' });
  assert.equal(url, 'https://api.x.ai/v1/chat/completions');
});

test('extractText handles each API style', () => {
  assert.equal(extractText(API_STYLES.OPENAI, { choices: [{ message: { content: 'OK' } }] }), 'OK');
  assert.equal(extractText(API_STYLES.ANTHROPIC, { content: [{ text: 'OK' }] }), 'OK');
  assert.equal(extractText(API_STYLES.GEMINI, { candidates: [{ content: { parts: [{ text: 'OK' }] } }] }), 'OK');
  assert.equal(extractText(API_STYLES.OPENAI, {}), '');
});
