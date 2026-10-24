/*
 * QuillTest — provider registry + request-builder tests
 * Run: npm test   (node --test, Node 18+; picks up tests/*.test.mjs)
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import {
  PROVIDERS,
  API_STYLES,
  TEST_MAX_TOKENS,
  getProvider,
  keyOptional,
  authHeaders,
  buildTestRequest,
  buildListModelsRequest,
  extractModelIds,
  extractText,
  buildMultiConfig,
  normalizeConfig,
  CONFIG_VERSION,
  buildChatRequest,
  validateBase,
  isLoopbackHost,
  scrubSecrets,
} from '../src/ai/providers.mjs';
import { HTML_PATH, extractBlock, renderBlock } from '../scripts/sync-browser-registry.mjs';

test('all requested providers are present', () => {
  const ids = PROVIDERS.map((p) => p.id);
  for (const id of ['openai', 'anthropic', 'google', 'xai', 'meta', 'deepseek', 'qwen', 'mistral', 'local', 'custom']) {
    assert.ok(ids.includes(id), `missing provider: ${id}`);
  }
  assert.equal(new Set(ids).size, ids.length, 'provider ids must be unique');
});

test('every provider has the fields the wizard relies on', () => {
  for (const p of PROVIDERS) {
    assert.equal(typeof p.id, 'string');
    assert.equal(typeof p.label, 'string');
    assert.ok(Object.values(API_STYLES).includes(p.apiStyle), `${p.id} bad apiStyle`);
    assert.equal(typeof p.keyEnv, 'string');
    assert.equal(typeof p.keysUrl, 'string');
    assert.equal(typeof p.notes, 'string');
    assert.ok(Array.isArray(p.models));
    assert.ok(!p.defaultBase.endsWith('/'), `${p.id} defaultBase must not end with /`);
    if (!p.requiresBase) assert.ok(p.defaultBase, `${p.id} needs a defaultBase or requiresBase`);
    if (p.maxTokensParam) assert.equal(p.apiStyle, API_STYLES.OPENAI, `${p.id}: maxTokensParam only applies to OpenAI-style`);
  }
});

test('getProvider resolves and rejects correctly', () => {
  assert.equal(getProvider('xai').label, 'xAI (Grok)');
  assert.equal(getProvider('nope'), null);
  assert.throws(() => buildTestRequest({ providerId: 'nope' }), /Unknown provider/);
});

test('only the local provider works without a key', () => {
  assert.equal(keyOptional('local'), true);
  for (const p of PROVIDERS.filter((x) => x.id !== 'local')) assert.equal(keyOptional(p.id), false, p.id);
});

test('OpenAI request targets chat/completions with Bearer auth and max_completion_tokens', () => {
  const { url, init } = buildTestRequest({ providerId: 'openai', base: 'https://api.openai.com/v1', apiKey: 'sk-test', model: 'gpt-5.4-mini' });
  assert.equal(url, 'https://api.openai.com/v1/chat/completions');
  assert.equal(init.method, 'POST');
  assert.equal(init.headers.authorization, 'Bearer sk-test');
  assert.equal(init.headers['content-type'], 'application/json');
  const body = JSON.parse(init.body);
  assert.equal(body.model, 'gpt-5.4-mini');
  assert.equal(body.max_completion_tokens, TEST_MAX_TOKENS);
  assert.equal(body.max_tokens, undefined, 'OpenAI reasoning models reject max_tokens');
});

test('other OpenAI-compatible providers keep max_tokens', () => {
  for (const id of ['xai', 'meta', 'deepseek', 'qwen', 'mistral', 'local']) {
    const { init } = buildTestRequest({ providerId: id, apiKey: 'k', model: 'm' });
    const body = JSON.parse(init.body);
    assert.equal(body.max_tokens, TEST_MAX_TOKENS, id);
    assert.equal(body.max_completion_tokens, undefined, id);
  }
});

test('DeepSeek base without /v1 still reaches /chat/completions and /models', () => {
  const test = buildTestRequest({ providerId: 'deepseek', apiKey: 'k' });
  assert.equal(test.url, 'https://api.deepseek.com/chat/completions');
  assert.equal(buildListModelsRequest({ providerId: 'deepseek', apiKey: 'k' }).url, 'https://api.deepseek.com/models');
});

test('local provider sends a placeholder Bearer token when no key is given', () => {
  const { init } = buildTestRequest({ providerId: 'local', apiKey: '', model: 'llama3.1' });
  assert.equal(init.headers.authorization, 'Bearer not-needed');
});

test('Anthropic request uses /messages and x-api-key', () => {
  const { url, init } = buildTestRequest({ providerId: 'anthropic', base: 'https://api.anthropic.com/v1', apiKey: 'k', model: 'claude-opus-5-5' });
  assert.equal(url, 'https://api.anthropic.com/v1/messages');
  assert.equal(init.headers['x-api-key'], 'k');
  assert.equal(init.headers['anthropic-version'], '2023-06-01');
  assert.equal(init.headers.authorization, undefined);
  const body = JSON.parse(init.body);
  assert.equal(body.model, 'claude-opus-5-5');
  assert.equal(body.max_tokens, TEST_MAX_TOKENS);
});

test('Gemini request puts model in path and key in the x-goog-api-key header, never the URL', () => {
  const { url, init } = buildTestRequest({ providerId: 'google', base: 'https://generativelanguage.googleapis.com/v1beta', apiKey: 'K', model: 'gemini-3-flash-preview' });
  assert.equal(url, 'https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent');
  assert.equal(init.headers['x-goog-api-key'], 'K');
  assert.ok(!url.includes('K'), 'key must not leak into the URL');
  const body = JSON.parse(init.body);
  assert.equal(body.generationConfig.maxOutputTokens, TEST_MAX_TOKENS);
});

test('model-list requests reuse the same auth headers as the test request', () => {
  for (const p of PROVIDERS) {
    const req = buildListModelsRequest({ providerId: p.id, base: p.defaultBase || 'https://x.example', apiKey: 'K' });
    assert.ok(req, `${p.id} should expose a model list`);
    assert.equal(req.init.method, 'GET');
    assert.deepEqual(req.init.headers, authHeaders(p, 'K'));
    assert.ok(!req.url.includes('K'), `${p.id}: key must not be in the URL`);
    assert.ok(req.url.endsWith('/models'), req.url);
  }
});

test('trailing slashes in base are normalized', () => {
  const { url } = buildTestRequest({ providerId: 'xai', base: 'https://api.x.ai/v1///', apiKey: 'x', model: 'grok-4.6' });
  assert.equal(url, 'https://api.x.ai/v1/chat/completions');
});

test('a provider with no suggested models requires an explicit model', () => {
  assert.throws(() => buildTestRequest({ providerId: 'custom', base: 'https://gw.example/v1', apiKey: 'k' }), /model id is required/);
});

test('extractModelIds handles OpenAI/Anthropic and Gemini list shapes', () => {
  assert.deepEqual(extractModelIds({ data: [{ id: 'a' }, { id: 'b' }] }), ['a', 'b']);
  assert.deepEqual(extractModelIds({ models: [{ name: 'models/gemini-x' }, { name: 'models/gemini-y' }] }), ['gemini-x', 'gemini-y']);
  assert.deepEqual(extractModelIds({}), []);
  assert.deepEqual(extractModelIds(null), []);
});

test('extractText handles each API style', () => {
  assert.equal(extractText(API_STYLES.OPENAI, { choices: [{ message: { content: 'OK' } }] }), 'OK');
  assert.equal(extractText(API_STYLES.ANTHROPIC, { content: [{ type: 'thinking', thinking: 'hmm' }, { type: 'text', text: 'OK' }] }), 'OK');
  assert.equal(extractText(API_STYLES.GEMINI, { candidates: [{ content: { parts: [{ text: 'OK' }] } }] }), 'OK');
  assert.equal(extractText(API_STYLES.OPENAI, {}), '');
  assert.equal(extractText(API_STYLES.OPENAI, { choices: [{ message: { content: null } }] }), '');
});

test('browser wizard carries an up-to-date copy of the registry', () => {
  const html = readFileSync(HTML_PATH, 'utf8');
  const block = extractBlock(html);
  assert.equal(block, renderBlock(), 'run: node scripts/sync-browser-registry.mjs');
  // And the inlined block is valid JS that reproduces the registry.
  const ctx = {};
  vm.runInNewContext(block.replace(/^const /gm, 'var ') + '\nresult = { PROVIDERS, TEST_MAX_TOKENS };', ctx);
  // JSON round-trip both sides: objects created inside the vm context have a foreign Object prototype.
  assert.deepEqual(JSON.parse(JSON.stringify(ctx.result.PROVIDERS)), JSON.parse(JSON.stringify(PROVIDERS)));
  assert.equal(ctx.result.TEST_MAX_TOKENS, TEST_MAX_TOKENS);
});

// ----- multi-provider config -----

test('buildMultiConfig builds a v2 config with ordered providers', () => {
  const cfg = buildMultiConfig(
    [{ providerId: 'openai' }, { providerId: 'anthropic' }, { providerId: 'xai' }],
    { mode: 'concurrent' },
  );
  assert.equal(cfg.version, CONFIG_VERSION);
  assert.equal(cfg.analysisMode, 'concurrent');
  assert.deepEqual(cfg.activeProviders, ['openai', 'anthropic', 'xai']);
  assert.equal(cfg.active, 'openai'); // back-compat pointer
  assert.equal(cfg.providers.anthropic.model, getProvider('anthropic').models[0]);
});

test('buildMultiConfig de-dupes and defaults an unknown mode to sequential', () => {
  const cfg = buildMultiConfig([{ providerId: 'openai' }, { providerId: 'openai' }], { mode: 'bogus' });
  assert.deepEqual(cfg.activeProviders, ['openai']);
  assert.equal(cfg.analysisMode, 'sequential');
});

test('buildMultiConfig omits keys unless saveKey is set', () => {
  const withKey = buildMultiConfig([{ providerId: 'openai', apiKey: 'sk-x', saveKey: true }], {});
  const noKey = buildMultiConfig([{ providerId: 'openai', apiKey: 'sk-x' }], {});
  assert.equal(withKey.providers.openai.apiKey, 'sk-x');
  assert.equal(noKey.providers.openai.apiKey, null);
});

test('buildMultiConfig throws on an unknown provider', () => {
  assert.throws(() => buildMultiConfig([{ providerId: 'nope' }], {}), /Unknown provider/);
});

test('normalizeConfig upgrades a v1 single-provider config', () => {
  const v1 = { version: 1, active: 'mistral', providers: { mistral: { providerId: 'mistral', base: 'https://api.mistral.ai/v1', model: 'mistral-large-latest' } } };
  const n = normalizeConfig(v1);
  assert.deepEqual(n.activeProviders, ['mistral']);
  assert.equal(n.analysisMode, 'sequential');
});

test('normalizeConfig drops active ids that have no provider entry', () => {
  const n = normalizeConfig({ version: 2, analysisMode: 'concurrent', activeProviders: ['openai', 'ghost'], providers: { openai: { providerId: 'openai' } } });
  assert.deepEqual(n.activeProviders, ['openai']);
  assert.equal(n.analysisMode, 'concurrent');
});

// ----- hardening: base validation, secret scrubbing, chat requests -----

test('validateBase accepts https and loopback http, rejects everything risky', () => {
  assert.equal(validateBase('https://api.openai.com/v1').ok, true);
  assert.equal(validateBase('http://localhost:11434/v1').ok, true);
  assert.equal(validateBase('http://127.0.0.1:8080').ok, true);
  assert.equal(validateBase('http://[::1]:1234/v1').ok, true);
  assert.equal(validateBase('http://api.example.com/v1').ok, false, 'plaintext to a remote host must be refused');
  assert.match(validateBase('http://api.example.com/v1').error, /cleartext/);
  assert.equal(validateBase('ftp://x.example').ok, false);
  assert.equal(validateBase('javascript:alert(1)').ok, false);
  assert.equal(validateBase('https://user:pw@x.example').ok, false, 'credentials in URL must be refused');
  assert.equal(validateBase('').ok, false);
  assert.equal(validateBase('not a url').ok, false);
  const allowed = validateBase('http://gw.lan/v1', { allowInsecure: true });
  assert.equal(allowed.ok, true);
  assert.match(allowed.warning, /cleartext/);
});

test('isLoopbackHost covers the local forms and nothing else', () => {
  for (const h of ['localhost', 'LOCALHOST', '127.0.0.1', '127.9.9.9', '::1', '[::1]', 'dev.localhost', '0.0.0.0']) assert.equal(isLoopbackHost(h), true, h);
  for (const h of ['localhost.evil.com', '128.0.0.1', '10.0.0.5', 'example.com', '']) assert.equal(isLoopbackHost(h), false, h);
});

test('buildMultiConfig refuses a plaintext remote base unless allowInsecure', () => {
  assert.throws(() => buildMultiConfig([{ providerId: 'custom', base: 'http://gw.example.com/v1' }]), /cleartext/);
  const cfg = buildMultiConfig([{ providerId: 'custom', base: 'http://gw.example.com/v1', model: 'm' }], { allowInsecure: true });
  assert.equal(cfg.providers.custom.base, 'http://gw.example.com/v1');
});

test('scrubSecrets removes exact keys and well-known key shapes', () => {
  const out = scrubSecrets('err: Bearer abcdefghij1234 bad sk-abcdefghijklmnopq key=MYEXACTSECRET x AIza' + 'A'.repeat(32), ['MYEXACTSECRET']);
  assert.ok(!out.includes('abcdefghij1234'));
  assert.ok(!out.includes('sk-abcdefghijklmnopq'));
  assert.ok(!out.includes('MYEXACTSECRET'));
  assert.ok(!out.includes('AIza' + 'A'.repeat(32)));
  assert.ok(out.includes('[REDACTED]'));
  assert.equal(scrubSecrets('plain', ['short']), 'plain', 'secrets under 6 chars are ignored to avoid shredding normal text');
  assert.equal(scrubSecrets(null), '');
});

test('buildChatRequest maps system + multi-turn messages per API style', () => {
  const chat = { system: 'SYS', messages: [{ role: 'user', content: 'U' }, { role: 'assistant', content: 'A' }], maxTokens: 123 };
  const o = JSON.parse(buildChatRequest({ providerId: 'openai', apiKey: 'k', model: 'm' }, chat).init.body);
  assert.deepEqual(o.messages.map((m) => m.role), ['system', 'user', 'assistant']);
  assert.equal(o.max_completion_tokens, 123);
  const a = JSON.parse(buildChatRequest({ providerId: 'anthropic', apiKey: 'k', model: 'm' }, chat).init.body);
  assert.equal(a.system, 'SYS');
  assert.deepEqual(a.messages.map((m) => m.role), ['user', 'assistant']);
  assert.equal(a.max_tokens, 123);
  const g = JSON.parse(buildChatRequest({ providerId: 'google', apiKey: 'k', model: 'm' }, chat).init.body);
  assert.equal(g.systemInstruction.parts[0].text, 'SYS');
  assert.deepEqual(g.contents.map((c) => c.role), ['user', 'model']);
  assert.equal(g.generationConfig.maxOutputTokens, 123);
  assert.throws(() => buildChatRequest({ providerId: 'openai', apiKey: 'k', model: 'm' }, { messages: [] }), /At least one message/);
});

test('buildTestRequest is buildChatRequest with one user message and the test cap (no system field)', () => {
  const o = JSON.parse(buildTestRequest({ providerId: 'openai', apiKey: 'k', model: 'm' }).init.body);
  assert.equal(o.messages.length, 1);
  assert.equal(o.messages[0].role, 'user');
  const a = JSON.parse(buildTestRequest({ providerId: 'anthropic', apiKey: 'k', model: 'm' }).init.body);
  assert.equal(a.system, undefined);
});

test('Gemini extractText skips thought parts from thinking models', () => {
  const json = { candidates: [{ content: { parts: [{ thought: true, text: 'reasoning…' }, { text: 'OK' }] } }] };
  assert.equal(extractText(API_STYLES.GEMINI, json), 'OK');
});
