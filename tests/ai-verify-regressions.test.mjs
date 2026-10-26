/*
 * Anne's Test — AI layer / ownership gate / store regression tests
 * Each test pins a defect found in review so it cannot come back.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { analyzeFindings, scrubParsedOutput } from '../src/ai/analyze.mjs';
import { issueChallenge, verifyHttp, verifyChallenge, WELL_KNOWN_DIR } from '../src/verify/ownership.mjs';
import { createStore } from '../src/verify/store.mjs';

const TOKEN = 'A'.repeat(52);
const res = (status, body, headers = {}) => ({ status, headers: new Headers(headers), text: async () => body });
const CONFIG = { version: 2, analysisMode: 'sequential', activeProviders: ['openai'], providers: { openai: { providerId: 'openai', base: 'https://api.openai.com/v1', model: 'gpt-5.4-mini', apiKeyEnv: 'OPENAI_API_KEY', apiKey: 'sk-testkey-openai-0001' } } };
const FINDINGS = [{ id: 'F-1', checkId: 'headers.csp', title: 'CSP missing', severity: 'medium', confidence: 'firm', location: 'https://x/' }];
const openaiReply = (content, finish_reason = 'stop') => async () => ({ ok: true, status: 200, text: async () => JSON.stringify({ choices: [{ message: { content }, finish_reason }] }) });

test('AI: a payload-shaped substring inside a JSON reply is scrubbed per field, not by deleting the line', async () => {
  const analysis = { findings: [{ id: 'F-1', falsePositive: false, confidence: 'firm', severity: 'medium', attackerPriority: 2, rationale: "input is reflected inside a <script> block; a classic ' OR 1=1 probe would show it", remediation: 'Encode output.' }], summary: 'one finding', worthChecking: [] };
  // compact single-line reply: the old line filter deleted the whole reply
  const r = await analyzeFindings(FINDINGS, CONFIG, { fetchImpl: openaiReply(JSON.stringify(analysis)) });
  const p = r.providers[0];
  assert.equal(p.ok, true);
  assert.ok(p.parsed, p.parseError);
  assert.equal(p.parsed.findings.length, 1);
  assert.match(p.parsed.findings[0].rationale, /reflected inside a \[filtered\] block; a classic \[filtered\] probe/);
  assert.equal(p.parsed.findings[0].remediation, 'Encode output.');
  assert.equal(p.filtered, true);
  assert.equal(p.scrubbedFragments, 2);
  assert.equal(r.consensus['F-1'].verdict, 'real');
  // pretty-printed: the key/value line used to vanish, dropping the rationale silently
  const pretty = await analyzeFindings(FINDINGS, CONFIG, { fetchImpl: openaiReply('```json\n' + JSON.stringify(analysis, null, 2) + '\n```') });
  assert.match(pretty.providers[0].parsed.findings[0].rationale, /\[filtered\]/);
  // direct unit
  const s = scrubParsedOutput({ a: ['x ../../etc/passwd y', { b: 'javascript:alert(1)' }], n: 1 });
  assert.deepEqual(s.value, { a: ['x [filtered]etc/passwd y', { b: '[filtered]lert(1)' }], n: 1 });
  assert.equal(s.replaced, 2);
});

test('AI: a reply cut off by the output limit is reported as truncated, not as a formatting failure', async () => {
  const r = await analyzeFindings(FINDINGS, CONFIG, { fetchImpl: openaiReply('{"findings": [{"id": "F-1", "rationale": "this goes on and on', 'length') });
  const p = r.providers[0];
  assert.equal(p.parsed, null);
  assert.equal(p.truncated, 'length');
  assert.match(p.parseError, /cut off by the provider's output limit/);
});

test('ownership: the verification record lasts the TTL from verification, not from issuance', async () => {
  const issued = new Date('2026-01-01T00:00:00Z');
  const ch = issueChallenge('https://ok.test', { token: TOKEN, now: issued });
  const late = new Date(issued.getTime() + 23.5 * 3600_000);
  const r = await verifyChallenge(ch, { now: late, fetchImpl: async () => res(200, ch.fileContents) });
  assert.equal(r.ok, true);
  assert.equal(r.record.expires, new Date(late.getTime() + 24 * 3600_000).toISOString());
  assert.equal(r.record.challengeExpires, ch.expires);
});

test('ownership: a same-origin redirect must stay at the well-known path', async () => {
  const ch = issueChallenge('https://ok.test', { token: TOKEN });
  let n = 0;
  const moved = await verifyHttp(ch, { fetchImpl: async () => (n++ === 0 ? res(302, '', { location: '/uploads/tenant/' + TOKEN + '.txt' }) : res(200, ch.fileContents)) });
  assert.equal(moved.ok, false);
  assert.match(moved.error, /redirected away from/);
  n = 0;
  const calls = [];
  const same = await verifyHttp(ch, { fetchImpl: async (url, init) => { calls.push(init); return n++ === 0 ? res(302, '', { location: WELL_KNOWN_DIR + TOKEN + '.txt?cache=1' }) : res(200, ch.fileContents); } });
  assert.equal(same.ok, true);
  assert.equal(calls[1].headers['user-agent'], calls[0].headers['user-agent'], 'the re-fetch identifies itself the same way');
});

test('ownership: an oversized verification file is rejected without downloading it all', async () => {
  const ch = issueChallenge('https://ok.test', { token: TOKEN });
  let reads = 0, cancelled = false;
  const chunk = new TextEncoder().encode('x'.repeat(4096));
  const streamed = { status: 200, headers: new Headers(), text: async () => { throw new Error('text() must not be used on a streamed body'); }, body: { getReader: () => ({ read: async () => { reads++; return { done: false, value: chunk }; }, cancel: async () => { cancelled = true; } }) } };
  const r = await verifyHttp(ch, { fetchImpl: async () => streamed });
  assert.equal(r.ok, false);
  assert.match(r.error, /larger than/);
  assert.equal(reads, 3, 'stopped right after the cap was crossed');
  assert.equal(cancelled, true);
  const declared = await verifyHttp(ch, { fetchImpl: async () => res(200, ch.fileContents, { 'content-length': String(10 * 1024) }) });
  assert.match(declared.error, /larger than/, 'a declared oversize is refused before reading');
});

test('store: JSON files are written atomically (no temp file left, content intact)', () => {
  const dir = mkdtempSync(join(tmpdir(), 'qt-store-'));
  const store = createStore(dir);
  store.saveVerified({ origin: 'https://a.test', expires: '2030-01-01T00:00:00Z' });
  store.saveVerified({ origin: 'https://b.test', expires: '2030-01-01T00:00:00Z' });
  assert.deepEqual(store.loadVerified().map((r) => r.origin).sort(), ['https://a.test', 'https://b.test']);
  assert.ok(!readdirSync(dir).some((f) => f.endsWith('.tmp')), readdirSync(dir).join(','));
});
