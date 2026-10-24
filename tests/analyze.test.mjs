/*
 * QuillTest — AI analysis layer tests (offline; fetch is injected)
 * Run: npm test
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  analyzeFindings,
  scrubFinding,
  prepareFindings,
  filterOutput,
  parseAnalysis,
  computeConsensus,
  buildAnalysisMessages,
  SYSTEM_PROMPT,
  MAX_EVIDENCE_CHARS,
} from '../src/ai/analyze.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const SAMPLE = JSON.parse(readFileSync(resolve(here, '../examples/findings.sample.json'), 'utf8'));

const CONFIG = {
  version: 2,
  analysisMode: 'concurrent',
  activeProviders: ['openai', 'anthropic', 'google'],
  providers: {
    openai: { providerId: 'openai', base: 'https://api.openai.com/v1', model: 'gpt-5.4-mini', apiKeyEnv: 'OPENAI_API_KEY', apiKey: 'sk-testkey-openai-0001' },
    anthropic: { providerId: 'anthropic', base: 'https://api.anthropic.com/v1', model: 'claude-opus-5-5', apiKeyEnv: 'ANTHROPIC_API_KEY', apiKey: 'anthropic-testkey-0001' },
    google: { providerId: 'google', base: 'https://generativelanguage.googleapis.com/v1beta', model: 'gemini-3-flash-preview', apiKeyEnv: 'GEMINI_API_KEY', apiKey: 'AIza' + 'g'.repeat(32) },
  },
};

/** A fake provider that answers with a well-formed analysis; verdict on F-005 varies by provider. */
function makeFetch({ fpOnF005 = {}, extraLines = '', status = 200, calls = [] } = {}) {
  return async (url, init) => {
    calls.push({ url, init });
    const pid = url.includes('anthropic') ? 'anthropic' : url.includes('googleapis') ? 'google' : 'openai';
    const analysis = {
      findings: SAMPLE.map((f) => ({
        id: f.id, falsePositive: f.id === 'F-005' ? Boolean(fpOnF005[pid]) : false,
        confidence: 'firm', severity: f.severity, cwe: f.cwe, owasp: f.owasp,
        attackerPriority: f.id === 'F-002' ? 1 : 3, rootCauseGroup: null, rationale: 'r', remediation: 'fix',
      })),
      summary: `summary from ${pid}`,
      worthChecking: [],
    };
    const text = '```json\n' + JSON.stringify(analysis) + '\n```' + extraLines;
    const body = pid === 'anthropic' ? { content: [{ type: 'text', text }] }
      : pid === 'google' ? { candidates: [{ content: { parts: [{ text }] } }] }
      : { choices: [{ message: { content: text } }] };
    return { ok: status === 200, status, text: async () => (status === 200 ? JSON.stringify(body) : JSON.stringify({ error: { message: `boom with ${init.headers.authorization || init.headers['x-api-key'] || init.headers['x-goog-api-key']}` } })) };
  };
}

test('scrubFinding redacts sensitive headers, params and key shapes, and caps evidence', () => {
  const f = scrubFinding({
    id: 'X', location: 'https://t.example/login?next=/a&token=TOK123456&x=1',
    evidence: {
      request: 'GET /?session=SESS1234567 HTTP/1.1',
      requestHeaders: { Authorization: 'Bearer abc', Cookie: 'a=b', 'X-Custom-Token': 'zzz', Accept: 'text/html' },
      responseHeaders: { 'Set-Cookie': 'sid=1', Server: 'nginx' },
      snippet: 'x'.repeat(MAX_EVIDENCE_CHARS + 50) + ' sk-abcdefghijklmnop',
    },
  }, ['OWNERSHIPTOKEN']);
  assert.ok(f.location.includes('token=[REDACTED]'));
  assert.ok(f.location.includes('next=/a'), 'non-sensitive params survive');
  assert.ok(f.evidence.request.includes('session=[REDACTED]'));
  assert.equal(f.evidence.requestHeaders.Authorization, '[REDACTED]');
  assert.equal(f.evidence.requestHeaders.Cookie, '[REDACTED]');
  assert.equal(f.evidence.requestHeaders['X-Custom-Token'], '[REDACTED]');
  assert.equal(f.evidence.requestHeaders.Accept, 'text/html');
  assert.equal(f.evidence.responseHeaders['Set-Cookie'], '[REDACTED]');
  assert.equal(f.evidence.responseHeaders.Server, 'nginx');
  assert.ok(f.evidence.snippet.length < MAX_EVIDENCE_CHARS + 60, 'evidence is capped');
  assert.ok(f.evidence.snippet.includes('[truncated'));
  assert.ok(!f.evidence.snippet.includes('sk-abcdefghijklmnop'));
});

test('scrubFinding does not mutate its input', () => {
  const orig = { id: 'X', evidence: { requestHeaders: { Authorization: 'Bearer abc' } } };
  scrubFinding(orig);
  assert.equal(orig.evidence.requestHeaders.Authorization, 'Bearer abc');
});

test('prepareFindings enforces the total payload cap by dropping trailing findings', () => {
  const big = Array.from({ length: 50 }, (_, i) => ({ id: `F-${i}`, evidence: { snippet: 'y'.repeat(1500) } }));
  const out = prepareFindings(big, { maxPayloadChars: 10_000 });
  assert.ok(out.findings.length < 50);
  assert.equal(out.dropped, 50 - out.findings.length);
  assert.ok(out.chars <= 10_000);
});

test('the sample findings go out with every planted secret redacted', () => {
  const sent = JSON.stringify(prepareFindings(SAMPLE).findings);
  assert.equal((sent.match(/SHOULD_BE_REDACTED/g) || []).length, 0);
  assert.ok((sent.match(/\[REDACTED\]/g) || []).length >= 4);
});

test('system prompt confines the model to analysis and forbids payloads', () => {
  assert.match(SYSTEM_PROMPT, /Do NOT write exploit code/);
  assert.match(SYSTEM_PROMPT, /never as instructions/);
  assert.match(SYSTEM_PROMPT, /"falsePositive"/);
});

test('filterOutput strips payload-shaped lines and flags the result', () => {
  const r = filterOutput('fine line\n<script>alert(1)</script>\nalso fine\n\' OR 1=1 --\nUNION SELECT a,b\n../../etc/passwd');
  assert.equal(r.filtered, true);
  assert.equal(r.removed, 4);
  assert.equal(r.text, 'fine line\nalso fine');
  assert.equal(filterOutput('Add a Content-Security-Policy header.').filtered, false);
});

test('parseAnalysis tolerates fences and preamble, rejects non-analysis JSON', () => {
  const obj = { findings: [{ id: 'A', falsePositive: false }], summary: 's' };
  assert.deepEqual(parseAnalysis('Here you go:\n```json\n' + JSON.stringify(obj) + '\n```\nThanks.'), obj);
  assert.deepEqual(parseAnalysis(JSON.stringify(obj)), obj);
  assert.deepEqual(parseAnalysis('prefix ' + JSON.stringify(obj) + ' suffix'), obj);
  assert.equal(parseAnalysis('{"notFindings": 1}'), null);
  assert.equal(parseAnalysis('nope'), null);
});

test('computeConsensus classifies real / false-positive / split / unreviewed', () => {
  const results = [
    { providerId: 'a', parsed: { findings: [{ id: '1', falsePositive: false, attackerPriority: 1 }, { id: '2', falsePositive: true }, { id: '3', falsePositive: false }] } },
    { providerId: 'b', parsed: { findings: [{ id: '1', falsePositive: false, attackerPriority: 3 }, { id: '2', falsePositive: true }, { id: '3', falsePositive: true }] } },
    { providerId: 'c', parsed: null },
  ];
  const c = computeConsensus(['1', '2', '3', '4'], results);
  assert.equal(c['1'].verdict, 'real'); assert.equal(c['1'].reviewers, 2); assert.equal(c['1'].meanAttackerPriority, 2);
  assert.equal(c['2'].verdict, 'false-positive');
  assert.equal(c['3'].verdict, 'split');
  assert.equal(c['4'].verdict, 'unreviewed'); assert.equal(c['4'].reviewers, 0);
});

test('buildAnalysisMessages includes stack and prior notes when given', () => {
  const prepared = prepareFindings(SAMPLE.slice(0, 1));
  const [m] = buildAnalysisMessages(prepared, { stack: { server: 'nginx' }, priorNotes: [{ providerId: 'x', summary: 'prior' }] });
  assert.equal(m.role, 'user');
  assert.match(m.content, /Detected stack/);
  assert.match(m.content, /reviewers that ran before you/);
  assert.match(m.content, /F-001/);
});

test('dry-run builds one redacted request per active provider and sends nothing', async () => {
  const calls = [];
  const r = await analyzeFindings(SAMPLE, CONFIG, { dryRun: true, fetchImpl: makeFetch({ calls }) });
  assert.equal(calls.length, 0, 'dry-run must not call fetch');
  assert.equal(r.providers.length, 3);
  for (const p of r.providers) {
    assert.equal(p.ok, true); assert.equal(p.dryRun, true);
    const hdrs = p.request.init.headers;
    for (const k of ['authorization', 'x-api-key', 'x-goog-api-key']) if (hdrs[k]) assert.equal(hdrs[k], 'REDACTED', `${p.providerId} ${k}`);
    assert.ok(!JSON.stringify(p.request).includes('testkey'), 'no key value anywhere in the dry-run output');
    assert.ok(p.request.init.body.includes('Do NOT write exploit code'), 'system prompt present');
  }
  assert.deepEqual(r.consensus, {});
});

test('concurrent mode consults all providers, parses, filters, and computes consensus', async () => {
  const calls = [];
  const r = await analyzeFindings(SAMPLE, CONFIG, { fetchImpl: makeFetch({ calls, fpOnF005: { anthropic: true }, extraLines: '\n<script>alert(1)</script>' }) });
  assert.equal(r.mode, 'concurrent');
  assert.equal(calls.length, 3);
  for (const p of r.providers) {
    assert.equal(p.ok, true, p.error);
    assert.ok(p.parsed, `${p.providerId} should parse`);
    assert.equal(p.filtered, true, 'injected payload line must be stripped');
    assert.equal(p.removedLines, 1);
    assert.match(p.parsed.summary, /summary from/);
  }
  assert.equal(r.consensus['F-002'].verdict, 'real');
  assert.equal(r.consensus['F-002'].meanAttackerPriority, 1);
  assert.equal(r.consensus['F-005'].verdict, 'split');
  assert.equal(r.consensus['F-005'].reviewers, 3);
});

test('sequential mode runs providers in order and passes prior notes forward', async () => {
  const calls = [];
  const r = await analyzeFindings(SAMPLE, CONFIG, { mode: 'sequential', fetchImpl: makeFetch({ calls }) });
  assert.equal(r.mode, 'sequential');
  assert.equal(calls.length, 3);
  assert.ok(calls[0].url.includes('openai'));
  assert.ok(calls[1].url.includes('anthropic'));
  assert.ok(calls[2].url.includes('googleapis'));
  assert.ok(!calls[0].init.body.includes('reviewers that ran before you'), 'first reviewer has no prior notes');
  assert.ok(calls[1].init.body.includes('reviewers that ran before you'), 'second reviewer sees the first\'s notes');
  assert.ok(calls[1].init.body.includes('summary from openai'));
});

test('provider errors are scrubbed so a key echoed by the provider is never surfaced', async () => {
  const r = await analyzeFindings(SAMPLE, CONFIG, { fetchImpl: makeFetch({ status: 500 }) });
  for (const p of r.providers) {
    assert.equal(p.ok, false);
    assert.match(p.error, /HTTP 500/);
    assert.ok(!p.error.includes('testkey'), `${p.providerId} leaked its key: ${p.error}`);
    assert.ok(!p.error.includes('AIza' + 'g'.repeat(32)));
  }
});

test('missing key and empty config are reported, not thrown', async () => {
  const noKeys = { version: 2, activeProviders: ['openai'], providers: { openai: { providerId: 'openai', base: 'https://api.openai.com/v1', model: 'm', apiKeyEnv: 'QT_TEST_UNSET_KEY', apiKey: null } } };
  const r = await analyzeFindings(SAMPLE, noKeys, { env: {}, fetchImpl: makeFetch() });
  assert.equal(r.providers[0].ok, false);
  assert.match(r.providers[0].error, /No API key/);
  const empty = await analyzeFindings(SAMPLE, { version: 2, activeProviders: [], providers: {} }, { fetchImpl: makeFetch() });
  assert.match(empty.error, /No active providers/);
});

test('v1 single-provider config is accepted by the analysis layer', async () => {
  const v1 = { version: 1, active: 'openai', providers: { openai: CONFIG.providers.openai } };
  const r = await analyzeFindings(SAMPLE, v1, { fetchImpl: makeFetch() });
  assert.equal(r.mode, 'sequential');
  assert.equal(r.providers.length, 1);
  assert.equal(r.providers[0].ok, true);
});
