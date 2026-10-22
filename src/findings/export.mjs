/*
 * QuillTest — findings export: JSON, CSV, SARIF 2.1.0
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 */
import { OWASP_2021, CWE, severityRank } from './model.mjs';

export const FORMATS = ['json', 'csv', 'sarif'];

export function exportFindings(record, format = 'json') {
  switch (format) {
    case 'json': return JSON.stringify({ tool: 'QuillTest', scanId: record.id, origin: record.origin, profile: record.profile, startedAt: record.startedAt, finishedAt: record.finishedAt, verification: record.verification, authorization: record.authorization, summary: record.summary, findings: record.findings }, null, 2) + '\n';
    case 'csv': return toCsv(record);
    case 'sarif': return JSON.stringify(toSarif(record), null, 2) + '\n';
    default: throw new RangeError(`Unknown export format ${JSON.stringify(format)}; one of ${FORMATS.join(', ')}`);
  }
}

function csvCell(v) {
  const s = v === null || v === undefined ? '' : String(v);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function toCsv(record) {
  const header = ['id', 'severity', 'confidence', 'status', 'checkId', 'title', 'url', 'key', 'owasp', 'cwe', 'description', 'remediation', 'foundAt'];
  const rows = [header.join(',')];
  for (const f of [...record.findings].sort((a, b) => severityRank(b.severity) - severityRank(a.severity))) {
    rows.push([f.id, f.severity, f.confidence, f.status, f.checkId, f.title, f.url, f.key || '', f.standards.owasp ? OWASP_2021[f.standards.owasp] : '', f.standards.cwe.map((n) => `CWE-${n}`).join(' '), f.description, f.remediation.summary, f.foundAt].map(csvCell).join(','));
  }
  return rows.join('\r\n') + '\r\n';
}

const SARIF_LEVEL = { informational: 'note', low: 'note', medium: 'warning', high: 'error', critical: 'error' };

export function toSarif(record) {
  const ruleIds = [...new Set(record.findings.map((f) => f.checkId))];
  const byRule = Object.fromEntries(record.findings.map((f) => [f.checkId, f]));
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: {
        name: 'QuillTest', informationUri: 'https://github.com/socrtwo/QuillTest', version: '0.0.0',
        rules: ruleIds.map((id) => { const f = byRule[id]; return { id, name: id, shortDescription: { text: f.title }, fullDescription: { text: f.description }, help: { text: f.remediation.summary }, helpUri: f.remediation.references[0], properties: { tags: [...f.standards.cwe.map((n) => `CWE-${n}`), ...(f.standards.owasp ? [f.standards.owasp] : [])], 'security-severity': String({ informational: 0, low: 3, medium: 5.5, high: 8, critical: 9.5 }[f.severity]) } }; }),
      } },
      invocations: [{ executionSuccessful: true, startTimeUtc: record.startedAt, endTimeUtc: record.finishedAt, properties: { origin: record.origin, profile: record.profile, verification: record.verification, authorization: record.authorization } }],
      results: record.findings.map((f) => ({
        ruleId: f.checkId, level: SARIF_LEVEL[f.severity], kind: f.status === 'open' ? 'fail' : f.status === 'false-positive' ? 'notApplicable' : 'pass',
        message: { text: `${f.title}: ${f.description}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.url } } }],
        partialFingerprints: { quilltestSignature: f.signature },
        properties: { severity: f.severity, confidence: f.confidence, status: f.status, key: f.key, cwe: f.standards.cwe.map((n) => ({ id: `CWE-${n}`, name: CWE[n] })), owasp: f.standards.owasp, evidence: f.evidence },
        ...(f.status !== 'open' ? { suppressions: [{ kind: 'external', justification: f.notes.join('; ') || f.status }] } : {}),
      })),
    }],
  };
}
