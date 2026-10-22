/*
 * QuillTest — injection detection (active, detection-only)
 * Part of the Quill suite. MIT License. Copyright (c) 2026 Paul D Pruitt.
 *
 * Three detectors, each confirming a flaw class by a benign signal, never by
 * exploiting it:
 *   - sqlError: a value containing a single quote provokes a database error
 *     message that a balanced control value does not. Error-based detection
 *     only — no boolean, timing, UNION, or data extraction.
 *   - ssti:     a benign arithmetic marker ({{7*7}} and friends) comes back
 *     evaluated (…49…), showing the input reaches a template engine.
 *   - crlf:     an encoded newline plus a harmless marker header appears as a
 *     real response header, showing newlines are not stripped (response
 *     splitting / header injection). The injected header is inert.
 */
import { randomBytes } from 'node:crypto';
import { defineCheck } from '../registry.mjs';

const SQL_ERRORS = [
  { re: /You have an error in your SQL syntax|check the manual that corresponds to your (MySQL|MariaDB)/i, db: 'MySQL/MariaDB' },
  { re: /Unclosed quotation mark after the character string|Incorrect syntax near|Microsoft OLE DB Provider for SQL Server|System\.Data\.SqlClient\.SqlException/i, db: 'SQL Server' },
  { re: /ORA-0\d{4}|Oracle error|quoted string not properly terminated/i, db: 'Oracle' },
  { re: /PG::(Syntax|Undefined|Internal)\w*Error|PSQLException|unterminated quoted string at or near|invalid input syntax for/i, db: 'PostgreSQL' },
  { re: /SQLITE_ERROR|SQLiteException|unrecognized token:|sqlite3\.OperationalError/i, db: 'SQLite' },
  { re: /SQLSTATE\[\w+\]|JDBC|ODBC|SQLException|database error|syntax error at or near/i, db: 'generic SQL' },
];

function sqlErrorIn(text) {
  for (const p of SQL_ERRORS) if (p.re.test(text)) return p.db;
  return null;
}

defineCheck([
  {
    id: 'injection.sqlError', title: 'SQL error provoked by an unbalanced quote (possible SQL injection)', kind: 'active', intrusiveness: 2,
    requests: 'two requests per parameter: one value containing a single quote, one balanced control; responses are compared for database error signatures',
    severity: 'high', confidence: 'firm', cwe: [89], owasp: 'A03', asvs: ['V5.3.4'],
    description: 'Adding a single quote to a parameter makes the server return a database error that a balanced value does not, which means the parameter reaches an SQL statement without safe parameterisation. Detection is by error signature only; QuillTest does not read or change any data.',
    remediation: { summary: 'Use parameterised queries / prepared statements (or a vetted ORM) for every query; never build SQL by concatenating request values. Return generic errors and log details server-side.', references: ['https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html'] },
    active: async (site) => {
      const points = site.points.slice(0, site.maxPointsPerCheck);
      const out = [];
      for (const point of points) {
        const control = site.send(point, `${point.original || '1'}qt${randomBytes(2).toString('hex')}`);
        if (!control) break;
        const controlRes = await control;
        const probe = site.send(point, `${point.original || '1'}'`);
        if (!probe) break;
        const probeRes = await probe;
        if (!probeRes || !probeRes.body) continue;
        const db = sqlErrorIn(probeRes.body);
        if (db && !sqlErrorIn(controlRes?.body || '')) {
          out.push({ url: point.url, key: point.name, description: `A single quote in "${point.name}" produced a ${db} error absent from the control response.`, evidence: { request: { url: point.action, param: point.name }, detail: { db, probeStatus: probeRes.status, controlStatus: controlRes?.status } } });
        }
      }
      return out;
    },
  },
  {
    id: 'injection.templateEval', title: 'Server-side template expression evaluated (possible template injection)', kind: 'active', intrusiveness: 2,
    requests: 'a few requests per parameter carrying benign arithmetic markers such as {{7*7}}; the response is checked for the evaluated result',
    severity: 'high', confidence: 'firm', cwe: [1336, 94], owasp: 'A03', asvs: ['V5.2.5'],
    description: 'A benign arithmetic marker placed in a parameter comes back evaluated (for example {{7*7}} returned as 49), which means the value is interpolated into a server-side template. That is the precondition for server-side template injection. QuillTest only checks the arithmetic result; it runs no code.',
    remediation: { summary: 'Never build templates from request input. Pass user data as template variables, not template source; where a sandbox is unavoidable, use a logic-less engine and a strict allowlist.', references: ['https://portswigger.net/web-security/server-side-template-injection'] },
    active: async (site) => {
      const points = site.points.slice(0, site.maxPointsPerCheck);
      const out = [];
      for (const point of points) {
        const tag = 'qt' + randomBytes(3).toString('hex');
        const want = `${tag}2401${tag}`;                        // 49*49 = 2401, unlikely to occur by chance
        const markers = [`${tag}{{49*49}}${tag}`, `${tag}\${49*49}${tag}`, `${tag}#{49*49}${tag}`, `${tag}<%= 49*49 %>${tag}`];
        for (const marker of markers) {
          const res = site.send(point, marker);
          if (!res) return out;
          const awaited = await res;
          if (awaited?.body?.includes(want)) { out.push({ url: point.url, key: point.name, description: `The "${point.name}" parameter interpolates into a server-side template: the marker ${marker.replace(tag, '…')} was returned evaluated.`, evidence: { request: { url: point.action, param: point.name }, detail: { marker, evaluatedTo: '2401' } } }); break; }
        }
      }
      return out;
    },
  },
  {
    id: 'injection.crlf', title: 'Newline in a parameter reaches a response header (CRLF / header injection)', kind: 'active', intrusiveness: 2,
    requests: 'one request per parameter whose value contains an encoded newline and an inert marker header name; the response headers are inspected',
    severity: 'medium', confidence: 'firm', cwe: [113, 93], owasp: 'A03', asvs: ['V5.1.5'],
    description: 'A parameter value containing a CR/LF sequence causes an inert marker header to appear in the response, which means newlines are not stripped before the value is written into a header. That allows HTTP response splitting and header injection. The injected header is harmless and sets nothing.',
    remediation: { summary: 'Strip or reject CR and LF in any value written to a response header (and in redirect Location values); use the framework\'s header API rather than building raw headers.', references: ['https://owasp.org/www-community/vulnerabilities/HTTP_Response_Splitting'] },
    active: async (site) => {
      const points = site.points.filter((p) => p.where === 'query').slice(0, site.maxPointsPerCheck);
      const out = [];
      for (const point of points) {
        const token = randomBytes(4).toString('hex');
        const marker = `x-quilltest-crlf-${token}`;
        const res = site.send(point, `${point.original}\r\n${marker}: 1`);
        if (!res) break;
        const awaited = await res;
        if (awaited?.headers?.[marker] !== undefined) out.push({ url: point.url, key: point.name, description: `A CR/LF in "${point.name}" injected a response header, so the value is written to headers without newline stripping.`, evidence: { request: { url: point.action, param: point.name }, detail: { injectedHeader: marker, status: awaited.status } } });
      }
      return out;
    },
  },
]);
