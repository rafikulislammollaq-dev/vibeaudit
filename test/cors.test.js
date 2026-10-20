/**
 * test/cors.test.js
 * ---------------------------------------------------------------------------
 * CORS misconfiguration detection.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createContext, createFileRecord } from '../lib/context.js';
import * as cors from '../checks/cors.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SERVER = fs.readFileSync(path.join(HERE, 'fixtures', 'server.ts'), 'utf8');

function contextFor(content) {
  return createContext({
    root: '/tmp/project',
    files: [createFileRecord({ relPath: 'src/server.ts', content, ext: '.ts' })],
    git: { available: false, tracked: null, history: [] },
  });
}

test('detects a wildcard origin combined with credentials as CRITICAL', () => {
  const findings = cors.run(contextFor(SERVER));
  const critical = findings.find((f) => f.title.includes('any website AND credentials'));
  assert.ok(critical, `expected a wildcard+credentials finding, got: ${findings.map((f) => f.title).join(' | ')}`);
  assert.equal(critical.severity, 'CRITICAL');
  assert.equal(critical.cwe, 'CWE-942');
});

test('detects cors({ origin: "*" })', () => {
  const findings = cors.run(contextFor(SERVER));
  const wildcard = findings.find((f) => f.title.includes('allow every origin'));
  assert.ok(wildcard, 'expected a wildcard origin finding');
  assert.equal(wildcard.severity, 'HIGH');
});

test('detects a reflected Origin header', () => {
  const source = `
    app.use((req, res, next) => {
      res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
      next();
    });
  `;
  const findings = cors.run(contextFor(source));
  const reflected = findings.find((f) => f.title.includes('reflects'));
  assert.ok(reflected, `expected a reflected origin finding, got: ${findings.map((f) => f.title).join(' | ')}`);
  assert.equal(reflected.severity, 'HIGH');
});

test('does not report a safe, explicit origin allowlist', () => {
  const source = `
    const ALLOWED_ORIGINS = ['https://myapp.com'];
    app.use(cors({ origin: ALLOWED_ORIGINS, credentials: true }));
  `;
  const findings = cors.run(contextFor(source));
  const defects = findings.filter((f) => (f.kind || 'defect') === 'defect');
  assert.equal(defects.length, 0, `expected no defects, got: ${defects.map((f) => f.title).join(' | ')}`);
});
