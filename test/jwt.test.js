/**
 * test/jwt.test.js
 * ---------------------------------------------------------------------------
 * JWT weaknesses: unsigned tokens, decode-instead-of-verify, and hard-coded
 * signing secret fallbacks.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createContext, createFileRecord } from '../lib/context.js';
import * as jwt from '../checks/jwt.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SERVER = fs.readFileSync(path.join(HERE, 'fixtures', 'server.ts'), 'utf8');

function contextFor(content) {
  return createContext({
    root: '/tmp/project',
    files: [createFileRecord({ relPath: 'src/server.ts', content, ext: '.ts' })],
    git: { available: false, tracked: null, history: [] },
  });
}

test('detects alg: none being accepted', () => {
  const findings = jwt.run(contextFor(SERVER));
  const algNone = findings.find((f) => f.title.includes('alg: none'));
  assert.ok(algNone, `expected an alg:none finding, got: ${findings.map((f) => f.title).join(' | ')}`);
  assert.equal(algNone.severity, 'CRITICAL');
  assert.equal(algNone.cwe, 'CWE-347');
  assert.ok(algNone.remediation.includes('HS256'), 'the fix must pin an algorithm');
});

test('detects jwt.decode() used instead of jwt.verify()', () => {
  const source = `
    export function readToken(token) {
      return jwt.decode(token);
    }
  `;
  const findings = jwt.run(contextFor(source));
  const decode = findings.find((f) => f.title.includes('decoded instead of verified'));
  assert.ok(decode, `expected a decode finding, got: ${findings.map((f) => f.title).join(' | ')}`);
  assert.equal(decode.severity, 'HIGH');
});

test('detects a signing secret with a hard-coded fallback', () => {
  const source = `
    const SECRET = process.env.JWT_SECRET || 'change-me-in-production';
  `;
  const findings = jwt.run(contextFor(source));
  const fallback = findings.find((f) => f.title.includes('hard-coded value'));
  assert.ok(fallback, `expected a fallback finding, got: ${findings.map((f) => f.title).join(' | ')}`);
  assert.equal(fallback.severity, 'HIGH');
  assert.ok(fallback.remediation.includes('throw'), 'the fix must fail loudly instead of falling back');
});

test('detects a verify call that does not pin the algorithm', () => {
  const source = `
    const payload = jwt.verify(token, process.env.JWT_SECRET);
  `;
  const findings = jwt.run(contextFor(source));
  const unpinned = findings.find((f) => f.title.includes('does not pin the algorithm'));
  assert.ok(unpinned, 'expected an unpinned algorithm finding');
  assert.equal(unpinned.severity, 'MEDIUM');
});

test('does not report a correctly implemented token check', () => {
  const source = `
    const payload = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] });
  `;
  const findings = jwt.run(contextFor(source));
  const defects = findings.filter((f) => (f.kind || 'defect') === 'defect');
  assert.equal(defects.length, 0, `expected no defects, got: ${defects.map((f) => f.title).join(' | ')}`);
});
