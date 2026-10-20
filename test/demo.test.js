/**
 * test/demo.test.js
 * ---------------------------------------------------------------------------
 * The demo fixture is the portfolio screenshot, so it has to work every time.
 *
 * These tests assert that the demo finds the SIX problems the fixture was
 * built to contain:
 *   1. a committed .env with a service_role key
 *   2. a table without Row Level Security
 *   3. a SECURITY DEFINER function without a safe search_path
 *   4. an alg:none JWT check
 *   5. a wildcard CORS handler
 *   6. a /api/debug route
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { runAudit } from '../lib/runner.js';
import { ensureFixture } from '../fixtures/build-fixture.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEMO_FIXTURE = path.join(HERE, '..', 'fixtures', 'vulnerable-app');

let cached = null;
async function demoReport() {
  if (!cached) {
    // The demo fixture is generated at runtime - see fixtures/build-fixture.mjs.
    await ensureFixture();
    cached = await runAudit({ target: DEMO_FIXTURE, demo: true });
  }
  return cached;
}

test('the demo produces at least one CRITICAL and at least one HIGH finding', async () => {
  const report = await demoReport();
  assert.ok(report.counts.CRITICAL >= 1, `expected a critical finding, counts: ${JSON.stringify(report.counts)}`);
  assert.ok(report.counts.HIGH >= 1, `expected a high finding, counts: ${JSON.stringify(report.counts)}`);
  assert.ok(report.findings.length >= 5, 'the demo should find a realistic number of problems');
});

test('the demo finds the committed .env with a service_role key', async () => {
  const report = await demoReport();
  const envFinding = report.findings.find(
    (f) => f.checkId === 'env-committed' && f.title.includes('committed to git'),
  );
  assert.ok(envFinding, 'the committed .env was not detected');
  assert.equal(envFinding.severity, 'HIGH');

  const serviceRole = report.findings.find(
    (f) => f.title.includes('service_role') && f.severity === 'CRITICAL',
  );
  assert.ok(serviceRole, 'the service_role key was not detected');
  assert.ok(serviceRole.location.startsWith('.env'), `unexpected location: ${serviceRole.location}`);
});

test('the demo finds the table without Row Level Security', async () => {
  const report = await demoReport();
  const finding = report.findings.find(
    (f) => f.checkId === 'rls' && f.title.includes('no Row Level Security'),
  );
  assert.ok(finding, 'the missing RLS table was not detected');
  assert.ok(['CRITICAL', 'HIGH'].includes(finding.severity));
  assert.match(finding.location, /\.sql/);
});

test('the demo finds the SECURITY DEFINER function without a safe search_path', async () => {
  const report = await demoReport();
  const finding = report.findings.find((f) => f.checkId === 'rls' && f.title.includes('SECURITY DEFINER'));
  assert.ok(finding, 'the SECURITY DEFINER function was not detected');
  assert.equal(finding.severity, 'CRITICAL');
});

test('the demo finds the alg:none token check', async () => {
  const report = await demoReport();
  const finding = report.findings.find((f) => f.checkId === 'jwt' && f.title.includes('alg: none'));
  assert.ok(finding, 'the alg:none check was not detected');
  assert.equal(finding.severity, 'CRITICAL');
});

test('the demo finds the wildcard CORS handler', async () => {
  const report = await demoReport();
  const finding = report.findings.find((f) => f.checkId === 'cors');
  assert.ok(finding, 'the CORS problem was not detected');
  assert.ok(['CRITICAL', 'HIGH'].includes(finding.severity));
});

test('the demo finds the /api/debug route', async () => {
  const report = await demoReport();
  const finding = report.findings.find(
    (f) => f.checkId === 'debug-routes' && f.title.includes('/api/debug'),
  );
  assert.ok(finding, 'the debug route was not detected');
});

test('the demo finds the service_role key inside the built client bundle', async () => {
  const report = await demoReport();
  const finding = report.findings.find(
    (f) => f.checkId === 'secrets-bundle' && f.severity === 'CRITICAL',
  );
  assert.ok(finding, 'the bundle leak was not detected');
  assert.match(finding.location, /dist\//);
});

test('the demo score is at the bottom of the scale and the verdict says so', async () => {
  const report = await demoReport();
  assert.ok(report.score < 40, `expected a low score, got ${report.score}`);
  assert.equal(report.verdict, 'Unsafe to ship');
});

test('the live checks are reported as skipped, never as passed, without a URL', async () => {
  const report = await demoReport();
  const live = report.checks.filter((c) => c.id.startsWith('live-'));
  assert.ok(live.length >= 2);
  for (const check of live) {
    assert.equal(check.state, 'skip', `${check.id} should be skipped, not ${check.state}`);
    assert.ok(check.notes.length > 0, `${check.id} must explain why it was skipped`);
  }
});
