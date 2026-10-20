/**
 * test/severity.test.js
 * ---------------------------------------------------------------------------
 * The severity vocabulary and the ship-readiness scoring model.
 *
 * The score is the number the client sees, so the arithmetic has to be
 * exactly right and completely deterministic.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  SEVERITIES,
  SEVERITY_RANK,
  SEVERITY_WEIGHT,
  compareSeverity,
  computeScore,
  countBySeverity,
  isScorable,
  normalizeSeverity,
  scoreFindings,
  severityRank,
  sortFindings,
  verdictFor,
} from '../lib/severity.js';

const finding = (severity, title = 'x') => ({ severity, title, kind: 'defect' });

test('the severity order is CRITICAL > HIGH > MEDIUM > LOW > INFO', () => {
  assert.deepEqual(SEVERITIES, ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
  assert.ok(SEVERITY_RANK.CRITICAL < SEVERITY_RANK.HIGH);
  assert.ok(SEVERITY_RANK.HIGH < SEVERITY_RANK.MEDIUM);
  assert.ok(SEVERITY_RANK.MEDIUM < SEVERITY_RANK.LOW);
  assert.ok(SEVERITY_RANK.LOW < SEVERITY_RANK.INFO);
  assert.equal(severityRank('critical'), 0);
  assert.equal(severityRank('nonsense'), SEVERITY_RANK.INFO);
  assert.equal(normalizeSeverity('high'), 'HIGH');
});

test('the weights are 25 / 12 / 4 / 1 / 0', () => {
  assert.equal(SEVERITY_WEIGHT.CRITICAL, 25);
  assert.equal(SEVERITY_WEIGHT.HIGH, 12);
  assert.equal(SEVERITY_WEIGHT.MEDIUM, 4);
  assert.equal(SEVERITY_WEIGHT.LOW, 1);
  assert.equal(SEVERITY_WEIGHT.INFO, 0);
});

test('the score starts at 100 and subtracts the weighted findings', () => {
  assert.equal(computeScore([]), 100);
  assert.equal(computeScore([finding('CRITICAL')]), 75);
  assert.equal(computeScore([finding('HIGH')]), 88);
  assert.equal(computeScore([finding('MEDIUM')]), 96);
  assert.equal(computeScore([finding('LOW')]), 99);
  assert.equal(computeScore([finding('CRITICAL'), finding('HIGH'), finding('MEDIUM'), finding('LOW')]), 58);
});

test('the score never goes below zero', () => {
  const many = Array.from({ length: 10 }, () => finding('CRITICAL'));
  assert.equal(computeScore(many), 0);
});

test('notes and passes do not move the score', () => {
  const findings = [
    finding('CRITICAL'),
    { severity: 'INFO', title: 'check passed', kind: 'pass' },
    { severity: 'INFO', title: 'check skipped', kind: 'skip' },
  ];
  assert.equal(computeScore(findings), 75);
  assert.equal(isScorable(findings[0]), true);
  assert.equal(isScorable(findings[1]), false);
});

test('the verdict follows the score bands', () => {
  assert.equal(verdictFor(100), 'Ready to ship');
  assert.equal(verdictFor(90), 'Ready to ship');
  assert.equal(verdictFor(89), 'Ship after fixing high findings');
  assert.equal(verdictFor(70), 'Ship after fixing high findings');
  assert.equal(verdictFor(69), 'Do not ship yet');
  assert.equal(verdictFor(40), 'Do not ship yet');
  assert.equal(verdictFor(39), 'Unsafe to ship');
  assert.equal(verdictFor(0), 'Unsafe to ship');
});

test('a single critical finding caps the verdict, whatever the score', () => {
  assert.equal(verdictFor(100, true), 'Do not ship yet');
  assert.equal(verdictFor(95, true), 'Do not ship yet');
  // A score that is already bad is not made any worse by the cap.
  assert.equal(verdictFor(20, true), 'Unsafe to ship');
});

test('scoreFindings returns the score, the verdict and the counts together', () => {
  const result = scoreFindings([finding('CRITICAL'), finding('HIGH'), finding('HIGH')]);
  assert.equal(result.score, 51);
  assert.equal(result.verdict, 'Do not ship yet');
  assert.equal(result.hasCritical, true);
  assert.equal(result.counts.CRITICAL, 1);
  assert.equal(result.counts.HIGH, 2);
  assert.equal(result.counts.MEDIUM, 0);
});

test('findings sort worst first', () => {
  const sorted = sortFindings([finding('LOW', 'l'), finding('CRITICAL', 'c'), finding('HIGH', 'h'), finding('MEDIUM', 'm')]);
  assert.deepEqual(sorted.map((f) => f.severity), ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
});

test('the comparator is stable for equal severities', () => {
  const a = { severity: 'HIGH', location: 'a.js', title: 'A' };
  const b = { severity: 'HIGH', location: 'b.js', title: 'B' };
  assert.ok(compareSeverity(a, b) < 0);
});

test('countBySeverity always returns every key', () => {
  const counts = countBySeverity([finding('CRITICAL')]);
  assert.deepEqual(counts, { CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 });
});
