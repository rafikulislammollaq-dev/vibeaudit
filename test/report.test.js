/**
 * test/report.test.js
 * ---------------------------------------------------------------------------
 * The report is the product, so these tests check the things a client will
 * actually look for: the plain-English summary, the top-5 list, the fix
 * prompts and the "checks that passed" section.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { runAudit } from '../lib/runner.js';
import { buildPlainSummary, buildTopFive, renderJson, renderMarkdown } from '../lib/report.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEMO_FIXTURE = path.join(HERE, '..', 'fixtures', 'vulnerable-app');

let cached = null;
async function demoReport() {
  if (!cached) {
    cached = await runAudit({ target: DEMO_FIXTURE, demo: true });
  }
  return cached;
}

test('the plain-English summary explains the result without jargon', async () => {
  const report = await demoReport();
  const summary = buildPlainSummary(report);

  assert.ok(summary.length > 100, 'the summary must be a real paragraph');
  assert.ok(summary.includes(`${report.score} out of 100`), 'the summary must state the score');
  assert.ok(/we found|did not find/i.test(summary), 'the summary must state how many issues there are');
  // No jargon from the CWE world, no raw file paths in the summary.
  assert.ok(!/CWE-\d+/.test(summary), 'the summary must not contain CWE references');
  assert.ok(!/\.sql|\.ts|\.js\b/.test(summary), 'the summary must not contain file names');
});

test('the report contains the plain-English summary section', async () => {
  const report = await demoReport();
  const markdown = renderMarkdown(report);
  assert.ok(markdown.includes('## What this means, in plain English'), 'the summary section is missing');
  assert.ok(markdown.includes('## Top 5 things to fix first'), 'the top 5 section is missing');
});

test('the top 5 section lists five items with a copy-paste prompt for each', async () => {
  const report = await demoReport();
  const topFive = buildTopFive(report);
  assert.ok(topFive.length > 0);
  assert.ok(topFive.length <= 5);

  for (const [index, item] of topFive.entries()) {
    assert.equal(item.rank, index + 1);
    assert.ok(item.title, 'each item needs a title');
    assert.ok(item.location, 'each item needs a location');
    assert.ok(item.fixPrompt, 'each item needs an AI-assistant prompt');
    assert.match(item.fixPrompt, /Fix this security issue/);
    assert.match(item.fixPrompt, /Required fix:/);
  }

  const markdown = renderMarkdown(report);
  assert.ok(markdown.includes('Paste this into your AI assistant'), 'the report must include the paste prompts');
});

test('the report groups the findings by severity', async () => {
  const report = await demoReport();
  const markdown = renderMarkdown(report);
  assert.ok(markdown.includes('### 🔴 Critical'), 'critical findings are not grouped');
  assert.ok(markdown.includes('### 🟠 High'), 'high findings are not grouped');
  assert.ok(markdown.includes('## All findings'), 'the findings section is missing');
});

test('the report lists the checks that passed and the checks that were skipped', async () => {
  const report = await demoReport();
  const markdown = renderMarkdown(report);
  assert.ok(markdown.includes('## Checks that passed'), 'the passed section is missing');
  assert.ok(markdown.includes('## Checks that were skipped, and why'), 'the skipped section is missing');
  assert.ok(markdown.includes('Live security headers were not checked'), 'the skipped live check should be explained');
});

test('the report ends with the methodology and the scoring explanation', async () => {
  const report = await demoReport();
  const markdown = renderMarkdown(report);
  assert.ok(markdown.includes('## Methodology, scope and limits'));
  assert.ok(markdown.includes('**How the score works**'));
  assert.ok(markdown.includes('25'), 'the weights must be documented in the report');
  assert.ok(markdown.includes('What this audit does NOT cover'));
});

test('the JSON output contains the score, the verdict and every finding', async () => {
  const report = await demoReport();
  const parsed = JSON.parse(renderJson(report));
  assert.equal(parsed.score, report.score);
  assert.equal(parsed.verdict, report.verdict);
  assert.ok(Array.isArray(parsed.findings));
  assert.equal(parsed.findings.length, report.findings.length);
  assert.ok(parsed.summary.includes('out of 100'));
  assert.ok(parsed.topFive.length > 0);
  for (const finding of parsed.findings) {
    assert.ok(finding.severity && finding.title && finding.location && finding.remediation);
  }
});
