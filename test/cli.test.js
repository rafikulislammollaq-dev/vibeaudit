/**
 * test/cli.test.js
 * ---------------------------------------------------------------------------
 * End-to-end tests of the command line tool.
 *
 * These spawn the real CLI as a child process - no in-process shortcuts - so
 * they prove the thing a client actually types works.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);
const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, '..', 'cli.js');
const DEMO_FIXTURE = path.join(HERE, '..', 'fixtures', 'vulnerable-app');

/** Run the CLI and return { code, stdout, stderr }. */
async function runCli(args, options = {}) {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [CLI, ...args], {
      cwd: options.cwd || path.join(HERE, '..'),
      timeout: 120_000,
      windowsHide: true,
      maxBuffer: 32 * 1024 * 1024,
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    return {
      code: typeof error.code === 'number' ? error.code : 1,
      stdout: error.stdout || '',
      stderr: error.stderr || '',
    };
  }
}

test('the CLI exits 0 and writes a report file when given --out', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vibeaudit-cli-'));
  const out = path.join(dir, 'report.md');

  const result = await runCli(['--target', DEMO_FIXTURE, '--out', out]);

  assert.equal(result.code, 0, `the CLI should exit 0\nstdout:\n${result.stdout}\nstderr:\n${result.stderr}`);

  const written = await fs.readFile(out, 'utf8');
  assert.ok(written.length > 500, 'the report file should not be empty');
  assert.ok(written.includes('# Security Audit Report'), 'the report should have a title');
  assert.ok(written.includes('Ship readiness:'), 'the report should have the score headline');
  assert.ok(written.includes('## What this means, in plain English'));
  assert.ok(written.includes('## Top 5 things to fix first'));
  assert.ok(written.includes('## Checks that passed'));
  assert.ok(written.includes('## Methodology, scope and limits'));
  assert.ok(written.includes('CRITICAL'), 'the demo project must produce critical findings');

  await fs.rm(dir, { recursive: true, force: true });
});

test('the CLI creates the folder for --out when it does not exist', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vibeaudit-cli-'));
  const out = path.join(dir, 'nested', 'deeper', 'report.md');

  const result = await runCli(['--target', DEMO_FIXTURE, '--out', out]);
  assert.equal(result.code, 0, result.stderr);
  await fs.access(out);
  await fs.rm(dir, { recursive: true, force: true });
});

test('the CLI prints the report to stdout when --out is not given', async () => {
  const result = await runCli(['--target', DEMO_FIXTURE]);
  assert.equal(result.code, 0, result.stderr);
  assert.ok(result.stdout.includes('# Security Audit Report'));
  assert.ok(result.stdout.includes('Ship readiness:'));
});

test('the CLI --json flag produces valid JSON', async () => {
  const result = await runCli(['--target', DEMO_FIXTURE, '--json']);
  assert.equal(result.code, 0, result.stderr);
  const parsed = JSON.parse(result.stdout);
  assert.ok(typeof parsed.score === 'number');
  assert.ok(typeof parsed.verdict === 'string');
  assert.ok(Array.isArray(parsed.findings));
});

test('the CLI --demo flag runs against the bundled fixture', async () => {
  const result = await runCli(['--demo']);
  assert.equal(result.code, 0, result.stderr);
  assert.ok(result.stdout.includes('DEMO PROJECT'));
  assert.ok(result.stdout.includes('Ship readiness:'));
});

test('the CLI refuses to scan a folder that does not exist', async () => {
  const result = await runCli(['--target', path.join(os.tmpdir(), 'definitely-not-here-12345')]);
  assert.equal(result.code, 1);
  assert.ok(/does not exist/i.test(result.stderr));
});

test('the CLI prints usage when it is given nothing to scan', async () => {
  const result = await runCli([]);
  assert.equal(result.code, 1);
  assert.ok(/--target|--demo/.test(result.stderr));
});

test('the CLI help text explains the authorisation flag', async () => {
  const result = await runCli(['--help']);
  assert.equal(result.code, 0);
  assert.ok(result.stdout.includes('--i-have-authorization'));
  assert.ok(result.stdout.includes('--demo'));
  assert.ok(result.stdout.includes('--target'));
});

test('the live checks are skipped when --url is given without the authorisation flag', async () => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vibeaudit-cli-'));
  const out = path.join(dir, 'report.md');

  // No --i-have-authorization: the tool must not contact the URL.
  const result = await runCli([
    '--target',
    DEMO_FIXTURE,
    '--url',
    'https://example.invalid',
    '--out',
    out,
  ]);

  assert.equal(result.code, 0, result.stderr);
  const written = await fs.readFile(out, 'utf8');
  assert.ok(written.includes('no authorisation given'), 'the report must say the live checks were skipped');
  assert.ok(!written.includes('HTTP 200'), 'no request should have been made');

  await fs.rm(dir, { recursive: true, force: true });
});
