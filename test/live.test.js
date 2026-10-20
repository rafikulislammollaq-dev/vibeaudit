/**
 * test/live.test.js
 * ---------------------------------------------------------------------------
 * The live-URL checks and their safety contract.
 *
 * These tests run against a LOCAL HTTP server on 127.0.0.1. Nothing in this
 * file touches the internet, and the server counts the requests it receives
 * so we can prove the tool's promises:
 *
 *   - no request is sent at all without --i-have-authorization
 *   - exactly one request is sent with it
 *   - the request is a read (GET), never a write
 *
 * That is the behaviour a client is being asked to trust, so it is worth
 * testing rather than asserting in the README.
 */

import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
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

let server;
let port;
let requests;

before(async () => {
  requests = [];
  server = http.createServer((req, res) => {
    requests.push({ method: req.method, url: req.url, headers: req.headers });
    // A deliberately bare response: no security headers at all.
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><body>hello</body></html>');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  port = server.address().port;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
});

/** Run the CLI and return { code, stdout, stderr }. */
async function runCli(args) {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [CLI, ...args], {
      cwd: path.join(HERE, '..'),
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

test('without --i-have-authorization the tool sends NO request at all', async () => {
  requests.length = 0;
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vibeaudit-live-'));
  const out = path.join(dir, 'report.md');

  const result = await runCli([
    '--target',
    DEMO_FIXTURE,
    '--url',
    `http://127.0.0.1:${port}`,
    '--out',
    out,
  ]);

  assert.equal(result.code, 0, result.stderr);
  assert.equal(requests.length, 0, 'the tool must not contact the site without the authorisation flag');

  const written = await fs.readFile(out, 'utf8');
  assert.ok(written.includes('no authorisation given'), 'the report must explain that the check was skipped');
  assert.ok(written.includes('Live security headers were not checked'));

  await fs.rm(dir, { recursive: true, force: true });
});

test('with --i-have-authorization the tool sends exactly ONE read request', async () => {
  requests.length = 0;
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vibeaudit-live-'));
  const out = path.join(dir, 'report.md');

  const result = await runCli([
    '--target',
    DEMO_FIXTURE,
    '--url',
    `http://127.0.0.1:${port}`,
    '--i-have-authorization',
    '--out',
    out,
  ]);

  assert.equal(result.code, 0, result.stderr);
  assert.equal(requests.length, 1, `expected exactly one request, got ${requests.length}`);
  assert.equal(requests[0].method, 'GET', 'the only request must be a read');
  assert.equal(requests[0].url, '/', 'the only request must be for the root of the URL');

  const written = await fs.readFile(out, 'utf8');
  assert.ok(written.includes('security header'), 'the report should include the header check result');
  assert.ok(/X-Frame-Options|Content-Security-Policy/i.test(written), 'the missing headers should be named');

  await fs.rm(dir, { recursive: true, force: true });
});

test('the Supabase read probe is skipped for a URL that is not a Supabase project', async () => {
  requests.length = 0;
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vibeaudit-live-'));
  const out = path.join(dir, 'report.md');

  await runCli([
    '--target',
    DEMO_FIXTURE,
    '--url',
    `http://127.0.0.1:${port}`,
    '--i-have-authorization',
    '--out',
    out,
  ]);

  const written = await fs.readFile(out, 'utf8');
  assert.ok(written.includes('not a Supabase project address'), 'the report must say the probe did not apply');
  // One request for the header check, and none for the Supabase probe.
  assert.equal(requests.length, 1, 'the Supabase probe must not send a request to a non-Supabase host');

  await fs.rm(dir, { recursive: true, force: true });
});
