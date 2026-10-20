/**
 * test/env-committed.test.js
 * ---------------------------------------------------------------------------
 * Detection of environment files that are committed to version control.
 *
 * The test creates a REAL git repository in a temp folder and commits the
 * .env file, because the whole point of the check is what git thinks, and
 * mocking git would test the mock rather than the behaviour.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { createContext, createFileRecord } from '../lib/context.js';
import * as envCommitted from '../checks/env-committed.js';

/** Create a temp folder that is a git repository with the given files. */
async function makeRepo(files) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vibeaudit-env-'));
  for (const [name, content] of Object.entries(files)) {
    await fs.writeFile(path.join(dir, name), content, 'utf8');
  }
  const git = (args) =>
    execFileSync('git', args, {
      cwd: dir,
      stdio: 'ignore',
      windowsHide: true,
    });
  git(['init', '-q']);
  git(['add', '-A']);
  git(['-c', 'user.email=test@example.com', '-c', 'user.name=test', 'commit', '-q', '-m', 'initial']);
  return dir;
}

/** Build the context the way the runner does, but from in-memory files. */
function contextFor(files, git) {
  return createContext({
    root: '/tmp/project',
    files: files.map((file) => createFileRecord(file)),
    git: git || { available: false, tracked: null, history: [] },
  });
}

test('reports a .env file that is committed to git', async () => {
  const dir = await makeRepo({
    '.env': 'SUPABASE_SERVICE_ROLE_KEY=abc\n',
    '.gitignore': 'node_modules\n',
  });

  const envFile = createFileRecord({ relPath: '.env', content: 'SUPABASE_SERVICE_ROLE_KEY=abc\n', category: 'env' });
  const gitignore = createFileRecord({ relPath: '.gitignore', content: 'node_modules\n', category: 'source' });

  const context = contextFor([envFile, gitignore], {
    available: true,
    tracked: new Set(['.env', '.gitignore']),
    history: [],
  });

  const findings = envCommitted.run(context);
  const committed = findings.find((f) => f.title.includes('committed to git'));
  assert.ok(committed, 'expected a finding about a committed .env');
  assert.equal(committed.severity, 'HIGH');
  assert.match(committed.location, /\.env$/);
  assert.ok(committed.remediation.includes('rotate'), 'the fix must include rotating the exposed keys');
  await fs.rm(dir, { recursive: true, force: true });
});

test('reports a .env file that is not excluded by .gitignore', () => {
  const envFile = createFileRecord({ relPath: '.env', content: 'A=1\n', category: 'env' });
  const gitignore = createFileRecord({ relPath: '.gitignore', content: 'node_modules\ndist/\n', category: 'source' });

  const context = contextFor([envFile, gitignore], {
    available: true,
    tracked: new Set(['.gitignore']),
    history: [],
  });

  const findings = envCommitted.run(context);
  const notIgnored = findings.find((f) => f.title.includes('not ignored by git'));
  assert.ok(notIgnored, 'expected a finding about an unprotected .env');
  assert.equal(notIgnored.severity, 'HIGH');

  const gitignoreFinding = findings.find((f) => f.title.includes('.gitignore does not exclude'));
  assert.ok(gitignoreFinding, 'expected a finding about the missing .gitignore rule');
});

test('does not report a .env file that is correctly git-ignored', () => {
  const envFile = createFileRecord({ relPath: '.env', content: 'A=1\n', category: 'env', gitignored: true });
  const gitignore = createFileRecord({ relPath: '.gitignore', content: '.env\nnode_modules\n', category: 'source' });

  const context = contextFor([envFile, gitignore], {
    available: true,
    tracked: new Set(['.gitignore']),
    history: [],
  });

  const findings = envCommitted.run(context);
  const defects = findings.filter((f) => (f.kind || 'defect') === 'defect');
  assert.equal(defects.length, 0, `expected no defects, got: ${defects.map((f) => f.title).join(', ')}`);
  assert.ok(findings.some((f) => f.kind === 'pass'), 'expected a "check passed" note');
});

test('does not report .env.example as a live environment file', () => {
  const example = createFileRecord({ relPath: '.env.example', content: 'API_URL=\n', category: 'env' });
  const context = contextFor([example], { available: true, tracked: new Set(['.env.example']), history: [] });

  const findings = envCommitted.run(context);
  const defects = findings.filter((f) => (f.kind || 'defect') === 'defect');
  assert.equal(defects.length, 0);
});
