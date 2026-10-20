/**
 * test/rls.test.js
 * ---------------------------------------------------------------------------
 * Row Level Security analysis: missing RLS, SECURITY DEFINER without a safe
 * search_path, and permissive policies.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createContext, createFileRecord } from '../lib/context.js';
import * as rls from '../checks/rls.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCHEMA = fs.readFileSync(path.join(HERE, 'fixtures', 'schema.sql'), 'utf8');

function contextFor(sql) {
  return createContext({
    root: '/tmp/project',
    files: [createFileRecord({ relPath: 'supabase/migrations/001_init.sql', content: sql, category: 'sql' })],
    git: { available: false, tracked: null, history: [] },
  });
}

test('detects a table that was created without Row Level Security', () => {
  const findings = rls.run(contextFor(SCHEMA));
  const missing = findings.find((f) => f.title.includes('"public.customers"') && f.title.includes('no Row Level Security'));
  assert.ok(missing, `expected a missing-RLS finding, got: ${findings.map((f) => f.title).join(' | ')}`);
  assert.equal(missing.severity, 'CRITICAL', 'a table of customer data without RLS is critical');
  assert.match(missing.location, /001_init\.sql:\d+/);
  assert.ok(missing.remediation.includes('ENABLE ROW LEVEL SECURITY'));
});

test('does not report a table that has Row Level Security enabled', () => {
  const findings = rls.run(contextFor(SCHEMA));
  const wrong = findings.find((f) => f.title.includes('"public.invoices"') && f.title.includes('no Row Level Security'));
  assert.equal(wrong, undefined, 'invoices has RLS enabled and must not be reported');
});

test('detects a SECURITY DEFINER function without a safe search_path', () => {
  const findings = rls.run(contextFor(SCHEMA));
  const definer = findings.find((f) => f.title.includes('SECURITY DEFINER'));
  assert.ok(definer, `expected a SECURITY DEFINER finding, got: ${findings.map((f) => f.title).join(' | ')}`);
  assert.equal(definer.severity, 'CRITICAL');
  assert.ok(definer.remediation.includes('search_path'), 'the fix must pin the search_path');
});

test('does not report a SECURITY DEFINER function that pins its search_path', () => {
  const sql = `
    create or replace function public.safe_total(id uuid)
    returns numeric
    language plpgsql
    security definer
    set search_path = public, pg_temp
    as $$ begin return 0; end; $$;
  `;
  const findings = rls.run(contextFor(sql));
  assert.equal(findings.find((f) => f.title.includes('SECURITY DEFINER')), undefined);
});

test('detects a permissive policy that allows every row', () => {
  const findings = rls.run(contextFor(SCHEMA));
  const permissive = findings.find((f) => f.title.includes('Permissive policy'));
  assert.ok(permissive, `expected a permissive policy finding, got: ${findings.map((f) => f.title).join(' | ')}`);
  assert.ok(['HIGH', 'CRITICAL'].includes(permissive.severity));
  assert.match(permissive.title, /public can read customers/);
});

test('skips (with an explanation) when there are no SQL files to analyse', () => {
  const context = createContext({
    root: '/tmp/project',
    files: [createFileRecord({ relPath: 'src/index.js', content: 'export const a = 1;\n' })],
    git: { available: false, tracked: null, history: [] },
  });
  const findings = rls.run(context);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].kind, 'skip');
  assert.match(findings[0].detail, /could not be reviewed/i);
  assert.match(findings[0].detail, /\.sql files/i);
});
