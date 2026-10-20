/**
 * test/secrets.test.js
 * ---------------------------------------------------------------------------
 * Secret detection and redaction.
 *
 * The redaction tests matter more than they look: this report gets emailed
 * and pasted into AI chat windows. If a raw key ever reaches the report, the
 * tool has made the client's problem worse.
 *
 * The credential values used here are assembled at runtime by
 * fixtures/secret-values.mjs rather than written inline. This repository is
 * published, and GitHub's push protection refuses any push containing a
 * string shaped like a live credential - even a fabricated one - and it
 * scans git history as well as the tip. The values below have exactly the
 * shape the scanner must catch; none of them point at anything.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { scanText, scanForSecrets, redactSecret, isPlaceholder, classifyJwt, decodeJwtPayload } from '../lib/secrets.js';
import {
  STRIPE_LIVE_KEY,
  AWS_ACCESS_KEY_ID,
  SLACK_WEBHOOK_URL,
  writeEnvFixture,
} from './fixtures/secret-values.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(HERE, 'fixtures');

test('detects a Stripe live secret key and marks it CRITICAL', () => {
  const hits = scanForSecrets(`STRIPE_SECRET_KEY=${STRIPE_LIVE_KEY}\n`);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].patternId, 'stripe-live-secret');
  assert.equal(hits[0].severity, 'CRITICAL');
  assert.match(hits[0].redacted, /^sk_live_/);
});

test('detects an AWS access key ID', () => {
  const hits = scanForSecrets(`AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}\n`);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].patternId, 'aws-access-key-id');
  assert.equal(hits[0].severity, 'HIGH');
});

test('detects a private key block', () => {
  const hits = scanForSecrets('-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, 'CRITICAL');
});

test('detects a Slack webhook URL', () => {
  const hits = scanForSecrets(`url=${SLACK_WEBHOOK_URL}`);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].patternId, 'slack-webhook');
});

test('redacts the secret value - the raw value never reaches the report', () => {
  const raw = STRIPE_LIVE_KEY;
  const hits = scanForSecrets(`STRIPE_SECRET_KEY=${raw}\n`);
  assert.equal(hits.length, 1);
  assert.ok(!hits[0].redacted.includes(raw), 'the redacted value must not contain the raw secret');
  assert.ok(hits[0].redacted.includes('REDACTED'), 'the redacted value must be marked as redacted');
  assert.ok(hits[0].redacted.startsWith('sk_live_'), 'a short identifying prefix is kept');
});

test('redactSecret keeps the prefix and never returns the whole value', () => {
  const secret = 'abcdefghijklmnopqrstuvwxyz0123456789';
  const redacted = redactSecret(secret, 6);
  assert.ok(redacted.startsWith('abcdef'));
  assert.ok(!redacted.includes(secret));
  assert.match(redacted, /len=36/);
});

test('ignores obvious placeholder values', () => {
  assert.equal(isPlaceholder('your-api-key-here'), true);
  assert.equal(isPlaceholder('changeme'), true);
  assert.equal(isPlaceholder('xxxxxxxx'), true);
  assert.equal(isPlaceholder('<your-key>'), true);
  assert.equal(isPlaceholder('short'), true);
  assert.equal(isPlaceholder(STRIPE_LIVE_KEY), false);
});

test('classifies a Supabase service_role JWT as CRITICAL and an anon JWT as public', () => {
  writeEnvFixture();
  const service = fs.readFileSync(path.join(FIXTURES, '.env'), 'utf8');
  const serviceKey = service.match(/SUPABASE_SERVICE_ROLE_KEY=(\S+)/)[1];
  const anonKey = service.match(/VITE_SUPABASE_ANON_KEY=(\S+)/)[1];

  assert.equal(classifyJwt(serviceKey).kind, 'supabase-service-role');
  assert.equal(classifyJwt(anonKey).kind, 'supabase-anon');
  assert.equal(decodeJwtPayload(serviceKey).role, 'service_role');

  const hits = scanText(service);
  const serviceHit = hits.find((h) => h.jwtKind === 'supabase-service-role');
  const anonHit = hits.find((h) => h.jwtKind === 'supabase-anon');
  assert.equal(serviceHit.severity, 'CRITICAL');
  assert.equal(anonHit.severity, 'INFO');
});

test('scanning the .env fixture finds the real keys and skips the placeholder', () => {
  writeEnvFixture();
  const content = fs.readFileSync(path.join(FIXTURES, '.env'), 'utf8');
  const hits = scanText(content);
  const ids = hits.map((h) => h.patternId);
  assert.ok(ids.includes('stripe-live-secret'));
  assert.ok(ids.includes('slack-webhook'));
  assert.ok(ids.includes('jwt-supabase-service-role'));
  assert.ok(!hits.some((h) => h.match.includes('your-api-key-here')));
});

test('reports the line number of the secret', () => {
  const content = ['line one', 'line two', `STRIPE_SECRET_KEY=${STRIPE_LIVE_KEY}`].join('\n');
  const hits = scanForSecrets(content);
  assert.equal(hits[0].line, 3);
});
