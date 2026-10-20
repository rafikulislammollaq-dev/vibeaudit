/**
 * checks/index.js
 * ---------------------------------------------------------------------------
 * The registry of every check the tool runs.
 *
 * WHY a registry: the report has to list every check that ran, including the
 * ones that passed and the ones that were skipped. A registry makes that
 * automatic, and it means adding a new check is a one-line change.
 *
 * ORDER MATTERS for the report: findings are grouped by severity at render
 * time, but "Top 5 things to fix first" respects this order for ties, so the
 * most damaging checks come first.
 */

import * as envCommitted from './env-committed.js';
import * as secretsSource from './secrets-source.js';
import * as secretsBundle from './secrets-bundle.js';
import * as rls from './rls.js';
import * as authz from './authz.js';
import * as cors from './cors.js';
import * as jwt from './jwt.js';
import * as debugRoutes from './debug-routes.js';
import * as deps from './deps.js';
import * as liveSupabase from './live-supabase.js';
import * as liveHeaders from './live-headers.js';

export const CHECKS = [
  envCommitted,
  secretsSource,
  secretsBundle,
  rls,
  authz,
  cors,
  jwt,
  debugRoutes,
  deps,
  liveSupabase,
  liveHeaders,
];

export default CHECKS;
