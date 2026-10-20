/**
 * checks/index.core.js
 * ---------------------------------------------------------------------------
 * The registry of every check the browser scanner runs.
 *
 * PORTED from the CLI's `checks/index.js`.
 *
 * WHY a registry: the report has to list every check that ran, including the
 * ones that passed and the ones that were skipped. A registry makes that
 * automatic, and it means adding a new check is a one-line change.
 *
 * ORDER MATTERS for the report: findings are grouped by severity at render
 * time, but "Top 5 things to fix first" respects this order for ties, so the
 * most damaging checks come first.
 *
 * WHAT IS NOT HERE: the CLI also has checks for third-party dependencies,
 * API-route authorisation and live-site probing. Those need the network or
 * the git repository, so they are not in the browser build - the report says
 * so explicitly instead of pretending they ran.
 */

(function (root) {
  'use strict';

  const S = (root.SCANNER = root.SCANNER || {});
  S.checks = S.checks || {};

  S.checks.CHECKS = [
    S.checks.envCommitted,
    S.checks.secrets,
    S.checks.rls,
    S.checks.jwt,
    S.checks.cors,
    S.checks.debugRoutes,
  ];
})(globalThis);
