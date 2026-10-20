/**
 * lib/severity.js
 * ---------------------------------------------------------------------------
 * The single source of truth for severity vocabulary, ranking and the
 * "ship readiness" scoring model.
 *
 * WHY a dedicated module: the score shown to a client and the verdict wording
 * are the two things a paying customer looks at first. Keeping them in one
 * file means the CLI, the JSON output, the Markdown report and the unit tests
 * can never drift apart. If you change a weight here, every consumer moves
 * together.
 */

/** Ordered from most to least severe. Index === rank (lower is worse). */
export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

/** Rank lookup used for sorting. Lower number = higher severity. */
export const SEVERITY_RANK = Object.freeze({
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFO: 4,
});

/**
 * Points deducted from the 100-point score per finding.
 *
 * WHY these numbers: a single CRITICAL must be able to sink a project on its
 * own (25 x 4 = 100), so "one critical" and "four criticals" both land in the
 * "do not ship" band. HIGH is deliberately close behind (12) because a live
 * secret key or a database table without row-level security is, in practice,
 * a data breach waiting to happen. MEDIUM and LOW are hygiene: worth fixing,
 * not worth blocking a launch over.
 */
export const SEVERITY_WEIGHT = Object.freeze({
  CRITICAL: 25,
  HIGH: 12,
  MEDIUM: 4,
  LOW: 1,
  INFO: 0,
});

/** Starting score before any deductions. */
export const MAX_SCORE = 100;

/**
 * Verdict bands, ordered from best to worst. The numeric value is the rank
 * used when we need to *cap* a verdict (see `verdictFor`).
 */
export const VERDICT_BANDS = Object.freeze([
  { min: 90, key: 'ready', label: 'Ready to ship' },
  { min: 70, key: 'fix-high', label: 'Ship after fixing high findings' },
  { min: 40, key: 'do-not-ship', label: 'Do not ship yet' },
  { min: 0, key: 'unsafe', label: 'Unsafe to ship' },
]);

/** Verdict labels indexed by rank (0 = worst). */
export const VERDICT_BY_RANK = Object.freeze([
  'Unsafe to ship',
  'Do not ship yet',
  'Ship after fixing high findings',
  'Ready to ship',
]);

/**
 * Plain-English translation of a verdict, used in the summary paragraph.
 * The audience is a non-technical founder, so no jargon.
 */
export const VERDICT_PLAIN = Object.freeze({
  'Ready to ship':
    'the app looks safe enough to release to real users right now.',
  'Ship after fixing high findings':
    'the app is close, but the serious problems listed below need to be fixed first.',
  'Do not ship yet':
    'the app has real security problems that need to be fixed before real users can safely use it.',
  'Unsafe to ship':
    'the app currently has serious security holes and should not be exposed to users or real data until they are fixed.',
});

/** Normalise an arbitrary severity string to a known value. */
export function normalizeSeverity(value) {
  const upper = String(value || 'INFO').toUpperCase();
  return SEVERITY_RANK[upper] === undefined ? 'INFO' : upper;
}

/** Numeric rank of a severity (lower = worse). */
export function severityRank(severity) {
  const rank = SEVERITY_RANK[normalizeSeverity(severity)];
  return rank === undefined ? SEVERITY_RANK.INFO : rank;
}

/** Points a single finding costs. */
export function severityWeight(severity) {
  return SEVERITY_WEIGHT[normalizeSeverity(severity)];
}

/**
 * Comparator for sorting findings worst-first.
 * Ties are broken by location then title so report output is deterministic
 * across runs (important: a client compares two report versions).
 */
export function compareSeverity(a, b) {
  const diff = severityRank(a.severity) - severityRank(b.severity);
  if (diff !== 0) return diff;
  const loc = String(a.location || '').localeCompare(String(b.location || ''));
  if (loc !== 0) return loc;
  return String(a.title || '').localeCompare(String(b.title || ''));
}

/** Sort a copy of the findings list, worst first. */
export function sortFindings(findings) {
  return [...findings].sort(compareSeverity);
}

/**
 * Counts per severity, always returning every key so report tables never
 * show a blank cell.
 */
export function countBySeverity(findings) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const finding of findings) {
    counts[normalizeSeverity(finding.severity)] += 1;
  }
  return counts;
}

/**
 * A finding only costs points if it represents an actual weakness.
 * `kind` lets a check emit non-defect notes (e.g. "this check passed") that
 * still appear in the report but never move the score.
 */
export function isScorable(finding) {
  if (!finding) return false;
  const kind = finding.kind || 'defect';
  if (kind !== 'defect') return false;
  return severityWeight(finding.severity) > 0;
}

/**
 * The ship-readiness score: 100 minus the weighted cost of every scorable
 * finding, floored at 0.
 *
 * WHY a straight subtraction: it is trivially explainable to a client
 * ("each critical finding costs 25 points"), and it is deterministic, which
 * means two auditors produce comparable numbers.
 */
export function computeScore(findings) {
  const list = Array.isArray(findings) ? findings : [];
  let penalty = 0;
  for (const finding of list) {
    if (isScorable(finding)) penalty += severityWeight(finding.severity);
  }
  return Math.max(0, MAX_SCORE - penalty);
}

/**
 * Turn a score into a verdict.
 *
 * WHY the CRITICAL cap: a project can score 90+ purely because it has a large
 * codebase and a handful of LOW findings, yet still contain one critical
 * issue. Telling such a project "Ready to ship" would be irresponsible, so
 * any CRITICAL finding caps the verdict at "Do not ship yet" (rank 1).
 */
export function verdictFor(score, hasCritical = false) {
  const value = Number.isFinite(score) ? score : 0;
  let rank;
  if (value >= VERDICT_BANDS[0].min) rank = 3;
  else if (value >= VERDICT_BANDS[1].min) rank = 2;
  else if (value >= VERDICT_BANDS[2].min) rank = 1;
  else rank = 0;
  if (hasCritical && rank > 1) rank = 1;
  return VERDICT_BY_RANK[rank];
}

/** Convenience: the plain-English phrase for a verdict. */
export function verdictPlain(verdict) {
  return VERDICT_PLAIN[verdict] || '';
}

/**
 * Full scoring result for a set of findings.
 * Returned as one object so the CLI and the report can never compute a
 * score and a verdict from different inputs.
 */
export function scoreFindings(findings) {
  const list = Array.isArray(findings) ? findings : [];
  const counts = countBySeverity(list);
  const score = computeScore(list);
  const hasCritical = counts.CRITICAL > 0;
  const verdict = verdictFor(score, hasCritical);
  return {
    score,
    verdict,
    verdictPlain: verdictPlain(verdict),
    counts,
    hasCritical,
    scorableCount: list.filter(isScorable).length,
    total: list.length,
  };
}
