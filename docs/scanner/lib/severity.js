/**
 * lib/severity.js
 * ---------------------------------------------------------------------------
 * ES-module facade over `lib/severity.core.js`.
 * See the note in `lib/util.js` for why the implementation lives in a
 * classic script and this file is only the module surface.
 */

import './severity.core.js';

export const {
  SEVERITIES,
  SEVERITY_RANK,
  SEVERITY_WEIGHT,
  MAX_SCORE,
  VERDICT_BANDS,
  VERDICT_BY_RANK,
  VERDICT_PLAIN,
  normalizeSeverity,
  severityRank,
  severityWeight,
  compareSeverity,
  sortFindings,
  countBySeverity,
  isScorable,
  computeScore,
  verdictFor,
  verdictPlain,
  scoreFindings,
} = globalThis.SCANNER.lib.severity;
