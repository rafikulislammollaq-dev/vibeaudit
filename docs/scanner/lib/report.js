/**
 * lib/report.js
 * ---------------------------------------------------------------------------
 * ES-module facade over `lib/report.core.js`.
 * See the note in `lib/util.js` for why the implementation lives in a
 * classic script and this file is only the module surface.
 */

import './util.core.js';
import './severity.core.js';
import './report.core.js';

export const {
  SEVERITY_ICON,
  VERDICT_ICON,
  NOT_CHECKED,
  buildPlainSummary,
  listToSentence,
  stripSentenceEnd,
  asSentence,
  buildTopFive,
  groupBySeverity,
  renderMarkdown,
  renderConsoleSummary,
} = globalThis.SCANNER.lib.report;
