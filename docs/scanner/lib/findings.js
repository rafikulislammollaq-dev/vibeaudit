/**
 * lib/findings.js
 * ---------------------------------------------------------------------------
 * ES-module facade over `lib/findings.core.js`.
 * See the note in `lib/util.js` for why the implementation lives in a
 * classic script and this file is only the module surface.
 */

import './util.core.js';
import './severity.core.js';
import './findings.core.js';

export const { FINDING_KINDS, defaultFixPrompt, makeFinding, makePass, makeSkip } =
  globalThis.SCANNER.lib.findings;
