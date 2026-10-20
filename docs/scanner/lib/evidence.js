/**
 * lib/evidence.js
 * ---------------------------------------------------------------------------
 * ES-module facade over `lib/evidence.core.js`.
 * See the note in `lib/util.js` for why the implementation lives in a
 * classic script and this file is only the module surface.
 */

import './secrets.core.js';
import './evidence.core.js';

export const { redactedLine, evidenceBlock, lineNumber, codeWindow, clipSnippet } =
  globalThis.SCANNER.lib.evidence;
