/**
 * lib/secrets.js
 * ---------------------------------------------------------------------------
 * ES-module facade over `lib/secrets.core.js`.
 * See the note in `lib/util.js` for why the implementation lives in a
 * classic script and this file is only the module surface.
 */

import './secrets.core.js';

export const {
  SECRET_PATTERNS,
  GENERIC_ASSIGNMENT_REGEX,
  ENV_STYLE_ASSIGNMENT_REGEX,
  PLACEHOLDER_PATTERNS,
  JWT_REGEX,
  isPlaceholder,
  shannonEntropy,
  looksHighEntropy,
  redactSecret,
  decodeJwtPayload,
  classifyJwt,
  scanForSecrets,
  scanForJwts,
  scanForGenericAssignments,
  countLines,
  scanText,
} = globalThis.SCANNER.lib.secrets;
