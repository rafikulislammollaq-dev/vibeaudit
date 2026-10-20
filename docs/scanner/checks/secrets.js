/**
 * checks/secrets.js
 * ---------------------------------------------------------------------------
 * ES-module facade over `checks/secrets.core.js`.
 * See the note in `lib/util.js` for why the implementation lives in a
 * classic script and this file is only the module surface.
 */

import '../lib/util.core.js';
import '../lib/severity.core.js';
import '../lib/secrets.core.js';
import '../lib/findings.core.js';
import '../lib/evidence.core.js';
import './secrets.core.js';

const check = globalThis.SCANNER.checks.secrets;

export const id = check.id;
export const title = check.title;
export const severity = check.severity;
export const run = check.run;
export const status = check.status;
