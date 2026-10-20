/**
 * checks/rls.js
 * ---------------------------------------------------------------------------
 * ES-module facade over `checks/rls.core.js`.
 * See the note in `lib/util.js` for why the implementation lives in a
 * classic script and this file is only the module surface.
 */

import '../lib/util.core.js';
import '../lib/severity.core.js';
import '../lib/secrets.core.js';
import '../lib/sql.core.js';
import '../lib/findings.core.js';
import './rls.core.js';

const check = globalThis.SCANNER.checks.rls;

export const id = check.id;
export const title = check.title;
export const severity = check.severity;
export const run = check.run;
export const status = check.status;
