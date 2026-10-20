/**
 * checks/index.js
 * ---------------------------------------------------------------------------
 * ES-module facade over `checks/index.core.js`: the registry of every check
 * the browser scanner runs, in report order.
 * See the note in `lib/util.js` for why the implementation lives in a
 * classic script and this file is only the module surface.
 */

import '../lib/util.core.js';
import '../lib/severity.core.js';
import '../lib/secrets.core.js';
import '../lib/sql.core.js';
import '../lib/files.core.js';
import '../lib/findings.core.js';
import './env-committed.core.js';
import './secrets.core.js';
import './rls.core.js';
import './jwt.core.js';
import './cors.core.js';
import './debug-routes.core.js';
import './index.core.js';

export const CHECKS = globalThis.SCANNER.checks.CHECKS;
export default CHECKS;
