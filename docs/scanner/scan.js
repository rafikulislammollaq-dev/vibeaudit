/**
 * scan.js
 * ---------------------------------------------------------------------------
 * ES-module facade over `scan.core.js` - the browser scan engine.
 * See the note in `lib/util.js` for why the implementation lives in a
 * classic script and this file is only the module surface.
 */

import './lib/util.core.js';
import './lib/severity.core.js';
import './lib/secrets.core.js';
import './lib/sql.core.js';
import './lib/files.core.js';
import './lib/findings.core.js';
import './lib/evidence.core.js';
import './lib/report.core.js';
import './checks/index.core.js';
import './scan.core.js';

export const { scanProject, buildContext, TOOL } = globalThis.SCANNER.scan;
