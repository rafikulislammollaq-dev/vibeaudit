/**
 * self-test.js
 * ---------------------------------------------------------------------------
 * ES-module entry point for the served version of the self-test.
 * The implementation lives in `self-test.core.js` (a classic script) so the
 * same test can be run by double-clicking `self-test.html` from the
 * filesystem, where browsers refuse to load ES modules over file://.
 */

import './lib/util.core.js';
import './lib/severity.core.js';
import './lib/secrets.core.js';
import './lib/sql.core.js';
import './lib/files.core.js';
import './lib/findings.core.js';
import './lib/evidence.core.js';
import './lib/report.core.js';
// The ES-module facade, not the raw classic script: the facade loads every
// individual check before the registry runs. Without them the registry is
// full of undefined and every detection test fails.
import './checks/index.js';
import './scan.core.js';
import './self-test.core.js';
