/**
 * app.js
 * ---------------------------------------------------------------------------
 * ES-module entry point for the served version of the scanner.
 *
 * The implementation lives in `app.core.js` (a classic script) so that the
 * very same code also runs when `index.html` is opened directly from the
 * filesystem, where browsers refuse to load ES modules over file://.
 * This file simply pulls in every module and hands over to the app.
 */

import './lib/util.core.js';
import './lib/severity.core.js';
import './lib/secrets.core.js';
import './lib/sql.core.js';
import './lib/files.core.js';
import './lib/findings.core.js';
import './lib/evidence.core.js';
import './lib/report.core.js';
// Import the ES-module facade, not the raw classic script: the facade pulls in
// every individual check (secrets, rls, jwt, cors, debug-routes, env-committed)
// BEFORE checks/index.core.js runs. The registry builds its list from those
// namespaces at load time, so importing the registry on its own leaves the
// list full of undefined and the scanner reports nothing.
import './checks/index.js';
import './scan.core.js';
import './app.core.js';
