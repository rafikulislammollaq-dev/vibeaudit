/**
 * test/suite.js
 * ---------------------------------------------------------------------------
 * The test entry point.
 *
 * Node 22.6+ resolves a positional test-runner argument (such as `test/`) as a
 * glob and then loads the matched path as a module. A bare directory cannot
 * be executed, but a directory with a package.json "main" entry can - which is
 * why test/package.json points here.
 *
 * This file simply imports every test file, so one command runs them all.
 */

import './secrets.test.js';
import './env-committed.test.js';
import './rls.test.js';
import './cors.test.js';
import './jwt.test.js';
import './severity.test.js';
import './report.test.js';
import './demo.test.js';
import './live.test.js';
import './cli.test.js';
