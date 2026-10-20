/**
 * checks.js
 * ---------------------------------------------------------------------------
 * The public ES-module surface of every check the browser scanner runs.
 *
 *   import { runSecrets, runRls, CHECKS } from './checks.js';
 *
 * See the note in `lib/util.js` for why the implementations live in classic
 * scripts and these files are only the module surface.
 */

import './lib/util.core.js';
import './lib/severity.core.js';
import './lib/secrets.core.js';
import './lib/sql.core.js';
import './lib/files.core.js';
import './lib/findings.core.js';
import './lib/evidence.core.js';
import './checks/env-committed.core.js';
import './checks/secrets.core.js';
import './checks/rls.core.js';
import './checks/jwt.core.js';
import './checks/cors.core.js';
import './checks/debug-routes.core.js';
import './checks/index.core.js';

const C = globalThis.SCANNER.checks;

export const CHECKS = C.CHECKS;

export const runEnvCommitted = C.envCommitted.run;
export const runSecrets = C.secrets.run;
export const runRls = C.rls.run;
export const runJwt = C.jwt.run;
export const runCors = C.cors.run;
export const runDebugRoutes = C.debugRoutes.run;

export const gitignoreCoversEnv = C.envCommitted.gitignoreCoversEnv;
export const isEnvExample = C.envCommitted.isEnvExample;
