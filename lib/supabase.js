/**
 * lib/supabase.js
 * ---------------------------------------------------------------------------
 * Detects Supabase configuration inside a project.
 *
 * WHY a dedicated module: the Supabase anon key and the Supabase service_role
 * key are the two most important strings in a Lovable / Bolt / v0 app, and
 * they behave completely differently:
 *
 *  - anon key      : PUBLIC BY DESIGN. It ships in the browser bundle and is
 *                    supposed to be there. Its safety comes entirely from
 *                    Row Level Security.
 *  - service_role  : FULL ADMIN. It bypasses RLS. It must never be in the
 *                    browser, never in git, never in a `.env` that is
 *                    committed.
 *
 * The tool needs to find both so it can (a) warn when the admin key is in
 * the wrong place and (b) run one single, authorised read test with the
 * public key to see whether RLS is actually doing its job.
 */

import { classifyJwt } from './secrets.js';

/** Environment variable names that hold the Supabase project URL. */
const URL_VARS = [
  'VITE_SUPABASE_URL',
  'SUPABASE_URL',
  'NEXT_PUBLIC_SUPABASE_URL',
  'REACT_APP_SUPABASE_URL',
  'PUBLIC_SUPABASE_URL',
  'EXPO_PUBLIC_SUPABASE_URL',
];

/** Environment variable names that hold the *public* anon key. */
const ANON_VARS = [
  'VITE_SUPABASE_ANON_KEY',
  'SUPABASE_ANON_KEY',
  'NEXT_PUBLIC_SUPABASE_ANON_KEY',
  'REACT_APP_SUPABASE_ANON_KEY',
  'PUBLIC_SUPABASE_ANON_KEY',
  'EXPO_PUBLIC_SUPABASE_ANON_KEY',
];

/** Environment variable names that hold the *secret* service_role key. */
const SERVICE_VARS = [
  'SUPABASE_SERVICE_ROLE_KEY',
  'SUPABASE_SERVICE_KEY',
  'SUPABASE_SERVICE_ROLE',
  'VITE_SUPABASE_SERVICE_ROLE_KEY',
  'NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY',
];

/** Client-side frameworks where an env var ending in _PUBLIC_ / VITE_ is exposed. */
const CLIENT_PREFIXES = ['VITE_', 'NEXT_PUBLIC_', 'REACT_APP_', 'PUBLIC_', 'EXPO_PUBLIC_', 'NUXT_PUBLIC_'];

const ENV_ASSIGNMENT =
  /([A-Z0-9_]*(?:SUPABASE|DATABASE)[A-Z0-9_]*)\s*=\s*["']([^"'\n]{8,})["']/g;

/**
 * Find Supabase configuration in a set of files.
 *
 * @param {Array<{relPath:string, content:string}>} files
 * @returns {{projectUrl:string|null, anonKey:string|null, serviceRoleKey:string|null,
 *            clientFiles:Array, sources:Object}}
 */
export function detectSupabaseConfig(files) {
  const result = {
    projectUrl: null,
    anonKey: null,
    serviceRoleKey: null,
    projectUrlSource: null,
    anonKeySource: null,
    serviceRoleKeySource: null,
    clientExposedAnonFiles: [],
    clientExposedServiceFiles: [],
  };

  for (const file of files) {
    const content = file.content;
    if (!content) continue;

    for (const match of content.matchAll(ENV_ASSIGNMENT)) {
      const name = match[1].toUpperCase();
      const value = match[2].trim();
      if (!value) continue;

      if (!result.projectUrl && URL_VARS.includes(name)) {
        result.projectUrl = value;
        result.projectUrlSource = file.relPath;
      }
      if (!result.anonKey && ANON_VARS.includes(name)) {
        result.anonKey = value;
        result.anonKeySource = file.relPath;
      }
      if (!result.serviceRoleKey && SERVICE_VARS.includes(name)) {
        result.serviceRoleKey = value;
        result.serviceRoleKeySource = file.relPath;
      }
    }

    // Keys used directly in code, not via an env file.
    const jwtRegex = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;
    for (const match of content.matchAll(jwtRegex)) {
      const info = classifyJwt(match[0]);
      if (info.kind === 'supabase-anon' && !result.anonKey) {
        result.anonKey = match[0];
        result.anonKeySource = file.relPath;
      }
      if (info.kind === 'supabase-service-role' && !result.serviceRoleKey) {
        result.serviceRoleKey = match[0];
        result.serviceRoleKeySource = file.relPath;
      }
    }
  }

  // Which files are client-side code? These are the ones where a
  // service_role key would be shipped to every visitor.
  //
  // Build output is deliberately EXCLUDED here: the "secrets in the client
  // bundle" check already reports that, in more detail. Counting it twice
  // would inflate the score and annoy the client.
  for (const file of files) {
    const content = file.content || '';
    if (isBundlePath(file.relPath)) continue;
    const isClient = isClientSideFile(file.relPath, content);
    if (!isClient) continue;

    const jwtRegex = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;
    for (const match of content.matchAll(jwtRegex)) {
      const info = classifyJwt(match[0]);
      if (info.kind === 'supabase-service-role') {
        result.clientExposedServiceFiles.push(file.relPath);
      }
      if (info.kind === 'supabase-anon') {
        result.clientExposedAnonFiles.push(file.relPath);
      }
    }

    // A service_role key pulled in through a client-side env variable.
    const serviceImport = /(?:import\.meta\.env|process\.env)\s*\.?\s*\[?\s*['"]?(VITE_|NEXT_PUBLIC_|REACT_APP_|PUBLIC_|EXPO_PUBLIC_)?[A-Z0-9_]*SERVICE_ROLE/i;
    if (serviceImport.test(content)) {
      result.clientExposedServiceFiles.push(file.relPath);
    }
  }

  result.clientExposedServiceFiles = [...new Set(result.clientExposedServiceFiles)];
  result.clientExposedAnonFiles = [...new Set(result.clientExposedAnonFiles)];

  // Build output that contains the admin key (reported by the bundle check).
  result.serviceRoleInBundles = [];
  for (const file of files) {
    if (!isBundlePath(file.relPath) || !file.content) continue;
    const jwtRegex = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;
    for (const match of file.content.matchAll(jwtRegex)) {
      if (classifyJwt(match[0]).kind === 'supabase-service-role') {
        result.serviceRoleInBundles.push(file.relPath);
        break;
      }
    }
  }
  result.serviceRoleInBundles = [...new Set(result.serviceRoleInBundles)];

  return result;
}

/** Is this path inside a build output folder? */
export function isBundlePath(relPath) {
  return /(^|\/)(dist|build|out|\.next|\.output|vercel\/output)\//.test(String(relPath || ''));
}

/**
 * Is this file client-side code (its contents are downloaded by a browser)?
 *
 * Heuristics, in order of confidence:
 *  - EXPLICIT server folders win first (an Express `routes/` folder is server
 *    code even though "routes" sounds front-end-ish)
 *  - a browser-only env accessor (import.meta.env.VITE_*) is a strong signal
 *  - a clearly front-end folder or a .jsx/.tsx file
 *
 * WHY this matters: telling a client "your admin key is in client-side code"
 * when it is actually in a server file destroys trust in every other finding.
 */
export function isClientSideFile(relPath, content = '') {
  const path = String(relPath || '').toLowerCase();
  const text = String(content || '');

  // Explicitly server-side locations.
  if (/supabase\/functions|\/api\/|\/server\/|\/workers\/|\/edge\/|\/routes?\//.test(path)) return false;
  if (/\bDeno\./.test(text)) return false;

  // Browser bundlers expose these to the browser by design.
  if (/import\.meta\.env\.(VITE_|PUBLIC_)/.test(text)) return true;
  if (/process\.env\.NEXT_PUBLIC_/.test(text)) return true;
  if (/process\.env\.REACT_APP_/.test(text)) return true;
  if (/process\.env\.EXPO_PUBLIC_/.test(text)) return true;

  // Clearly front-end folders.
  if (/(^|\/)(components|pages|views|hooks|context|client|frontend|widgets)\//.test(path)) return true;
  if (/\.(jsx|tsx)$/.test(path)) return true;
  if (path.startsWith('public/')) return true;

  return false;
}

/** Does this env variable name end up in the browser bundle? */
export function isClientExposedEnvName(name) {
  return CLIENT_PREFIXES.some((prefix) => String(name || '').startsWith(prefix));
}
