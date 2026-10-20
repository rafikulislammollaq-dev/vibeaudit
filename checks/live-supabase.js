/**
 * checks/live-supabase.js
 * ---------------------------------------------------------------------------
 * CHECK 3 - Supabase key handling, plus ONE authorised read test.
 *
 * PART A (always runs, offline): find the Supabase keys in the project.
 *  - An anon key in client code is EXPECTED and is not a finding on its own.
 *  - A service_role key in client code is CRITICAL: it turns your browser
 *    bundle into a full database admin key.
 *
 * PART B (only with --url AND --i-have-authorization): send exactly ONE
 * request to the Supabase REST API for ONE table we already know about from
 * the project's own SQL files, using the public anon key:
 *
 *     GET {supabase-url}/rest/v1/{table}?select=*&limit=1
 *
 * If the server answers with a row, the table is readable by anybody on the
 * internet - a critical broken access control finding.
 *
 * SAFETY: we never enumerate tables, never try more than one table, never
 * attempt to authenticate, and never send anything other than a read.
 */

import { makeFinding, makePass, makeSkip } from '../lib/findings.js';
import { detectSupabaseConfig } from '../lib/supabase.js';
import { isSupabaseHost, probeSupabaseAnonRead } from '../lib/http.js';
import { analyseSql, isSensitiveTableName } from '../lib/sql.js';
import { redactSecret } from '../lib/secrets.js';

export const id = 'live-supabase';
export const title = 'Supabase key exposure and public data access';
export const severity = 'CRITICAL';

export async function run(context) {
  const findings = [];

  const supabase = context.supabase || detectSupabaseConfig(context.files.filter((f) => f.content));
  context.supabase = supabase;

  // ------------------------------------------------- PART A: key handling
  if (!supabase.anonKey && !supabase.serviceRoleKey) {
    findings.push(
      makeSkip(
        'No Supabase keys found in the project',
        'We looked for a Supabase URL and keys in the environment files and source code. None were found, so this ' +
          'check has nothing to work with. This is normal for projects that do not use Supabase.',
        context.root,
      ),
    );
  } else {
    if (supabase.anonKey) {
      findings.push(
        makePass(
          'Supabase public (anon) key found - this one is supposed to be public',
          `The anon key (${redactSecret(supabase.anonKey, 12)}) was found in ${
            supabase.anonKeySource || 'the project'
          }. It is designed to be visible in the browser; its safety depends entirely on Row Level Security.`,
          supabase.anonKeySource || '',
        ),
      );
    }

    if (supabase.clientExposedServiceFiles.length) {
      for (const file of supabase.clientExposedServiceFiles) {
        findings.push(
          makeFinding({
            severity: 'CRITICAL',
            title: `Supabase service_role (admin) key is used in client-side code: ${file}`,
            detail:
              'The service_role key bypasses every Row Level Security policy. When it is referenced from browser code ' +
              'the bundler inlines it into the JavaScript file that every visitor downloads, so any visitor can copy ' +
              'it and read or modify every row in your database.',
            plain:
              'Your website hands a full administrator key for your database to every single visitor. Anyone who ' +
              'opens the page source can take it and read all of your users\' data.',
            location: file,
            remediation:
              'Move every service_role call to the server:\n\n' +
              '  1. Rename the environment variable so it is NOT exposed to the browser:\n' +
              '       SUPABASE_SERVICE_ROLE_KEY=...        (no VITE_ / NEXT_PUBLIC_ prefix)\n' +
              '  2. Use it only in an Edge Function, an API route or a server action:\n\n' +
              '       // supabase/functions/list-users/index.ts\n' +
              '       const supabaseAdmin = createClient(\n' +
              '         Deno.env.get("SUPABASE_URL")!,\n' +
              '         Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,   // server side only\n' +
              '       );\n\n' +
              '  3. In the browser, create the client with the anon key only:\n\n' +
              '       const supabase = createClient(\n' +
              '         import.meta.env.VITE_SUPABASE_URL!,\n' +
              '         import.meta.env.VITE_SUPABASE_ANON_KEY!      // public key is fine here\n' +
              '       );\n\n' +
              '  4. Rebuild the app and delete the old build folder so the leaked copy cannot be served from a cache.\n' +
              '  5. Rotate the service_role key in the Supabase dashboard afterwards.',
            evidence:
              'The service_role key is referenced from a file that runs in the browser, so it is compiled into the ' +
              'client bundle.',
            cwe: 'CWE-798',
          }),
        );
      }
    } else if (supabase.serviceRoleKey) {
      if (supabase.serviceRoleInBundles && supabase.serviceRoleInBundles.length) {
        // The bundle check already reports this as a critical finding, so we
        // add a note rather than a second finding (which would double-count
        // the score and read as noise).
        findings.push(
          makePass(
            'The Supabase admin key also ships inside the built client bundle',
            `Found in: ${supabase.serviceRoleInBundles.join(', ')}. This is reported as a critical finding by the ` +
              '"secrets in the client bundle" check above.',
            supabase.serviceRoleInBundles.join(', '),
          ),
        );
      } else {
        findings.push(
          makePass(
            'Supabase service_role (admin) key was found only on the server side',
            `The admin key (${redactSecret(supabase.serviceRoleKey, 12)}) is stored in ${
              supabase.serviceRoleKeySource || 'the project'
            }. It is not referenced from browser code, which is the correct setup.`,
            supabase.serviceRoleKeySource || '',
          ),
        );
      }
    }
  }

  // ------------------------------------------- PART B: the single live probe
  if (!context.url) {
    findings.push(
      makeSkip(
        'Live "can anyone read my data?" test was not run',
        'This test needs the address of your live Supabase project. Pass --url https://yourproject.supabase.co ' +
          'together with --i-have-authorization to include it. We only send one read request for a single table; ' +
          'we never try to sign in and never look for other tables.',
        context.root,
      ),
    );
    return findings;
  }

  if (!context.authorized) {
    findings.push(
      makeSkip(
        'Live "can anyone read my data?" test was not run (no authorisation given)',
        'The --i-have-authorization flag was not passed, so we did not send any request to the live site. Add that ' +
          'flag only if you own the site or have written permission to test it.',
        context.url,
      ),
    );
    return findings;
  }

  if (!isSupabaseHost(context.url)) {
    findings.push(
      makeSkip(
        'Live data-access test not applicable to this URL',
        `The supplied URL (${context.url}) is not a Supabase project address, so the Supabase REST read test does ` +
          'not apply to it. Pass the Supabase project URL (https://<project>.supabase.co) to run this test.',
        context.url,
      ),
    );
    return findings;
  }

  if (!supabase.anonKey) {
    findings.push(
      makeSkip(
        'Live data-access test could not run: no public key found',
        'The test needs the project\'s public anon key. It was not found in the project files, so we have nothing ' +
          'to test with. You can find it in the Supabase dashboard under Project Settings > API.',
        context.url,
      ),
    );
    return findings;
  }

  // Pick exactly ONE table: a sensitive one if possible, otherwise the first
  // table we saw in the SQL files. We never enumerate.
  const sqlFiles = context.files.filter((file) => file.category === 'sql' && file.content);
  const sql = analyseSql(sqlFiles);
  const candidates = [...sql.tables.keys()];
  let targetTable = candidates.find(isSensitiveTableName) || candidates[0] || null;

  if (!targetTable) {
    findings.push(
      makeSkip(
        'Live data-access test could not run: no table names available',
        'We only test tables that already appear in your project\'s SQL files, because this tool never enumerates ' +
          'or guesses table names. Add your migrations to the repository (or export the schema from the Supabase ' +
          'dashboard) and re-run the audit.',
        context.url,
      ),
    );
    return findings;
  }

  const probe = await probeSupabaseAnonRead(context.url, supabase.anonKey, targetTable);

  if (!probe.ok) {
    findings.push(
      makeSkip(
        'Live data-access test could not complete',
        `The request to ${context.url} did not complete (${probe.error}). This can happen if the project is paused, ` +
          'the URL is wrong, or the network is blocked. Nothing was changed and no sign-in was attempted.',
        context.url,
      ),
    );
    return findings;
  }

  if (probe.status === 200 && Array.isArray(probe.parsed)) {
    if (probe.rows > 0) {
      findings.push(
        makeFinding({
          severity: 'CRITICAL',
          title: `Live data exposure: "${targetTable}" is readable by anyone without signing in`,
          detail:
            `We sent one read request to ${probe.url} using only the public anon key - the same key every visitor ` +
            `has - and the database returned ${probe.rows} row(s). No sign-in was attempted. That means anybody on ` +
            'the internet can read this table, and the same is likely true of the other tables in the same project.',
          plain:
            'We tested your live database the same way an anonymous visitor would, and it handed back real data ' +
            'without asking anyone to sign in. That is the most serious kind of problem we look for.',
          location: `${targetTable} (via ${context.url})`,
          remediation:
            'Turn on Row Level Security for the table and add policies that restrict access:\n\n' +
            `    ALTER TABLE public.${targetTable.split('.').pop()} ENABLE ROW LEVEL SECURITY;\n\n` +
            `    CREATE POLICY "users read own rows" ON public.${targetTable.split('.').pop()}\n` +
            '      FOR SELECT TO authenticated\n' +
            '      USING (auth.uid() = user_id);\n\n' +
            'Then re-run the audit - the same public request should come back empty or 401/403.\n\n' +
            'Also check the other tables in the same project, because they usually have the same problem.',
          evidence: `Request: GET ${probe.url}\nResponse: HTTP ${probe.status}, ${probe.rows} row(s) returned\nBody preview: ${probe.bodyPreview}`,
          cwe: 'CWE-284',
        }),
      );
    } else {
      findings.push(
        makeFinding({
          severity: 'HIGH',
          title: `Live check: "${targetTable}" accepted an unauthenticated read`,
          detail:
            `The public anon key was allowed to run a SELECT on "${targetTable}" without signing in. The table ` +
            'happened to be empty, so no data leaked, but the request was accepted - which means Row Level Security ' +
            'is not protecting this table. As soon as it contains a row, that row is public.',
          plain:
            'Your database let an anonymous visitor ask for the contents of this table. It was empty today, so ' +
            'nothing was stolen, but the door is open.',
          location: `${targetTable} (via ${context.url})`,
          remediation:
            'Enable Row Level Security and add policies so the anonymous role cannot read the table:\n\n' +
            `    ALTER TABLE public.${targetTable.split('.').pop()} ENABLE ROW LEVEL SECURITY;\n` +
            `    CREATE POLICY "own rows only" ON public.${targetTable.split('.').pop()}\n` +
            '      FOR ALL TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);',
          evidence: `Request: GET ${probe.url}\nResponse: HTTP ${probe.status}, 0 rows returned (the read was allowed)`,
          cwe: 'CWE-284',
        }),
      );
    }
  } else if (probe.status === 401 || probe.status === 403) {
    findings.push(
      makePass(
        'Live check passed: the public key cannot read data without signing in',
        `A single read request for "${targetTable}" with the public anon key was rejected with HTTP ${probe.status}. ` +
          'Row Level Security is doing its job on this table.',
        context.url,
      ),
    );
  } else {
    findings.push(
      makeSkip(
        `Live check returned an unexpected response (HTTP ${probe.status})`,
        `The request to ${probe.url} returned HTTP ${probe.status}. We could not interpret that as "protected" or ` +
          '"exposed", so we are not claiming either way.',
        context.url,
      ),
    );
  }

  return findings;
}

export function status(context) {
  if (!context.url) {
    return {
      state: 'skip',
      notes: ['No --url was supplied, so the live checks did not run.'],
    };
  }
  if (!context.authorized) {
    return {
      state: 'skip',
      notes: ['--i-have-authorization was not supplied, so no request was sent to the live site.'],
    };
  }
  return { state: 'unknown', notes: [] };
}
