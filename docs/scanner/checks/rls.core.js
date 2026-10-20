/**
 * checks/rls.core.js
 * ---------------------------------------------------------------------------
 * CHECK 3 - Postgres Row Level Security analysis.
 *
 * PORTED from the CLI's `checks/rls.js`.
 *
 * WHY THIS MATTERS (and why it is the headline check of this tool):
 *  - 98% of apps behind a public Supabase URL had at least one exploitable
 *    flaw in 2026.
 *  - 10.3% of sampled Lovable apps exposed real user data purely because a
 *    table had no Row Level Security policy.
 *  - A `SECURITY DEFINER` function without a fixed `search_path` is the
 *    classic Postgres privilege-escalation path: the caller can hijack the
 *    function's search path and run code as the table owner.
 *
 * We detect:
 *  1. CREATE TABLE without a matching ENABLE ROW LEVEL SECURITY
 *  2. SECURITY DEFINER functions without SET search_path
 *  3. Permissive policies (USING (true) / WITH CHECK (true))
 *  4. GRANTs to the `anon` role on tables without RLS
 *  5. RLS enabled but no policies at all (locks everyone out)
 *  6. Tables the application reads/writes that have no migration we could review
 */

(function (root) {
  'use strict';

  const S = (root.SCANNER = root.SCANNER || {});
  S.checks = S.checks || {};

  const id = 'rls';
  const title = 'Postgres Row Level Security (RLS) on Supabase tables';
  const severity = 'CRITICAL';

  function run(context) {
    const findings = [];
    const { makeFinding, makePass, makeSkip } = S.lib.findings;
    const sqlFiles = context.files.filter((file) => file.category === 'sql' && file.content);

    if (!sqlFiles.length) {
      findings.push(
        makeSkip(
          'No SQL files found to analyse',
          'We looked for .sql files (migrations, schema files, seed files). There were none in the target folder, so ' +
            'Row Level Security could not be reviewed. If your database is managed by a hosted platform, open the ' +
            'database SQL editor and export the schema, then re-run the scan against that folder.',
          context.root,
        ),
      );
      return findings;
    }

    const sql = context.sql;
    const references = context.references;

    // ---------------------------------------------------------------- 1. RLS
    const unprotected = [];
    for (const table of sql.tables.values()) {
      if (table.rlsEnabled && !table.rlsDisabled) continue;
      if (table.rlsDisabled) continue;
      unprotected.push(table);
    }

    for (const table of unprotected) {
      const sensitive = S.lib.sql.isSensitiveTableName(table.name);
      const usedBy = [...references.keys()].filter((ref) => {
        const refShort = ref.split('.').pop();
        const tableShort = table.name.split('.').pop();
        return ref === table.name || refShort === tableShort;
      });

      const appUsage = usedBy.length
        ? ` The app reads or writes this table in: ${usedBy.slice(0, 4).join(', ')}.`
        : '';

      findings.push(
        makeFinding({
          severity: sensitive ? 'CRITICAL' : 'HIGH',
          title: `Table "${table.name}" has no Row Level Security enabled`,
          detail:
            `The table is created in ${table.file} but no "ALTER TABLE ... ENABLE ROW LEVEL SECURITY" statement was ` +
            `found for it.${appUsage} Without RLS, anybody who obtains the public (anon) key can read every row and ` +
            `write to the table - the URL and the anon key are shipped inside your app.`,
          plain: sensitive
            ? 'A table that stores your customers\' personal information can be read or changed by anyone on the ' +
              'internet, not just your signed-in users.'
            : 'One of your database tables can be read or changed by anyone on the internet, not just your signed-in ' +
              'users.',
          location: `${table.file}:${table.line}`,
          remediation:
            'Turn on Row Level Security for this table and add policies that describe who may see which rows. ' +
            'Typical pattern for a per-user table:\n\n' +
            '    ALTER TABLE public.' +
            table.name.split('.').pop() +
            ' ENABLE ROW LEVEL SECURITY;\n\n' +
            '    -- Let a signed-in user see only their own row\n' +
            '    CREATE POLICY "users see own rows" ON public.' +
            table.name.split('.').pop() +
            '\n' +
            '      FOR SELECT USING (auth.uid() = id);\n\n' +
            '    -- Let a signed-in user change only their own row\n' +
            '    CREATE POLICY "users update own rows" ON public.' +
            table.name.split('.').pop() +
            '\n' +
            '      FOR UPDATE USING (auth.uid() = id) WITH CHECK (auth.uid() = id);\n\n' +
            '    -- Admins can see everything (only if you really have admins)\n' +
            '    -- CREATE POLICY "admins see all" ON public.' +
            table.name.split('.').pop() +
            '\n' +
            '      FOR ALL TO authenticated USING (is_admin()) WITH CHECK (is_admin());\n\n' +
            'Replace the column names with the real ones in your table, and add a policy for INSERT and DELETE too.',
          evidence: `CREATE TABLE for "${table.name}" found in ${table.file}:${table.line}\nNo matching "ALTER TABLE ... ENABLE ROW LEVEL SECURITY" statement was found.`,
          cwe: 'CWE-284',
        }),
      );
    }

    // -------------------------------------------------- 2. SECURITY DEFINER
    for (const fn of sql.functions) {
      if (!fn.securityDefiner) continue;
      if (fn.hasSearchPath) continue;

      findings.push(
        makeFinding({
          severity: 'CRITICAL',
          title: `SECURITY DEFINER function without a safe search_path: ${fn.name}`,
          detail:
            `${fn.name} is declared SECURITY DEFINER, which means it runs with the privileges of the function owner ` +
            '(usually the database owner, i.e. full access). Because it does not pin its search_path, a caller can ' +
            'hijack the search path and make the function resolve objects they control - which turns the function ' +
            'into an arbitrary code execution / full database takeover primitive.',
          plain:
            'One of your database functions runs with full administrator powers and can be tricked into giving away ' +
            'control of your whole database.',
          location: `${fn.file}:${fn.line}`,
          remediation:
            'Pin the search_path to a trusted, empty schema so the function can only resolve objects you control:\n\n' +
            '    CREATE OR REPLACE FUNCTION public.' +
            fn.name.replace(/^public\./, '') +
            '()\n' +
            '    RETURNS ...\n' +
            '    LANGUAGE plpgsql\n' +
            '    SECURITY DEFINER\n' +
            '    SET search_path = public, pg_temp;   -- <-- this line fixes it\n' +
            '    AS $$\n' +
            '    ...\n' +
            '    $$;\n\n' +
            'Also make sure the function does not call SECURITY DEFINER functions in a chain, and give the function ' +
            'its own least-privilege role instead of using the table owner.',
          evidence: `function ${fn.name} in ${fn.file}:${fn.line}\nDeclares SECURITY DEFINER but no "SET search_path" was found in its body.`,
          cwe: 'CWE-269',
        }),
      );
    }

    // ------------------------------------------------- 3. permissive policies
    for (const policy of sql.policies) {
      if (!policy.permissiveUsing && !policy.permissiveWithCheck) continue;
      const table = sql.tables.get(policy.table);
      const tableIsProtected = table && table.rlsEnabled && !table.rlsDisabled;
      findings.push(
        makeFinding({
          severity: tableIsProtected ? 'HIGH' : 'CRITICAL',
          title: `Permissive policy "${policy.name}" on table "${policy.table}"`,
          detail:
            'The policy allows every row (USING (true) / WITH CHECK (true)).' +
            (tableIsProtected
              ? ' Row Level Security is enabled on this table, but this policy makes it allow everything, so it has the ' +
                'same effect as having no protection at all.'
              : ' Row Level Security is not even enabled on this table, so this policy is the only thing standing between ' +
                'the public and your data - and it stands for nothing.'),
          plain:
            'A database rule on this table allows every visitor to see and change all of its rows, which is the same as ' +
            'having no rule at all.',
          location: `${policy.file}:${policy.line}`,
          remediation:
            'Replace the blanket rule with a rule that checks who is asking. Examples:\n\n' +
            '    -- Only signed-in users, and only their own rows\n' +
            '    CREATE POLICY "own rows only" ON public.' +
            policy.table.split('.').pop() +
            '\n' +
            '      FOR ALL TO authenticated\n' +
            '      USING (auth.uid() = user_id)\n' +
            '      WITH CHECK (auth.uid() = user_id);\n\n' +
            '    -- Public read of a lookup table (e.g. country codes) is fine:\n' +
            '    -- CREATE POLICY "public read" ON public.countries FOR SELECT USING (true);\n' +
            'Only use USING (true) for tables that are genuinely meant to be public.',
          evidence: `policy "${policy.name}" on "${policy.table}" in ${policy.file}:${policy.line}\n${policy.clause.trim().slice(0, 300)}`,
          cwe: 'CWE-284',
        }),
      );
    }

    // ------------------------------------------------------- 4. GRANT to anon
    for (const grant of sql.grants) {
      if (grant.role !== 'anon') continue;
      const table = grant.table ? sql.tables.get(grant.table) : null;
      const protectedTable = table && table.rlsEnabled && !table.rlsDisabled;
      findings.push(
        makeFinding({
          severity: protectedTable ? 'LOW' : 'CRITICAL',
          title: `Privileges granted to the "anon" role${grant.table ? ` on "${grant.table}"` : ''}`,
          detail:
            'The "anon" role is the unauthenticated public role - it is the key that ships in your browser bundle. ' +
            'Granting it privileges on a table that has no Row Level Security means anonymous internet traffic can ' +
            'read and write that table directly.',
          plain:
            'Your database gives permission to any visitor who has not signed in, on a table that is not protected by ' +
            'the row-level rules.',
          location: `${grant.file}:${grant.line}`,
          remediation:
            'Do not grant privileges to "anon" on tables that hold user data. Let Supabase\'s default PostgREST ' +
            'grants apply and control access with Row Level Security policies instead:\n\n' +
            '    REVOKE ALL ON TABLE public.' +
            (grant.table || 'your_table').split('.').pop() +
            ' FROM anon;\n\n' +
            '    ALTER TABLE public.' +
            (grant.table || 'your_table').split('.').pop() +
            ' ENABLE ROW LEVEL SECURITY;',
          evidence: `GRANT ${grant.privileges} TO ${grant.role}  (${grant.file}:${grant.line})`,
          cwe: 'CWE-284',
        }),
      );
    }

    // ------------------------------------------- 5. RLS on but no policies
    for (const table of sql.tables.values()) {
      if (!table.rlsEnabled || table.rlsDisabled) continue;
      if (table.policies.length === 0) {
        findings.push(
          makeFinding({
            severity: 'MEDIUM',
            title: `Table "${table.name}" has Row Level Security enabled but no policies`,
            detail:
              'With RLS enabled and no policies, nobody - not even signed-in users - can read or write the table. ' +
              'This usually shows up as "the app stopped working" after a security fix.',
            plain:
              'Your database table is locked down so tightly that even your own signed-in users cannot use it, which ' +
              'usually breaks part of the app.',
            location: `${table.file}:${table.line}`,
            remediation:
              'Add policies that describe the intended access, for example:\n\n' +
              '    CREATE POLICY "own rows" ON public.' +
              table.name.split('.').pop() +
              '\n' +
              '      FOR ALL TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);\n\n' +
              'If the table is meant to be public, use "FOR SELECT USING (true)".',
            evidence: `"ENABLE ROW LEVEL SECURITY" found for "${table.name}" but no CREATE POLICY statement was found for it.`,
            cwe: 'CWE-284',
          }),
        );
      }
    }

    // ------------------------------- 6. tables used by the app without RLS
    for (const [refName, ref] of references) {
      const short = refName.split('.').pop();
      const known = [...sql.tables.values()].some((t) => t.name.split('.').pop() === short);
      if (known) continue;
      const inEdgeFunction = ref.files.some((f) => /supabase\/functions|\/api\/|\/routes?\//i.test(f));
      findings.push(
        makeFinding({
          severity: 'MEDIUM',
          title: `Table "${short}" is used by the app but has no migration we could review`,
          detail:
            `The application reads or writes "${short}" (in ${ref.files.join(', ')}), but no CREATE TABLE statement ` +
            'for it exists in the SQL files in this project. That usually means the table was created directly in the ' +
            'Supabase dashboard, so its Row Level Security settings are invisible in the code - and dashboards are ' +
            'exactly where RLS gets forgotten.',
          plain:
            'Part of your app uses a database table whose access rules are not written down in your code, so we could ' +
            'not confirm that the right people can reach it.',
          location: ref.lines.length ? `${ref.lines[0].file}:${ref.lines[0].line}` : ref.files.join(', '),
          remediation:
            'Export the schema from the Supabase SQL editor (Dashboard > SQL Editor > select the table > "Download ' +
            'schema") and commit it into the repository so access rules are reviewable. Then enable Row Level Security ' +
            'on any table that holds user data and add policies for it:\n\n' +
            '    ALTER TABLE public.' +
            short +
            ' ENABLE ROW LEVEL SECURITY;\n' +
            '    CREATE POLICY "own rows" ON public.' +
            short +
            '\n' +
            '      FOR ALL TO authenticated USING (auth.uid() = user_id) WITH CHECK (auth.uid() = user_id);\n\n' +
            (inEdgeFunction
              ? 'Note: this table is used from an Edge Function, which runs with the service_role key and therefore ' +
                'bypasses RLS. Make sure that function verifies the caller\'s identity itself.\n'
              : ''),
          evidence: `Table reference "${short}" found in:\n${ref.files.join('\n')}\nNo CREATE TABLE statement found in the project SQL files.`,
          cwe: 'CWE-284',
        }),
      );
    }

    if (!findings.length) {
      findings.push(
        makePass(
          'Row Level Security looks correct on the tables we found',
          `Analysed ${sqlFiles.length} SQL file(s), ${sql.tables.size} table(s), ${sql.policies.length} policy/policies ` +
            `and ${sql.functions.length} function(s).`,
          sqlFiles.map((f) => f.relPath).join(', '),
        ),
      );
    }

    return findings;
  }

  function status(context) {
    const sqlFiles = context.files.filter((file) => file.category === 'sql');
    if (!sqlFiles.length) {
      return {
        state: 'skip',
        notes: ['No .sql files were found, so database access rules could not be reviewed.'],
      };
    }
    return { state: 'unknown', notes: [] };
  }

  S.checks.rls = { id, title, severity, run, status };
})(globalThis);
