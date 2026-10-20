/**
 * lib/sql.core.js
 * ---------------------------------------------------------------------------
 * A focused Postgres/SQL analyser for the checks that need it.
 *
 * PORTED from the CLI's `audit/lib/sql.js`. This is deliberately a
 * *heuristic* parser, not a SQL engine: it reads the shapes that show up in
 * real Supabase migrations and reports them with file and line references.
 * It never executes anything - and in the browser there is no database to
 * execute against anyway.
 */

(function (root) {
  'use strict';

  const S = (root.SCANNER = root.SCANNER || {});
  S.lib = S.lib || {};

  const CREATE_TABLE =
    /\bCREATE\s+(?:GLOBAL\s+TEMPORARY\s+|TEMPORARY\s+|TEMP\s+|UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:([A-Za-z_]\w*)\.)?("?[\w$]+"?)/gi;
  const ENABLE_RLS =
    /\bALTER\s+TABLE\s+(?:ONLY\s+)?(?:([A-Za-z_]\w*)\.)?("?[\w$]+"?)\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi;
  const DISABLE_RLS =
    /\bALTER\s+TABLE\s+(?:ONLY\s+)?(?:([A-Za-z_]\w*)\.)?("?[\w$]+"?)\s+DISABLE\s+ROW\s+LEVEL\s+SECURITY/gi;
  const FORCE_RLS =
    /\bALTER\s+TABLE\s+(?:ONLY\s+)?(?:([A-Za-z_]\w*)\.)?("?[\w$]+"?)\s+FORCE\s+ROW\s+LEVEL\s+SECURITY/gi;
  const CREATE_FUNCTION =
    /\bCREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s*\(/gi;
  // NOTE: the policy NAME is a capturing group (group 1). The name may be
  // quoted and may contain spaces, e.g. create policy "anyone can read orders".
  const CREATE_POLICY =
    /\bCREATE\s+POLICY\s+("[^"]+"|[^\s]+)\s+ON\s+(?:([A-Za-z_]\w*)\.)?("?[\w$]+"?)([\s\S]{0,600}?);/gi;
  const GRANT_STATEMENT = /\bGRANT\s+([\s\S]{0,200}?)\bTO\s+([A-Za-z_]\w*)/gi;
  const REFERENCES_TABLE = /\.from\(\s*['"`]([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)?)['"`]\s*\)/g;
  const RPC_CALL = /\.rpc\(\s*['"`]([A-Za-z_]\w*)['"`]/g;

  /** Strip quotes / schema prefix so `public."profiles"` and `profiles` match. */
  function normalizeTableName(schema, rawName) {
    const name = String(rawName || '').replace(/"/g, '').toLowerCase();
    const prefix = schema ? String(schema).replace(/"/g, '').toLowerCase() : null;
    if (!name) return '';
    if (prefix && !name.includes('.')) return `${prefix}.${name}`;
    return name;
  }

  /**
   * Extract the body of a CREATE FUNCTION block so we can tell whether it
   * declares `SET search_path` and whether it is SECURITY DEFINER.
   */
  function extractFunctionBlock(text, startIndex) {
    const dollar = /(\$[A-Za-z_]*\$)/g;
    dollar.lastIndex = startIndex;
    const opening = dollar.exec(text);
    if (opening) {
      const delimiter = opening[1];
      const bodyStart = opening.index + delimiter.length;
      const closing = text.indexOf(delimiter, bodyStart);
      if (closing !== -1) {
        return { block: text.slice(startIndex, closing + delimiter.length), body: text.slice(bodyStart, closing) };
      }
    }
    // Single-quoted body: AS '...'
    const semi = text.indexOf(';', startIndex);
    return { block: text.slice(startIndex, semi === -1 ? undefined : semi + 1), body: '' };
  }

  /**
   * Analyse a set of SQL files.
   *
   * @param {Array<{relPath:string, content:string}>} sqlFiles
   * @returns {object} aggregated SQL knowledge
   */
  function analyseSql(sqlFiles) {
    const tables = new Map();
    const functions = [];
    const policies = [];
    const grants = [];
    const referencedTables = new Map();
    const rpcCalls = new Map();

    const countLines = S.lib.secrets.countLines;

    const ensureTable = (fullName, file, line) => {
      if (!tables.has(fullName)) {
        tables.set(fullName, {
          name: fullName,
          shortName: fullName.split('.').pop(),
          file,
          line,
          rlsEnabled: false,
          rlsDisabled: false,
          rlsForced: false,
          policies: [],
        });
      }
      return tables.get(fullName);
    };

    for (const file of sqlFiles) {
      const text = file.content || '';

      for (const match of text.matchAll(CREATE_TABLE)) {
        const name = normalizeTableName(match[1], match[2]);
        if (!name) continue;
        const table = ensureTable(name, file.relPath, countLines(text, match.index));
        table.line = Math.min(table.line || Infinity, countLines(text, match.index));
      }

      for (const match of text.matchAll(ENABLE_RLS)) {
        const name = normalizeTableName(match[1], match[2]);
        if (!name) continue;
        const table = ensureTable(name, file.relPath, countLines(text, match.index));
        table.rlsEnabled = true;
      }

      for (const match of text.matchAll(DISABLE_RLS)) {
        const name = normalizeTableName(match[1], match[2]);
        if (!name) continue;
        const table = ensureTable(name, file.relPath, countLines(text, match.index));
        table.rlsDisabled = true;
      }

      for (const match of text.matchAll(FORCE_RLS)) {
        const name = normalizeTableName(match[1], match[2]);
        if (!name) continue;
        const table = ensureTable(name, file.relPath, countLines(text, match.index));
        table.rlsForced = true;
      }

      for (const match of text.matchAll(CREATE_FUNCTION)) {
        const name = match[1].replace(/"/g, '').toLowerCase();
        const { block, body } = extractFunctionBlock(text, match.index);
        const securityDefiner = /\bSECURITY\s+DEFINER\b/i.test(block);
        const hasSearchPath = /\bSET\s+(?:LOCAL\s+)?search_path\b/i.test(block);
        const language = (block.match(/LANGUAGE\s+([A-Za-z_]\w*)/i) || [])[1] || null;
        functions.push({
          name,
          file: file.relPath,
          line: countLines(text, match.index),
          securityDefiner,
          hasSearchPath,
          language,
          bodyPreview: body.slice(0, 400),
          blockPreview: block.slice(0, 500),
        });
      }

      for (const match of text.matchAll(CREATE_POLICY)) {
        const policyName = match[1].replace(/"/g, '');
        const tableName = normalizeTableName(match[2], match[3]);
        const clause = match[4] || '';
        const permissiveUsing = /USING\s*\(\s*true\s*\)/i.test(clause);
        const permissiveWithCheck = /WITH\s+CHECK\s*\(\s*true\s*\)/i.test(clause);
        const policy = {
          name: policyName,
          table: tableName,
          file: file.relPath,
          line: countLines(text, match.index),
          clause: clause.slice(0, 400),
          permissiveUsing,
          permissiveWithCheck,
          forRole: (clause.match(/TO\s+([A-Za-z_"\w,\s]+?)(?:\s+USING|\s+WITH|$)/i) || [])[1]?.trim() || null,
        };
        policies.push(policy);
        const table = tables.get(tableName);
        if (table) table.policies.push(policy);
      }

      for (const match of text.matchAll(GRANT_STATEMENT)) {
        const privileges = (match[1] || '').replace(/\s+/g, ' ').trim();
        const role = (match[2] || '').toLowerCase();
        if (!['anon', 'authenticated', 'public'].includes(role)) continue;
        const tableMatch = privileges.match(/ON\s+(?:TABLE\s+)?(?:([A-Za-z_]\w*)\.)?("?[\w$]+"?)/i);
        const tableName = tableMatch ? normalizeTableName(tableMatch[1], tableMatch[2]) : '';
        grants.push({
          privileges: privileges.slice(0, 200),
          role,
          table: tableName,
          file: file.relPath,
          line: countLines(text, match.index),
        });
      }
    }

    return {
      tables,
      functions,
      policies,
      grants,
      referencedTables,
      rpcCalls,
      tableNames: [...tables.keys()],
    };
  }

  /**
   * Find the tables an application touches (Supabase/PostgREST style calls).
   * Used to detect "table is used by the app but has no RLS".
   */
  function collectTableReferences(codeFiles) {
    const references = new Map();
    const rpcs = new Map();
    const countLines = S.lib.secrets.countLines;

    for (const file of codeFiles) {
      const text = file.content || '';
      for (const match of text.matchAll(REFERENCES_TABLE)) {
        const raw = match[1].toLowerCase();
        if (!references.has(raw)) references.set(raw, { name: raw, files: [], lines: [] });
        const entry = references.get(raw);
        if (entry.files.length < 5) entry.files.push(file.relPath);
        entry.lines.push({ file: file.relPath, line: countLines(text, match.index) });
      }
      for (const match of text.matchAll(RPC_CALL)) {
        const raw = match[1].toLowerCase();
        if (!rpcs.has(raw)) rpcs.set(raw, { name: raw, files: [], lines: [] });
        const entry = rpcs.get(raw);
        if (entry.files.length < 5) entry.files.push(file.relPath);
        entry.lines.push({ file: file.relPath, line: countLines(text, match.index) });
      }
    }

    return { references, rpcs };
  }

  /**
   * Tables that hold user data and would be damaging if world-readable.
   * Used to prioritise which table the single live probe should target.
   */
  function isSensitiveTableName(name) {
    const short = String(name || '').split('.').pop();
    return /(user|profile|customer|account|order|payment|invoice|subscription|message|conversation|session|token|contact|lead|patient|member|employee|address|wallet|transaction)/i.test(
      short,
    );
  }

  S.lib.sql = {
    CREATE_TABLE,
    ENABLE_RLS,
    DISABLE_RLS,
    FORCE_RLS,
    CREATE_FUNCTION,
    CREATE_POLICY,
    GRANT_STATEMENT,
    REFERENCES_TABLE,
    RPC_CALL,
    normalizeTableName,
    extractFunctionBlock,
    analyseSql,
    collectTableReferences,
    isSensitiveTableName,
  };
})(globalThis);
