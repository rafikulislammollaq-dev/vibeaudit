/**
 * lib/sql.js
 * ---------------------------------------------------------------------------
 * ES-module facade over `lib/sql.core.js`.
 * See the note in `lib/util.js` for why the implementation lives in a
 * classic script and this file is only the module surface.
 */

import './secrets.core.js';
import './sql.core.js';

export const {
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
} = globalThis.SCANNER.lib.sql;
