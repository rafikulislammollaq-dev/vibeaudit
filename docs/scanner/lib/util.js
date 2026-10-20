/**
 * lib/util.js
 * ---------------------------------------------------------------------------
 * ES-module facade over `lib/util.core.js`.
 *
 * WHY the split: the scanner must work both when the folder is served over
 * http(s) (ES modules) and when `index.html` is opened straight from the
 * filesystem, where browsers refuse to load ES modules over file://. The
 * logic lives once in the `.core.js` classic script; this file exposes it as
 * a normal ES module for the served build and for the node-based tests.
 */

import './util.core.js';

export const {
  toPosix,
  lineOf,
  lineTextAt,
  shortHash,
  nowIso,
  truncate,
  firstLine,
  fence,
  plural,
  escapeTableCell,
  decodeBase64Url,
  formatBytes,
  escapeHtml,
} = globalThis.SCANNER.lib.util;
