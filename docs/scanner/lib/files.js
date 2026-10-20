/**
 * lib/files.js
 * ---------------------------------------------------------------------------
 * ES-module facade over `lib/files.core.js`.
 * See the note in `lib/util.js` for why the implementation lives in a
 * classic script and this file is only the module surface.
 */

import './files.core.js';

export const {
  SKIP_DIRS,
  BUNDLE_DIRS,
  TEXT_EXTENSIONS,
  TEXT_FILENAMES,
  CODE_EXTENSIONS,
  BUNDLE_PREFIXES,
  MAX_FILE_BYTES,
  MAX_FILES,
  classifyFile,
  isCodeFile,
  isTextLike,
  isAlwaysScanned,
  createFileRecord,
  looksBinary,
} = globalThis.SCANNER.lib.files;
