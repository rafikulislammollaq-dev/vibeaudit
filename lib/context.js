/**
 * lib/context.js
 * ---------------------------------------------------------------------------
 * Builds the "scan context" - the object every check receives.
 *
 * WHY a separate module: the context is the contract between the engine and
 * the checks. Keeping the factory in one place means a check can be run
 * against a real folder (by the CLI) or against a handful of in-memory files
 * (by the test suite) without changing a line of check code. That is what
 * makes the checks unit-testable, and it is also how the tool can be
 * embedded in another service.
 */

import { codeWindow } from './evidence.js';

/**
 * Create a file record. Checks only ever look at these fields.
 *
 * @param {object} input
 * @param {string} input.relPath  path relative to the project root
 * @param {string} [input.content]
 * @param {string} [input.ext]     file extension including the dot
 */
export function createFileRecord(input) {
  const relPath = String(input.relPath || '');
  const name = relPath.split('/').pop() || relPath;
  const ext = input.ext !== undefined ? input.ext : (name.includes('.') ? name.slice(name.lastIndexOf('.')) : '');
  return {
    relPath,
    absPath: input.absPath || relPath,
    name,
    ext: String(ext).toLowerCase(),
    size: input.size !== undefined ? input.size : (input.content || '').length,
    category: input.category || 'source',
    gitignored: Boolean(input.gitignored),
    tracked: Boolean(input.tracked),
    content: input.content === undefined ? null : input.content,
  };
}

/**
 * Build a scan context.
 *
 * @param {object} options
 * @param {string} options.root
 * @param {Array} options.files
 * @param {object} options.git
 * @param {string|null} [options.url]
 * @param {boolean} [options.authorized]
 */
export function createContext(options = {}) {
  const context = {
    root: options.root || process.cwd(),
    target: options.target || options.root || process.cwd(),
    files: options.files || [],
    git: options.git || { available: false, tracked: null, history: [], historyTruncated: false, reason: 'not scanned' },
    sql: options.sql || null,
    references: options.references || new Map(),
    supabase: options.supabase || null,
    url: options.url || null,
    authorized: Boolean(options.authorized),
    options: options.options || {},
    demo: Boolean(options.demo),

    /**
     * A numbered window of lines around an offset - used for code evidence.
     * Keeping it on the context means every finding quotes code the same way.
     */
    window(content, index, lineCount = 10) {
      return codeWindow(content, index, lineCount);
    },
  };
  return context;
}
