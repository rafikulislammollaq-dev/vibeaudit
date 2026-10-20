/**
 * lib/util.core.js
 * ---------------------------------------------------------------------------
 * Small, dependency-free helpers shared across the browser scanner.
 *
 * Ported from the CLI's `audit/lib/util.js`. The only meaningful change is
 * `shortHash` (the CLI uses node:crypto, which does not exist in a browser)
 * and `decodeBase64Url` (the CLI uses Buffer, the browser uses atob +
 * TextDecoder). The behaviour of everything else is identical, so a report
 * produced here reads exactly like a report produced by the CLI.
 *
 * WHY this file has no `import` / `export`:
 *   The scanner has to run in two ways - as ES modules when the folder is
 *   served, and as plain classic scripts when the page is opened straight
 *   from the filesystem (file://), because browsers refuse to load ES
 *   modules over file://. Every `*.core.js` file is therefore a classic
 *   script that publishes itself on `globalThis.SCANNER`, and the sibling
 *   `*.js` file is a thin ES-module facade over it. One implementation,
 *   two loaders, no build step.
 */

(function (root) {
  'use strict';

  const S = (root.SCANNER = root.SCANNER || {});
  S.lib = S.lib || {};

  const util = {};

  /** Convert Windows separators to POSIX ones so paths look the same everywhere. */
  util.toPosix = function toPosix(p) {
    return String(p == null ? '' : p).replace(/\\/g, '/');
  };

  /** 1-based line number of a character offset inside `content`. */
  util.lineOf = function lineOf(content, index) {
    if (!content || index < 0) return 1;
    let line = 1;
    const upto = content.slice(0, index);
    for (let i = 0; i < upto.length; i += 1) {
      if (upto[i] === '\n') line += 1;
    }
    return line;
  };

  /** The single line of `content` containing `index`, trimmed. */
  util.lineTextAt = function lineTextAt(content, index) {
    if (!content) return '';
    const start = content.lastIndexOf('\n', Math.max(0, index - 1)) + 1;
    const end = content.indexOf('\n', index);
    return content.slice(start, end === -1 ? content.length : end).trim();
  };

  /**
   * Short, stable id for a finding.
   *
   * WHY not SHA-1: the browser has no node:crypto. FNV-1a gives the same
   * shape of id (8 hex characters, deterministic for the same input) which
   * is all the report needs - the id only has to be stable so two runs of
   * the scanner can be compared.
   */
  util.shortHash = function shortHash(input) {
    const text = String(input == null ? '' : input);
    let hash = 0x811c9dc5;
    for (let i = 0; i < text.length; i += 1) {
      hash ^= text.charCodeAt(i);
      hash = (hash + ((hash << 1) + (hash << 4) + (hash << 7) + (hash << 8) + (hash << 24))) >>> 0;
    }
    return hash.toString(16).padStart(8, '0');
  };

  /** ISO-8601 timestamp for report headers. */
  util.nowIso = function nowIso() {
    return new Date().toISOString();
  };

  /** Collapse whitespace and clip to `max` characters. */
  util.truncate = function truncate(text, max) {
    const limit = max || 400;
    const value = String(text == null ? '' : text);
    if (value.length <= limit) return value;
    return `${value.slice(0, limit - 1)}…`;
  };

  /** First non-empty line of a block of text. */
  util.firstLine = function firstLine(text) {
    const line = String(text == null ? '' : text)
      .split('\n')
      .map((l) => l.trim())
      .find((l) => l.length > 0);
    return line || '';
  };

  /**
   * Wrap `content` in a fenced code block, growing the fence when the content
   * itself contains backticks so the Markdown never breaks.
   */
  util.fence = function fence(content, language) {
    const text = String(content == null ? '' : content).replace(/\r\n/g, '\n');
    const longestRun = (text.match(/`+/g) || []).reduce((max, run) => Math.max(max, run.length), 0);
    const ticks = '`'.repeat(Math.max(3, longestRun + 1));
    return `${ticks}${language || ''}\n${text}\n${ticks}`;
  };

  /** Pluralise a noun against a count ("1 finding" / "3 findings"). */
  util.plural = function plural(count, singular, pluralForm) {
    const many = pluralForm || `${singular}s`;
    return `${count} ${count === 1 ? singular : many}`;
  };

  /** Escape a string for safe inclusion inside a Markdown table cell. */
  util.escapeTableCell = function escapeTableCell(text) {
    return String(text == null ? '' : text)
      .replace(/\|/g, '\\|')
      .replace(/\r?\n/g, ' ');
  };

  /**
   * URL-safe base64 decode that tolerates missing padding (JWT payloads).
   * Browser equivalent of the CLI's Buffer-based helper.
   */
  util.decodeBase64Url = function decodeBase64Url(value) {
    try {
      const padded = String(value).replace(/-/g, '+').replace(/_/g, '/');
      const withPadding = padded + '='.repeat((4 - (padded.length % 4)) % 4);
      const binary = atob(withPadding);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
      return new TextDecoder('utf-8').decode(bytes);
    } catch {
      return '';
    }
  };

  /** Human readable byte size ("1.4 MB"). */
  util.formatBytes = function formatBytes(bytes) {
    const value = Number(bytes) || 0;
    if (value < 1024) return `${value} B`;
    if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KB`;
    if (value < 1024 * 1024 * 1024) return `${(value / (1024 * 1024)).toFixed(1)} MB`;
    return `${(value / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  };

  /** Escape text so it can be dropped into HTML safely. */
  util.escapeHtml = function escapeHtml(text) {
    return String(text == null ? '' : text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  };

  S.lib.util = util;
})(globalThis);
