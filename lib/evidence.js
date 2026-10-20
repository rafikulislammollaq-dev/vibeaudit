/**
 * lib/evidence.js
 * ---------------------------------------------------------------------------
 * Helpers that turn a raw match inside a file into something a human can act
 * on: the file path, the line number and the offending source line with the
 * secret replaced by a redaction.
 *
 * WHY a separate module: the redaction has to happen in exactly one place.
 * If two checks build evidence differently, one of them will eventually
 * leak a raw credential into a client report.
 */

import { countLines } from './secrets.js';

/**
 * Extract the source line containing `index` from `content`.
 * Returns the line with the secret replaced by `redacted`.
 */
export function redactedLine(content, index, match, redacted) {
  const text = String(content || '');
  const start = text.lastIndexOf('\n', Math.max(0, index - 1)) + 1;
  const end = text.indexOf('\n', index);
  const line = text.slice(start, end === -1 ? text.length : end);
  const safe = match && line.includes(match) ? line.replace(match, redacted) : line;
  return safe.replace(/\t/g, '  ').trimEnd();
}

/**
 * Build the standard evidence block used by every finding.
 *
 * @param {object} params
 * @param {string} params.location  e.g. "src/server.js:42"
 * @param {string} params.snippet    the (already redacted) offending line
 * @param {string} [params.note]     extra context line above the snippet
 */
export function evidenceBlock({ location, snippet, note }) {
  const parts = [];
  if (location) parts.push(`at ${location}`);
  if (note) parts.push(note);
  if (snippet) {
    parts.push('');
    parts.push(snippet);
  }
  return parts.join('\n');
}

/** 1-based line number for an offset. */
export function lineNumber(content, index) {
  return countLines(content, index);
}

/**
 * Render a numbered window of code around an offset.
 *
 * WHY numbered lines: a client pasting a fix into an AI assistant needs to
 * say "line 42", not "somewhere near the top".
 */
export function codeWindow(content, index, lineCount = 10) {
  const text = String(content || '');
  const lines = text.split('\n');
  const targetLine = text.slice(0, Math.max(0, index)).split('\n').length;
  const start = Math.max(0, targetLine - 3);
  const end = Math.min(lines.length, start + lineCount);
  return lines
    .slice(start, end)
    .map((line, offset) => {
      const number = start + offset + 1;
      const marker = number === targetLine ? '>>' : '  ';
      return `${marker} ${String(number).padStart(4, ' ')} | ${line.replace(/\t/g, '  ')}`;
    })
    .join('\n');
}

/**
 * Cap the number of code lines included in a finding's evidence so the
 * Markdown report stays readable and does not turn into a code dump.
 */
export function clipSnippet(snippet, maxLines = 12) {
  const lines = String(snippet || '').split('\n');
  if (lines.length <= maxLines) return lines.join('\n');
  const kept = lines.slice(0, maxLines);
  kept.push(`... (${lines.length - maxLines} more lines)`);
  return kept.join('\n');
}
