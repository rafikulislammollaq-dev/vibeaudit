/**
 * lib/util.js
 * ---------------------------------------------------------------------------
 * Small, dependency-free helpers shared across the scanner.
 *
 * Nothing here is security-sensitive; it exists so the check modules stay
 * focused on detection logic instead of string plumbing.
 */

import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';

/** Convert a Windows path to POSIX separators so output looks the same everywhere. */
export function toPosix(p) {
  return String(p).split(path.sep).join('/');
}

/**
 * Path of `target` relative to `root`, always POSIX-style and never absolute.
 * Findings quote this so a client can find the file in their repo.
 */
export function relativePosix(root, target) {
  return toPosix(path.relative(root, target));
}

/** 1-based line number of a character offset inside `content`. */
export function lineOf(content, index) {
  if (!content || index < 0) return 1;
  let line = 1;
  const upto = content.slice(0, index);
  for (let i = 0; i < upto.length; i += 1) {
    if (upto[i] === '\n') line += 1;
  }
  return line;
}

/** The single line of `content` containing `index`, trimmed. */
export function lineTextAt(content, index) {
  if (!content) return '';
  const start = content.lastIndexOf('\n', Math.max(0, index - 1)) + 1;
  const end = content.indexOf('\n', index);
  return content.slice(start, end === -1 ? content.length : end).trim();
}

/** Short, stable id for a finding (used in JSON output and report anchors). */
export function shortHash(input) {
  return createHash('sha1').update(String(input)).digest('hex').slice(0, 8);
}

/** ISO-8601 timestamp for report headers. */
export function nowIso() {
  return new Date().toISOString();
}

/** Collapse whitespace and clip to `max` characters. */
export function truncate(text, max = 400) {
  const value = String(text == null ? '' : text);
  if (value.length <= max) return value;
  return `${value.slice(0, max - 1)}…`;
}

/** First non-empty line of a block of text. */
export function firstLine(text) {
  const line = String(text || '')
    .split('\n')
    .map((l) => l.trim())
    .find((l) => l.length > 0);
  return line || '';
}

/**
 * Wrap `content` in a fenced code block, growing the fence when the content
 * itself contains backticks so the Markdown never breaks.
 */
export function fence(content, language = '') {
  const text = String(content == null ? '' : content).replace(/\r\n/g, '\n');
  const longestRun = (text.match(/`+/g) || []).reduce((max, run) => Math.max(max, run.length), 0);
  const ticks = '`'.repeat(Math.max(3, longestRun + 1));
  return `${ticks}${language}\n${text}\n${ticks}`;
}

/**
 * Read a UTF-8 file, returning null instead of throwing.
 * Checks run over arbitrary user trees, so "file vanished" must never crash
 * the scan.
 */
export async function readFileSafe(filePath) {
  try {
    return await fs.readFile(filePath, 'utf8');
  } catch {
    return null;
  }
}

/** True when the path exists and is a regular file. */
export async function isFile(filePath) {
  try {
    const stat = await fs.stat(filePath);
    return stat.isFile();
  } catch {
    return false;
  }
}

/** True when the path exists and is a directory. */
export async function isDirectory(filePath) {
  try {
    const stat = await fs.stat(filePath);
    return stat.isDirectory();
  } catch {
    return false;
  }
}

/** Escape a string for safe inclusion inside a Markdown table cell. */
export function escapeTableCell(text) {
  return String(text == null ? '' : text)
    .replace(/\|/g, '\\|')
    .replace(/\r?\n/g, ' ');
}

/** Pluralise a noun against a count ("1 finding" / "3 findings"). */
export function plural(count, singular, pluralForm = `${singular}s`) {
  return `${count} ${count === 1 ? singular : pluralForm}`;
}

/** URL-safe base64 decode that tolerates missing padding (JWT payloads). */
export function decodeBase64Url(value) {
  try {
    const padded = value.replace(/-/g, '+').replace(/_/g, '/');
    const withPadding = padded + '='.repeat((4 - (padded.length % 4)) % 4);
    return Buffer.from(withPadding, 'base64').toString('utf8');
  } catch {
    return '';
  }
}
