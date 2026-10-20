/**
 * lib/git.js
 * ---------------------------------------------------------------------------
 * Thin, defensive wrapper around the `git` CLI.
 *
 * WHY shell out to git instead of parsing .git ourselves: we need
 * `git ls-files` (the exact list of tracked files) and `git log -p` (the
 * history). Re-implementing either correctly is a lot of work and easy to
 * get subtly wrong; git already does it perfectly.
 *
 * Every function degrades gracefully: if git is missing, the directory is not
 * a repository, or a command fails, we return an empty/neutral result so the
 * scan continues and the affected check reports "could not verify" instead of
 * crashing.
 */

import { execFile } from 'node:child_process';
import path from 'node:path';
import { isDirectory, isFile } from './util.js';

/** Never let a git command hang a client scan for more than this. */
const GIT_TIMEOUT_MS = 20_000;

/** Cap on how many commits of history we read (speed vs. coverage trade-off). */
export const DEFAULT_MAX_COMMITS = 150;

/** Cap on bytes of `git log -p` output we are willing to scan. */
export const DEFAULT_MAX_HISTORY_BYTES = 8 * 1024 * 1024;

/**
 * Run a git command and capture stdout.
 * Resolves to `{ ok, stdout, stderr, code }`; never throws.
 */
function runGit(args, cwd, { timeout = GIT_TIMEOUT_MS, maxBuffer = 32 * 1024 * 1024 } = {}) {
  return new Promise((resolve) => {
    execFile(
      'git',
      args,
      { cwd, timeout, maxBuffer, windowsHide: true, encoding: 'utf8' },
      (error, stdout, stderr) => {
        resolve({
          ok: !error,
          stdout: stdout || '',
          stderr: stderr || '',
          code: error && typeof error.code === 'number' ? error.code : error ? 1 : 0,
          error: error ? error.message : null,
        });
      },
    );
  });
}

/**
 * Does this directory contain a git repository?
 * Handles both normal repos (.git directory) and worktrees/submodules
 * (.git file pointing elsewhere).
 */
export async function isGitRepo(root) {
  const gitPath = path.join(root, '.git');
  if (await isDirectory(gitPath)) return true;
  if (await isFile(gitPath)) return true;

  // The directory may also sit inside a repository that lives further up -
  // a monorepo, or a sub-project of a larger repo. `git ls-files` and
  // `git log` are always run with cwd=root, so the paths they return are
  // relative to the directory we are scanning, not to the repo root. That
  // means walking up is safe here: we never pull in unrelated projects,
  // we just learn that the files we are looking at are tracked by
  // whatever repository contains them.
  //
  // This matters in practice: a client sends you one sub-project of a
  // monorepo, and the file that leaks their service_role key is committed
  // in the parent repo. Missing that would be the whole point of the tool.
  const toplevel = await runGit(['rev-parse', '--show-toplevel'], root);
  if (!toplevel.ok) return false;
  const top = toplevel.stdout.trim();
  return Boolean(top) && !/^fatal:/i.test(top);
}

/**
 * List the files git is tracking.
 * Returns a Set of POSIX-style relative paths, or null when git is not
 * available (so callers can distinguish "not tracked" from "unknown").
 */
export async function trackedFiles(root) {
  const result = await runGit(['ls-files', '-z'], root);
  if (!result.ok) return null;
  const set = new Set();
  for (const entry of result.stdout.split('\0')) {
    const trimmed = entry.trim();
    if (trimmed) set.add(trimmed.split(path.sep).join('/'));
  }
  return set;
}

/**
 * Read the patch history and return the raw diff text, capped in both
 * commits and bytes.
 *
 * `--unified=0` keeps only the changed lines (plus their line numbers), which
 * is exactly what we need and is dramatically smaller than full diffs.
 */
export async function historyDiff(root, { maxCommits = DEFAULT_MAX_COMMITS, maxBytes = DEFAULT_MAX_HISTORY_BYTES } = {}) {
  const result = await runGit(
    [
      'log',
      '--all',
      '--patch',
      '--no-color',
      '--unified=0',
      '--no-textconv',
      `--max-count=${maxCommits}`,
    ],
    root,
  );
  if (!result.ok) {
    return { ok: false, text: '', truncated: false, error: result.error };
  }
  const text = result.stdout.length > maxBytes ? result.stdout.slice(0, maxBytes) : result.stdout;
  return {
    ok: true,
    text,
    truncated: result.stdout.length > maxBytes,
    commits: (result.stdout.match(/^commit /gm) || []).length,
    error: null,
  };
}

/**
 * Parse `git log -p` output into per-commit, per-file added lines.
 *
 * @returns {Array<{commit, author, date, file, line, text}>}
 */
export function parseHistoryPatches(diffText) {
  const lines = String(diffText || '').split('\n');
  const entries = [];
  let commit = null;
  let author = null;
  let date = null;
  let file = null;
  let newLineNo = 0;

  for (const raw of lines) {
    if (raw.startsWith('commit ')) {
      commit = raw.slice(7).trim().split(/\s+/)[0] || null;
      author = null;
      date = null;
      continue;
    }
    if (raw.startsWith('Author:')) {
      author = raw.slice(7).trim();
      continue;
    }
    if (raw.startsWith('Date:')) {
      date = raw.slice(5).trim();
      continue;
    }
    if (raw.startsWith('diff --git ')) {
      const match = raw.match(/diff --git a\/(.+?) b\/(.+)$/);
      file = match ? match[2] : null;
      newLineNo = 0;
      continue;
    }
    if (raw.startsWith('@@')) {
      const hunk = raw.match(/@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
      newLineNo = hunk ? parseInt(hunk[1], 10) : 0;
      continue;
    }
    if (raw.startsWith('+') && !raw.startsWith('+++')) {
      if (file && commit) {
        entries.push({
          commit,
          author,
          date,
          file: file.split(path.sep).join('/'),
          line: newLineNo,
          text: raw.slice(1),
        });
      }
      newLineNo += 1;
      continue;
    }
    if (!raw.startsWith('-') && !raw.startsWith('\\')) {
      // Context line (or a diff header) - advance the new-file line counter.
      newLineNo += 1;
    }
  }

  return entries;
}

/**
 * Everything the checks need to know about the repository.
 * `available` is false when the directory is not a git repository (or git is
 * not installed), in which case "committed" questions must be reported as
 * unknown rather than as "safe".
 */
export async function inspectRepository(root, options = {}) {
  const available = await isGitRepo(root);
  if (!available) {
    return {
      available: false,
      tracked: null,
      history: [],
      historyTruncated: false,
      reason: 'No .git directory found in the target folder.',
    };
  }

  const tracked = await trackedFiles(root);
  const history = options.includeHistory === false
    ? { entries: [], truncated: false, ok: true }
    : await (async () => {
        const diff = await historyDiff(root, options);
        return {
          entries: diff.ok ? parseHistoryPatches(diff.text) : [],
          truncated: diff.truncated,
          ok: diff.ok,
          error: diff.error,
        };
      })();

  return {
    available: true,
    tracked,
    history: history.entries,
    historyTruncated: history.truncated,
    historyError: history.error || null,
    reason: tracked === null ? 'git is installed but the repository could not be read.' : null,
  };
}
