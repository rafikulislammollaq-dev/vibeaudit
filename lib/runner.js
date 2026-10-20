/**
 * lib/runner.js
 * ---------------------------------------------------------------------------
 * The audit engine: builds the scan context, runs every check, and assembles
 * the report object.
 *
 * The CLI is a thin wrapper around `runAudit()`. That split exists so the
 * tests can run a full audit against a folder without spawning a process,
 * and so the tool can be embedded in another Node script later.
 */

import path from 'node:path';
import fs from 'node:fs/promises';

import { walkFiles } from './fs-walk.js';
import { inspectRepository } from './git.js';
import { detectSupabaseConfig } from './supabase.js';
import { analyseSql, collectTableReferences } from './sql.js';
import { createContext } from './context.js';
import { scoreFindings, sortFindings } from './severity.js';
import { FINDING_KINDS } from './findings.js';
import { nowIso } from './util.js';
import { normalizeBaseUrl } from './http.js';
import { CHECKS } from '../checks/index.js';

/** How much of the git history we read (keeps big repos fast). */
const HISTORY_OPTIONS = { maxCommits: 150, maxBytes: 8 * 1024 * 1024 };

/**
 * Build the context object every check receives.
 */
export async function buildContext(options) {
  const root = path.resolve(options.target);

  const files = await walkFiles(root, { readContent: true });

  const git = await inspectRepository(root, {
    includeHistory: options.includeHistory !== false,
    ...HISTORY_OPTIONS,
  });

  // Pre-compute the SQL and table-reference knowledge so several checks can
  // share it instead of parsing the same files three times.
  const sqlFiles = files.filter((file) => file.category === 'sql' && file.content);
  const sql = analyseSql(sqlFiles);
  const codeFiles = files.filter((file) => (file.category === 'source' || file.category === 'config') && file.content);
  const { references } = collectTableReferences(codeFiles);
  const supabase = detectSupabaseConfig(files.filter((file) => file.content));

  const url = options.url ? normalizeBaseUrl(options.url) : null;

  return createContext({
    root,
    target: options.target,
    files,
    git,
    sql,
    references,
    supabase,
    url,
    authorized: Boolean(options.authorized),
    options,
    demo: Boolean(options.demo),
  });
}

/**
 * Run every check and build the full report object.
 *
 * @param {object} options
 * @param {string} options.target          absolute or relative path to the project
 * @param {string|null} [options.url]      live base URL (opt-in only)
 * @param {boolean} [options.authorized]   the --i-have-authorization acknowledgement
 * @param {boolean} [options.includeHistory]
 * @param {boolean} [options.demo]
 * @param {string[]} [options.only]        restrict to these check ids
 */
export async function runAudit(options = {}) {
  const startedAt = Date.now();
  const context = await buildContext(options);

  const selected = options.only && options.only.length
    ? CHECKS.filter((check) => options.only.includes(check.id))
    : CHECKS;

  const checkResults = [];
  const findings = [];

  for (const check of selected) {
    const checkStarted = Date.now();
    let checkFindings = [];
    let state = 'pass';
    let notes = [];

    try {
      const raw = await check.run(context);
      checkFindings = Array.isArray(raw) ? raw : [];
      const defects = checkFindings.filter((f) => (f.kind || FINDING_KINDS.DEFECT) === FINDING_KINDS.DEFECT);

      if (defects.length) {
        state = 'fail';
      } else if (checkFindings.some((finding) => finding.kind === FINDING_KINDS.SKIP)) {
        // A check that could not run says so itself, by emitting a skip note.
        // That is more reliable than asking a separate status() function to
        // guess the same thing. The note's own text becomes the explanation
        // shown in the report.
        state = 'skip';
        notes = checkFindings
          .filter((finding) => finding.kind === FINDING_KINDS.SKIP)
          .map((finding) => finding.detail)
          .filter(Boolean);
      } else if (typeof check.status === 'function') {
        const status = await check.status(context);
        // The check ran and found nothing, so it passed - unless the check
        // itself says that part of its work could not be done (for example
        // "there is no .git folder, so I cannot tell you whether the .env is
        // committed"). That is a skip, not a pass.
        state = status?.state === 'skip' ? 'skip' : 'pass';
        notes = status?.notes || [];
      } else {
        state = 'pass';
      }

      // Annotate every finding with its check so the report can group them.
      for (const finding of checkFindings) {
        finding.checkId = check.id;
        finding.checkTitle = check.title;
        findings.push(finding);
      }
    } catch (error) {
      state = 'error';
      notes = [String(error?.message || error)];
      checkFindings = [
        {
          severity: 'INFO',
          kind: FINDING_KINDS.ERROR,
          title: `Check "${check.title}" could not be completed`,
          detail: `The scanner hit an unexpected problem while running this check: ${String(error?.message || error)}`,
          location: check.id,
          remediation: 'This is a tool problem, not a finding about your project. Re-run the audit and report it if it repeats.',
          evidence: String(error?.stack || error?.message || error),
          fixPrompt: '',
          id: `${check.id}-error`,
          plain: '',
        },
      ];
      for (const finding of checkFindings) {
        finding.checkId = check.id;
        finding.checkTitle = check.title;
        findings.push(finding);
      }
    }

    checkResults.push({
      id: check.id,
      title: check.title,
      severity: check.severity,
      state,
      notes,
      durationMs: Date.now() - checkStarted,
      findingCount: checkFindings.filter((f) => (f.kind || FINDING_KINDS.DEFECT) === FINDING_KINDS.DEFECT).length,
    });
  }

  const defectFindings = findings.filter(
    (finding) => (finding.kind || FINDING_KINDS.DEFECT) === FINDING_KINDS.DEFECT,
  );
  const scored = scoreFindings(defectFindings);

  const report = {
    tool: { name: 'vibeaudit', version: '1.0.0' },
    generatedAt: nowIso(),
    durationMs: Date.now() - startedAt,
    target: context.root,
    targetLabel: options.targetLabel || context.root,
    demo: context.demo,
    liveUrl: context.url,
    authorized: context.authorized,
    fileCount: context.files.length,
    gitAvailable: context.git.available,
    score: scored.score,
    verdict: scored.verdict,
    verdictPlain: scored.verdictPlain,
    counts: scored.counts,
    hasCritical: scored.hasCritical,
    findings: sortFindings(defectFindings),
    notes: findings.filter((finding) => (finding.kind || FINDING_KINDS.DEFECT) !== FINDING_KINDS.DEFECT),
    checks: checkResults,
    options: {
      includeHistory: options.includeHistory !== false,
      historyTruncated: context.git.historyTruncated,
    },
  };

  return report;
}

/**
 * Verify that a target folder exists and looks like a project.
 * Returns an error message, or null when the target is usable.
 */
export async function validateTarget(target) {
  try {
    const stat = await fs.stat(target);
    if (!stat.isDirectory()) return `"${target}" is not a folder.`;
  } catch {
    return `The folder "${target}" does not exist.`;
  }
  return null;
}
