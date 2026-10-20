/**
 * scan.core.js
 * ---------------------------------------------------------------------------
 * The browser scan engine: builds the scan context, runs every check and
 * assembles the report object.
 *
 * PORTED from the CLI's `lib/runner.js`. The differences are the honest ones
 * - a browser has no git repository and no live URL - so the git and
 * HTTP-specific steps are simply not part of the browser pipeline.
 */

(function (root) {
  'use strict';

  const S = (root.SCANNER = root.SCANNER || {});
  S.scan = S.scan || {};

  const TOOL = { name: 'AI Ship Check (browser)', version: '1.0.0' };

  /**
   * Build the context object every check receives.
   *
   * @param {object} options
   * @param {string} options.root      a label for the project
   * @param {Array}  options.files     file records
   */
  function buildContext(options) {
    const opts = options || {};
    const files = opts.files || [];

    // Pre-compute the SQL and table-reference knowledge so several checks can
    // share it instead of parsing the same files three times.
    const sqlFiles = files.filter((file) => file.category === 'sql' && file.content);
    const sql = S.lib.sql.analyseSql(sqlFiles);
    const codeFiles = files.filter(
      (file) => (file.category === 'source' || file.category === 'config') && file.content,
    );
    const { references } = S.lib.sql.collectTableReferences(codeFiles);

    return {
      root: opts.root || 'the selected folder',
      files,
      sql,
      references,
      /**
       * A numbered window of lines around an offset - used for code evidence.
       * Keeping it on the context means every finding quotes code the same way.
       */
      window(content, index, lineCount) {
        return S.lib.evidence.codeWindow(content, index, lineCount);
      },
    };
  }

  /**
   * Run every check and build the full report object.
   *
   * @param {object} options
   * @param {Array}  options.files   file records: { relPath, name, ext, size, category, content }
   * @param {string} [options.label]  the project name shown in the report
   * @param {function} [options.onProgress] called with ({ phase, done, total })
   */
  function scanProject(options) {
    const opts = options || {};
    const startedAt = Date.now();
    const files = opts.files || [];
    const context = buildContext({ root: opts.label || 'the selected folder', files });

    const checkResults = [];
    const findings = [];
    const checks = S.checks.CHECKS;

    for (let i = 0; i < checks.length; i += 1) {
      const check = checks[i];
      if (typeof opts.onProgress === 'function') {
        opts.onProgress({ phase: 'check', check: check.title, done: i, total: checks.length });
      }

      let checkFindings = [];
      let state = 'pass';
      let notes = [];

      try {
        const raw = check.run(context);
        checkFindings = Array.isArray(raw) ? raw : [];
        const defects = checkFindings.filter((f) => (f.kind || 'defect') === 'defect');

        if (defects.length) {
          state = 'fail';
        } else if (checkFindings.some((finding) => finding.kind === 'skip')) {
          // A check that could not run says so itself, by emitting a skip note.
          state = 'skip';
          notes = checkFindings
            .filter((finding) => finding.kind === 'skip')
            .map((finding) => finding.detail)
            .filter(Boolean);
        } else if (typeof check.status === 'function') {
          const status = check.status(context);
          state = status && status.state === 'skip' ? 'skip' : 'pass';
          notes = (status && status.notes) || [];
        } else {
          state = 'pass';
        }

        for (const finding of checkFindings) {
          finding.checkId = check.id;
          finding.checkTitle = check.title;
          findings.push(finding);
        }
      } catch (error) {
        state = 'error';
        notes = [String((error && error.message) || error)];
        const errorFinding = {
          severity: 'INFO',
          kind: 'error',
          title: `Check "${check.title}" could not be completed`,
          detail: `The scanner hit an unexpected problem while running this check: ${String(
            (error && error.message) || error,
          )}`,
          location: check.id,
          remediation:
            'This is a tool problem, not a finding about your project. Re-run the scan and report it if it repeats.',
          evidence: String((error && error.stack) || error),
          fixPrompt: '',
          id: `${check.id}-error`,
          plain: '',
          checkId: check.id,
          checkTitle: check.title,
        };
        findings.push(errorFinding);
      }

      checkResults.push({
        id: check.id,
        title: check.title,
        severity: check.severity,
        state,
        notes,
        findingCount: checkFindings.filter((f) => (f.kind || 'defect') === 'defect').length,
      });
    }

    const defectFindings = findings.filter((f) => (f.kind || 'defect') === 'defect');
    const scored = S.lib.severity.scoreFindings(defectFindings);

    const report = {
      tool: TOOL,
      generatedAt: S.lib.util.nowIso(),
      durationMs: Date.now() - startedAt,
      target: opts.label || 'the selected folder',
      targetLabel: opts.label || 'the selected folder',
      fileCount: files.length,
      totalBytes: files.reduce((sum, file) => sum + (file.size || 0), 0),
      gitAvailable: false,
      liveUrl: null,
      score: scored.score,
      verdict: scored.verdict,
      verdictPlain: scored.verdictPlain,
      counts: scored.counts,
      hasCritical: scored.hasCritical,
      findings: S.lib.severity.sortFindings(defectFindings),
      notes: findings.filter((f) => (f.kind || 'defect') !== 'defect'),
      checks: checkResults,
    };

    report.markdown = S.lib.report.renderMarkdown(report);
    return report;
  }

  S.scan.scanProject = scanProject;
  S.scan.buildContext = buildContext;
  S.scan.TOOL = TOOL;
})(globalThis);
