/**
 * lib/findings.core.js
 * ---------------------------------------------------------------------------
 * The finding factory.
 *
 * PORTED from the CLI's `audit/lib/findings.js`.
 *
 * WHY a factory: every finding in the report has the same shape, so the
 * renderer never has to guard against `finding.detail` being undefined, and
 * the client always gets the same information in the same order. It also
 * gives us one place to attach the "paste this into your AI assistant"
 * prompt, which is the single most useful thing a non-technical founder can
 * do with the report.
 */

(function (root) {
  'use strict';

  const S = (root.SCANNER = root.SCANNER || {});
  S.lib = S.lib || {};

  /** Finding kinds. Only 'defect' findings subtract points from the score. */
  const FINDING_KINDS = Object.freeze({
    DEFECT: 'defect',
    NOTE: 'note',
    PASS: 'pass',
    SKIP: 'skip',
    ERROR: 'error',
  });

  /**
   * Build the default "paste this into Cursor / Lovable" prompt.
   *
   * WHY this matters commercially: the client's next action is almost never
   * "call a developer". It is "paste this into the AI tool that built my
   * app". Handing them the exact prompt removes all the friction between the
   * audit and the fix.
   */
  function defaultFixPrompt(finding) {
    const location = finding.location || 'the affected file';
    const lines = [
      `Fix this security issue in \`${location}\`.`,
      '',
      `Issue: ${finding.title}`,
    ];
    if (finding.detail) lines.push(`What is wrong: ${finding.detail}`);
    if (finding.evidence) {
      lines.push('');
      lines.push('Here is the offending code (values are redacted, use the real file on disk):');
      lines.push('```');
      lines.push(String(finding.evidence).slice(0, 1500));
      lines.push('```');
    }
    lines.push('');
    lines.push(`Required fix: ${finding.remediation}`);
    lines.push('');
    lines.push('Rules:');
    lines.push('- Make the smallest change that fully fixes the issue.');
    lines.push('- Do not weaken or remove existing authentication, authorisation or validation.');
    lines.push('- Keep the current file structure, naming and code style.');
    lines.push('- If the same pattern exists elsewhere in the project, fix it there too and tell me where.');
    lines.push('- When you are done, show me the diff and explain in one sentence what changed.');
    return lines.join('\n');
  }

  /**
   * Create a normalised finding.
   *
   * Required fields (per the tool's public contract):
   *   severity, title, detail, location, remediation, evidence
   * Optional:
   *   plain       - one non-technical sentence for the plain-English summary
   *   fixPrompt   - override the generated AI-assistant prompt
   *   kind        - 'defect' (default) | 'note' | 'pass' | 'skip' | 'error'
   *   checkId     - filled in by the runner
   *   cwe         - optional reference for the technically minded
   */
  function makeFinding(input) {
    const source = input || {};
    const finding = {
      severity: S.lib.severity.normalizeSeverity(source.severity),
      title: String(source.title || 'Untitled finding'),
      detail: String(source.detail || ''),
      location: String(source.location || 'unknown location'),
      remediation: String(source.remediation || 'No remediation text supplied.'),
      evidence: source.evidence == null ? '' : String(source.evidence),
      plain: source.plain ? String(source.plain) : '',
      kind: source.kind || FINDING_KINDS.DEFECT,
      cwe: source.cwe || null,
      fixPrompt: source.fixPrompt ? String(source.fixPrompt) : defaultFixPrompt(source),
      checkId: source.checkId || null,
      checkTitle: source.checkTitle || null,
    };
    finding.id =
      source.id ||
      `${finding.checkId || 'finding'}-${S.lib.util.shortHash(
        `${finding.title}|${finding.location}|${finding.evidence}`,
      )}`;
    return finding;
  }

  /** A "check passed" note. Rendered in the checklist, never scored. */
  function makePass(title, detail, location) {
    return makeFinding({
      severity: 'INFO',
      kind: FINDING_KINDS.PASS,
      title,
      detail,
      location: location || '',
      remediation: 'Nothing to do - this check passed.',
    });
  }

  /** A "check skipped" note. Explains *why*, which builds client trust. */
  function makeSkip(title, detail, location) {
    return makeFinding({
      severity: 'INFO',
      kind: FINDING_KINDS.SKIP,
      title,
      detail,
      location: location || '',
      remediation: 'Re-run the scan with the missing input to include this check.',
    });
  }

  S.lib.findings = {
    FINDING_KINDS,
    defaultFixPrompt,
    makeFinding,
    makePass,
    makeSkip,
  };
})(globalThis);
