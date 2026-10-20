/**
 * checks/secrets-source.js
 * ---------------------------------------------------------------------------
 * CHECK 2 - secret scanning in source files AND in git history.
 *
 * WHY THIS MATTERS: 59% of the public Lovable/Bolt/v0 repositories studied in
 * 2026 had at least one critical issue, and secret leakage is the most
 * common critical issue. AI assistants happily paste a real-looking key
 * into a file, and `git commit` then makes it permanent.
 *
 * The git history scan is capped (commits + bytes) so the tool stays fast on
 * a large repository. Secrets that were deleted but remain in history are
 * reported separately, because "I deleted the file" does NOT remove the key.
 */

import { makeFinding, makePass } from '../lib/findings.js';
import { scanText, SECRET_PATTERNS } from '../lib/secrets.js';
import { redactedLine, evidenceBlock, lineNumber } from '../lib/evidence.js';

export const id = 'secrets-source';
export const title = 'Hard-coded secrets in source code and git history';
export const severity = 'CRITICAL';

/** Files we do not scan for secrets (bundle output has its own check). */
const EXCLUDED_CATEGORIES = new Set(['bundle']);

export function run(context) {
  const findings = [];
  const scannedFiles = [];
  const workingTreeMatches = new Set();

  for (const file of context.files) {
    if (EXCLUDED_CATEGORIES.has(file.category)) continue;
    if (!file.content) continue;
    scannedFiles.push(file.relPath);

    const hits = scanText(file.content, { includeGeneric: file.category === 'source' });
    for (const hit of hits) {
      // An anon key is PUBLIC BY DESIGN (it ships in every browser bundle).
      // Reporting it as a leak would be wrong and would train the client to
      // ignore the report. We note it instead.
      if (hit.jwtKind === 'supabase-anon') continue;

      workingTreeMatches.add(hit.match);
      const line = lineNumber(file.content, hit.index);
      const snippet = redactedLine(file.content, hit.index, hit.match, hit.redacted);

      findings.push(
        makeFinding({
          severity: hit.severity,
          title: `${hit.title} found in ${file.relPath}`,
          detail: `${hit.why} The value below is redacted - open the file on disk to see it.`,
          plain:
            hit.severity === 'CRITICAL'
              ? 'A powerful secret key is sitting in your project files. Anyone who gets hold of it can act as you.'
              : 'A secret key is sitting in your project files and should not be there.',
          location: `${file.relPath}:${line}`,
          remediation:
            'Remove the hard-coded value. Read it from an environment variable at runtime ' +
            '(process.env.X for Node, import.meta.env.VITE_X for Vite, process.env.NEXT_PUBLIC_X for Next.js) ' +
            'and rotate the exposed key in the provider\'s dashboard immediately - removing it from the code does ' +
            'not invalidate it.',
          evidence: evidenceBlock({
            location: `${file.relPath}:${line}`,
            snippet,
          }),
          cwe: 'CWE-798',
        }),
      );
    }
  }

  // ---------------------------------------------------------------- history
  const historyFindings = scanHistory(context, workingTreeMatches);
  findings.push(...historyFindings);

  if (!findings.length) {
    findings.push(
      makePass(
        'No hard-coded secrets found',
        `Scanned ${scannedFiles.length} source file(s) against ${SECRET_PATTERNS.length} credential patterns, plus ` +
          `${context.git.available ? `${context.git.history.length} history line(s)` : 'no git history (no .git folder)'}.`,
        scannedFiles.length ? '' : context.root,
      ),
    );
  }

  return findings;
}

/**
 * Scan the git history for secrets that are no longer in the working tree.
 *
 * WHY only "history only" secrets are reported as findings: a secret that is
 * still in the working tree is already reported (and the client will rotate
 * it). What we add here is the crucial message that DELETING a secret from
 * the code does not remove it from the history.
 */
function scanHistory(context, workingTreeMatches) {
  const findings = [];
  if (!context.git.available || !context.git.history.length) return findings;

  const seen = new Set();
  let historyOnly = 0;

  for (const entry of context.git.history) {
    if (!entry.text || entry.text.length > 4000) continue;
    const hits = scanText(entry.text);
    for (const hit of hits) {
      if (hit.jwtKind === 'supabase-anon') continue;
      if (workingTreeMatches.has(hit.match)) continue;
      const key = `${hit.match}|${entry.file}`;
      if (seen.has(key)) continue;
      seen.add(key);
      historyOnly += 1;

      findings.push(
        makeFinding({
          severity: hit.severity === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
          title: `Secret still present in git history: ${entry.file}`,
          detail:
            `${hit.title} was committed and then removed from the working tree, but it is still stored in the ` +
            'repository history. Anyone who clones the repo can retrieve it with "git log -p".',
          plain:
            'A secret you thought you deleted is still saved inside your code history and can still be recovered.',
          location: `${entry.file} (commit ${String(entry.commit || '').slice(0, 8)})`,
          remediation:
            'Rotate the key immediately, then purge it from the history (for example with `git filter-repo` or ' +
            'BFG). Rotating first is what actually protects you - history rewriting is cleanup.',
          evidence: evidenceBlock({
            location: `${entry.file} (commit ${String(entry.commit || '').slice(0, 8)})`,
            snippet: hit.redacted,
            note: `matched pattern "${hit.patternId}"`,
          }),
          cwe: 'CWE-798',
        }),
      );
    }
  }

  if (historyOnly > 0) {
    findings.push(
      makeFinding({
        severity: 'MEDIUM',
        title: `${historyOnly} secret value(s) remain recoverable from git history`,
        detail:
          'We scanned the commit history and found credentials that are no longer in your current files but are ' +
          'still stored in the repository.',
        plain:
          'Some old secret passwords are still stored inside your code history and can be recovered by anyone with ' +
          'access to the repository.',
        location: 'git history',
        remediation:
          'Rotate every affected key, then rewrite the history to remove the old values. Consider running the audit ' +
          'again afterwards to confirm the history is clean.',
        evidence: 'git log -p was scanned for credential patterns.',
        cwe: 'CWE-798',
      }),
    );
  }

  return findings;
}

/** Status for the report's passed/skipped sections. */
export function status(context) {
  if (!context.git.available) {
    return {
      state: 'unknown',
      notes: ['Git history was not scanned because the target folder is not a git repository.'],
    };
  }
  if (context.git.historyTruncated) {
    return {
      state: 'unknown',
      notes: ['The git history was truncated for speed - older commits may not have been scanned.'],
    };
  }
  return { state: 'unknown', notes: [] };
}
