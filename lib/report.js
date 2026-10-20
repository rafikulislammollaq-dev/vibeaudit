/**
 * lib/report.js
 * ---------------------------------------------------------------------------
 * Report rendering: the Markdown a client reads, and the JSON a machine
 * reads.
 *
 * THE REPORT IS THE PRODUCT. The client is usually a non-technical founder
 * who shipped an AI-built app and is worried about their customers' data.
 * They will read the first paragraph, then the "Top 5 things to fix first"
 * list, then paste those prompts into their AI assistant. Everything else
 * exists to back that up.
 *
 * Structure (deliberately in this order):
 *   1. Headline + score + verdict         - the answer, in one line
 *   2. What this means (plain English)     - for a non-technical reader
 *   3. Top 5 things to fix first            - the actual work plan
 *   4. Findings grouped by severity         - the detail
 *   5. Checks that passed                    - proof of what was tested
 *   6. Checks that were skipped              - honesty about coverage
 *   7. Methodology & scope                   - what a professional audit covers
 */

import { SEVERITIES } from './severity.js';
import { fence, plural } from './util.js';

/** Emoji markers - they survive copy/paste into Slack, Notion and email. */
const SEVERITY_ICON = {
  CRITICAL: '🔴',
  HIGH: '🟠',
  MEDIUM: '🟡',
  LOW: '🔵',
  INFO: '⚪',
};

const VERDICT_ICON = {
  'Ready to ship': '✅',
  'Ship after fixing high findings': '⚠️',
  'Do not ship yet': '⛔',
  'Unsafe to ship': '🚨',
};

/**
 * The plain-English summary.
 *
 * WHY so much effort here: a founder who reads "RLS policy uses USING (true)"
 * learns nothing and panics. A founder who reads "anyone on the internet can
 * read your customers' table" understands exactly what to do next.
 */
export function buildPlainSummary(report) {
  const { counts, score, verdict, verdictPlain } = report;
  const total = counts.CRITICAL + counts.HIGH + counts.MEDIUM + counts.LOW;
  const fileCount = report.fileCount;
  const top = buildTopFive(report);

  const opening =
    `We checked ${plural(fileCount, 'file')} in your project for the security mistakes that AI-built apps make most ` +
    `often - leaked passwords and keys, database tables that anyone on the internet can read, and admin pages that ` +
    'are not protected. ';

  let countSentence;
  if (total === 0) {
    countSentence =
      'We did not find any security problems in the files we scanned, which is a good result - though it only ' +
      'covers the code you gave us, not the parts of your app we could not see.';
  } else {
    const parts = [];
    if (counts.CRITICAL) parts.push(plural(counts.CRITICAL, 'serious problem'));
    if (counts.HIGH) parts.push(plural(counts.HIGH, 'important problem'));
    if (counts.MEDIUM) parts.push(plural(counts.MEDIUM, 'medium problem'));
    if (counts.LOW) parts.push(plural(counts.LOW, 'small problem'));
    // One category reads better with a colon than with a dash.
    countSentence = `We found ${total} issue${total === 1 ? '' : 's'}${parts.length === 1 ? ':' : ' -'} ${listToSentence(parts)}. `;
  }

  const scoreSentence = `That gives a readiness score of ${score} out of 100, which means ${verdictPlain}`;

  let worstSentence = '';
  if (top.length) {
    const first = top[0];
    const plain = stripSentenceEnd(first.plain || first.detail);
    // Calling a low-severity nit "the most urgent one" would be silly, so
    // the wording follows the severity.
    const urgent = first.severity === 'CRITICAL' || first.severity === 'HIGH';
    const lead = urgent ? 'The most urgent one is' : 'The main thing to tidy up is';
    worstSentence = ` ${lead}: ${plain.charAt(0).toUpperCase()}${plain.slice(1)}`;
    if (top.length > 1) {
      // The second item is named by its title rather than its plain-English
      // summary: two findings of the same kind share the same wording, and
      // repeating it reads like a stutter.
      const second = stripSentenceEnd(top[1].title);
      worstSentence += `, followed by ${second.toLowerCase()}`;
    }
    worstSentence += '. All of these can be fixed without rebuilding the app.';
  } else {
    worstSentence = ' Keep this report and re-run the audit after any future changes to the app.';
  }

  const closing = report.liveUrl
    ? ' We also made a small number of read-only requests to your live site to check its public settings; nothing was ' +
      'changed and no sign-in was attempted.'
    : ' We only looked at the files you gave us - we did not test your live site, so the online parts of your app still ' +
      'need a separate check.';

  return `${opening}${countSentence}${scoreSentence}${worstSentence}${closing}`;
}

/** Join a list into "a, b and c". */
export function listToSentence(items) {
  if (!items.length) return '';
  if (items.length === 1) return items[0];
  return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
}

/**
 * Remove the trailing punctuation from a fragment.
 * Finding details usually end with a full stop; pasting them into a larger
 * sentence must not produce "act as you.,".
 */
export function stripSentenceEnd(text) {
  return String(text || '').trim().replace(/[.\s]+$/, '');
}

/**
 * Normalise a fragment into a single sentence.
 */
export function asSentence(text) {
  const trimmed = stripSentenceEnd(text);
  if (!trimmed) return '';
  return `${trimmed.charAt(0).toUpperCase()}${trimmed.slice(1)}.`;
}

/**
 * The five things to fix first.
 *
 * WHY five: it is the most a non-technical person will act on in one
 * sitting. Ten items gets ignored; five gets done.
 */
export function buildTopFive(report) {
  const findings = report.findings || [];
  const top = findings.slice(0, 5);
  return top.map((finding, index) => ({
    rank: index + 1,
    id: finding.id,
    title: finding.title,
    severity: finding.severity,
    plain: finding.plain || '',
    detail: finding.detail,
    location: finding.location,
    remediation: finding.remediation,
    fixPrompt: finding.fixPrompt,
    evidence: finding.evidence,
  }));
}

/* -------------------------------------------------------------------------- */
/* Markdown rendering                                                          */
/* -------------------------------------------------------------------------- */

/** Render the full Markdown report. */
export function renderMarkdown(report) {
  const lines = [];
  const title = report.demo ? 'Security Audit - DEMO PROJECT' : 'Security Audit Report';

  lines.push(`# ${title}`);
  lines.push('');
  lines.push(
    `**Target:** \`${report.targetLabel}\`  |  **Scanned:** ${report.generatedAt}  |  ` +
      `**Tool:** ${report.tool.name} v${report.tool.version}  |  **Duration:** ${(report.durationMs / 1000).toFixed(1)}s`,
  );
  lines.push('');

  // ---------------------------------------------------------- headline
  const icon = VERDICT_ICON[report.verdict] || '';
  lines.push(`## ${icon} Ship readiness: ${report.score}/100 - ${report.verdict}`);
  lines.push('');
  lines.push('| Critical | High | Medium | Low |');
  lines.push('|---|---|---|---|');
  lines.push(
    `| ${report.counts.CRITICAL} | ${report.counts.HIGH} | ${report.counts.MEDIUM} | ${report.counts.LOW} |`,
  );
  lines.push('');
  if (report.hasCritical) {
    lines.push(
      '> **At least one CRITICAL issue was found, so this project cannot be called ready to ship no matter how ' +
        'high the score is.** Critical issues are the ones that put your customers\' data at risk.',
    );
    lines.push('');
  }

  // ------------------------------------------------- plain-English summary
  lines.push('## What this means, in plain English');
  lines.push('');
  lines.push(buildPlainSummary(report));
  lines.push('');

  // ----------------------------------------------------------- top five
  const topFive = buildTopFive(report);
  lines.push('## Top 5 things to fix first');
  lines.push('');
  if (!topFive.length) {
    lines.push('Nothing came back - no fixes were needed in the files we scanned.');
    lines.push('');
  } else {
    for (const item of topFive) {
      lines.push(`### ${item.rank}. ${SEVERITY_ICON[item.severity]} ${item.title}`);
      lines.push('');
      if (item.plain) {
        lines.push(`**In plain English:** ${item.plain}`);
        lines.push('');
      }
      lines.push(`**Where:** \`${item.location}\``);
      lines.push('');
      if (item.evidence) {
        lines.push('**What we saw:**');
        lines.push('');
        lines.push(fence(item.evidence));
        lines.push('');
      }
      lines.push('**Paste this into your AI assistant (Cursor, Lovable, Bolt, Claude...):**');
      lines.push('');
      lines.push(fence(item.fixPrompt, 'text'));
      lines.push('');
    }
  }

  // ------------------------------------------------------------ findings
  lines.push('## All findings');
  lines.push('');
  const grouped = groupBySeverity(report.findings || []);
  const hasAny = Object.values(grouped).some((list) => list.length);
  if (!hasAny) {
    lines.push('No security issues were found in the files we scanned.');
    lines.push('');
  }
  for (const severity of SEVERITIES) {
    const list = grouped[severity] || [];
    if (!list.length) continue;
    lines.push(`### ${SEVERITY_ICON[severity]} ${severity.charAt(0) + severity.slice(1).toLowerCase()} (${list.length})`);
    lines.push('');
    for (const finding of list) {
      lines.push(`#### ${finding.title}`);
      lines.push('');
      lines.push(`- **Severity:** ${finding.severity}${finding.cwe ? ` (${finding.cwe})` : ''}`);
      lines.push(`- **Where:** \`${finding.location}\``);
      lines.push(`- **Check:** ${finding.checkTitle || finding.checkId || 'n/a'}`);
      lines.push('');
      lines.push(finding.detail);
      lines.push('');
      if (finding.evidence) {
        lines.push('**Evidence (secrets are redacted):**');
        lines.push('');
        lines.push(fence(finding.evidence));
        lines.push('');
      }
      lines.push('**How to fix it:**');
      lines.push('');
      lines.push(finding.remediation);
      lines.push('');
      if (finding.fixPrompt) {
        lines.push('**Paste this into your AI assistant:**');
        lines.push('');
        lines.push(fence(finding.fixPrompt, 'text'));
        lines.push('');
      }
    }
  }

  // ------------------------------------------------------- checks passed
  const passed = (report.checks || []).filter((check) => check.state === 'pass');
  const failed = (report.checks || []).filter((check) => check.state === 'fail');
  const skipped = (report.checks || []).filter((check) => check.state === 'skip' || check.state === 'error');

  lines.push('## Checks that passed');
  lines.push('');
  lines.push('These are the things we looked for and did **not** find. They are listed so you know what was covered.');
  lines.push('');
  if (!passed.length) {
    lines.push('- _No check completed without finding something._');
  } else {
    for (const check of passed) {
      const detail = (report.notes || []).find((note) => note.checkId === check.id && note.kind === 'pass');
      lines.push(`- ✅ **${check.title}**${detail ? ` - ${detail.detail}` : ''}`);
    }
  }
  lines.push('');

  lines.push('## Checks that were skipped, and why');
  lines.push('');
  lines.push('We would rather tell you what we could not check than let you assume it was fine.');
  lines.push('');
  if (!skipped.length) {
    lines.push('- _Every check in the tool ran._');
  } else {
    for (const check of skipped) {
      // The check's own skip note explains the situation far better than the
      // check title alone, so we show both - but never the same sentence twice.
      const note = (report.notes || []).find((n) => n.checkId === check.id && n.kind === 'skip');
      const shown = new Set();
      lines.push(`- ⏭️ **${check.title}**`);
      if (note) {
        lines.push(`  - ${note.title}`);
        shown.add(note.title.trim());
        if (note.detail) {
          lines.push(`  - ${note.detail}`);
          shown.add(note.detail.trim());
        }
      }
      for (const noteText of check.notes || []) {
        if (shown.has(String(noteText).trim())) continue;
        lines.push(`  - ${noteText}`);
      }
      if (!note && (!check.notes || !check.notes.length)) {
        lines.push('  - This check did not produce a result for this project.');
      }
    }
  }
  lines.push('');

  if (failed.length) {
    lines.push('## Checks that found something');
    lines.push('');
    for (const check of failed) {
      lines.push(`- ⚠️ **${check.title}** - ${plural(check.findingCount, 'finding')}`);
      // A check can find problems AND be unable to complete part of its work
      // (for example: the dependency names were checked but npm audit could
      // not run). We say so, rather than letting the reader assume full
      // coverage.
      const skipNote = (report.notes || []).find((n) => n.checkId === check.id && n.kind === 'skip');
      if (skipNote) {
        lines.push(`  - Part of this check could not run - ${skipNote.title}: ${skipNote.detail}`);
      }
    }
    lines.push('');
  }

  // ------------------------------------------------------- methodology
  lines.push('---');
  lines.push('');
  lines.push('## Methodology, scope and limits');
  lines.push('');
  lines.push('**What we did**');
  lines.push('');
  lines.push(
    `- Read ${plural(report.fileCount, 'file')} from the project folder you pointed us at (ignored folders such as ` +
      'node_modules and build caches were skipped, but the built output was scanned for leaked keys).',
  );
  lines.push(
    report.gitAvailable
      ? '- Checked which files are committed to git, and scanned the commit history for credentials that were ' +
        'deleted but remain recoverable.'
      : '- The project folder is not a git repository, so we could not check the commit history or whether ' +
        'environment files are committed.',
  );
  if (report.liveUrl) {
    lines.push(
      `- Sent ${report.authorized ? 'a small number of read-only requests' : 'no requests'} to ${report.liveUrl} to ` +
        'check the public security settings. No sign-in was attempted and nothing was changed.',
    );
  } else {
    lines.push('- Did not test the live site. Pass --url (with --i-have-authorization) to include the online checks.');
  }
  lines.push('');
  lines.push('**What this audit does NOT cover**');
  lines.push('');
  lines.push('- Your live server configuration, hosting settings, DNS, firewalls or database server settings.');
  lines.push('- Third-party services you use (payment providers, email sending, analytics) beyond the keys we found.');
  lines.push('- The security of the browser extensions, devices or networks your customers use.');
  lines.push(
    '- A full penetration test. This is a focused code and configuration review of the files you gave us, which is ' +
      'what catches the overwhelming majority of real incidents in AI-built apps.',
  );
  lines.push('- Anything in parts of the codebase that were not present in the folder you provided.');
  lines.push('');
  lines.push('**How the score works**');
  lines.push('');
  lines.push(
    'The score starts at 100 and each finding deducts points: **25** for a critical issue, **12** for a high one, ' +
      '**4** for a medium one and **1** for a low one. The score cannot go below 0. The verdict comes from the score:',
  );
  lines.push('');
  lines.push('- **90+** Ready to ship');
  lines.push('- **70-89** Ship after fixing high findings');
  lines.push('- **40-69** Do not ship yet');
  lines.push('- **below 40** Unsafe to ship');
  lines.push('');
  lines.push(
    'If there is even one critical finding, the verdict is capped at "Do not ship yet" - a high score can never ' +
      'hide a problem that puts customer data at risk.',
  );
  lines.push('');
  lines.push('**Reminder**');
  lines.push('');
  lines.push(
    'This tool was run with your authorisation. Keep the output private: the report names the files and functions ' +
      'that need fixing, which tells an attacker exactly where to look.',
  );
  lines.push('');

  return lines.join('\n');
}

/** Group findings by severity, preserving the severity order. */
export function groupBySeverity(findings) {
  const grouped = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [], INFO: [] };
  for (const finding of findings) {
    const severity = finding.severity || 'INFO';
    if (!grouped[severity]) grouped[severity] = [];
    grouped[severity].push(finding);
  }
  return grouped;
}

/* -------------------------------------------------------------------------- */
/* JSON rendering                                                              */
/* -------------------------------------------------------------------------- */

/**
 * Render the machine-readable report.
 * Same information as the Markdown, but stable and easy to diff between runs.
 */
export function renderJson(report) {
  return JSON.stringify(
    {
      tool: report.tool,
      generatedAt: report.generatedAt,
      durationMs: report.durationMs,
      target: report.target,
      targetLabel: report.targetLabel,
      demo: report.demo,
      liveUrl: report.liveUrl,
      authorized: report.authorized,
      fileCount: report.fileCount,
      gitAvailable: report.gitAvailable,
      score: report.score,
      verdict: report.verdict,
      summary: buildPlainSummary(report),
      counts: report.counts,
      hasCritical: report.hasCritical,
      topFive: buildTopFive(report),
      findings: (report.findings || []).map((finding) => ({
        id: finding.id,
        severity: finding.severity,
        title: finding.title,
        plain: finding.plain || null,
        detail: finding.detail,
        location: finding.location,
        remediation: finding.remediation,
        evidence: finding.evidence,
        fixPrompt: finding.fixPrompt,
        checkId: finding.checkId,
        checkTitle: finding.checkTitle,
        cwe: finding.cwe || null,
      })),
      checks: report.checks,
      notes: (report.notes || []).map((note) => ({
        checkId: note.checkId,
        kind: note.kind,
        title: note.title,
        detail: note.detail,
      })),
    },
    null,
    2,
  );
}

/** Short one-line console summary used by the CLI when writing to a file. */
export function renderConsoleSummary(report) {
  const icon = VERDICT_ICON[report.verdict] || '';
  const c = report.counts;
  return (
    `${icon} ${report.verdict} - ${report.score}/100  ` +
    `(${c.CRITICAL} critical, ${c.HIGH} high, ${c.MEDIUM} medium, ${c.LOW} low)`
  );
}
