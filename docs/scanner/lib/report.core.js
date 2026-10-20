/**
 * lib/report.core.js
 * ---------------------------------------------------------------------------
 * Report rendering: the Markdown a client reads.
 *
 * PORTED from the CLI's `audit/lib/report.js`. The tone is deliberately
 * identical - the CLI report and this browser report are the same product,
 * and a client should not be able to tell which one produced the text.
 *
 * The two differences are honest ones:
 *   1. There is no git repository and no live URL in a browser, so those
 *      paragraphs are replaced by the "What this does NOT check" section.
 *   2. The browser version adds an explicit scope statement, because a tool
 *      that runs locally must be clear about the limits of what it saw.
 */

(function (root) {
  'use strict';

  const S = (root.SCANNER = root.SCANNER || {});
  S.lib = S.lib || {};

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
   * What the browser version genuinely cannot do.
   *
   * WHY this is a first-class part of the product: the CLI can reach further
   * (it reads git history, it can probe a live URL, it can run a dependency
   * audit). A lead magnet that quietly pretends to cover the same ground
   * would destroy trust the first time a client notices.
   */
  const NOT_CHECKED = [
    {
      title: 'Your live website and server',
      detail:
        'This scan never touches the network. It cannot see the security headers your server actually returns ' +
        '(Content-Security-Policy, HSTS, X-Frame-Options), your TLS setup, your DNS, or anything your hosting ' +
        'provider exposes. The command-line version of this tool can make a small number of read-only requests to a ' +
        'live URL when you explicitly authorise it.',
    },
    {
      title: 'Known vulnerabilities in your dependencies',
      detail:
        'We did not run "npm audit" and we did not look up CVE numbers for the packages in package.json. A ' +
        'dependency with a published vulnerability is invisible to this scan. The command-line version does check ' +
        'this.',
    },
    {
      title: 'Your git history',
      detail:
        'A browser cannot read .git, so we cannot tell whether a secret was committed and later deleted, and we ' +
        'cannot confirm whether your .env file is actually tracked. We can only read your .gitignore rules. The ' +
        'command-line version scans the commit history.',
    },
    {
      title: 'Runtime behaviour and business-logic bugs',
      detail:
        'We read code, we do not run it. Broken authorisation in a route handler, leaky API responses and logic ' +
        'errors only show up when the app is actually running. The command-line version has additional checks for ' +
        'missing authorisation on API routes.',
    },
    {
      title: 'Anything outside the folder you picked',
      detail:
        'Only the files you selected were read. A separate backend service, a mobile app, an infrastructure ' +
        'repository or a second Supabase project would not be covered.',
    },
    {
      title: 'A penetration test',
      detail:
        'This is a focused review of the code you gave us, which is what catches the overwhelming majority of real ' +
        'incidents in AI-built apps. It is not a penetration test and it is not a substitute for one.',
    },
  ];

  /**
   * The plain-English summary.
   *
   * WHY so much effort here: a founder who reads "RLS policy uses USING (true)"
   * learns nothing and panics. A founder who reads "anyone on the internet can
   * read your customers' table" understands exactly what to do next.
   */
  function buildPlainSummary(report) {
    const counts = report.counts || {};
    const score = report.score;
    const verdictPlain = report.verdictPlain;
    const total =
      (counts.CRITICAL || 0) + (counts.HIGH || 0) + (counts.MEDIUM || 0) + (counts.LOW || 0);
    const fileCount = report.fileCount;
    const top = buildTopFive(report);
    const plural = S.lib.util.plural;

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
      worstSentence = ' Keep this report and re-run the scan after any future changes to the app.';
    }

    const closing =
      ' We only looked at the files you gave us - we did not test your live site, so the online parts of your app ' +
      'still need a separate check.';

    return `${opening}${countSentence}${scoreSentence}${worstSentence}${closing}`;
  }

  /** Join a list into "a, b and c". */
  function listToSentence(items) {
    if (!items.length) return '';
    if (items.length === 1) return items[0];
    return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`;
  }

  /**
   * Remove the trailing punctuation from a fragment.
   * Finding details usually end with a full stop; pasting them into a larger
   * sentence must not produce "act as you.,".
   */
  function stripSentenceEnd(text) {
    return String(text || '').trim().replace(/[.\s]+$/, '');
  }

  /**
   * Normalise a fragment into a single sentence.
   */
  function asSentence(text) {
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
  function buildTopFive(report) {
    const findings = (report && report.findings) || [];
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

  /** Group findings by severity, preserving the severity order. */
  function groupBySeverity(findings) {
    const grouped = { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [], INFO: [] };
    for (const finding of findings || []) {
      const severity = finding.severity || 'INFO';
      if (!grouped[severity]) grouped[severity] = [];
      grouped[severity].push(finding);
    }
    return grouped;
  }

  /** Render the full Markdown report. */
  function renderMarkdown(report) {
    const lines = [];
    const fence = S.lib.util.fence;
    const severities = S.lib.severity.SEVERITIES;

    lines.push('# Security Audit Report');
    lines.push('');
    lines.push(
      `**Target:** \`${report.targetLabel}\`  |  **Scanned:** ${report.generatedAt}  |  ` +
        `**Tool:** ${report.tool.name} v${report.tool.version}  |  **Duration:** ${(report.durationMs / 1000).toFixed(1)}s`,
    );
    lines.push('');
    lines.push('> Scanned locally in your browser. No file was uploaded and no network request was made.');
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
    for (const severity of severities) {
      const list = grouped[severity] || [];
      if (!list.length) continue;
      lines.push(
        `### ${SEVERITY_ICON[severity]} ${severity.charAt(0) + severity.slice(1).toLowerCase()} (${list.length})`,
      );
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
        lines.push(`- ⚠️ **${check.title}** - ${S.lib.util.plural(check.findingCount, 'finding')}`);
        const skipNote = (report.notes || []).find((n) => n.checkId === check.id && n.kind === 'skip');
        if (skipNote) {
          lines.push(`  - Part of this check could not run - ${skipNote.title}: ${skipNote.detail}`);
        }
      }
      lines.push('');
    }

    // ----------------------------------------------- what this does NOT check
    lines.push('## What this does NOT check');
    lines.push('');
    lines.push(
      'This scan ran entirely in your browser, on the files you selected. That makes it fast, private and free - ' +
        'but it also means it stops where your folder stops. Here is exactly what it did not look at:',
    );
    lines.push('');
    for (const item of NOT_CHECKED) {
      lines.push(`- **${item.title}.** ${item.detail}`);
    }
    lines.push('');
    lines.push(
      'The full commercial review goes further: it reads the git history, runs a dependency vulnerability audit, ' +
        'audits every API route for missing authorisation, and - with your written permission - makes a small ' +
        'number of read-only requests against your live site to check the security headers your server really sends.',
    );
    lines.push('');

    // ------------------------------------------------------- methodology
    lines.push('---');
    lines.push('');
    lines.push('## Methodology, scope and limits');
    lines.push('');
    lines.push('**What we did**');
    lines.push('');
    lines.push(
      `- Read ${S.lib.util.plural(report.fileCount, 'file')} from the folder you pointed us at, in your browser. ` +
        'Nothing was uploaded: the files were read with the browser File API and analysed locally.',
    );
    lines.push(
      '- Looked for hard-coded credentials (live payment keys, database admin keys, service-role tokens, private ' +
        'keys, webhook URLs), unsafe .env handling, Postgres tables without Row Level Security, permissive ' +
        'database policies, unsafe functions, weak token verification, wildcard CORS and leftover debug routes.',
    );
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
      'Keep the output private: the report names the files and functions that need fixing, which tells an attacker ' +
        'exactly where to look. And treat any secret we found as compromised - deleting it from the code does not ' +
        'invalidate it, only rotating it in the provider\'s dashboard does.',
    );
    lines.push('');

    return lines.join('\n');
  }

  /** Short one-line summary used by the UI header. */
  function renderConsoleSummary(report) {
    const icon = VERDICT_ICON[report.verdict] || '';
    const c = report.counts;
    return (
      `${icon} ${report.verdict} - ${report.score}/100  ` +
      `(${c.CRITICAL} critical, ${c.HIGH} high, ${c.MEDIUM} medium, ${c.LOW} low)`
    );
  }

  S.lib.report = {
    SEVERITY_ICON,
    VERDICT_ICON,
    NOT_CHECKED,
    buildPlainSummary,
    listToSentence,
    stripSentenceEnd,
    asSentence,
    buildTopFive,
    groupBySeverity,
    renderMarkdown,
    renderConsoleSummary,
  };
})(globalThis);
