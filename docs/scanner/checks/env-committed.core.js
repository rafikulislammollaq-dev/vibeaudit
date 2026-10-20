/**
 * checks/env-committed.core.js
 * ---------------------------------------------------------------------------
 * CHECK 2 - environment files (.env) and whether .gitignore protects them.
 *
 * PORTED from the CLI's `checks/env-committed.js`.
 *
 * WHY THIS MATTERS: a study of 400 public repositories built with Lovable,
 * Bolt and v0 found 18.5% had a committed .env file. A committed .env is
 * the single most common way an AI-built app ends up with a leaked database
 * admin key, because the AI assistant writes the .env for you and then
 * `git add .` swallows it.
 *
 * WHAT IS DIFFERENT IN THE BROWSER: a browser cannot see git, so we cannot
 * tell you whether the file is ALREADY committed - only whether your
 * .gitignore rules would commit it next time somebody runs "git add .".
 * The report says so explicitly rather than pretending otherwise.
 */

(function (root) {
  'use strict';

  const S = (root.SCANNER = root.SCANNER || {});
  S.checks = S.checks || {};

  const id = 'env-committed';
  const title = 'Environment files (.env) and .gitignore protection';
  const severity = 'HIGH';

  /** `.env.example` and friends are templates, not live configuration. */
  function isEnvExample(name) {
    return /\.(example|sample|template|dist|defaults)$/i.test(String(name || ''));
  }

  /**
   * Does the .gitignore mention .env at all?
   *
   * PORTED from the CLI. `!.env.example` alone does NOT protect `.env` -
   * only a real `.env` rule (or a broad `*.env` / `.env*` rule) does.
   */
  function gitignoreCoversEnv(content) {
    const lines = String(content || '')
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#'));
    return lines.some((line) => {
      const negated = line.startsWith('!');
      const pattern = negated ? line.slice(1) : line;
      const cleaned = pattern.replace(/^\//, '');
      if (!/^\.env/i.test(cleaned)) return false;
      if (negated) return false;
      return /^\.env\*?$|^\.env\*/.test(cleaned) || cleaned === '.env';
    });
  }

  function run(context) {
    const findings = [];
    const { makeFinding, makePass } = S.lib.findings;

    const envFiles = context.files.filter((file) => file.category === 'env');
    const live = envFiles.filter((file) => !isEnvExample(file.name));
    const examples = envFiles.filter((file) => isEnvExample(file.name));

    const gitignoreFile = context.files.find(
      (file) => file.name === '.gitignore' && !file.relPath.includes('/'),
    );
    const gitignoreContent = gitignoreFile ? gitignoreFile.content || '' : null;
    const covered = gitignoreContent !== null ? gitignoreCoversEnv(gitignoreContent) : null;

    for (const file of live) {
      if (covered) {
        findings.push(
          makePass(
            `Local environment file present and correctly ignored: ${file.relPath}`,
            'This file exists on disk and your .gitignore excludes it, so it will not be published. This is the ' +
              'correct setup.',
            file.relPath,
          ),
        );
        continue;
      }

      findings.push(
        makeFinding({
          severity: 'HIGH',
          title: `Environment file is not ignored by git: ${file.relPath}`,
          detail:
            'The file exists and your .gitignore does not exclude it. The next person (or the next AI assistant) ' +
            'who runs "git add ." will commit your live secrets. A browser cannot check your git history, so we ' +
            'cannot tell you whether it has already been committed - check that yourself.',
          plain:
            'Your app\'s secret passwords are stored in a file that is not protected from being published to your ' +
            'code repository.',
          location: file.relPath,
          remediation:
            'Add the file name to .gitignore (for example ".env", ".env.local" and ".env.*" with an exception for ' +
            '".env.example"), then run "git rm --cached <file>" if it was already committed, and rotate every secret ' +
            'inside the file - removing the file from the repository does not invalidate the keys.',
          evidence: `${file.relPath} exists and is NOT matched by any .gitignore rule.`,
          cwe: 'CWE-798',
        }),
      );
    }

    // A .gitignore that never mentions .env is the root cause behind most
    // committed-environment-file findings, so call it out separately.
    if (gitignoreFile && !covered) {
      findings.push(
        makeFinding({
          severity: 'MEDIUM',
          title: '.gitignore does not exclude .env files',
          detail:
            'Your .gitignore file has no rule for .env files. This is the single most common reason AI-built apps ' +
            'publish their secrets.',
          plain:
            'Your project is not set up to keep its secret passwords out of the code repository, so they can be ' +
            'published by accident.',
          location: '.gitignore',
          remediation:
            'Add these lines to .gitignore:\n\n' +
            '    # Environment files - never commit these\n' +
            '    .env\n' +
            '    .env.local\n' +
            '    .env.*\n' +
            '    !.env.example\n',
          evidence: gitignoreContent
            ? gitignoreContent.split('\n').slice(0, 30).join('\n')
            : '(the .gitignore file is empty or unreadable)',
          cwe: 'CWE-538',
        }),
      );
    }

    if (examples.length && !live.length) {
      findings.push(
        makePass(
          'Environment configuration is templated, not committed',
          `Found ${examples.length} .env.example template file(s) and no live .env file.`,
          examples.map((f) => f.relPath).join(', '),
        ),
      );
    }

    if (!findings.length) {
      findings.push(
        makePass(
          'No environment files found',
          'We looked for .env, .env.local and other .env* files and did not find any.',
          '',
        ),
      );
    }

    return findings;
  }

  function status(context) {
    return {
      state: 'unknown',
      notes: [
        'A browser cannot read your git history, so we could not confirm whether an environment file is already ' +
          'committed. We checked for .env files on disk and whether .gitignore excludes them.',
      ],
    };
  }

  S.checks.envCommitted = {
    id,
    title,
    severity,
    run,
    status,
    isEnvExample,
    gitignoreCoversEnv,
  };
})(globalThis);
