/**
 * checks/env-committed.js
 * ---------------------------------------------------------------------------
 * CHECK 1 - environment files committed to version control.
 *
 * WHY THIS MATTERS: a study of 400 public repositories built with Lovable,
 * Bolt and v0 found 18.5% had a committed .env file. A committed .env is
 * the single most common way an AI-built app ends up with a leaked database
 * admin key, because the AI assistant writes the .env for you and then
 * `git add .` swallows it.
 *
 * We look at three signals, in order of confidence:
 *   1. git tracks the file           -> definite breach (HIGH)
 *   2. the file exists and git does NOT ignore it -> about to be committed
 *   3. the file exists and IS git ignored -> normal local practice (INFO)
 */

import { makeFinding, makePass } from '../lib/findings.js';

export const id = 'env-committed';
export const title = 'Environment files (.env) committed to version control';
export const severity = 'HIGH';

/** `.env.example` and friends are templates, not live configuration. */
export function isEnvExample(name) {
  return /\.(example|sample|template|dist|defaults)$/i.test(String(name || ''));
}

/** Does the .gitignore mention .env at all? */
function gitignoreCoversEnv(content) {
  const lines = String(content || '')
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
  return lines.some((line) => {
    const negated = line.startsWith('!');
    const pattern = negated ? line.slice(1) : line;
    if (!/^\.env/i.test(pattern.replace(/^\//, ''))) return false;
    // `!.env.example` alone does NOT protect `.env` - only a real `.env`
    // rule (or a broad `*.env` / `.env*` rule) does.
    if (negated) return false;
    return /^\.env\*?$|^\.env\*/.test(pattern.replace(/^\//, '')) || pattern.replace(/^\//, '') === '.env';
  });
}

export function run(context) {
  const findings = [];
  const envFiles = context.files.filter((file) => file.category === 'env');

  const live = envFiles.filter((file) => !isEnvExample(file.name));
  const examples = envFiles.filter((file) => isEnvExample(file.name));

  for (const file of live) {
    const tracked = context.git.tracked ? context.git.tracked.has(file.relPath) : false;

    if (tracked) {
      findings.push(
        makeFinding({
          severity: 'HIGH',
          title: `Environment file is committed to git: ${file.relPath}`,
          detail:
            'This file holds the real secrets for your app (database admin key, payment keys, API tokens). ' +
            'Because it is committed, the keys are in your git history, on your hosting provider, and in every ' +
            'clone of the repo - including any public backup of it.',
          plain:
            'Your app\'s secret passwords are stored in a file that is published to your code repository, so anyone ' +
            'with access to the repo can use them.',
          location: file.relPath,
          remediation:
            'Remove the file from git tracking (git rm --cached .env), add ".env" to .gitignore, create a ' +
            '.env.example file that contains only the variable NAMES with blank values, and rotate every secret ' +
            'that was in the file. Rotating is essential - removing the file does not remove it from history.',
          evidence:
            'This file is tracked by git (confirmed with "git ls-files").\n' +
            'Anyone who clones the repository receives the live secret values.',
          cwe: 'CWE-798',
        }),
      );
    } else if (file.gitignored) {
      findings.push(
        makePass(
          `Local environment file present and correctly ignored: ${file.relPath}`,
          'This file exists on disk but .gitignore excludes it, so it will not be published. This is the correct setup.',
          file.relPath,
        ),
      );
    } else {
      findings.push(
        makeFinding({
          severity: 'HIGH',
          title: `Environment file is not ignored by git: ${file.relPath}`,
          detail:
            'The file exists and your .gitignore does not exclude it. The next person (or the next AI assistant) who ' +
            'runs "git add ." will commit your live secrets.',
          plain:
            'Your app\'s secret passwords are stored in a file that is not protected from being published to your ' +
            'code repository.',
          location: file.relPath,
          remediation:
            'Add the file name to .gitignore (for example ".env", ".env.local" and ".env.*" with an exception for ' +
            '".env.example"), then run "git rm --cached <file>" if it was already committed.',
          evidence: `${file.relPath} exists and is NOT matched by any .gitignore rule.`,
          cwe: 'CWE-798',
        }),
      );
    }
  }

  // A .gitignore that never mentions .env is the root cause behind most
  // committed-environment-file findings, so call it out separately.
  const gitignoreFile = context.files.find((file) => file.name === '.gitignore' && file.relPath === '.gitignore');
  if (gitignoreFile && !gitignoreCoversEnv(gitignoreFile.content)) {
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
        evidence: gitignoreFile.content
          ? gitignoreFile.content.split('\n').slice(0, 30).join('\n')
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

  return findings;
}

/** Status used by the "checks that passed" / "checks skipped" sections. */
export function status(context) {
  if (!context.git.available) {
    return {
      state: 'skip',
      notes: [
        'No .git directory was found, so we could not confirm whether any .env file is committed to version control.',
        'We still checked for .env files on disk and whether .gitignore excludes them.',
      ],
    };
  }
  return { state: 'unknown', notes: [] };
}
