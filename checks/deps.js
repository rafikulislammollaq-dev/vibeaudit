/**
 * checks/deps.js
 * ---------------------------------------------------------------------------
 * CHECK 10 - dependency risk.
 *
 * WHY THIS MATTERS: AI-generated apps lean on whatever package the assistant
 * reaches for first, and those packages are not always maintained. A vulnerable
 * dependency is a hole in your app that you did not write and cannot see.
 *
 * We do two things:
 *  1. Run `npm audit --json --omit=dev` (production dependencies only, so we
 *     do not drown the client in dev-tool noise) and map the results.
 *  2. Flag dependency NAMES that are known to be risky for AI-built apps,
 *     with a version check where the risk is version-specific.
 *
 * npm audit needs network access. When it cannot run we say so explicitly -
 * a check that silently passes because the network was down would be worse
 * than no check at all.
 */

import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { makeFinding, makePass, makeSkip } from '../lib/findings.js';

export const id = 'deps';
export const title = 'Third-party dependency risk';
export const severity = 'MEDIUM';

/** npm audit severity -> our severity. */
const NPM_SEVERITY_MAP = {
  critical: 'CRITICAL',
  high: 'HIGH',
  moderate: 'MEDIUM',
  low: 'LOW',
  info: 'INFO',
};

/**
 * Dependencies that are a bad fit for an AI-built app.
 *
 * `test` receives the installed version string and returns true when the
 * dependency is risky. Version strings are compared with a simple numeric
 * tuple comparison, which is enough for the cases below.
 */
export const KNOWN_RISKY_DEPENDENCIES = [
  {
    name: 'jsonwebtoken',
    maxExclusive: '9.0.0',
    severity: 'HIGH',
    note: 'Versions before 9.0.0 allow the "alg: none" bypass and other verification mistakes.',
    fix: 'Upgrade to jsonwebtoken@^9.0.0 and pass { algorithms: ["HS256"] } to verify().',
  },
  {
    name: 'jwt-decode',
    severity: 'MEDIUM',
    note:
      'jwt-decode only decodes tokens, it never verifies them. It is fine for reading a token, dangerous as the ' +
      'only thing you do with one.',
    fix: 'Use jsonwebtoken.verify() (or jose) for verification. Keep jwt-decode for display-only code.',
  },
  {
    name: 'lodash',
    maxExclusive: '4.17.21',
    severity: 'HIGH',
    note: 'Versions before 4.17.21 are vulnerable to prototype pollution.',
    fix: 'Upgrade to lodash@^4.17.21 or newer.',
  },
  {
    name: 'minimist',
    maxExclusive: '1.2.6',
    severity: 'HIGH',
    note: 'Older versions allow prototype pollution through command line arguments.',
    fix: 'Upgrade to minimist@^1.2.6 or newer.',
  },
  {
    name: 'axios',
    maxExclusive: '1.3.2',
    severity: 'MEDIUM',
    note: 'Older versions follow redirects to internal addresses, which can be used for server-side request forgery.',
    fix: 'Upgrade to axios@^1.3.2 or newer.',
  },
  {
    name: 'express',
    maxExclusive: '4.19.0',
    severity: 'MEDIUM',
    note: 'Older 4.x versions have open redirect and other request handling issues.',
    fix: 'Upgrade to express@^4.19.0 (or express@^5) and re-run the audit.',
  },
  {
    name: 'next',
    maxExclusive: '13.5.6',
    severity: 'HIGH',
    note: 'Older Next.js versions had cache poisoning and information disclosure issues.',
    fix: 'Upgrade to a currently supported Next.js release (14.x or newer).',
  },
  {
    name: 'node-fetch',
    maxExclusive: '2.6.7',
    severity: 'MEDIUM',
    note: 'Older node-fetch versions leak authorization headers on redirect.',
    fix: 'Upgrade to node-fetch@^2.6.7, or use the built-in fetch in Node 18+.',
  },
  {
    name: 'moment',
    severity: 'LOW',
    note: 'moment is unmaintained and ships a large legacy surface. Not a vulnerability, but not a good default.',
    fix: 'Consider replacing moment with date-fns or dayjs.',
  },
  {
    name: 'eval',
    severity: 'HIGH',
    note: 'The eval package (and eval-like helpers) run arbitrary code and are a common source of remote code execution.',
    fix: 'Remove the eval package and parse with JSON.parse() or a schema validator such as zod.',
  },
];

/** Compare two dotted version strings. Returns -1, 0 or 1. */
export function compareVersions(a, b) {
  const left = String(a || '0').split(/[.\-+]/).map((n) => parseInt(n, 10) || 0);
  const right = String(b || '0').split(/[.\-+]/).map((n) => parseInt(n, 10) || 0);
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i += 1) {
    const l = left[i] || 0;
    const r = right[i] || 0;
    if (l !== r) return l < r ? -1 : 1;
  }
  return 0;
}

/**
 * Work out how to run npm.
 *
 * WHY this is fiddly: on Windows `npm` is a .cmd shim, and modern Node
 * refuses to spawn a .cmd file directly (EINVAL) unless a shell is used. We
 * do not want a shell, so we look for npm's JavaScript entry point and run
 * it with the same node binary that is running this tool. That is both safer
 * and more portable.
 *
 * @returns {{command:string, prefixArgs:string[], shell:boolean}}
 */
export function resolveNpmCommand() {
  // 1. When we are ourselves running under npm, this points at npm-cli.js.
  const execPath = process.env.npm_execpath;
  if (execPath && /\.js$/i.test(execPath)) {
    return { command: process.execPath, prefixArgs: [execPath], shell: false };
  }

  // 2. A standard Node installation keeps npm next to the node binary.
  try {
    const candidate = path.join(
      path.dirname(process.execPath),
      'node_modules',
      'npm',
      'bin',
      'npm-cli.js',
    );
    if (existsSync(candidate)) {
      return { command: process.execPath, prefixArgs: [candidate], shell: false };
    }
  } catch {
    /* fall through to the shell path */
  }

  // 3. Last resort: the command on the PATH. On Windows that needs a shell
  //    because it is a .cmd shim.
  if (process.platform === 'win32') {
    return { command: 'npm.cmd', prefixArgs: [], shell: true };
  }
  return { command: 'npm', prefixArgs: [], shell: false };
}

/** Run npm audit and return the parsed JSON (or an error). */
function runNpmAudit(root, timeoutMs = 90_000) {
  const { command, prefixArgs, shell } = resolveNpmCommand();
  return new Promise((resolve) => {
    execFile(
      command,
      [...prefixArgs, 'audit', '--json', '--omit=dev'],
      {
        cwd: root,
        timeout: timeoutMs,
        windowsHide: true,
        maxBuffer: 32 * 1024 * 1024,
        encoding: 'utf8',
        shell,
      },
      (error, stdout, stderr) => {
        const text = String(stdout || '').trim();
        if (!text) {
          resolve({ ok: false, error: cleanNpmError(stderr, error) });
          return;
        }
        let parsed;
        try {
          parsed = JSON.parse(text);
        } catch (parseError) {
          resolve({ ok: false, error: `Could not parse npm audit output: ${parseError.message}` });
          return;
        }
        // IMPORTANT: npm reports its own failures as JSON with an "error"
        // key and a zero-length "vulnerabilities" object. Treating that as
        // "no vulnerabilities found" would be a silent false PASS, which is
        // exactly the kind of lie this tool must never tell.
        if (parsed && parsed.error) {
          const summary = parsed.error.summary || parsed.error.code || 'npm audit failed';
          resolve({ ok: false, error: String(summary).split('\n')[0] });
          return;
        }
        resolve({ ok: true, report: parsed });
      },
    );
  });
}

/** Turn an execFile failure into a short, readable reason. */
function cleanNpmError(stderr, error) {
  const raw = String(stderr || '').trim();
  if (raw) return raw.split('\n').slice(0, 3).join(' ').trim();
  const message = String(error?.message || '').trim();
  // Node prefixes the failure with "Command failed: <the whole command>",
  // which is noise for a client. Keep the part after it.
  const withoutCommand = message.replace(/^Command failed:[^\n]*\n?/, '');
  return (withoutCommand || message || 'npm audit could not be run').split('\n').slice(0, 3).join(' ').trim();
}

export async function run(context) {
  const findings = [];

  const packageJsonFile = context.files.find(
    (file) => file.relPath === 'package.json' && file.category === 'config',
  );
  if (!packageJsonFile || !packageJsonFile.content) {
    findings.push(
      makeSkip(
        'No package.json found',
        'Dependency checking needs a package.json. This project does not use npm, so there is nothing to audit.',
        context.root,
      ),
    );
    return findings;
  }

  let manifest = null;
  try {
    manifest = JSON.parse(packageJsonFile.content);
  } catch {
    findings.push(
      makeFinding({
        severity: 'LOW',
        title: 'package.json could not be parsed',
        detail: 'The file exists but is not valid JSON, so we could not list the dependencies.',
        plain: 'The list of libraries your app uses could not be read.',
        location: 'package.json',
        remediation: 'Fix the JSON syntax in package.json (a trailing comma is the usual cause).',
        evidence: 'JSON parse error while reading package.json.',
      }),
    );
  }

  const dependencies = { ...(manifest?.dependencies || {}), ...(manifest?.devDependencies || {}) };
  const productionDependencies = manifest?.dependencies || {};

  // --------------------------------------- known-risky dependency names
  const alreadyReported = new Set();
  for (const risky of KNOWN_RISKY_DEPENDENCIES) {
    const version = dependencies[risky.name];
    if (!version) continue;
    const isDevOnly = !productionDependencies[risky.name];
    let triggered = true;
    if (risky.maxExclusive) {
      const cleaned = String(version).replace(/^[\^~>=<\s]*/, '');
      triggered = compareVersions(cleaned, risky.maxExclusive) < 0;
    }
    if (!triggered) continue;
    alreadyReported.add(risky.name);

    findings.push(
      makeFinding({
        severity: isDevOnly ? 'LOW' : risky.severity,
        title: `Risky dependency "${risky.name}@${version}"${isDevOnly ? ' (development only)' : ''}`,
        detail:
          `${risky.note}${isDevOnly ? ' This package is only used while developing, so the risk to your live site ' +
            'is much smaller - but it can still compromise a developer machine.' : ''}`,
        plain:
          'Your app uses a library that has a known weakness or is a well-known bad default for projects built by ' +
          'AI tools.',
        location: 'package.json',
        remediation:
          `${risky.fix}\n\nAfter changing it, run "npm install" and re-run this audit so we can confirm the new ` +
          'version is clean.',
        evidence: `"${risky.name}": "${version}" in package.json`,
        cwe: 'CWE-1104',
      }),
    );
  }

  // -------------------------------------------------- npm audit results
  const hasLockfile = context.files.some((file) =>
    ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb'].includes(file.name),
  );

  if (!hasLockfile) {
    // npm audit cannot work without a lockfile, so we do not waste time
    // trying - and we say plainly that the check did not run.
    findings.push(
      makeSkip(
        'npm audit could not be run (no lockfile)',
        'npm audit compares the exact versions in your lockfile against the npm security database, and this ' +
          'project has no lockfile, so there was nothing to check. The list of known-risky package names above ' +
          'was still checked.',
        'package.json',
      ),
    );
  } else {
    const audit = await runNpmAudit(context.root);

    if (!audit.ok) {
      findings.push(
        makeSkip(
          'npm audit could not be run',
          `We could not run "npm audit" in this folder (${audit.error}). This check needs network access to the ` +
            'npm registry. The list of known-risky package names above was still checked.',
          'package.json',
        ),
      );
    } else {
      const report = audit.report || {};
      const vulnerabilities = report.vulnerabilities || {};
      const names = Object.keys(vulnerabilities);
      let critical = 0;
      let high = 0;
      let medium = 0;
      let low = 0;

      for (const name of names) {
        // The curated list above already explained this package in more
        // detail (it knows the exact version that is unsafe), so we do not
        // report it twice and inflate the score.
        if (alreadyReported.has(name)) continue;
        const entry = vulnerabilities[name] || {};
        const severity = NPM_SEVERITY_MAP[String(entry.severity || '').toLowerCase()] || 'MEDIUM';
        if (severity === 'CRITICAL') critical += 1;
        else if (severity === 'HIGH') high += 1;
        else if (severity === 'MEDIUM') medium += 1;
        else if (severity === 'LOW') low += 1;

        const via = (entry.via || [])
          .map((v) => (typeof v === 'string' ? v : `${v.title} (${v.url || ''})`))
          .filter(Boolean)
          .slice(0, 3)
          .join('\n');
        const range = entry.range ? `Affected versions: ${entry.range}` : '';
        const fixAvailable = entry.fixAvailable
          ? `Fix available: ${typeof entry.fixAvailable === 'object' ? `upgrade to ${entry.fixAvailable.name}@${entry.fixAvailable.version}` : entry.fixAvailable}`
          : 'No automatic fix published yet.';

        findings.push(
          makeFinding({
            severity,
            title: `Vulnerable dependency "${name}" (${severity.toLowerCase()})`,
            detail:
              'The npm security database reports a known vulnerability in a package this project depends on. ' +
              'AI-generated projects often pull in libraries without checking their maintenance status.',
            plain:
              severity === 'CRITICAL' || severity === 'HIGH'
                ? 'One of the libraries your app uses has a known, published weakness that attackers actively use.'
                : 'One of the libraries your app uses has a known, published weakness.',
            location: 'package.json',
            remediation:
              `Upgrade the package:\n\n    npm install ${name}@latest\n\n` +
              `Then re-run "npm install" and this audit.\n\n${range}\n${fixAvailable}`,
            evidence: `${via || 'Advisory details were not included in the npm output.'}`,
            cwe: 'CWE-1104',
          }),
        );
      }

      if (!names.length) {
        findings.push(
          makePass(
            'npm audit found no known vulnerabilities in production dependencies',
            `We ran "npm audit --omit=dev" against ${Object.keys(productionDependencies).length} production dependency/dependencies.`,
            'package.json',
          ),
        );
      }
    }
  }

  if (!hasLockfile) {
    findings.push(
      makeFinding({
        severity: 'LOW',
        title: 'No lockfile found',
        detail:
          'Without a lockfile (package-lock.json / yarn.lock / pnpm-lock.yaml) there is no fixed list of the exact ' +
          'versions you ship, so a build tomorrow can install different - possibly vulnerable - code than today.',
        plain:
          'Your project does not record the exact versions of its libraries, so every build can quietly change what ' +
          'is installed.',
        location: 'package.json',
        remediation: 'Run "npm install" and commit the generated package-lock.json to the repository.',
        evidence: 'No package-lock.json, yarn.lock or pnpm-lock.yaml was found in the target folder.',
        cwe: 'CWE-1104',
      }),
    );
  }

  return findings;
}

export function status(context) {
  if (!context.files.some((file) => file.relPath === 'package.json')) {
    return { state: 'skip', notes: ['No package.json - this project does not use npm.'] };
  }
  return { state: 'unknown', notes: [] };
}
