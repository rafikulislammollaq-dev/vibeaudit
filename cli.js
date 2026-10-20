#!/usr/bin/env node
/**
 * audit/cli.js
 * ---------------------------------------------------------------------------
 * The command line entry point.
 *
 *   node audit/cli.js --target <dir> [--url https://app.example.com] [--out report.md] [--json]
 *   node audit/cli.js --demo
 *
 * The CLI is deliberately thin: it parses arguments, calls the runner and
 * renders the result. All of the interesting logic lives in lib/ and
 * checks/, which is what makes the tool testable and reusable.
 *
 * EXIT CODES
 *   0  the scan completed
 *   1  the scan could not run
 *   2  --fail-on-critical was passed and a critical finding exists
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

import { parseArgs, HELP_TEXT } from './lib/cli-args.js';
import { runAudit, validateTarget } from './lib/runner.js';
import { renderMarkdown, renderJson, renderConsoleSummary, buildPlainSummary } from './lib/report.js';
import { ensureFixture } from './fixtures/build-fixture.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIXTURE_DIR = path.join(HERE, 'fixtures', 'vulnerable-app');
const VERSION = '1.0.0';

/**
 * Resolve the output path.
 *
 * WHY the special case for "/tmp": the documented examples use POSIX paths.
 * On Windows "/tmp/report.md" would mean "C:\tmp\report.md", which usually
 * does not exist and cannot be created without admin rights. Mapping it to
 * the OS temp directory makes the documented command work everywhere.
 */
function resolveOutputPath(output) {
  const raw = String(output);
  if (process.platform === 'win32' && (raw === '/tmp' || raw.startsWith('/tmp/') || raw.startsWith('/tmp\\'))) {
    const rest = raw.slice('/tmp'.length).replace(/^[\\/]+/, '');
    return path.join(os.tmpdir(), rest);
  }
  return path.resolve(raw);
}

async function main() {
  const argv = process.argv.slice(2);
  const { options, errors } = parseArgs(argv);

  if (options.help) {
    console.log(HELP_TEXT.trim());
    return 0;
  }
  if (options.version) {
    console.log(`vibeaudit v${VERSION}`);
    return 0;
  }
  if (errors.length) {
    console.error('Could not start the scan:');
    for (const error of errors) console.error(`  - ${error}`);
    console.error('\nRun "node audit/cli.js --help" for usage.');
    return 1;
  }

  // ------------------------------------------------------ resolve the target
  let target = options.target;
  let targetLabel = options.target;
  if (options.demo) {
    // The demo fixture is generated at runtime (see fixtures/build-fixture.mjs)
    // so this repository can be published without credential-shaped strings in
    // it. Build it before scanning, or the demo has nothing to find.
    await ensureFixture();
    target = FIXTURE_DIR;
    targetLabel = path.relative(process.cwd(), FIXTURE_DIR) || FIXTURE_DIR;
  } else {
    target = path.resolve(target);
    targetLabel = path.relative(process.cwd(), target) || target;
  }

  const targetError = await validateTarget(target);
  if (targetError) {
    console.error(`Could not start the scan: ${targetError}`);
    return 1;
  }

  if (!options.quiet && !options.json) {
    console.log('Scanning ' + (options.demo ? 'the bundled demo project' : targetLabel) + ' ...\n');
  }

  let report;
  try {
    report = await runAudit({
      target,
      targetLabel,
      url: options.url,
      authorized: options.authorized,
      includeHistory: options.includeHistory,
      demo: options.demo,
    });
  } catch (error) {
    console.error('The scan failed unexpectedly:');
    console.error(String(error?.stack || error?.message || error));
    return 1;
  }

  const markdown = renderMarkdown(report);
  const json = renderJson(report);

  // ------------------------------------------------------------- output
  if (options.out) {
    const outputPath = resolveOutputPath(options.out);
    try {
      await fs.mkdir(path.dirname(outputPath), { recursive: true });
      await fs.writeFile(outputPath, options.json ? json : markdown, 'utf8');
      if (!options.quiet) {
        console.log(`Report written to ${outputPath}`);
        console.log(renderConsoleSummary(report));
      }
    } catch (error) {
      console.error(`Could not write the report to ${outputPath}: ${error.message}`);
      return 1;
    }
  } else if (options.json) {
    console.log(json);
  } else if (options.quiet) {
    // Quiet mode: the headline and the plain-English summary only.
    console.log(renderConsoleSummary(report));
    console.log('');
    console.log(buildPlainSummary(report));
  } else {
    console.log(markdown);
  }

  if (options.failOnCritical && report.hasCritical) {
    console.error('\n--fail-on-critical: critical findings are present.');
    return 2;
  }

  return 0;
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error) => {
    console.error('Unexpected error:');
    console.error(String(error?.stack || error));
    process.exitCode = 1;
  });

// Exported for the test suite so it can assert on the summary text without
// spawning a process.
export { buildPlainSummary };
