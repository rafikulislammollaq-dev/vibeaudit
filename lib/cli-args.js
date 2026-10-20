/**
 * lib/cli-args.js
 * ---------------------------------------------------------------------------
 * Command line parsing.
 *
 * WHY hand-rolled: the tool has zero runtime dependencies, and a dependency
 * just to parse five flags would be absurd. The parser is a pure function so
 * the tests can exercise it without spawning a process.
 */

/**
 * Parse argv into an options object.
 *
 * @param {string[]} argv arguments AFTER `node script.js`
 * @returns {{options:object, errors:string[], help:boolean, version:boolean}}
 */
export function parseArgs(argv = []) {
  const options = {
    target: null,
    url: null,
    out: null,
    json: false,
    demo: false,
    authorized: false,
    includeHistory: true,
    quiet: false,
    failOnCritical: false,
    help: false,
    version: false,
  };
  const errors = [];

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case '--target':
      case '-t':
        options.target = argv[i + 1] || null;
        i += 1;
        break;
      case '--url':
      case '-u':
        options.url = argv[i + 1] || null;
        i += 1;
        break;
      case '--out':
      case '-o':
        options.out = argv[i + 1] || null;
        i += 1;
        break;
      case '--json':
        options.json = true;
        break;
      case '--demo':
        options.demo = true;
        break;
      case '--i-have-authorization':
        options.authorized = true;
        break;
      case '--no-history':
        options.includeHistory = false;
        break;
      case '--quiet':
      case '-q':
        options.quiet = true;
        break;
      case '--fail-on-critical':
        options.failOnCritical = true;
        break;
      case '--help':
      case '-h':
        options.help = true;
        break;
      case '--version':
      case '-v':
        options.version = true;
        break;
      default:
        if (arg.startsWith('--')) {
          errors.push(`Unknown option: ${arg}`);
        } else if (arg.startsWith('-')) {
          errors.push(`Unknown option: ${arg}`);
        } else {
          // A bare path is treated as the target - a friendly shortcut.
          if (!options.target) options.target = arg;
          else errors.push(`Unexpected argument: ${arg}`);
        }
    }
  }

  if (options.url !== null && !options.url) errors.push('--url needs a value, for example --url https://yourapp.com');
  if (options.out !== null && !options.out) errors.push('--out needs a file name, for example --out report.md');
  if (options.target !== null && !options.target) errors.push('--target needs a folder, for example --target ./my-app');

  if (!options.help && !options.version && !options.demo && !options.target) {
    errors.push('Nothing to scan. Pass --target <folder> (or --demo to run against the bundled example).');
  }

  return { options, errors, help: options.help, version: options.version };
}

/** The --help text. Written for a non-technical founder, not a developer. */
export const HELP_TEXT = `
vibeaudit - security audit for AI-built apps
=============================================================================

Scans the folder of an app that was built with Lovable, Bolt, Cursor, Replit,
v0 or Supabase and tells you - in plain English - what to fix before you let
real users near it.

USAGE
  node audit/cli.js --target <folder> [options]
  node audit/cli.js --demo

OPTIONS
  -t, --target <folder>     The project folder to scan. This is the main thing.
  -u, --url <url>           The address of your live site (optional). Enables the
                            live checks for security headers and Supabase data access.
  -o, --out <file>          Write the Markdown report to this file.
                            Without it, the report is printed to the terminal.
      --json                Print the report as JSON instead of Markdown.
      --i-have-authorization
                            Required before any request is sent to --url.
                            Only pass this if you own the site or have written
                            permission to test it.
      --demo                Run against the bundled example project that
                            deliberately contains security problems.
      --no-history          Skip the git history scan (a little faster).
      --fail-on-critical    Exit with code 2 if a critical finding is found
                            (for use in CI).
  -q, --quiet               Only print the headline and the score.
  -h, --help                Show this help.
  -v, --version             Show the version.

EXAMPLES
  node audit/cli.js --demo
  node audit/cli.js --target ./my-lovable-app
  node audit/cli.js --target ./my-app --out report.md
  node audit/cli.js --target ./my-app --url https://myapp.com --i-have-authorization
  node audit/cli.js --target ./my-app --json > report.json

EXIT CODES
  0  the scan completed (findings are reported in the output, not in the code)
  1  the scan could not run (bad folder, unreadable file)
  2  --fail-on-critical was used and a critical finding exists
`;
