/**
 * checks/cors.core.js
 * ---------------------------------------------------------------------------
 * CHECK 5 - CORS misconfiguration.
 *
 * PORTED from the CLI's `checks/cors.js`.
 *
 * WHY THIS MATTERS: CORS is the browser's rule about which other websites may
 * talk to your API. The dangerous combination is a wildcard origin (`*`)
 * together with credentials (`Access-Control-Allow-Credentials: true`). It
 * means "any website on the internet may call my API using the visitor's
 * session". A reflected origin (echoing back whatever `Origin` header the
 * caller sent) is the same problem wearing a disguise.
 *
 * We detect:
 *  - Access-Control-Allow-Origin: * together with credentials
 *  - a reflected Origin header
 *  - cors({ origin: '*' }) and cors({ origin: true })
 */

(function (root) {
  'use strict';

  const S = (root.SCANNER = root.SCANNER || {});
  S.checks = S.checks || {};

  const id = 'cors';
  const title = 'CORS (cross-origin) configuration';
  const severity = 'HIGH';

  function run(context) {
    const findings = [];
    const { makeFinding, makePass, makeSkip } = S.lib.findings;
    const { countLines } = S.lib.secrets;
    const { isCodeFile } = S.lib.files;

    const codeFiles = context.files.filter((file) => isCodeFile(file) && file.content);

    if (!codeFiles.length) {
      findings.push(
        makeSkip('No source code found', 'CORS is configured in code, and no code was found.', context.root),
      );
      return findings;
    }

    for (const file of codeFiles) {
      const content = file.content;

      // ----------------------------------------- wildcard + credentials
      //
      // The header can be set in several shapes:
      //   res.setHeader('Access-Control-Allow-Origin', '*')
      //   res.setHeader("Access-Control-Allow-Origin": "*")
      //   res.header('Access-Control-Allow-Origin', origin)
      // so the separator is a comma OR a colon.
      const allowOrigin = /['"`]Access-Control-Allow-Origin['"`]\s*[:=,]\s*([^;\n]{0,80})/gi;
      const allowCredentials = /['"`]Access-Control-Allow-Credentials['"`]\s*[:=,]\s*(true|['"`]true['"`])/gi;
      const credentialsMatch = content.match(allowCredentials);

      for (const match of content.matchAll(allowOrigin)) {
        const value = (match[1] || '').trim();
        const line = countLines(content, match.index);
        const isWildcard = /['"`]\*['"`]/.test(value) || value === '*';
        const isReflected = /req\.headers\s*[\[.](\s*['"`]?origin)/i.test(value) || /originHeader/i.test(value);
        // Whether this is a response header (as opposed to a request option) is
        // decided by the surrounding code, not by the value itself.
        const around = content.slice(Math.max(0, match.index - 60), match.index + 60);
        const isFunction = /\b(setHeader|header|append|writeHead)\s*\(|\bset\s*\(/i.test(around);

        if (isWildcard && credentialsMatch) {
          findings.push(
            makeFinding({
              severity: 'CRITICAL',
              title: `CORS allows any website AND credentials (${file.relPath})`,
              detail:
                'The response tells browsers that any origin may call this API and that the request may include ' +
                'cookies/authorisation headers. Any website your users visit can then make requests to your API as if ' +
                'they were signed in, and read the responses. This is the classic cross-site data theft bug.',
              plain:
                'Any website your visitors go to could secretly use your app as if they were signed in, and read their ' +
                'private information.',
              location: `${file.relPath}:${line}`,
              remediation:
                'Never combine a wildcard with credentials. Allow only the origins you control:\n\n' +
                '    const ALLOWED_ORIGINS = ["https://yourapp.com", "https://www.yourapp.com"];\n\n' +
                '    app.use(cors({\n' +
                '      origin: (origin, callback) => {\n' +
                '        if (!origin || ALLOWED_ORIGINS.includes(origin)) return callback(null, true);\n' +
                '        return callback(new Error("Origin not allowed"));\n' +
                '      },\n' +
                '      credentials: true,\n' +
                '    }));\n\n' +
                'Or use the cors package with an explicit list:\n\n' +
                '    app.use(cors({ origin: ALLOWED_ORIGINS, credentials: true }));\n\n' +
                'Remove the manual "Access-Control-Allow-Origin: *" line if you use the cors package.',
              evidence: context.window(content, match.index, 8),
              cwe: 'CWE-942',
            }),
          );
          continue;
        }

        if (isWildcard) {
          findings.push(
            makeFinding({
              severity: 'HIGH',
              title: `CORS allows requests from any website (${file.relPath})`,
              detail:
                'The API answers requests from any origin. If any endpoint returns private data without checking the ' +
                'session, a malicious page can read your users\' data. Without credentials the browser blocks cookies, ' +
                'but bearer tokens sent by a script are still readable.',
              plain:
                'Any website on the internet is allowed to ask your server for data, which is wider than it needs to be.',
              location: `${file.relPath}:${line}`,
              remediation:
                'List the origins you actually use:\n\n' +
                '    const ALLOWED_ORIGINS = ["https://yourapp.com"];\n' +
                '    res.setHeader("Access-Control-Allow-Origin", ALLOWED_ORIGINS.includes(origin) ? origin : false);\n\n' +
                'If the API is only called by your own app, restrict it to your app\'s origin.',
              evidence: context.window(content, match.index, 8),
              cwe: 'CWE-942',
            }),
          );
          continue;
        }

        if (isReflected && isFunction) {
          findings.push(
            makeFinding({
              severity: 'HIGH',
              title: `CORS reflects the caller's Origin header (${file.relPath})`,
              detail:
                'Whatever origin the caller sends is echoed back as allowed. That is the same as allowing every ' +
                'website, but it also hides the problem from a casual reader of the code.',
              plain: 'Your server allows whichever website asks, instead of only the ones you listed.',
              location: `${file.relPath}:${line}`,
              remediation:
                'Check the origin against a fixed allowlist before echoing it back:\n\n' +
                '    const ALLOWED_ORIGINS = ["https://yourapp.com"];\n' +
                '    const origin = req.headers.origin;\n' +
                '    res.setHeader("Access-Control-Allow-Origin",\n' +
                '      ALLOWED_ORIGINS.includes(origin) ? origin : "https://yourapp.com");\n\n' +
                'Never do `res.setHeader("Access-Control-Allow-Origin", req.headers.origin)` directly.',
              evidence: context.window(content, match.index, 8),
              cwe: 'CWE-942',
            }),
          );
        }
      }

      // ------------------------------------------- cors() package options
      const corsOptions = /cors\s*\(\s*\{([\s\S]{0,400}?)\}\s*\)/gi;
      for (const match of content.matchAll(corsOptions)) {
        const options = match[1] || '';
        const line = countLines(content, match.index);
        const wildcardOrigin = /origin\s*:\s*['"`]\*['"`]/.test(options);
        const originTrue = /origin\s*:\s*true\b/.test(options);
        const reflected = /origin\s*:\s*req\.headers\.origin|origin\s*:\s*\(\s*origin\s*,/.test(options);

        if (!wildcardOrigin && !originTrue && !reflected) continue;

        const isWildcard = wildcardOrigin || originTrue;
        findings.push(
          makeFinding({
            severity: isWildcard ? 'HIGH' : 'MEDIUM',
            title: `CORS is configured to allow every origin (${file.relPath})`,
            detail: wildcardOrigin
              ? 'cors() is configured with a wildcard origin. Every website can call this API from a browser.'
              : originTrue
                ? 'cors({ origin: true }) reflects whatever origin the caller sends, which allows every website.'
                : 'cors() is configured with a function that reflects the caller\'s origin, which allows every website.',
            plain:
              'Your server accepts requests from any website on the internet, which is wider than your app needs.',
            location: `${file.relPath}:${line}`,
            remediation:
              'Use an explicit list of the origins you trust:\n\n' +
              '    const ALLOWED_ORIGINS = ["https://yourapp.com", "https://www.yourapp.com"];\n' +
              '    app.use(cors({ origin: ALLOWED_ORIGINS, credentials: true }));\n\n' +
              'For a single origin you can write: app.use(cors({ origin: "https://yourapp.com" })).',
            evidence: context.window(content, match.index, 6),
            cwe: 'CWE-942',
          }),
        );
      }
    }

    if (!findings.length) {
      findings.push(
        makePass(
          'No dangerous CORS configuration found',
          `Reviewed ${codeFiles.length} code file(s) for wildcard origins, reflected origins and wildcard + credentials.`,
          codeFiles.length ? '' : context.root,
        ),
      );
    }

    return findings;
  }

  function status(context) {
    const codeFiles = context.files.filter((file) => file.category === 'source' && file.content);
    if (!codeFiles.length) {
      return { state: 'skip', notes: ['No source code was found, so CORS configuration could not be reviewed.'] };
    }
    return { state: 'unknown', notes: [] };
  }

  S.checks.cors = { id, title, severity, run, status };
})(globalThis);
