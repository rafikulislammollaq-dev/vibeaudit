/**
 * checks/secrets.core.js
 * ---------------------------------------------------------------------------
 * CHECK 1 - hard-coded secrets in any file of the project.
 *
 * PORTED from the CLI's `checks/secrets-source.js` and `checks/secrets-bundle.js`,
 * merged into one check because the browser reads the source tree and the
 * build output in the same pass.
 *
 * WHY THIS MATTERS: secret leakage is the most common critical issue in
 * AI-built apps. AI assistants happily paste a real-looking key into a file,
 * and then it ends up in the repository and in the bundle every visitor
 * downloads.
 *
 * TWO ABSOLUTE RULES:
 *   1. A raw secret is never put into a finding, into the DOM, or into the
 *      Markdown report. Only a short prefix and the length are shown.
 *   2. The Supabase anon key is public BY DESIGN (it ships in every browser
 *      bundle), so it is reported as INFO only and never costs points.
 */

(function (root) {
  'use strict';

  const S = (root.SCANNER = root.SCANNER || {});
  S.checks = S.checks || {};

  const id = 'secrets';
  const title = 'Hard-coded secrets (API keys, tokens, private keys)';
  const severity = 'CRITICAL';

  /**
   * Direct string probes for build output.
   *
   * WHY not just the generic secret patterns: minified bundles rewrite string
   * concatenation, so `"service_" + "role"` or `sk_live_${x}` can hide from a
   * regex. Searching for the literal fragments catches the common variants.
   */
  const BUNDLE_PROBES = [
    {
      id: 'service-role-literal',
      title: 'Supabase service_role key in the client bundle',
      severity: 'CRITICAL',
      needles: ['service_role', 'serviceRole', 'service-role'],
      why:
        'The service_role key is a full bypass of Row Level Security. It must never reach the browser - anyone who ' +
        'downloads the bundle can read and write every table in your database.',
      cwe: 'CWE-798',
    },
    {
      id: 'stripe-live-literal',
      title: 'Stripe live secret key in the client bundle',
      severity: 'CRITICAL',
      needles: ['sk_live_'],
      why: 'A live Stripe secret key in the browser lets anyone charge or refund real payments.',
      cwe: 'CWE-798',
    },
    {
      id: 'private-key-literal',
      title: 'Private key material in the client bundle',
      severity: 'CRITICAL',
      needles: ['-----BEGIN', 'PRIVATE KEY-----'],
      why: 'Private key material in a browser bundle lets anyone impersonate you.',
      cwe: 'CWE-798',
    },
    {
      id: 'aws-key-literal',
      title: 'AWS access key ID in the client bundle',
      severity: 'HIGH',
      needles: ['AKIA'],
      why: 'AWS credentials in the browser are world-readable.',
      cwe: 'CWE-798',
    },
  ];

  function run(context) {
    const findings = [];
    const scannedFiles = [];
    const { makeFinding, makePass } = S.lib.findings;
    const { scanText, classifyJwt } = S.lib.secrets;
    const { redactedLine, evidenceBlock, lineNumber } = S.lib.evidence;

    for (const file of context.files) {
      if (!file.content) continue;
      const isBundle = file.category === 'bundle';
      scannedFiles.push(file.relPath);

      // ------------------------------------------- catalogue + JWT patterns
      const hits = scanText(file.content, {
        includeGeneric: file.category === 'source' || file.category === 'config' || file.category === 'env',
      });

      for (const hit of hits) {
        // The Supabase anon key is PUBLIC BY DESIGN (it ships in every
        // browser bundle). Reporting it as a leak would be wrong and would
        // train the client to ignore the report, so it is INFO only.
        const isAnonKey = hit.jwtKind === 'supabase-anon';
        const line = lineNumber(file.content, hit.index);
        const snippet = redactedLine(file.content, hit.index, hit.match, hit.redacted);

        findings.push(
          makeFinding({
            severity: isAnonKey ? 'INFO' : hit.severity,
            title: `${hit.title} found in ${file.relPath}`,
            detail: isAnonKey
              ? 'This is the Supabase "anon" key, which is designed to be public - it ships in every browser bundle. ' +
                'It is listed here for completeness and does not cost any points. The "service_role" key is the one ' +
                'that must never leave the server.'
              : `${hit.why} The value below is redacted - open the file on disk to see it.`,
            plain: isAnonKey
              ? 'This key is meant to be public, so it is not a problem. We are showing it so you know it was found.'
              : hit.severity === 'CRITICAL'
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

      // --------------------------------------------------- bundle literals
      if (isBundle) {
        for (const probe of BUNDLE_PROBES) {
          for (const needle of probe.needles) {
            let index = file.content.indexOf(needle);
            while (index !== -1) {
              // A bare mention of the word "service_role" is not proof that the
              // key is there - it could be a type name or a comment. Only report
              // it when a real JWT follows it, or when the literal is a key
              // prefix such as "sk_live_".
              const confirmed = confirmBundleHit(file.content, index, needle);
              if (!confirmed) {
                index = file.content.indexOf(needle, index + needle.length);
                continue;
              }
              const line = lineNumber(file.content, index);
              const snippet = redactedLine(file.content, index, confirmed.match, confirmed.redacted);
              findings.push(
                makeFinding({
                  severity: probe.severity,
                  title: `${probe.title} (${file.relPath})`,
                  detail: `${probe.why} Anyone can read this by opening your website and viewing the page source.`,
                  plain:
                    'A powerful secret key was baked into the website files that every visitor downloads. ' +
                    'Anyone who visits your site could take it and use it to get into your data.',
                  location: `${file.relPath}:${line}`,
                  remediation:
                    'Move the secret to the server side. In Vite, only variables prefixed with VITE_ are exposed to the ' +
                    'browser, so rename your service-role variable to SUPABASE_SERVICE_ROLE_KEY (no prefix) and read it ' +
                    'in a server route / edge function. In Next.js, only NEXT_PUBLIC_ variables are exposed, so use ' +
                    'SUPABASE_SERVICE_ROLE_KEY for anything secret. Then rebuild and delete the old build folder so the ' +
                    'old bundle cannot be served from a cache.',
                  evidence: evidenceBlock({
                    location: `${file.relPath}:${line}`,
                    snippet,
                  }),
                  cwe: probe.cwe,
                }),
              );
              index = file.content.indexOf(needle, index + needle.length);
            }
          }
        }
      }
    }

    if (!findings.length) {
      findings.push(
        makePass(
          'No hard-coded secrets found',
          `Scanned ${scannedFiles.length} file(s) against ${S.lib.secrets.SECRET_PATTERNS.length} credential ` +
            'patterns, plus JWTs and generic secret assignments.',
          scannedFiles.length ? '' : context.root,
        ),
      );
    }

    return findings;
  }

  /**
   * Confirm that a literal probe really is a credential and not, for example, a
   * TypeScript type name such as `ServiceRole`.
   */
  function confirmBundleHit(content, index, needle) {
    if (needle === 'sk_live_') {
      const match = content.slice(index).match(/sk_live_[0-9A-Za-z]{10,}/);
      if (!match) return null;
      return { match: match[0], redacted: `${match[0].slice(0, 8)}${'*'.repeat(16)}[REDACTED]` };
    }
    if (needle === 'AKIA') {
      const match = content.slice(index).match(/AKIA[0-9A-Z]{16}/);
      if (!match) return null;
      return { match: match[0], redacted: `AKIA****[REDACTED len=${match[0].length}]` };
    }
    if (needle === 'PRIVATE KEY-----' || needle === '-----BEGIN') {
      const match = content.slice(index).match(/-----BEGIN [A-Z ]*PRIVATE KEY-----/);
      if (!match) return null;
      return { match: match[0], redacted: '-----BEGIN PRIVATE KEY-----[REDACTED]' };
    }
    // service_role: require a real JWT immediately after it.
    const window = content.slice(index, index + 400);
    const jwt = window.match(/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/);
    if (!jwt) return null;
    const info = S.lib.secrets.classifyJwt(jwt[0]);
    if (info.kind !== 'supabase-service-role') return null;
    return {
      match: jwt[0],
      redacted: `eyJhbGciOi...${'*'.repeat(12)}[REDACTED len=${jwt[0].length}] role=service_role`,
    };
  }

  function status(context) {
    const codeFiles = context.files.filter((file) => file.content);
    if (!codeFiles.length) {
      return { state: 'skip', notes: ['No readable files were found, so no secrets could be looked for.'] };
    }
    return { state: 'unknown', notes: [] };
  }

  S.checks.secrets = { id, title, severity, run, status };
})(globalThis);
