/**
 * checks/secrets-bundle.js
 * ---------------------------------------------------------------------------
 * CHECK 7 - secrets shipped in the built client bundle.
 *
 * WHY THIS MATTERS: this is the single most common way a Supabase app gets
 * "hacked" without anyone touching the server. The `service_role` key is
 * supposed to be server-only, but AI assistants routinely import it from
 * `import.meta.env` inside a React component. Vite and Next.js then inline
 * it into the JavaScript bundle that every visitor downloads, where anyone
 * can read it with "view source".
 *
 * We scan build output (dist/, build/, .next/, out/, public/) for:
 *  - the Supabase service_role key
 *  - live Stripe secret keys
 *  - private key headers
 *  - AWS access key IDs
 *  - source maps (which publish your original source code)
 */

import { makeFinding, makePass, makeSkip } from '../lib/findings.js';
import { scanText, classifyJwt } from '../lib/secrets.js';
import { redactedLine, evidenceBlock, lineNumber } from '../lib/evidence.js';

export const id = 'secrets-bundle';
export const title = 'Secrets shipped inside the built client bundle';
export const severity = 'CRITICAL';

/**
 * Direct string probes.
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

export function run(context) {
  const findings = [];
  const bundleFiles = context.files.filter((file) => file.category === 'bundle' && file.content !== null);

  if (!bundleFiles.length) {
    findings.push(
      makeSkip(
        'No built client bundle found',
        'We looked for dist/, build/, .next/, out/ and public/build/. None of them exist in the target folder, ' +
          'so we could not check whether secrets ship to the browser. Build the project (npm run build) and run the ' +
          'audit again to include this check.',
        context.root,
      ),
    );
    return findings;
  }

  let hits = 0;

  for (const file of bundleFiles) {
    const content = file.content;

    // 1. Direct literal probes.
    for (const probe of BUNDLE_PROBES) {
      for (const needle of probe.needles) {
        let index = content.indexOf(needle);
        while (index !== -1) {
          // A bare mention of the word "service_role" is not proof that the
          // key is there - it could be a type name or a comment. Only report
          // it when a real JWT follows it, or when the literal is a key
          // prefix such as "sk_live_".
          const confirmed = confirmBundleHit(content, index, needle);
          if (!confirmed) {
            index = content.indexOf(needle, index + needle.length);
            continue;
          }
          hits += 1;
          const line = lineNumber(content, index);
          const snippet = redactedLine(content, index, confirmed.match, confirmed.redacted);
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
          index = content.indexOf(needle, index + needle.length);
        }
      }
    }

    // 2. Full secret pattern scan (catches AWS keys, private keys, JWTs).
    const matches = scanText(content);
    for (const match of matches) {
      if (match.jwtKind === 'supabase-anon') continue;
      if (match.severity === 'INFO') continue;
      hits += 1;
      const line = lineNumber(content, match.index);
      const snippet = redactedLine(content, match.index, match.match, match.redacted);
      findings.push(
        makeFinding({
          severity: match.severity,
          title: `${match.title} in the built bundle (${file.relPath})`,
          detail: match.why,
          plain: 'A secret password was baked into the website files that every visitor downloads.',
          location: `${file.relPath}:${line}`,
          remediation:
            'Remove the secret from the client build. Keep it on the server, rebuild the app, and delete the old ' +
            'build folder (and any CDN cache) so the leaked copy cannot be served.',
          evidence: evidenceBlock({ location: `${file.relPath}:${line}`, snippet }),
          cwe: 'CWE-798',
        }),
      );
    }

    // NOTE: source maps are reported by the "debug routes" check, which
    // covers both the .map files themselves and the sourceMappingURL
    // comments that point at them. Reporting them twice would be noise.
  }

  if (!hits) {
    findings.push(
      makePass(
        'No secrets found in the built client bundle',
        `Scanned ${bundleFiles.length} built file(s) for service-role keys, live payment keys, private keys and ` +
          'AWS credentials.',
        bundleFiles.map((f) => f.relPath).slice(0, 5).join(', '),
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
  const info = classifyJwt(jwt[0]);
  if (info.kind !== 'supabase-service-role') return null;
  return {
    match: jwt[0],
    redacted: `eyJhbGciOi...${'*'.repeat(12)}[REDACTED len=${jwt[0].length}] role=service_role`,
  };
}

/** Status helper for the report. */
export function status(context) {
  const bundleFiles = context.files.filter((file) => file.category === 'bundle');
  if (!bundleFiles.length) {
    return {
      state: 'skip',
      notes: ['No build output (dist/, build/, .next/, out/) was found in the target folder.'],
    };
  }
  return { state: 'unknown', notes: [] };
}
