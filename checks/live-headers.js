/**
 * checks/live-headers.js
 * ---------------------------------------------------------------------------
 * CHECK 9 - security response headers on the live site.
 *
 * WHY THIS MATTERS: these headers are the browser's built-in protections.
 * They are cheap to add and missing them is the norm on AI-built apps,
 * because nobody asked the AI to add them:
 *
 *  - Strict-Transport-Security  : force HTTPS for 2 years
 *  - Content-Security-Policy     : stops injected scripts (XSS) from running
 *  - X-Content-Type-Options     : stops a file being re-interpreted as code
 *  - Referrer-Policy             : stops URLs (which can contain tokens)
 *                                  leaking to other sites
 *  - X-Frame-Options             : stops clickjacking (your app being
 *                                  embedded in a fake login box)
 *
 * This check sends ONE GET request to the URL the operator supplied. It does
 * not attempt authentication and does not follow anything but the normal
 * redirect chain.
 */

import { makeFinding, makePass, makeSkip } from '../lib/findings.js';
import { fetchSecurityHeaders } from '../lib/http.js';

export const id = 'live-headers';
export const title = 'Security headers on the live site';
export const severity = 'MEDIUM';

/** header name -> [human label, why it matters, what to set] */
export const SECURITY_HEADERS = [
  {
    name: 'strict-transport-security',
    label: 'Strict-Transport-Security (HSTS)',
    why: 'forces the browser to use HTTPS for two years, so a visitor can never be silently downgraded to http://',
    fix: 'Strict-Transport-Security: max-age=63072000; includeSubDomains',
  },
  {
    name: 'content-security-policy',
    label: 'Content-Security-Policy (CSP)',
    why: 'stops injected scripts and frames from running - the main defence against cross-site scripting',
    fix: "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://*.supabase.co; frame-ancestors 'none'",
  },
  {
    name: 'x-content-type-options',
    label: 'X-Content-Type-Options',
    why: 'stops the browser guessing that a file is something other than what the server said it is',
    fix: 'X-Content-Type-Options: nosniff',
  },
  {
    name: 'referrer-policy',
    label: 'Referrer-Policy',
    why: 'stops the full address of a page (which can contain a reset token) from leaking to other sites',
    fix: 'Referrer-Policy: strict-origin-when-cross-origin',
  },
  {
    name: 'x-frame-options',
    label: 'X-Frame-Options',
    why: 'stops your app being embedded in a fake sign-in box on another site (clickjacking)',
    fix: 'X-Frame-Options: DENY',
  },
];

export async function run(context) {
  const findings = [];

  if (!context.url) {
    findings.push(
      makeSkip(
        'Live security headers were not checked',
        'This check needs the address of your live site. Pass --url https://yourapp.com (together with ' +
          '--i-have-authorization) to include it.',
        context.root,
      ),
    );
    return findings;
  }

  if (!context.authorized) {
    findings.push(
      makeSkip(
        'Live security headers were not checked (no authorisation given)',
        'The --i-have-authorization flag was not passed, so we sent no request to the live site. Add it only if you ' +
          'own the site or have written permission to test it.',
        context.url,
      ),
    );
    return findings;
  }

  const response = await fetchSecurityHeaders(context.url);

  if (!response.ok) {
    findings.push(
      makeSkip(
        'Live security headers could not be read',
        `The request to ${context.url} did not complete (${response.error}). Nothing was changed and no sign-in was ` +
          'attempted.',
        context.url,
      ),
    );
    return findings;
  }

  const headers = response.headers || {};

  // The header map from fetch() is lower-cased, but be defensive anyway.
  const normalised = {};
  for (const [key, value] of Object.entries(headers)) normalised[String(key).toLowerCase()] = value;

  const actuallyMissing = SECURITY_HEADERS.filter((header) => !normalised[header.name]);
  const actuallyPresent = SECURITY_HEADERS.filter((header) => normalised[header.name]);

  if (!actuallyMissing.length) {
    findings.push(
      makePass(
        'All five recommended security headers are present',
        `We fetched ${response.finalUrl || context.url} and confirmed: ${actuallyPresent.map((h) => h.label).join(', ')}.`,
        context.url,
      ),
    );
    return findings;
  }

  const isHttps = String(context.url).toLowerCase().startsWith('https://');

  findings.push(
    makeFinding({
      severity: actuallyMissing.length >= 3 ? 'MEDIUM' : 'LOW',
      title: `Live site is missing ${actuallyMissing.length} security header(s)`,
      detail:
        `We fetched ${response.finalUrl || context.url} and looked at the response headers. The following recommended ` +
        `headers were not present: ${actuallyMissing.map((h) => h.label).join(', ')}. ` +
        (isHttps
          ? 'The site is served over HTTPS, which is good.'
          : 'Note: the site was reached over plain HTTP. Serve it over HTTPS first - HSTS and the other headers ' +
            'only make sense over an encrypted connection.'),
      plain:
        'Your website is missing some of the browser protections that stop common attacks. They are quick to add ' +
        'and they reduce real risk.',
      location: context.url,
      remediation:
        'Add the missing headers at the server or hosting layer. For example in Express:\n\n' +
        actuallyMissing
          .map((header) => `    res.setHeader("${header.name}", "${header.fix}");  // ${header.label}`)
          .join('\n') +
        '\n\nOn Vercel/Netlify add them in vercel.json or netlify.toml; on Nginx add them in the server block; on ' +
        'Cloudflare use the "Transform Rules" feature.\n\n' +
        'In Next.js you can add them in next.config.js:\n\n' +
        '    async headers() {\n' +
        '      return [{\n' +
        '        source: "/(.*)",\n' +
        '        headers: [\n' +
        actuallyMissing
          .map((header) => `          { key: "${header.name}", value: "${header.fix}" },`)
          .join('\n') +
        '\n        ],\n' +
        '      }];\n' +
        '    }',
      evidence:
        `GET ${response.finalUrl || context.url} -> HTTP ${response.status}\n` +
        `Missing: ${actuallyMissing.map((h) => h.name).join(', ')}\n` +
        `Present: ${actuallyPresent.map((h) => h.name).join(', ') || '(none)'}`,
      cwe: 'CWE-693',
    }),
  );

  // A wildcard CSP is present but useless.
  const csp = normalised['content-security-policy'];
  if (csp && /default-src\s+\*/i.test(csp) && !/frame-ancestors/i.test(csp)) {
    findings.push(
      makeFinding({
        severity: 'LOW',
        title: 'Content-Security-Policy is effectively disabled (wildcard *)',
        detail:
          'A policy of "default-src *" allows scripts, frames and connections from anywhere, which blocks nothing. ' +
          'It also does not set frame-ancestors, so clickjacking is still possible.',
        plain: 'Your website has a security rule that allows everything, so it does not actually protect anything.',
        location: context.url,
        remediation:
          'Replace the wildcard with an explicit list, and always set frame-ancestors:\n\n' +
          "    Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
          "img-src 'self' data: https:; connect-src 'self' https://*.supabase.co; frame-ancestors 'none'",
        evidence: `Content-Security-Policy: ${csp}`,
        cwe: 'CWE-693',
      }),
    );
  }

  return findings;
}

export function status(context) {
  if (!context.url) {
    return { state: 'skip', notes: ['No --url was supplied, so the live header check did not run.'] };
  }
  if (!context.authorized) {
    return { state: 'skip', notes: ['--i-have-authorization was not supplied, so no request was sent.'] };
  }
  return { state: 'unknown', notes: [] };
}
