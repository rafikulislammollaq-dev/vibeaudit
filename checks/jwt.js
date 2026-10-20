/**
 * checks/jwt.js
 * ---------------------------------------------------------------------------
 * CHECK 11 - JSON Web Token weaknesses.
 *
 * WHY THIS MATTERS: JSON Web Tokens are how most AI-built apps carry "who is
 * this person". Three mistakes account for nearly all JWT vulnerabilities:
 *
 *  1. `alg: "none"` - the token says "I am not signed" and the server
 *     believes it. An attacker forges any identity they like.
 *  2. Using `jwt.decode()` where `jwt.verify()` was needed - decode() does
 *     no verification at all; it just reads the payload.
 *  3. A signing secret that falls back to a hard-coded default
 *     (`process.env.JWT_SECRET || "devsecret"`), so the real secret is only
 *     as strong as the fallback.
 */

import { makeFinding, makePass, makeSkip } from '../lib/findings.js';
import { countLines } from '../lib/secrets.js';
import { isCodeFile } from '../lib/fs-walk.js';

export const id = 'jwt';
export const title = 'JWT (token) verification weaknesses';
export const severity = 'CRITICAL';

/** `alg: "none"` in any spelling. */
const ALG_NONE =
  /(?:alg(?:orithm)?\s*[:=]\s*['"`]none['"`]|algorithms?\s*:\s*\[[^\]]*['"`]none['"`][^\]]*\]|\balg\s*===\s*['"`]none['"`]|verify\s*\([^)]*,\s*null\s*,\s*\{[^}]*algorithms)/gi;

/** jwt.decode() used where verification was needed. */
const JWT_DECODE = /\bjwt\s*\.\s*decode\s*\(|\bdecode\s*\(\s*(?:token|jwt|access_token|authToken)\b/gi;

/** `jwt.verify()` without an algorithms allowlist. */
const JWT_VERIFY = /\bjwt\s*\.\s*verify\s*\(/gi;

/** A secret taken from the environment with a hard-coded fallback. */
const ENV_FALLBACK =
  /process\.env\s*\.\s*([A-Z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD)[A-Z0-9_]*)\s*(\|\||\?\?)\s*['"`]([^'"`]{4,})['"`]/g;

export function run(context) {
  const findings = [];
  const codeFiles = context.files.filter(
    (file) => isCodeFile(file) && file.content,
  );

  if (!codeFiles.length) {
    findings.push(makeSkip('No source code found', 'Token handling is implemented in code; no code was found.', context.root));
    return findings;
  }

  for (const file of codeFiles) {
    const content = file.content;

    // ------------------------------------------------------- alg: none
    for (const match of content.matchAll(ALG_NONE)) {
      const line = countLines(content, match.index);
      findings.push(
        makeFinding({
          severity: 'CRITICAL',
          title: `Token verification accepts unsigned tokens (alg: none) (${file.relPath})`,
          detail:
            'The verification code allows the "none" algorithm, which means a token with no signature at all is ' +
            'accepted. Anybody can hand-write a token claiming to be any user, including an admin.',
          plain:
            'Your app accepts a sign-in token that anybody can write by hand, so someone could pretend to be any ' +
            'user - including you.',
          location: `${file.relPath}:${line}`,
          remediation:
            'Remove "none" from the accepted algorithms and pin the ones you expect:\n\n' +
            '    const payload = jwt.verify(token, process.env.JWT_SECRET, {\n' +
            '      algorithms: ["HS256"],       // <-- explicit list, no "none"\n' +
            '    });\n\n' +
            'Also reject tokens whose header says "none" before verification:\n\n' +
            '    const decoded = jwt.decode(token, { complete: true });\n' +
            '    if (!decoded || String(decoded.header.alg).toLowerCase() === "none") {\n' +
            '      throw new Error("Unsigned token rejected");\n' +
            '    }',
          evidence: context.window(content, match.index, 8),
          cwe: 'CWE-347',
        }),
      );
    }

    // --------------------------------------------- decode used as verify
    const decodes = [...content.matchAll(JWT_DECODE)];
    const verifies = [...content.matchAll(JWT_VERIFY)];
    for (const match of decodes) {
      const line = countLines(content, match.index);
      const after = content.slice(match.index, match.index + 500);
      // A decode immediately followed by a verify is a normal pattern.
      if (/jwt\s*\.\s*verify\s*\(/.test(after)) continue;
      // A file that verifies somewhere else is likely doing header decoding.
      if (verifies.length && /complete\s*:\s*true/.test(content)) continue;
      findings.push(
        makeFinding({
          severity: 'HIGH',
          title: `Token is decoded instead of verified (${file.relPath})`,
          detail:
            'jwt.decode() only reads the contents of a token - it does not check the signature. A decoded token is ' +
            'attacker-controlled input. Only jwt.verify() proves the token was issued by you and has not been edited.',
          plain:
            'Your app reads a sign-in token without checking that it is genuine, so a visitor could edit it and ' +
            'pretend to be somebody else.',
          location: `${file.relPath}:${line}`,
          remediation:
            'Verify the token instead of decoding it:\n\n' +
            '    // WRONG: jwt.decode(token)\n' +
            '    const { payload } = jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"] });\n\n' +
            'If you need the header as well, use jwt.decode(token, { complete: true }) but ONLY to read the ' +
            'algorithm, and always call jwt.verify() before trusting any claim.',
          evidence: context.window(content, match.index, 8),
          cwe: 'CWE-345',
        }),
      );
    }

    // ------------------------------------- verify without an allowlist
    for (const match of verifies) {
      const after = content.slice(match.index, match.index + 300);
      if (/algorithms?\s*:/.test(after)) continue;
      const line = countLines(content, match.index);
      findings.push(
        makeFinding({
          severity: 'MEDIUM',
          title: `Token verification does not pin the algorithm (${file.relPath})`,
          detail:
            'jwt.verify() without an "algorithms" list accepts whichever algorithm the token asks for. That is the ' +
            'classic algorithm-confusion setup.',
          plain:
            'Your sign-in tokens are checked without pinning the type of signature, which leaves a well-known trick ' +
            'open.',
          location: `${file.relPath}:${line}`,
          remediation:
            'Pin the algorithm explicitly:\n\n' +
            '    jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["HS256"] });',
          evidence: context.window(content, match.index, 5),
          cwe: 'CWE-327',
        }),
      );
    }

    // ------------------------------------- hard-coded secret fallbacks
    for (const match of content.matchAll(ENV_FALLBACK)) {
      const variable = match[1];
      const fallback = match[3];
      // A fallback like "change-me" or "replace-this" is ALWAYS reported: it
      // is the classic "somebody forgot to set the variable" default, and it
      // is the one that ends up signing production tokens.
      const alwaysReport = /^(change|replace|insert|fixme|todo|default|secret|pass)/i.test(fallback);
      if (!alwaysReport && /^(your|dev|test|local|example|demo)/i.test(fallback)) {
        // A clearly development-only fallback is only worth mentioning in a
        // file that is itself a development file.
        if (!/local|dev|test|example/i.test(file.relPath)) continue;
      }
      const line = countLines(content, match.index);
      findings.push(
        makeFinding({
          severity: 'HIGH',
          title: `Signing secret falls back to a hard-coded value: ${variable} (${file.relPath})`,
          detail:
            'When the environment variable is missing, the code silently uses a value written into the source. ' +
            'That value is in your git history, and if the environment variable is ever missing in production, ' +
            'every token is signed with a secret the whole world can read.',
          plain:
            'If the secret setting is ever missing, your app quietly falls back to a password that is written in ' +
            'plain sight in your code.',
          location: `${file.relPath}:${line}`,
          remediation:
            'Fail loudly instead of falling back:\n\n' +
            '    const secret = process.env.JWT_SECRET;\n' +
            '    if (!secret) throw new Error("JWT_SECRET is not set");\n\n' +
            'If you need a development fallback, only use it when NODE_ENV is not production:\n\n' +
            '    const secret = process.env.JWT_SECRET ?? (process.env.NODE_ENV === "production" ? null : "dev-only-secret");\n' +
            '    if (!secret) throw new Error("JWT_SECRET is not set");',
          evidence: context.window(content, match.index, 6),
          cwe: 'CWE-798',
        }),
      );
    }
  }

  if (!findings.length) {
    findings.push(
      makePass(
        'No JWT weaknesses found',
        `Reviewed ${codeFiles.length} code file(s) for unsigned-token acceptance, decode-without-verify, unpinned ` +
          'algorithms and hard-coded signing secrets.',
        codeFiles.length ? '' : context.root,
      ),
    );
  }

  return findings;
}

export function status(context) {
  const codeFiles = context.files.filter((file) => file.category === 'source' && file.content);
  if (!codeFiles.length) {
    return { state: 'skip', notes: ['No source code was found, so token handling could not be reviewed.'] };
  }
  return { state: 'unknown', notes: [] };
}
