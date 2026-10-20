/**
 * lib/secrets.core.js
 * ---------------------------------------------------------------------------
 * Secret detection: pattern catalogue, matching and redaction.
 *
 * PORTED from the CLI's `audit/lib/secrets.js`.
 *
 * DESIGN RULES (these matter for a client-facing report):
 *  1. A finding NEVER contains the raw secret. The report is going to be
 *     emailed, committed to a repo and pasted into ChatGPT. We show a short
 *     prefix (enough to identify which key) plus the length, then redact.
 *  2. Every pattern carries a fixed severity so two runs of the scanner give
 *     the same output.
 *  3. Placeholder-looking values ("your-api-key-here", "changeme", "***") are
 *     ignored. AI code generators emit a LOT of these and flagging them would
 *     destroy the signal-to-noise ratio of the report.
 */

(function (root) {
  'use strict';

  const S = (root.SCANNER = root.SCANNER || {});
  S.lib = S.lib || {};

  const util = () => S.lib.util;

  /**
   * Credential patterns.
   *
   * `regex`  - the pattern (global flag required)
   * `id`     - stable identifier used in evidence and tests
   * `title`  - human readable name shown to a non-technical client
   * `severity` - CRITICAL for keys that grant write/admin access to live data
   * `prefix` - how many leading characters are safe to show before redaction
   */
  const SECRET_PATTERNS = [
    {
      id: 'stripe-live-secret',
      title: 'Stripe live secret key',
      severity: 'CRITICAL',
      prefix: 8,
      regex: /\bsk_live_[0-9A-Za-z]{16,}\b/g,
      why: 'A live Stripe secret key can charge, refund and read customer payment data.',
    },
    {
      id: 'stripe-restricted-key',
      title: 'Stripe restricted live key',
      severity: 'CRITICAL',
      prefix: 10,
      regex: /\brk_live_[0-9A-Za-z]{16,}\b/g,
      why: 'A restricted live key still moves real money.',
    },
    {
      id: 'stripe-test-secret',
      title: 'Stripe test secret key',
      severity: 'HIGH',
      prefix: 8,
      regex: /\bsk_test_[0-9A-Za-z]{16,}\b/g,
      why: 'Test keys are lower impact, but they are still secrets and are frequently copied into production.',
    },
    {
      id: 'private-key',
      title: 'Private key file contents',
      severity: 'CRITICAL',
      prefix: 27,
      regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g,
      why: 'A private key can impersonate a server, a user or a signing authority.',
    },
    {
      id: 'firebase-service-account',
      title: 'Firebase / Google service account private key',
      severity: 'CRITICAL',
      prefix: 0,
      regex: /"private_key"\s*:\s*"-----BEGIN PRIVATE KEY-----/g,
      why: 'A service account key grants full access to a Firebase project.',
    },
    {
      id: 'aws-access-key-id',
      title: 'AWS access key ID',
      severity: 'HIGH',
      prefix: 4,
      regex: /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
      why: 'An AWS key ID paired with a leaked secret grants access to your cloud account.',
    },
    {
      id: 'aws-secret-access-key',
      title: 'AWS secret access key',
      severity: 'CRITICAL',
      prefix: 0,
      regex: /aws_secret_access_key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
      captureGroup: 1,
      why: 'The AWS secret key is the half of the credential pair that actually authenticates.',
    },
    {
      id: 'slack-webhook',
      title: 'Slack incoming webhook URL',
      severity: 'HIGH',
      prefix: 26,
      regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9+\/=_-]{10,}/g,
      why: 'Anyone with this URL can post messages into your internal Slack channels.',
    },
    {
      id: 'discord-webhook',
      title: 'Discord webhook URL',
      severity: 'HIGH',
      prefix: 30,
      regex: /https:\/\/(?:discord(?:app)?\.com|discord\.com)\/api\/webhooks\/\d+\/[A-Za-z0-9_-]{20,}/g,
      why: 'Anyone with this URL can post messages into your Discord server.',
    },
    {
      id: 'github-token',
      title: 'GitHub access token',
      severity: 'CRITICAL',
      prefix: 7,
      regex: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b/g,
      why: 'A GitHub token can push code, read private repositories and open pull requests.',
    },
    {
      id: 'anthropic-key',
      title: 'Anthropic API key',
      severity: 'HIGH',
      prefix: 7,
      regex: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
      why: 'An Anthropic key can be used to run up a bill against your account.',
    },
    {
      id: 'openai-key',
      title: 'OpenAI API key',
      severity: 'HIGH',
      prefix: 7,
      regex: /\bsk-(?!live_|test_|ant-)[A-Za-z0-9]{32,}\b/g,
      why: 'An OpenAI key can be used to run up a bill against your account.',
    },
    {
      id: 'google-api-key',
      title: 'Google API key',
      severity: 'HIGH',
      prefix: 4,
      regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
      why: 'A Google API key can expose Maps, Places or Firebase data depending on its restrictions.',
    },
    {
      id: 'sendgrid-key',
      title: 'SendGrid API key',
      severity: 'HIGH',
      prefix: 3,
      regex: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g,
      why: 'A SendGrid key can send email as your domain, which is a ready-made phishing kit.',
    },
    {
      id: 'twilio-account-sid',
      title: 'Twilio account SID',
      severity: 'MEDIUM',
      prefix: 4,
      regex: /\bAC[0-9a-fA-F]{32}\b/g,
      why: 'A Twilio SID identifies the account; usually stored next to the far more dangerous auth token.',
    },
    {
      id: 'npm-token',
      title: 'npm access token',
      severity: 'HIGH',
      prefix: 6,
      regex: /\bnpm_[A-Za-z0-9]{30,}\b/g,
      why: 'An npm token can publish packages as you.',
    },
  ];

  /**
   * Generic "this looks like an assignment of a secret to a literal string"
   * pattern. Much noisier than the catalogue above, so it only runs as a
   * secondary pass and is reported as MEDIUM.
   */
  const GENERIC_ASSIGNMENT_REGEX =
    /(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|private[_-]?token|refresh[_-]?token|session[_-]?secret|encryption[_-]?key|jwt[_-]?secret|password|passwd)\s*[:=]\s*["'`]([^"'`\n]{8,})["'`]/gi;

  /**
   * Environment-variable style assignments - the shape AI code generators
   * produce most often: `STRIPE_SECRET_KEY=...`, `OPENAI_API_KEY="..."`,
   * `DB_PASSWORD='...'`.
   *
   * WHY this exists in addition to the generic pattern: the generic pattern
   * only knows a fixed list of lowercase key names, so `STRIPE_SECRET_KEY` or
   * `GITHUB_TOKEN` slipped through. This one matches ANY identifier that
   * ends in SECRET / TOKEN / PASSWORD / API_KEY (or _KEY / _PWD), which is
   * exactly the set the brief asks for.
   *
   * The value may be quoted (group 3) or bare (group 4). Bare values are
   * what you find in a real .env file, so both shapes have to work.
   */
  const ENV_STYLE_ASSIGNMENT_REGEX =
    /\b([A-Za-z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY)[A-Za-z0-9_]*)\s*[:=]\s*(?:(["'`])([^"'`\n]{8,})\2|([A-Za-z0-9_\-./+=~]{12,}))/g;

  /** Values that are obviously placeholders and must not be reported. */
  const PLACEHOLDER_PATTERNS = [
    /^x{3,}/i,
    /^\*+$/,
    /^your[-_ ]?/i,
    /^my[-_ ]?/i,
    /^example/i,
    /^sample/i,
    /^changeme/i,
    /^change[-_]?me/i,
    /^replace/i,
    /^insert/i,
    /^placeholder/i,
    /^dummy/i,
    /^fake/i,
    /^todo/i,
    /^fixme/i,
    /^redacted/i,
    /^<.*>$/,
    /^\{\{.*\}\}$/,
    /^process\.env/i,
    /^import\.meta\.env/i,
    /^env\./i,
    /^string$/i,
    /^none$/i,
    /^null$/i,
    /^undefined$/i,
    /^true$/i,
    /^false$/i,
    /^\$\{.*\}$/,
    /^\$[A-Z_]+$/,
    /^localhost/i,
    /^http:\/\/localhost/i,
  ];

  /**
   * Values that look like placeholders. We keep the list deliberately broad:
   * a false positive costs a client more trust than a missed placeholder does.
   */
  function isPlaceholder(value) {
    const raw = String(value || '').trim();
    if (raw.length < 8) return true;
    if (PLACEHOLDER_PATTERNS.some((re) => re.test(raw))) return true;
    // A value with no letters at all is usually a numeric constant.
    if (!/[A-Za-z]/.test(raw)) return true;
    // "aaaa..." / "123123..." style repeats.
    if (/^(.)\1{7,}$/.test(raw)) return true;
    return false;
  }

  /**
   * Shannon entropy of a string, in bits per character.
   *
   * WHY: the generic "key = value" pattern matches plenty of ordinary
   * strings. A real secret is much less predictable than a sentence, so the
   * browser version only reports generic assignments whose value actually
   * looks random.
   */
  function shannonEntropy(value) {
    const text = String(value || '');
    if (!text.length) return 0;
    const counts = new Map();
    for (const ch of text) counts.set(ch, (counts.get(ch) || 0) + 1);
    let entropy = 0;
    for (const n of counts.values()) {
      const p = n / text.length;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  /** Is this value long and random-looking enough to be a real credential? */
  function looksHighEntropy(value) {
    const text = String(value || '');
    if (text.length < 16) return false;
    return shannonEntropy(text) >= 3;
  }

  /**
   * Redact a secret for display.
   *
   * WHY keep a short prefix: the client needs to know *which* key leaked
   * ("ah, that's the Stripe one") without the report containing a usable
   * credential. The prefix of a well-known format is not itself sensitive.
   */
  function redactSecret(value, keep) {
    const raw = String(value == null ? '' : value);
    const prefixLength = keep === undefined ? 6 : keep;
    if (!raw) return '';
    if (raw.length <= prefixLength) return `${'*'.repeat(raw.length)}[REDACTED len=${raw.length}]`;
    const head = raw.slice(0, prefixLength);
    const maskLength = Math.min(24, Math.max(4, raw.length - prefixLength));
    return `${head}${'*'.repeat(maskLength)}[REDACTED len=${raw.length}]`;
  }

  /**
   * A JWT-looking string.
   * Kept separate from the catalogue because JWTs need decoding before we can
   * tell a harmless anon key from a deadly service_role key.
   */
  const JWT_REGEX = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;

  /**
   * Decode a JWT payload and return the parsed object, or null.
   * Never throws: this runs on untrusted text.
   */
  function decodeJwtPayload(token) {
    const parts = String(token || '').split('.');
    if (parts.length !== 3) return null;
    const json = util().decodeBase64Url(parts[1]);
    if (!json || !json.trim().startsWith('{')) return null;
    try {
      const parsed = JSON.parse(json);
      return parsed && typeof parsed === 'object' ? parsed : null;
    } catch {
      return null;
    }
  }

  /**
   * Classify a JWT by its `role` claim.
   *
   * WHY this matters so much: Supabase ships two keys. The `anon` key is
   * *designed* to be public (it lives in the browser bundle). The
   * `service_role` key is a full admin bypass of Row Level Security and must
   * never leave the server. Telling the two apart is the single highest-value
   * thing this scanner does for Lovable / Bolt / v0 apps.
   */
  function classifyJwt(token) {
    const payload = decodeJwtPayload(token);
    if (!payload) return { kind: 'jwt', role: null };
    const role = payload.role || payload['https://supabase.co/role'] || null;
    if (role === 'service_role') return { kind: 'supabase-service-role', role };
    if (role === 'anon') return { kind: 'supabase-anon', role };
    if (role === 'authenticated') return { kind: 'supabase-authenticated', role };
    return { kind: 'jwt', role: role || null };
  }

  /**
   * Scan a block of text for catalogue secrets.
   *
   * @returns {Array<{patternId,title,severity,match,redacted,index,line,why}>}
   */
  function scanForSecrets(text, options) {
    const opts = options || {};
    const offsetLine = opts.offsetLine || 0;
    const content = String(text || '');
    const results = [];

    for (const pattern of SECRET_PATTERNS) {
      // A fresh RegExp per call: the shared objects carry the /g flag, and
      // `lastIndex` on a shared global regex is a classic source of
      // intermittent, "why did it miss it?" bugs.
      const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
      let match;
      while ((match = regex.exec(content)) !== null) {
        const raw = match[pattern.captureGroup ? pattern.captureGroup : 0];
        if (!raw) continue;
        const value = pattern.captureGroup ? raw : match[0];
        if (isPlaceholder(value)) continue;
        const index = pattern.captureGroup ? match.index + match[0].indexOf(raw) : match.index;
        results.push({
          patternId: pattern.id,
          title: pattern.title,
          severity: pattern.severity,
          why: pattern.why,
          match: value,
          redacted: redactSecret(value, pattern.prefix),
          index,
          line: offsetLine + countLines(content, match.index),
        });
        if (match.index === regex.lastIndex) regex.lastIndex += 1;
      }
    }

    return results;
  }

  /**
   * Scan for Supabase-style JWTs and classify them.
   * Runs separately because the severity depends on the decoded role.
   */
  function scanForJwts(text, options) {
    const opts = options || {};
    const offsetLine = opts.offsetLine || 0;
    const content = String(text || '');
    const results = [];
    const regex = new RegExp(JWT_REGEX.source, JWT_REGEX.flags);
    let match;
    while ((match = regex.exec(content)) !== null) {
      const token = match[0];
      const info = classifyJwt(token);
      let severity = 'MEDIUM';
      let title = 'JSON Web Token embedded in source';
      if (info.kind === 'supabase-service-role') {
        severity = 'CRITICAL';
        title = 'Supabase service_role key in source';
      } else if (info.kind === 'supabase-anon') {
        severity = 'INFO';
        title = 'Supabase anon (public) key in source';
      } else if (info.kind === 'supabase-authenticated') {
        severity = 'MEDIUM';
        title = 'Supabase user session token in source';
      }
      results.push({
        patternId: `jwt-${info.kind}`,
        title,
        severity,
        why:
          info.kind === 'supabase-service-role'
            ? 'The service_role key bypasses every Row Level Security policy. Anyone holding it can read and write every table.'
            : 'Tokens embedded in source code end up in git history and in the browser bundle.',
        match: token,
        redacted: `${redactSecret(token, 12)} role=${info.role || 'unknown'}`,
        index: match.index,
        line: offsetLine + countLines(content, match.index),
        role: info.role,
        jwtKind: info.kind,
      });
      if (match.index === regex.lastIndex) regex.lastIndex += 1;
    }
    return results;
  }

  /**
   * Generic assignment scan (API_KEY = "literal").
   * Reported separately because it is noisier and lower severity.
   */
  function scanForGenericAssignments(text, options) {
    const opts = options || {};
    const offsetLine = opts.offsetLine || 0;
    const content = String(text || '');
    const results = [];
    const seen = new Set();

    const record = (value, index, name) => {
      if (!value) return;
      if (seen.has(value)) return;
      if (isPlaceholder(value)) return;
      // Skip when the "secret" is actually a reference to another variable.
      if (/^[\w.$-]+$/.test(value) && /^(process|import\.meta|env)\./.test(value)) return;
      seen.add(value);
      results.push({
        patternId: 'generic-secret-assignment',
        title: name
          ? `Hard-coded value assigned to ${name}`
          : 'Hard-coded secret value in source',
        severity: 'MEDIUM',
        why: 'Hard-coded credentials end up in git history and in any build of the app.',
        match: value,
        redacted: redactSecret(value, 4),
        index,
        line: offsetLine + countLines(content, index),
      });
    };

    const regex = new RegExp(GENERIC_ASSIGNMENT_REGEX.source, GENERIC_ASSIGNMENT_REGEX.flags);
    let match;
    while ((match = regex.exec(content)) !== null) {
      record(match[1], match.index, null);
      if (match.index === regex.lastIndex) regex.lastIndex += 1;
    }

    // The environment-variable shaped assignments. These are only reported
    // when the value is long AND random-looking, because `TOKEN: "bearer"` or
    // `API_KEY: "your-key-here"` are everywhere in generated code.
    const envRegex = new RegExp(ENV_STYLE_ASSIGNMENT_REGEX.source, ENV_STYLE_ASSIGNMENT_REGEX.flags);
    while ((match = envRegex.exec(content)) !== null) {
      const name = match[1];
      const value = match[3] || match[4];
      if (!value) continue;
      // The value is the last thing in the match, so its start offset is
      // exact (for the quoted form we skip the closing quote).
      const valueStart = match.index + match[0].length - value.length - (match[3] ? 1 : 0);
      if (looksHighEntropy(value)) record(value, valueStart, name);
      if (match.index === envRegex.lastIndex) envRegex.lastIndex += 1;
    }

    return results;
  }

  /** Number of newlines before an offset (+1 for the first line). */
  function countLines(content, index) {
    let line = 1;
    const text = String(content || '');
    for (let i = 0; i < index && i < text.length; i += 1) {
      if (text[i] === '\n') line += 1;
    }
    return line;
  }

  /**
   * Run every secret scan over a block of text.
   * `includeGeneric` is off by default because generic assignments are noisy;
   * the caller decides per file type.
   */
  function scanText(text, options) {
    const opts = options || {};
    const includeGeneric = opts.includeGeneric === true;
    let results = [...scanForSecrets(text, opts), ...scanForJwts(text, opts)];
    if (includeGeneric) results = results.concat(scanForGenericAssignments(text, opts));
    // De-duplicate identical secret hits reported by two patterns at the same offset.
    const seen = new Set();
    return results.filter((r) => {
      const key = `${r.match}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  S.lib.secrets = {
    SECRET_PATTERNS,
    GENERIC_ASSIGNMENT_REGEX,
    ENV_STYLE_ASSIGNMENT_REGEX,
    PLACEHOLDER_PATTERNS,
    JWT_REGEX,
    isPlaceholder,
    shannonEntropy,
    looksHighEntropy,
    redactSecret,
    decodeJwtPayload,
    classifyJwt,
    scanForSecrets,
    scanForJwts,
    scanForGenericAssignments,
    countLines,
    scanText,
  };
})(globalThis);
