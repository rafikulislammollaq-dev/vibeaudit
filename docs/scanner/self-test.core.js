/**
 * self-test.core.js
 * ---------------------------------------------------------------------------
 * The self-test runner.
 *
 * It builds small in-memory fixtures (a bad .env, a bad .sql, a CORS
 * snippet, a JWT snippet, a debug route) and runs the real checks against
 * them, then prints PASS / FAIL for every expectation.
 *
 * WHY this exists: the tool ships with no server and no build step, so the
 * only honest way to prove the checks still work is to run them here. Open
 * this file from the filesystem (double-click it) and it prints
 * "ALL CHECKS PASSED" when the scanner behaves as documented.
 */

(function (root) {
  'use strict';

  const S = (root.SCANNER = root.SCANNER || {});
  S.selfTest = S.selfTest || {};

  /* ------------------------------------------------------------------ */
  /* fixtures                                                            */
  /* ------------------------------------------------------------------ */

  // Assembled rather than written out, for the same reason the CLI test
  // fixtures are: GitHub's push protection refuses any push containing a
  // string shaped like a live credential, even a fabricated one. The value
  // below points at no Stripe account and has never been live.
  const STRIPE_LIVE_KEY = 'sk_' + 'live_' + '51QaBcDeFgHiJkLmNoPqRsTuVwXyZ0123';

  /** Build a JWT-looking string with a chosen payload. */
  function makeJwt(payload) {
    const encode = (value) =>
      btoa(JSON.stringify(value)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return `${encode({ alg: 'HS256', typ: 'JWT' })}.${encode(payload)}.${'a'.repeat(43)}`;
  }

  const SERVICE_ROLE_JWT = makeJwt({
    role: 'service_role',
    iss: 'supabase',
    iat: 1700000000,
    exp: 1900000000,
  });

  const ANON_JWT = makeJwt({ role: 'anon', iss: 'supabase', iat: 1700000000, exp: 1900000000 });

  const BAD_ENV = [
    '# a deliberately terrible .env',
    `STRIPE_SECRET_KEY=${STRIPE_LIVE_KEY}`,
    `SUPABASE_SERVICE_ROLE=${SERVICE_ROLE_JWT}`,
    `SUPABASE_ANON=${ANON_JWT}`,
    'OPENAI_API_KEY=Zx8Kq2Lm9Vt4Rw7Yb3Nc6Hd1Fs5Gp0Jq',
    'DATABASE_URL=postgresql://postgres:password@db.example.com:5432/prod',
    '',
  ].join('\n');

  const BAD_SQL = [
    'create table public.profiles (',
    '  id uuid primary key,',
    '  user_id uuid not null,',
    '  full_name text,',
    '  email text',
    ');',
    '',
    'create or replace function public.delete_any_user(target uuid)',
    'returns void',
    'language plpgsql',
    'security definer',
    'as $$',
    'begin',
    '  delete from public.profiles where id = target;',
    'end;',
    '$$;',
    '',
    'create policy "anyone can read profiles" on public.profiles',
    '  for select',
    '  using (true);',
    '',
  ].join('\n');

  const CORS_SNIPPET = [
    "const cors = require('cors');",
    '',
    "app.use(cors({ origin: '*', credentials: true }));",
    '',
    "res.setHeader('Access-Control-Allow-Origin', '*');",
    "res.setHeader('Access-Control-Allow-Credentials', 'true');",
    '',
  ].join('\n');

  const JWT_DECODE_SNIPPET = [
    "const jwt = require('jsonwebtoken');",
    '',
    'function currentUser(token) {',
    '  const payload = jwt.decode(token);',
    '  return payload;',
    '}',
    '',
  ].join('\n');

  const JWT_VERIFY_SNIPPET = [
    "const jwt = require('jsonwebtoken');",
    '',
    'function verifyUser(token) {',
    '  return jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["none"] });',
    '}',
    '',
  ].join('\n');

  const DEBUG_SNIPPET = [
    "app.get('/api/debug', (req, res) => {",
    '  res.json({ env: process.env, secret: process.env.SUPABASE_SERVICE_ROLE_KEY });',
    '});',
    '',
  ].join('\n');

  const BUNDLE_SNIPPET = 'console.log("hi");\n//# sourceMappingURL=assets/index-abc123.js.map\n';

  const GITIGNORE_OK = ['node_modules', '.env', '.env.local', 'dist', ''].join('\n');
  const GITIGNORE_BAD = ['node_modules', 'dist', ''].join('\n');

  /* ------------------------------------------------------------------ */
  /* helpers                                                             */
  /* ------------------------------------------------------------------ */

  function file(relPath, content) {
    const name = relPath.split('/').pop();
    return S.lib.files.createFileRecord({
      relPath,
      name,
      ext: name.includes('.') ? name.slice(name.lastIndexOf('.')) : '',
      size: content.length,
      content,
    });
  }

  function scan(files, label) {
    return S.scan.scanProject({ files, label: label || 'self-test fixtures' });
  }

  function titles(report) {
    return report.findings.map((f) => f.title);
  }

  function hasFinding(report, matcher) {
    return report.findings.some((f) => matcher(f.title) || matcher(f.detail || ''));
  }

  /* ------------------------------------------------------------------ */
  /* the test suite                                                      */
  /* ------------------------------------------------------------------ */

  function buildTests() {
    const tests = [];
    const add = (name, fn) => tests.push({ name, fn });

    // ---------------------------------------------------------- secrets
    add('Stripe live key is reported as CRITICAL', () => {
      const report = scan([file('.env', BAD_ENV)]);
      const hit = report.findings.find((f) => f.title.includes('Stripe live secret key'));
      if (!hit) return { ok: false, detail: 'no finding for the Stripe live key' };
      if (hit.severity !== 'CRITICAL') return { ok: false, detail: `severity was ${hit.severity}` };
      return { ok: true };
    });

    add('The raw secret never reaches the report', () => {
      const report = scan([file('.env', BAD_ENV)]);
      if (report.markdown.includes(STRIPE_LIVE_KEY)) {
        return { ok: false, detail: 'the full Stripe key appears in the Markdown report' };
      }
      if (!report.markdown.includes('[REDACTED')) {
        return { ok: false, detail: 'no redaction marker in the report' };
      }
      return { ok: true };
    });

    add('Supabase service_role key is reported as CRITICAL', () => {
      const report = scan([file('.env', BAD_ENV)]);
      const hit = report.findings.find((f) => f.title.includes('service_role'));
      if (!hit) return { ok: false, detail: 'no finding for the service_role key' };
      if (hit.severity !== 'CRITICAL') return { ok: false, detail: `severity was ${hit.severity}` };
      return { ok: true };
    });

    add('Supabase anon key is INFO only and costs no points', () => {
      const report = scan([file('.env', BAD_ENV)]);
      const hit = report.findings.find((f) => f.title.includes('anon (public) key'));
      if (!hit) return { ok: false, detail: 'no finding for the anon key' };
      if (hit.severity !== 'INFO') return { ok: false, detail: `severity was ${hit.severity}` };
      if (S.lib.severity.severityWeight(hit.severity) !== 0) {
        return { ok: false, detail: 'the anon key costs points' };
      }
      return { ok: true };
    });

    add('A high-entropy SECRET assignment is reported as MEDIUM', () => {
      const report = scan([file('.env', BAD_ENV)]);
      const hit = report.findings.find((f) => f.title.includes('OPENAI_API_KEY'));
      if (!hit) return { ok: false, detail: 'no finding for the generic API key assignment' };
      if (hit.severity !== 'MEDIUM') return { ok: false, detail: `severity was ${hit.severity}` };
      return { ok: true };
    });

    // -------------------------------------------------------------- env
    add('.env without a .gitignore rule is a HIGH finding', () => {
      const report = scan([file('.env', BAD_ENV), file('.gitignore', GITIGNORE_BAD)]);
      const hit = report.findings.find((f) => f.title.includes('is not ignored by git'));
      if (!hit) return { ok: false, detail: 'no finding for the unprotected .env' };
      if (hit.severity !== 'HIGH') return { ok: false, detail: `severity was ${hit.severity}` };
      return { ok: true };
    });

    add('.env covered by .gitignore is not a finding', () => {
      const report = scan([file('.env', BAD_ENV), file('.gitignore', GITIGNORE_OK)]);
      const hit = report.findings.find((f) => f.title.includes('is not ignored by git'));
      if (hit) return { ok: false, detail: 'the protected .env was still reported' };
      if (!report.notes.some((n) => n.kind === 'pass' && n.title.includes('correctly ignored'))) {
        return { ok: false, detail: 'no "correctly ignored" pass note' };
      }
      return { ok: true };
    });

    add('.gitignore that never mentions .env is a MEDIUM finding', () => {
      const report = scan([file('.env', BAD_ENV), file('.gitignore', GITIGNORE_BAD)]);
      const hit = report.findings.find((f) => f.title.includes('.gitignore does not exclude .env'));
      if (!hit) return { ok: false, detail: 'no finding for the incomplete .gitignore' };
      if (hit.severity !== 'MEDIUM') return { ok: false, detail: `severity was ${hit.severity}` };
      return { ok: true };
    });

    // -------------------------------------------------------------- rls
    add('A table without ENABLE ROW LEVEL SECURITY is reported', () => {
      const report = scan([file('supabase/migrations/0001_init.sql', BAD_SQL)]);
      const hit = report.findings.find((f) => f.title.includes('has no Row Level Security enabled'));
      if (!hit) return { ok: false, detail: 'no finding for the unprotected table' };
      if (hit.severity !== 'CRITICAL') return { ok: false, detail: `severity was ${hit.severity}` };
      return { ok: true };
    });

    add('SECURITY DEFINER without SET search_path is CRITICAL', () => {
      const report = scan([file('supabase/migrations/0001_init.sql', BAD_SQL)]);
      const hit = report.findings.find((f) => f.title.includes('SECURITY DEFINER function without a safe search_path'));
      if (!hit) return { ok: false, detail: 'no finding for the unsafe function' };
      if (hit.severity !== 'CRITICAL') return { ok: false, detail: `severity was ${hit.severity}` };
      return { ok: true };
    });

    add('A permissive USING (true) policy is reported', () => {
      const report = scan([file('supabase/migrations/0001_init.sql', BAD_SQL)]);
      const hit = report.findings.find((f) => f.title.includes('Permissive policy'));
      if (!hit) return { ok: false, detail: 'no finding for the permissive policy' };
      return { ok: true };
    });

    // ------------------------------------------------------------- jwt
    add('alg: "none" is reported as CRITICAL', () => {
      const report = scan([file('src/routes/session.js', JWT_VERIFY_SNIPPET)]);
      const hit = report.findings.find((f) => f.title.includes('accepts unsigned tokens'));
      if (!hit) return { ok: false, detail: 'no finding for alg: none' };
      if (hit.severity !== 'CRITICAL') return { ok: false, detail: `severity was ${hit.severity}` };
      return { ok: true };
    });

    add('jwt.decode() where verification was expected is reported', () => {
      const report = scan([file('src/lib/jwt.js', JWT_DECODE_SNIPPET)]);
      const hit = report.findings.find((f) => f.title.includes('decoded instead of verified'));
      if (!hit) return { ok: false, detail: 'no finding for the unverified token' };
      if (hit.severity !== 'HIGH') return { ok: false, detail: `severity was ${hit.severity}` };
      return { ok: true };
    });

    // ------------------------------------------------------------ cors
    add('Wildcard CORS with credentials is reported as CRITICAL', () => {
      const report = scan([file('src/server.js', CORS_SNIPPET)]);
      const hit = report.findings.find((f) => f.title.includes('CORS allows any website AND credentials'));
      if (!hit) return { ok: false, detail: 'no finding for the wildcard CORS' };
      if (hit.severity !== 'CRITICAL') return { ok: false, detail: `severity was ${hit.severity}` };
      return { ok: true };
    });

    // ----------------------------------------------------------- debug
    add('A /api/debug route is reported', () => {
      const report = scan([file('src/routes/debug.js', DEBUG_SNIPPET)]);
      const hit = report.findings.find((f) => f.title.includes('Debug or test route exposed'));
      if (!hit) return { ok: false, detail: 'no finding for the debug route' };
      return { ok: true };
    });

    add('Published source maps are reported', () => {
      const report = scan([file('dist/assets/index.js', BUNDLE_SNIPPET)]);
      const hit = report.findings.find((f) => f.title.includes('Source maps are published'));
      if (!hit) return { ok: false, detail: 'no finding for the source map reference' };
      if (hit.severity !== 'MEDIUM') return { ok: false, detail: `severity was ${hit.severity}` };
      return { ok: true };
    });

    // --------------------------------------------------------- scoring
    add('The score is 100 - 25*critical - 12*high - 4*medium - 1*low', () => {
      const findings = [
        { severity: 'CRITICAL', kind: 'defect' },
        { severity: 'HIGH', kind: 'defect' },
        { severity: 'MEDIUM', kind: 'defect' },
        { severity: 'LOW', kind: 'defect' },
      ];
      const score = S.lib.severity.computeScore(findings);
      if (score !== 58) return { ok: false, detail: `expected 58, got ${score}` };
      return { ok: true };
    });

    add('The score never goes below 0', () => {
      const findings = Array.from({ length: 6 }, () => ({ severity: 'CRITICAL', kind: 'defect' }));
      const score = S.lib.severity.computeScore(findings);
      if (score !== 0) return { ok: false, detail: `expected 0, got ${score}` };
      return { ok: true };
    });

    add('INFO findings and pass notes never cost points', () => {
      const findings = [
        { severity: 'INFO', kind: 'defect' },
        { severity: 'INFO', kind: 'pass' },
        { severity: 'LOW', kind: 'defect' },
      ];
      const score = S.lib.severity.computeScore(findings);
      if (score !== 99) return { ok: false, detail: `expected 99, got ${score}` };
      return { ok: true };
    });

    add('One CRITICAL caps the verdict at "Do not ship yet"', () => {
      const verdict = S.lib.severity.verdictFor(100, true);
      if (verdict !== 'Do not ship yet') return { ok: false, detail: `verdict was "${verdict}"` };
      const clean = S.lib.severity.verdictFor(100, false);
      if (clean !== 'Ready to ship') return { ok: false, detail: `clean verdict was "${clean}"` };
      return { ok: true };
    });

    add('The verdict bands are 90+ / 70-89 / 40-69 / below 40', () => {
      const cases = [
        [100, 'Ready to ship'],
        [90, 'Ready to ship'],
        [89, 'Ship after fixing high findings'],
        [70, 'Ship after fixing high findings'],
        [69, 'Do not ship yet'],
        [40, 'Do not ship yet'],
        [39, 'Unsafe to ship'],
        [0, 'Unsafe to ship'],
      ];
      for (const [score, expected] of cases) {
        const verdict = S.lib.severity.verdictFor(score, false);
        if (verdict !== expected) {
          return { ok: false, detail: `score ${score} gave "${verdict}", expected "${expected}"` };
        }
      }
      return { ok: true };
    });

    add('The severity weights are 25 / 12 / 4 / 1 / 0', () => {
      const expected = { CRITICAL: 25, HIGH: 12, MEDIUM: 4, LOW: 1, INFO: 0 };
      for (const [severity, weight] of Object.entries(expected)) {
        const actual = S.lib.severity.severityWeight(severity);
        if (actual !== weight) return { ok: false, detail: `${severity} weighs ${actual}, expected ${weight}` };
      }
      return { ok: true };
    });

    // ---------------------------------------------------------- report
    add('The report has a summary, a top 5 and a scope section', () => {
      const report = scan([file('.env', BAD_ENV), file('src/server.js', CORS_SNIPPET)]);
      const summary = S.lib.report.buildPlainSummary(report);
      if (!summary.includes('readiness score of')) return { ok: false, detail: 'no score sentence' };
      if (!report.markdown.includes('Top 5 things to fix first')) return { ok: false, detail: 'no top five' };
      if (!report.markdown.includes('What this does NOT check')) return { ok: false, detail: 'no scope section' };
      if (!report.markdown.includes('All findings')) return { ok: false, detail: 'no findings section' };
      if (S.lib.report.buildTopFive(report).length === 0) return { ok: false, detail: 'no top five entries' };
      return { ok: true };
    });

    add('Every finding carries a copy-paste fix prompt', () => {
      const report = scan([file('.env', BAD_ENV), file('src/server.js', CORS_SNIPPET)]);
      for (const finding of report.findings) {
        if (!finding.fixPrompt) return { ok: false, detail: `"${finding.title}" has no fix prompt` };
        if (!finding.location) return { ok: false, detail: `"${finding.title}" has no location` };
      }
      return { ok: true };
    });

    add('The scanner made no network requests', () => {
      if (typeof performance === 'undefined' || !performance.getEntriesByType) return { ok: true };
      if (typeof location === 'undefined') return { ok: true };
      const origin = location.protocol === 'file:' ? 'file://' : location.origin;
      const external = performance
        .getEntriesByType('resource')
        .map((entry) => entry.name)
        .filter((name) => !name.startsWith(origin) && !name.startsWith('data:'));
      if (external.length) {
        return { ok: false, detail: `external requests: ${external.join(', ')}` };
      }
      return { ok: true };
    });

    return tests;
  }

  /* ------------------------------------------------------------------ */
  /* runner                                                              */
  /* ------------------------------------------------------------------ */

  function run() {
    const tests = buildTests();
    const results = tests.map((test) => {
      try {
        const outcome = test.fn();
        if (outcome && outcome.ok === false) {
          return { name: test.name, ok: false, detail: outcome.detail };
        }
        return { name: test.name, ok: true, detail: '' };
      } catch (error) {
        return { name: test.name, ok: false, detail: String((error && error.message) || error) };
      }
    });

    const passed = results.filter((r) => r.ok).length;
    const failed = results.length - passed;
    return { results, passed, failed, total: results.length };
  }

  function render() {
    const host = document.getElementById('results');
    if (!host) return;
    const outcome = run();

    const summary = document.createElement('p');
    summary.className = outcome.failed === 0 ? 'verdict-pass' : 'verdict-fail';
    summary.textContent =
      outcome.failed === 0
        ? `ALL CHECKS PASSED (${outcome.passed}/${outcome.total})`
        : `${outcome.failed} of ${outcome.total} CHECKS FAILED`;
    host.appendChild(summary);

    const list = document.createElement('ol');
    list.className = 'test-list';
    for (const result of outcome.results) {
      const item = document.createElement('li');
      item.className = result.ok ? 'pass' : 'fail';
      const tag = document.createElement('b');
      tag.textContent = result.ok ? 'PASS' : 'FAIL';
      item.appendChild(tag);
      const name = document.createElement('span');
      name.textContent = ` ${result.name}`;
      item.appendChild(name);
      if (result.detail) {
        const detail = document.createElement('em');
        detail.textContent = ` - ${result.detail}`;
        item.appendChild(detail);
      }
      list.appendChild(item);
    }
    host.appendChild(list);

    const consoleLine = outcome.failed === 0 ? 'ALL CHECKS PASSED' : `${outcome.failed} CHECKS FAILED`;
    if (typeof console !== 'undefined' && console.log) console.log(consoleLine);
    for (const result of outcome.results) {
      if (typeof console !== 'undefined' && console.log) {
        console.log(`${result.ok ? 'PASS' : 'FAIL'} - ${result.name}${result.detail ? ` (${result.detail})` : ''}`);
      }
    }
  }

  S.selfTest.run = run;
  S.selfTest.buildTests = buildTests;

  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', render);
    } else {
      render();
    }
  }
})(globalThis);
