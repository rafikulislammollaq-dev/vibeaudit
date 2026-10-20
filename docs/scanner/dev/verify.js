/**
 * dev/verify.js
 * ---------------------------------------------------------------------------
 * Node verification harness for the browser scanner.
 *
 * It does four things:
 *   1. Imports every module and prints its exports (proves there are no
 *      import errors and no circular-dependency surprises).
 *   2. Runs the same self-test suite that `self-test.html` runs in the
 *      browser, and prints PASS/FAIL per check.
 *   3. Prints the findings each check produces for the fixtures, so the
 *      detection logic can be eyeballed.
 *   4. Greps the whole folder for network calls (fetch / XHR / WebSocket /
 *      sendBeacon / EventSource) and for remote script or stylesheet links.
 *
 * Run it with:  node dev/verify.js      (from the site/scanner folder)
 */

import { readdir, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');

const line = (text = '') => console.log(text);
const rule = () => line('-'.repeat(78));

/* ------------------------------------------------------------------ */
/* 1. module imports                                                    */
/* ------------------------------------------------------------------ */

const MODULES = [
  './lib/util.js',
  './lib/severity.js',
  './lib/secrets.js',
  './lib/sql.js',
  './lib/findings.js',
  './lib/evidence.js',
  './lib/files.js',
  './lib/report.js',
  './checks/env-committed.js',
  './checks/secrets.js',
  './checks/rls.js',
  './checks/jwt.js',
  './checks/cors.js',
  './checks/debug-routes.js',
  './checks/index.js',
  './checks.js',
  './scan.js',
];

rule();
line('1. MODULE IMPORT CHECK');
rule();

let importFailures = 0;
for (const specifier of MODULES) {
  const url = new URL(specifier, `file:///${root.replace(/\\/g, '/')}/`).href;
  try {
    const module = await import(url);
    const keys = Object.keys(module).sort();
    line(`  OK   ${specifier.padEnd(28)} exports: ${keys.length ? keys.join(', ') : '(none - classic core script)'}`);
  } catch (error) {
    importFailures += 1;
    line(`  FAIL ${specifier.padEnd(28)} ${error.message}`);
  }
}
line();

/* ------------------------------------------------------------------ */
/* 2. the browser self-test suite                                       */
/* ------------------------------------------------------------------ */

await import(new URL('./self-test.core.js', `file:///${root.replace(/\\/g, '/')}/`).href);
const { S } = { S: globalThis.SCANNER };
const selfTest = S.selfTest;

rule();
line('2. SELF-TEST SUITE (the same suite self-test.html runs)');
rule();

const outcome = selfTest.run();
for (const result of outcome.results) {
  const tag = result.ok ? 'PASS' : 'FAIL';
  line(`  ${tag}  ${result.name}${result.detail ? `  --  ${result.detail}` : ''}`);
}
line();
line(`  ${outcome.passed}/${outcome.total} passed`);
line();

/* ------------------------------------------------------------------ */
/* 3. findings per check, against the fixtures                          */
/* ------------------------------------------------------------------ */

const files = S.lib.files;

function file(relPath, content) {
  const name = relPath.split('/').pop();
  return files.createFileRecord({
    relPath,
    name,
    ext: name.includes('.') ? name.slice(name.lastIndexOf('.')) : '',
    size: content.length,
    content,
  });
}

/** Build a JWT-shaped string for a Supabase role. Assembled from parts so no
 *  credential-shaped literal is ever committed to the repository. */
const jwt = (role) =>
  [
    Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url'),
    Buffer.from(JSON.stringify({ role, iss: 'supabase', iat: 1700000000 })).toString('base64url'),
    'a'.repeat(43),
  ].join('.');

const FIXTURES = [  file(
    '.env',
    [
      'STRIPE_SECRET_KEY=' + 'sk_' + 'live_' + '51QaBcDeFgHiJkLmNoPqRsTuVwXyZ0123',
      'SUPABASE_SERVICE_ROLE=' + jwt('service_role'),
      'SUPABASE_ANON=' + jwt('anon'),
      'OPENAI_API_KEY=Zx8Kq2Lm9Vt4Rw7Yb3Nc6Hd1Fs5Gp0Jq',
      'DATABASE_URL=postgresql://postgres:password@db.example.com:5432/prod',
    ].join('\n'),
  ),
  file(
    'supabase/migrations/0001_init.sql',
    [
      'create table public.profiles (',
      '  id uuid primary key,',
      '  user_id uuid not null,',
      '  full_name text',
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
    ].join('\n'),
  ),
  file(
    'src/server.js',
    [
      "const cors = require('cors');",
      "app.use(cors({ origin: '*', credentials: true }));",
      "res.setHeader('Access-Control-Allow-Origin', '*');",
      "res.setHeader('Access-Control-Allow-Credentials', 'true');",
    ].join('\n'),
  ),
  file(
    'src/lib/jwt.js',
    [
      "const jwt = require('jsonwebtoken');",
      'function checkUser(token) {',
      '  const payload = jwt.decode(token);',
      '  return payload;',
      '}',
    ].join('\n'),
  ),
  file(
    'src/routes/session.js',
    [
      "const jwt = require('jsonwebtoken');",
      'function verifyUser(token) {',
      '  return jwt.verify(token, process.env.JWT_SECRET, { algorithms: ["none"] });',
      '}',
    ].join('\n'),
  ),
  file(
    'src/routes/debug.js',
    [
      "app.get('/api/debug', (req, res) => {",
      '  res.json({ env: process.env });',
      '});',
    ].join('\n'),
  ),
  file('dist/assets/index.js', 'console.log("hi");\n//# sourceMappingURL=assets/index-abc123.js.map\n'),
  file('.gitignore', 'node_modules\ndist\n'),
];

rule();
line('3. FINDINGS PRODUCED BY EACH CHECK (fixture project)');
rule();

const report = S.scan.scanProject({ files: FIXTURES, label: 'vulnerable-app-fixture' });

for (const check of report.checks) {
  const own = report.findings.filter((f) => f.checkId === check.id);
  line(`  ${check.title}  [${check.state}]`);
  if (!own.length) {
    line('    (no findings)');
  }
  for (const finding of own) {
    line(`    - ${finding.severity.padEnd(8)} ${finding.title}`);
    line(`      where: ${finding.location}`);
  }
  line();
}

rule();
line('4. SCORE');
rule();
line(`  score            : ${report.score}/100`);
line(`  verdict          : ${report.verdict}`);
line(`  plain verdict    : ${report.verdictPlain}`);
line(
  `  counts           : critical=${report.counts.CRITICAL} high=${report.counts.HIGH} ` +
    `medium=${report.counts.MEDIUM} low=${report.counts.LOW} info=${report.counts.INFO}`,
);
line(`  hasCritical      : ${report.hasCritical}`);
line();
line('  Plain-English summary:');
line(`  ${S.lib.report.buildPlainSummary(report)}`);
line();
line('  Top 5:');
for (const item of S.lib.report.buildTopFive(report)) {
  line(`   ${item.rank}. [${item.severity}] ${item.title}`);
}
line();

/* ------------------------------------------------------------------ */
/* 5. no network calls anywhere in the folder                           */
/* ------------------------------------------------------------------ */

rule();
line('5. NETWORK CALL AUDIT (no fetch / XHR / WebSocket / CDN)');
rule();

const NETWORK_PATTERNS = [
  /\bfetch\s*\(/,
  /\bXMLHttpRequest\b/,
  /\bWebSocket\b/,
  /\bnavigator\.sendBeacon\b/,
  /\bEventSource\b/,
  /\bimportScripts\s*\(/,
  /\bnavigator\.connection\b/,
  /https?:\/\/[^\s'"`)]+/,
];

async function walk(dir) {
  const out = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await walk(full)));
    else out.push(full);
  }
  return out;
}

const allFiles = await walk(root);
let networkHits = 0;
let remoteLinkHits = 0;

for (const filePath of allFiles) {
  const rel = path.relative(root, filePath).replace(/\\/g, '/');
  if (!/\.(js|html|css)$/.test(rel)) continue;
  // dev/ holds the node verification scripts, not part of the shipped tool.
  if (rel.startsWith('dev/')) continue;
  const content = await readFile(filePath, 'utf8');
  const lines = content.split('\n');

  lines.forEach((text, index) => {
    const trimmed = text.trim();
    if (trimmed.startsWith('*') || trimmed.startsWith('//') || trimmed.startsWith('<!--')) return;
    for (const pattern of NETWORK_PATTERNS) {
      if (!pattern.test(text)) continue;
      // A URL inside a comment or a string that is documentation is not a
      // request; a real API call is. Report both, let the reader judge.
      if (pattern.source.includes('https?:\\/\\/')) {
        if (/<(?:script|link)[^>]+(?:src|href)=["']https?:/i.test(text)) {
          remoteLinkHits += 1;
          line(`  REMOTE ASSET  ${rel}:${index + 1}  ${trimmed.slice(0, 110)}`);
        }
        continue;
      }
      networkHits += 1;
      line(`  NETWORK CALL  ${rel}:${index + 1}  ${trimmed.slice(0, 110)}`);
    }
  });
}

line(`  network calls found  : ${networkHits}`);
line(`  remote assets found  : ${remoteLinkHits}`);
line('  (dev/ is excluded: those are the node verification scripts, not shipped code)');
line();

/* ------------------------------------------------------------------ */
/* summary                                                              */
/* ------------------------------------------------------------------ */

rule();
const ok = importFailures === 0 && outcome.failed === 0 && networkHits === 0 && remoteLinkHits === 0;
if (ok) {
  line('ALL CHECKS PASSED');
} else {
  line(
    `FAILED: ${importFailures} import error(s), ${outcome.failed} self-test failure(s), ` +
      `${networkHits} network call(s), ${remoteLinkHits} remote asset(s)`,
  );
}
rule();

process.exit(ok ? 0 : 1);
