# vibeaudit

**A security audit for the apps you built with AI.**

You shipped an app with Lovable, Bolt, Cursor, Replit, v0 or Supabase. It works.
It looks good. And you have a gnawing feeling about the security, because
nobody - including the AI that wrote the code - ever checked.

`vibeaudit` is a command line tool that checks an AI-built app for the exact
problems that AI-built apps have, and explains them in plain English with a
fix you can paste straight back into your AI assistant.

```
🚨 Unsafe to ship - 0/100  (12 critical, 20 high, 7 medium, 2 low)
```

---

## Who this is for

- **A non-technical founder** who launched an AI-built app and needs to know
  whether their customers' data is safe. You do not need to read code. The
  report starts with a paragraph in plain English, and every finding ends with
  a prompt you can paste into Lovable, Cursor, Bolt, Claude or ChatGPT.
- **A developer** who wants the machine-readable version: `--json` gives you
  every finding with a file, a line number, a CWE reference and a fix.

This is also the engine behind a freelance security-review service, so it is
built to be run on a client project end to end and produce something you can
send in an email.

## Why this exists (the numbers)

Real 2026 measurements of AI-built apps, which is what the checks target:

| Finding | Source |
|---|---|
| 63% of 62 scanned Lovable apps had critical or high severity vulnerabilities, with 10 findings per app on average | DEV.to, Jun 2026 |
| 18.5% of 400 public Lovable/Bolt/v0 repos had a committed `.env`; 59% had at least one critical issue | VibeSafe |
| 98% of apps behind a public Supabase URL had at least one exploitable flaw; 10.3% exposed real user data through missing Row Level Security | vibe-eval |
| 2,038 critical vulnerabilities and 400+ exposed credentials across 5,600 analysed vibe-coded apps | Escape DAST, Aug 2026 |
| `SECURITY DEFINER` functions without a safe `search_path` are the classic Postgres privilege-escalation path | Postgres documentation |

Those are the failure modes this tool looks for, in that order of severity.

---

## Install-free quickstart

There is **nothing to install**. Node.js 20 or newer is the only requirement -
no `npm install`, no dependencies, no build step.

```bash
# 1. See what it finds. Runs against a bundled, deliberately broken demo app.
node audit/cli.js --demo

# 2. Scan a real project.
node audit/cli.js --target ./my-lovable-app

# 3. Save the report to send to your client.
node audit/cli.js --target ./my-lovable-app --out report.md

# 4. Machine-readable output for a script or a CI job.
node audit/cli.js --target ./my-lovable-app --json > report.json
```

> Running it from inside this folder? Use `node cli.js --demo`.
> Running it from the parent folder? Use `node audit/cli.js --demo`.

### All the options

| Option | What it does |
|---|---|
| `-t, --target <folder>` | The project folder to scan. The main thing. |
| `-u, --url <url>` | The address of the live site. Enables the live checks (see the safety section). |
| `-o, --out <file>` | Write the Markdown report to a file instead of the terminal. |
| `--json` | Emit JSON instead of Markdown (also applies to `--out`). |
| `--i-have-authorization` | **Required** before any request is sent to `--url`. |
| `--demo` | Run against the bundled demo project. |
| `--no-history` | Skip the git history scan (a little faster). |
| `--fail-on-critical` | Exit with code 2 if a critical finding exists (for CI). |
| `-q, --quiet` | Print only the headline and the summary paragraph. |
| `-h, --help` | Full usage. |

**Exit codes:** `0` the scan completed, `1` the scan could not run,
`2` `--fail-on-critical` was used and a critical finding exists.

---

## What each check looks for

| # | Check | What it finds | Typical severity |
|---|---|---|---|
| 1 | `env-committed` | `.env`, `.env.local`, `.env.production` committed to git, or present and not excluded by `.gitignore` | HIGH |
| 2 | `secrets-source` | API keys, Stripe secret keys, Supabase `service_role` JWTs, AWS keys, private keys, Slack/Discord webhooks, Firebase service accounts - in source **and in git history** (deleted secrets that are still recoverable) | CRITICAL / HIGH |
| 3 | `live-supabase` | The Supabase admin key used in browser code, plus one authorised live read that proves whether a table is readable without signing in | CRITICAL |
| 4 | `rls` | `CREATE TABLE` without `ENABLE ROW LEVEL SECURITY`; `SECURITY DEFINER` without `SET search_path`; permissive `USING (true)` policies; `GRANT` to the `anon` role; tables used by the app that have no migration we could review | CRITICAL / HIGH |
| 5 | `authz` | `auth.getUser()` used without checking the result; `getSession()` on the server; a `user_id` or `role` trusted from a request body or from `localStorage`; admin endpoints with no role check | HIGH |
| 6 | `debug-routes` | `/api/debug`, `/api/test` and similar; `express.static('.')` (which publishes `/.env`); source maps in production; `next.config` dev flags; `DEBUG=true` defaults; GraphQL introspection left on | MEDIUM / HIGH |
| 7 | `secrets-bundle` | `service_role`, live Stripe keys, private keys and AWS keys inside the built client bundle (`dist/`, `build/`, `.next/`, `out/`) | CRITICAL |
| 8 | `cors` | `Access-Control-Allow-Origin: *` combined with credentials; a reflected `Origin`; `cors({ origin: '*' })` | CRITICAL / HIGH |
| 9 | `live-headers` | Missing HSTS, CSP, `X-Content-Type-Options`, `Referrer-Policy`, `X-Frame-Options` on the live site | MEDIUM |
| 10 | `deps` | `npm audit --json --omit=dev` results mapped to severities, plus a curated list of dependency names that are bad defaults for AI-built apps (`jsonwebtoken` < 9, `jwt-decode`, `lodash` < 4.17.21, `minimist`, `axios`, `express`, `next`, `node-fetch`, `eval`) | MEDIUM / HIGH |
| 11 | `jwt` | `alg: "none"` accepted; `jwt.decode()` used where `jwt.verify()` was needed; a signing secret that falls back to a hard-coded value; `verify()` without an algorithm allowlist | CRITICAL / HIGH |

Every check also reports what it **checked and did not find**, so the client can
see the coverage rather than having to trust it.

---

## How the score works

The score starts at 100 and each finding deducts points:

| Severity | Points | Meaning |
|---|---|---|
| CRITICAL | 25 | Customer data or money is exposed, or an attacker can impersonate somebody |
| HIGH | 12 | A serious hole that a targeted attacker would find quickly |
| MEDIUM | 4 | Worth fixing before launch |
| LOW | 1 | Hygiene |
| INFO | 0 | Notes only (for example "this check passed") |

The score never goes below 0, and the verdict follows it:

| Score | Verdict |
|---|---|
| 90-100 | Ready to ship |
| 70-89 | Ship after fixing high findings |
| 40-69 | Do not ship yet |
| 0-39 | Unsafe to ship |

**One rule on top of that:** if there is even one CRITICAL finding, the verdict
is capped at "Do not ship yet". A large codebase with a handful of low-severity
findings can score 90+, but a single critical issue still blocks a launch -
a score must never be able to hide a problem that puts customer data at risk.

---

## Example output

```
# Security Audit - DEMO PROJECT

**Target:** `fixtures\vulnerable-app`  |  **Scanned:** 2026-10-20T08:11:50.305Z
**Tool:** vibeaudit v1.0.0  |  **Duration:** 0.1s

## 🚨 Ship readiness: 0/100 - Unsafe to ship

| Critical | High | Medium | Low |
|---|---|---|---|
| 12 | 20 | 7 | 2 |

> **At least one CRITICAL issue was found, so this project cannot be called
> ready to ship no matter how high the score is.**

## What this means, in plain English

We checked 16 files in your project for the security mistakes that AI-built
apps make most often - leaked passwords and keys, database tables that anyone
on the internet can read, and admin pages that are not protected. We found 40
issues - 12 serious problems, 20 important problems, 7 medium problems and 2
small problems. That gives a readiness score of 0 out of 100, which means the
app currently has serious security holes and should not be exposed to users or
real data until they are fixed. The most urgent one is: A powerful secret key
is sitting in your project files. Anyone who gets hold of it can act as you,
followed by stripe live secret key found in .env. All of these can be fixed
without rebuilding the app. We only looked at the files you gave us - we did
not test your live site, so the online parts of your app still need a separate
check.

## Top 5 things to fix first

### 1. 🔴 Supabase service_role key in source found in .env

**In plain English:** A powerful secret key is sitting in your project files.
Anyone who gets hold of it can act as you.

**Where:** `.env:17`

**Paste this into your AI assistant (Cursor, Lovable, Bolt, Claude...):**

```text
Fix this security issue in `.env:17`.

Issue: Supabase service_role key in source found in .env
What is wrong: The service_role key bypasses every Row Level Security policy.
Anyone holding it can read and write every table. The value below is redacted -
open the file on disk to see it.

Required fix: Remove the hard-coded value. Read it from an environment variable
at runtime and rotate the exposed key in the provider's dashboard immediately -
removing it from the code does not invalidate it.

Rules:
- Make the smallest change that fully fixes the issue.
- Do not weaken or remove existing authentication, authorisation or validation.
- Keep the current file structure, naming and code style.
- If the same pattern exists elsewhere in the project, fix it there too and
  tell me where.
- When you are done, show me the diff and explain in one sentence what changed.
```

...then the full list of findings grouped by severity, the checks that passed,
the checks that were skipped and why, and a methodology and scope appendix.
```

The full report is deliberately long: it is a deliverable you send to a
client, and every finding carries the file, the line, the evidence (always
**redacted**), a copy-pasteable fix and a ready-to-paste AI prompt.

---

## Using it on a client project

### 1. A cloned repository

```bash
git clone https://github.com/theirs/their-app.git
node audit/cli.js --target ./their-app --out audit-report.md
```

The tool reads the git history, so it can also tell you about secrets that were
deleted but are still recoverable from the commits.

### 2. A zip file

```bash
unzip their-app.zip -d ./their-app
node audit/cli.js --target ./their-app --out audit-report.md
```

No `.git` folder means the history is not scanned, and the report says so
explicitly rather than pretending the check passed.

### 3. A live site

```bash
node audit/cli.js --target ./their-app \
  --url https://their-app.com \
  --i-have-authorization \
  --out audit-report.md
```

This adds two live checks: the security response headers, and one single
read-only request that proves whether a database table is readable without
signing in.

### 4. What to send the client

`--out audit-report.md` produces a single self-contained Markdown file: the
headline, the plain-English summary, the top five, every finding with its fix,
the list of checks that passed, the list of checks that were skipped, and the
scope appendix. Send that file. Do not send the raw JSON - it is for
automation.

---

## Safety, authorisation and scope

**This tool only ever touches a system you are authorised to test.** Read this
before pointing it at anything that is not your own machine.

- The live-URL checks **require** both `--url <url>` and
  `--i-have-authorization`. Without the flag, those checks report **SKIPPED**
  with a note explaining why. They are never reported as passed.
- The tool only ever contacts the exact URL you passed. It does not follow
  links out of it, does not try other hostnames and does not scan ports.
- It **never brute forces**, never tries to guess an endpoint, never attempts
  to sign in, and never tries any password or token.
- It **never enumerates tables**. The single Supabase probe uses one table
  name that already appears in the project's own SQL files, and sends exactly
  one request: `GET {project-url}/rest/v1/{table}?select=*&limit=1` with the
  public anon key. No other table is tried.
- It **sends only reads**. Nothing is written, changed or deleted. The only
  other request it makes is a single `GET` to the root of the URL you supplied,
  to read the response headers.
- It reads a response body of at most 64 KB and never downloads the site.
- The `npm audit` step contacts the npm registry, and only the npm registry.

**Authorisation.** You must own the code and the site, or have written
permission from the owner. Passing `--i-have-authorization` is your
declaration that you have it. Keep the report private: it names the exact
files and functions that need fixing, which tells an attacker where to look.

**Data handling.** The tool runs entirely on your machine. It sends nothing
about your client's code to any third party. The only exception is
`npm audit`, which sends the package names and versions in `package.json` to
the npm registry - that is what the npm registry is for, but tell your client
before you run it on their repository.

---

## Project layout

```
audit/
  cli.js                  the command line entry point
  lib/
    severity.js           severity vocabulary, ranking, the scoring model
    fs-walk.js            gitignore-aware file walking and classification
    secrets.js            the credential pattern catalogue and redaction
    git.js                git ls-files / git log -p integration
    sql.js                Postgres analysis (tables, RLS, policies, functions)
    supabase.js           Supabase key and client/server side detection
    http.js               the ONLY place that touches the network
    context.js            the scan context every check receives
    runner.js             the audit engine
    report.js             Markdown and JSON rendering, the plain-English summary
    evidence.js           redacted code excerpts
    cli-args.js           argument parsing
  checks/                 one module per check: { id, title, severity, run }
  fixtures/vulnerable-app/  a small, deliberately insecure demo project
  test/                   node:test suite
```

### Adding a check

A check is one file in `checks/` exporting `{ id, title, severity, run }`:

```js
export const id = 'my-check';
export const title = 'What this check looks for';
export const severity = 'HIGH';

export function run(context) {
  const findings = [];
  for (const file of context.files) {
    // ... detect something ...
    findings.push(makeFinding({
      severity: 'HIGH',
      title: 'Something is wrong',
      detail: 'Why it matters, in a sentence.',
      plain: 'The same thing, for a founder who does not read code.',
      location: `${file.relPath}:42`,
      remediation: 'The exact fix, with a code snippet.',
      evidence: 'The offending code, with any secret redacted.',
    }));
  }
  return findings;
}
```

Register it in `checks/index.js` and it appears in the report, in the score and
in the passed/skipped sections automatically. `context` gives you the file
list, the git state, the parsed SQL, the Supabase configuration and a
`context.window()` helper for redacted code excerpts.

---

## Design decisions

- **Zero runtime dependencies.** Node 20+ and the standard library only
  (`node:fs`, `node:path`, `node:child_process`, `node:https`/`fetch`,
  `node:crypto`, `node:timers`). Nothing to install, nothing to audit, and the
  tool runs on a client machine without asking them to trust a package tree.
  The only external call the tool makes is `npm audit`, using the `npm` that
  is already installed.
- **Secrets are never printed.** Every secret in a finding is replaced with a
  short identifying prefix and `[REDACTED len=...]`. The report is going to be
  emailed and pasted into AI chat windows; a tool that leaks the key it found
  makes the problem worse.
- **The anon key is not a finding.** The Supabase anon key is public by
  design. Reporting it would train clients to ignore the report. What matters
  is whether Row Level Security actually protects the tables, which is why the
  tool sends one read to check.
- **The client-facing report is the product.** The engine is table stakes; the
  deliverable is a document a founder can read in five minutes and act on.
- **Skipped is not passed.** A check that could not run says so and says why.

---

## Running the tests

```bash
node --test test/
```

69 tests covering secret detection and redaction, committed `.env` detection
against a real temporary git repository, the RLS and `SECURITY DEFINER`
detection, CORS, the JWT checks, the severity model and scoring, the report
rendering, the demo fixture, the live-URL safety contract against a local
test server, and the CLI end to end (including `--out`).

> Node 22.6+ resolves a positional test-runner argument as a glob and then
> loads the matched path as a module, so `test/package.json` has a `main`
> entry pointing at `test/suite.js`. On Node 20 the same command finds the
> test files directly.

## Licence

MIT. The bundled demo fixture contains syntactically valid but non-functional
keys.
