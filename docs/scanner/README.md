# AI Ship Check - the browser security scanner

A free, **100% client-side** security scanner for AI-built apps. Drop a project
folder onto the page, get a ship-readiness score, a plain-English summary and a
copy-paste fix prompt for every finding.

**Your code never leaves this browser.** There is no `fetch`, no `XMLHttpRequest`,
no `WebSocket`, no analytics, no telemetry, no CDN, no cookies and no server.
Open the page source and check - or run `node dev/verify.js`, which greps the
whole folder for network calls and fails if it finds one.

- No build step, no bundler, no npm dependencies.
- Works when the folder is served over http(s) **and** when `index.html` is
  opened directly from the filesystem (`file://`).
- Open `self-test.html` to verify the scanner against inline fixtures. It
  prints `ALL CHECKS PASSED` when every check behaves as documented.

---

## How to use it

1. Open `index.html` (double-click it, or deploy the folder - see below).
2. Drop your project folder onto the drop zone, or press <kbd>Enter</kbd> on it
   and pick a folder, or use **Choose files instead** to select individual
   files.
3. Wait a second or two. You get the score, the summary, the top five fixes and
   the full list of findings.
4. Hit **Copy the whole report (Markdown)** and paste it into Cursor, Lovable,
   Bolt or ChatGPT - every finding also has its own copy-paste fix prompt.

Nothing is uploaded. The files are read with the browser's own File API
(`<input type="file" webkitdirectory>` for folders, the Directory Entries API
for dropped folders) and analysed in memory.

If a dropped folder cannot be read, the tool says so in a **"Things we could
not read"** panel instead of silently skipping it.

---

## What it checks

The detection logic is ported from the CLI auditor in `../audit/`, with the
same severities, the same wording and the same scoring model.

| # | Check | What it looks for | Severities |
|---|-------|-------------------|------------|
| 1 | **Hard-coded secrets** | Stripe live/restricted/test keys, Supabase `service_role` JWTs (CRITICAL) and `anon` JWTs (INFO only - that key is public by design), AWS access key IDs and secret access keys, Slack and Discord webhook URLs, GitHub / npm / Anthropic / OpenAI / Google / SendGrid keys, private key blocks, Firebase service-account keys, and generic assignments to any variable named `*SECRET*`, `*TOKEN*`, `*PASSWORD*`, `*API_KEY*` when the value is long and random-looking. Also probes built bundles for `service_role`, `sk_live_` and private key material. | CRITICAL / HIGH / MEDIUM / INFO |
| 2 | **Environment files** | A live `.env` / `.env.local` that your `.gitignore` does not cover (HIGH), and a `.gitignore` that never mentions `.env` at all (MEDIUM). | HIGH / MEDIUM |
| 3 | **Postgres Row Level Security** | `CREATE TABLE` with no matching `ALTER TABLE ... ENABLE ROW LEVEL SECURITY`; `SECURITY DEFINER` functions with no `SET search_path`; permissive policies (`USING (true)` / `WITH CHECK (true)`); `GRANT ... TO anon` on an unprotected table; RLS enabled with no policies at all; tables the app uses that have no migration in your project. | CRITICAL / HIGH / MEDIUM / LOW |
| 4 | **JWT verification** | `alg: "none"` and `algorithms: ["none"]` (CRITICAL), `jwt.decode()` used where `jwt.verify()` was needed (HIGH), `jwt.verify()` without an algorithm allowlist (MEDIUM), signing secrets that fall back to a hard-coded default (HIGH). | CRITICAL / HIGH / MEDIUM |
| 5 | **CORS** | `Access-Control-Allow-Origin: *` **together with** `Access-Control-Allow-Credentials: true` (CRITICAL), wildcard origin on its own (HIGH), a reflected `Origin` header (HIGH), `cors({ origin: '*' })` / `cors({ origin: true })` (HIGH). | CRITICAL / HIGH / MEDIUM |
| 6 | **Debug routes and dev leftovers** | Routes matching `/api/debug`, `/api/test`, `/api/dev`, `/api/_internal` and the wider `app.get('/debug')` family; `express.static(".")` serving the whole project folder; code that sends a `.env` over HTTP; `DEBUG=true` defaults; GraphQL introspection left on; `next.config` source-map and ignore-build-error flags; source maps and `sourceMappingURL` references in the build. | CRITICAL / HIGH / MEDIUM / LOW |

Secrets are **always redacted**: a finding shows a short prefix and the length
(`sk_live_51********[REDACTED len=35]`), never a usable credential. The
self-test asserts that the raw key never reaches the report.

### How the score works

Ported exactly from `audit/lib/severity.js`:

```
score = 100 - (25 x critical) - (12 x high) - (4 x medium) - (1 x low)   (floored at 0)
```

| Score | Verdict |
|-------|---------|
| 90+ | Ready to ship |
| 70-89 | Ship after fixing high findings |
| 40-69 | Do not ship yet |
| below 40 | Unsafe to ship |

**One CRITICAL finding caps the verdict at "Do not ship yet"**, whatever the
score. A project can score 90+ because it is big and tidy and still contain
one critical hole; the report will not call that "ready".

INFO findings (for example the public Supabase anon key) and "check passed"
notes never move the score.

---

## What this does NOT check

The report has its own **"What this does NOT check"** section, in the UI and in
the Markdown. It says the same thing, so nobody has to guess:

- **Your live website and server.** No HTTP request is made to your app, so
  the scanner cannot see the security headers your server really returns
  (CSP, HSTS, X-Frame-Options), your TLS setup, DNS or hosting configuration.
- **Known vulnerabilities in your dependencies.** There is no `npm audit` and
  no CVE lookup for `package.json`.
- **Your git history.** A browser cannot read `.git`, so the scanner cannot
  tell you whether a secret was committed and later deleted, and it cannot
  confirm that your `.env` is already tracked. It can only read your
  `.gitignore` rules.
- **Runtime behaviour.** The scanner reads code, it does not run it. Broken
  authorisation, leaky API responses and business-logic bugs only show up when
  the app runs.
- **Anything outside the folder you picked.** A separate backend service, a
  mobile app or a second Supabase project would not be covered.
- **A penetration test.** This is a focused review of the code you gave us.

### What the browser version cannot do that the CLI can

| Check | CLI (`../audit/`) | Browser |
|-------|-------------------|---------|
| `npm audit` / CVE lookup on dependencies | yes | no |
| API-route authorisation audit (`checks/authz.js`) | yes | no |
| Live-site probing: real security headers, TLS, live Supabase endpoints | yes (opt-in, with `--i-have-authorization`) | no |
| Git history scan (secrets deleted but still recoverable) | yes | no |
| "Is this `.env` actually tracked by git?" | yes (`git ls-files`) | no - only `.gitignore` rules |
| Source files, SQL, secrets, JWT, CORS, debug routes | yes | **yes - identical logic and severities** |

The CLI is the paid product: it reaches further because it runs on a machine
that has git, npm and (with permission) network access. The browser scanner is
the free lead magnet: it proves the value in ten seconds, on private code,
with nothing to install.

---

## Deploying it for free

The folder is plain static files. Upload the `scanner/` folder as it is - no
build command, no environment variables, no server-side anything.

### Netlify (free tier)

1. Push the repo to GitHub and create a new Netlify site from it, or use
   **Add new site -> Deploy manually** and drag the `scanner/` folder onto the
   page.
2. Build settings: **Build command**: leave empty. **Publish directory**:
   `scanner` (or `site/scanner` if you deploy the whole `site/` folder).
3. Deploy. You get a `https://<name>.netlify.app` URL.

### GitHub Pages (free)

1. Create the repo, put the `scanner/` folder at the root (or in `/docs`).
2. **Settings -> Pages -> Build and deployment -> Source: Deploy from a
   branch**, branch `main`, folder `/ (root)` or `/docs`.
3. The site is served from `https://<user>.github.io/<repo>/`.

### Cloudflare Pages (free)

1. **Create a project -> Connect to Git** (or **Direct Upload**, drag the
   `scanner/` folder in).
2. Build settings: **Build command**: leave empty. **Build output directory**:
   `scanner` (or `site/scanner`).
3. Deploy.

Any other static host works exactly the same way - it is just HTML, CSS and
ES modules.

> `package.json` in this folder exists only so the Node verification script can
> treat the `.js` files as ES modules. It declares **no dependencies** and no
> build step, and static hosts ignore it.

---

## File layout

```
site/scanner/
├── index.html            the app (drop zone, results, scope section)
├── scanner.css           the theme - the colour tokens are copied from site/styles.css
├── app.js                ES-module entry point (served mode)
├── app.core.js           the app implementation (classic script)
├── checks.js             ES-module facade: every check, re-exported
├── scan.js               ES-module facade: the scan engine
├── self-test.html        the fixture-based test page
├── self-test.js          ES-module entry point for the self-test
├── self-test.core.js     the self-test implementation
├── lib/                  util, severity, secrets, sql, findings, evidence, report, files
├── checks/               secrets, env-committed, rls, jwt, cors, debug-routes
├── dev/verify.js         the Node verification harness (not part of the shipped tool)
├── dev/serve.js          a tiny local static server, for clicking through the UI
├── package.json          "type": "module" only - no dependencies
└── README.md
```

### Why there are two files per module

Browsers refuse to load **ES modules over `file://`** (the scheme reports a
null origin and module fetches are subject to CORS). A tool that claims to
work by double-clicking `index.html` therefore cannot rely on ES modules
alone.

So each module exists twice:

- `name.core.js` - the implementation. A classic script that publishes itself
  on `globalThis.SCANNER`. It has no `import`/`export`, which means it is
  valid both as a classic script **and** as an ES module.
- `name.js` - a thin ES-module facade that imports the core file and
  re-exports its API. This is what the served build imports, and what the
  Node tests import.

`index.html` decides at runtime: on `file://` it loads the core files as
classic scripts in order, over http(s) it loads `app.js` as a module. **One
implementation, two loaders, no build step.** `dev/verify.js` replays the
classic-script order in a bare V8 context and scans a fixture with it, so the
`file://` path is tested too, not just the served one.

---

## Verifying it

### In the browser

Open `self-test.html`. It runs the real detection logic against small inline
fixtures (a bad `.env`, a bad `.sql` migration, a CORS snippet, a JWT snippet,
a debug route) and prints PASS/FAIL per expectation, ending with:

```
ALL CHECKS PASSED (25/25)
```

### In Node

```
cd site/scanner
node dev/verify.js
```

That harness:

1. imports every module and prints its exports (proves there are no import
   errors),
2. runs the same self-test suite the browser page runs,
3. prints every finding each check produces for a vulnerable fixture project,
   plus the resulting score, verdict and plain-English summary,
4. greps the whole folder for `fetch` / `XMLHttpRequest` / `WebSocket` /
   `sendBeacon` / `EventSource` / remote assets and fails if it finds any,
5. walks the import graph of `app.js`, `scan.js` and `self-test.js` and
   requires that every check module is reachable,
6. replays the `file://` classic-script load order in a bare V8 context and
   runs a real scan in it.

It exits `0` and prints `ALL CHECKS PASSED` when everything is green.

### Clicking through the UI locally

```
cd site/scanner
node dev/serve.js          # http://localhost:8123
```

`dev/serve.js` is a development convenience only. The deployed tool is a folder
of static files with no server at all.

---

## Browser support

Chrome, Edge, Firefox and Safari, current versions. The folder picker needs
`webkitdirectory` (all of them) and the drag-and-drop folder support uses
`DataTransferItem.webkitGetAsEntry` (all of them); if a browser does not
expose it, the page falls back to the plain file list and says so.

## Licence

Part of the security-review service. The detection patterns are ported from the
CLI auditor in `../audit/`.
