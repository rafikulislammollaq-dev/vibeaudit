/**
 * build-fixture.mjs - materialise the deliberately-insecure demo project.
 *
 * WHY THE SECRETS ARE GENERATED AT RUNTIME INSTEAD OF BEING COMMITTED:
 *
 * This tool is published. GitHub's push protection refuses any push that
 * contains a string shaped like a live credential - even a fabricated one -
 * and it scans git history as well as the tip. A demo fixture full of
 * realistic-looking keys would therefore make the repository impossible to
 * publish, which defeats the purpose of shipping the tool in the first place.
 *
 * So the vulnerable files are written here, at runtime, from values that are
 * constructed rather than stored. Nothing in the published tree contains a
 * credential-shaped literal, and the demo still exercises the exact detection
 * paths it is supposed to: a Supabase service_role JWT, a Stripe live key, an
 * AWS access key, a Slack webhook and a Stripe webhook secret.
 *
 * Everything below is fabricated. The keys grant access to nothing. The
 * Supabase project URL is not a real project.
 *
 * The builder is idempotent: if the fixture already has its files and its own
 * git repository, it does nothing.
 */

import { execFile } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const HERE = dirname(fileURLToPath(import.meta.url));

/** The vulnerable project the demo scans. */
export const FIXTURE_DIR = join(HERE, "vulnerable-app");

/** Run a command, never throw. */
function run(cmd, args, cwd) {
  return new Promise((res) => {
    execFile(cmd, args, { cwd, timeout: 30_000, windowsHide: true }, (error, stdout, stderr) => {
      res({ ok: !error, stdout: stdout || "", stderr: stderr || "" });
    });
  });
}

/** base64url, so the generated JWT looks like a JWT. */
const b64u = (s) => Buffer.from(s, "utf8").toString("base64url");

/**
 * Build a JWT-shaped string. The payload is what the scanner keys on
 * (role: service_role). The signature is not a signature for anything.
 */
function makeJwt(payload) {
  const header = b64u(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64u(JSON.stringify(payload));
  const signature = b64u("vibeaudit-demo-signature-grants-access-to-nothing");
  return `${header}.${body}.${signature}`;
}

/**
 * The credential-shaped values. Each is assembled from parts so that no
 * contiguous secret pattern appears in this source file.
 */
function buildSecrets() {
  const projectUrl = "https://" + "kqmztvbrxzuctewpmjyp" + ".supabase.co";

  const anonKey = makeJwt({
    role: "anon",
    iss: "supabase",
    iat: 1735689600,
    exp: 2000000000,
  });

  const serviceRoleKey = makeJwt({
    role: "service_role",
    iss: "supabase",
    iat: 1735689600,
    exp: 2000000000,
  });

  const stripeLiveKey = "sk_" + "live_" + "51QexampleEXAMPLEkeyEXAMPLEkey9876";
  const stripeWebhookSecret = "whsec_" + "9f2b1c4d6e8f0a1b3c5d7e9f0a1b2c3d";
  const openaiKey = "sk-" + "9aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AbCdEfGh";
  const awsAccessKeyId = "AKIA" + "IOSFODNN7EXAMPLE";
  const awsSecretAccessKey =
    "wJalrXUtnFEMI" + "/K7MDENG" + "/bPxRfiCYEXAMPLEKEY";
  const slackWebhook =
    "https://hooks." + "slack.com/services/T0A1B2C3D4/B0E1F2G3H4/aBcDeFgHiJkLmNoPqRsTuVwX";

  return {
    projectUrl,
    anonKey,
    serviceRoleKey,
    stripeLiveKey,
    stripeWebhookSecret,
    openaiKey,
    awsAccessKeyId,
    awsSecretAccessKey,
    slackWebhook,
  };
}

/** The .env file, as an AI code generator writes it. */
function envFile(s) {
  return `# ---------------------------------------------------------------------------
# DEMO FIXTURE - this file is deliberately insecure.
#
# It exists so that \`node audit/cli.js --demo\` shows what the tool finds in a
# typical Lovable / Bolt / v0 project. Every problem below is a real mistake
# that AI code generators make, and every one of them is detected by the
# scanner. Nothing in this folder is meant to be a good example.
#
# The values are generated at runtime by fixtures/build-fixture.mjs so that this
# repository can be published without shipping credential-shaped strings.
# ---------------------------------------------------------------------------

# Supabase - the project URL and the PUBLIC key.
# The public "anon" key is meant to be visible in the browser. That is fine.
VITE_SUPABASE_URL=${s.projectUrl}
VITE_SUPABASE_ANON_KEY=${s.anonKey}

# THIS KEY MUST NEVER BE HERE. The service_role key bypasses every
# Row Level Security policy in the database. It is committed to git.
SUPABASE_SERVICE_ROLE_KEY=${s.serviceRoleKey}

# Live payment key - can move real money.
STRIPE_SECRET_KEY=${s.stripeLiveKey}

# Internal Slack channel - anyone with this URL can post into it.
SLACK_WEBHOOK_URL=${s.slackWebhook}

# Cloud storage credentials.
AWS_ACCESS_KEY_ID=${s.awsAccessKeyId}
AWS_SECRET_ACCESS_KEY=${s.awsSecretAccessKey}

DATABASE_URL=postgresql://postgres:postgres@localhost:5432/postgres
JWT_SECRET=change-me-in-production
`;
}

/** The .env.local file, also committed, also leaking secrets. */
function envLocalFile(s) {
  return `# Local overrides - also committed, also containing live secrets.
VITE_SUPABASE_URL=${s.projectUrl}
SUPABASE_SERVICE_ROLE_KEY=${s.serviceRoleKey}
STRIPE_WEBHOOK_SECRET=${s.stripeWebhookSecret}
OPENAI_API_KEY=${s.openaiKey}
`;
}

/** The built client bundle, with the admin key baked in for every visitor. */
function bundleFile(s) {
  return `/**
 * dist/assets/index-a1b2c3.js - the built client bundle.
 *
 * DEMO FIXTURE: deliberately insecure. The admin key is baked into the
 * JavaScript that every visitor downloads, so anyone can copy it and read or
 * write every row in the database.
 */

const SUPABASE_URL = "${s.projectUrl}";
const SUPABASE_ANON_KEY = "${s.anonKey}";
const SUPABASE_SERVICE_ROLE_KEY = "${s.serviceRoleKey}";

export const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
export const config = { anonKey: SUPABASE_ANON_KEY, mode: "production" };
//# sourceMappingURL=index-a1b2c3.js.map
`;
}

/** The source map that ships alongside the bundle. */
function bundleMapFile(s) {
  return JSON.stringify(
    {
      version: 3,
      file: "index-a1b2c3.js",
      sources: ["webpack://_N_E/./src/lib/supabase.ts"],
      sourcesContent: [
        `// the client-side Supabase client\n` +
          `// SOURCEMAP LEAK: the admin key is visible in the map too.\n` +
          `export const SERVICE_ROLE = "${s.serviceRoleKey}";\n`,
      ],
      names: [],
      mappings: "AAAA",
    },
    null,
    2
  );
}

/**
 * Write the vulnerable files and make them genuinely committed.
 *
 * The inner git repository is the point: it is what turns "a .env file exists
 * on disk" into "a .env file is committed to git", which is the finding the
 * demo is built to show. It is created here rather than shipped, for the same
 * reason the secrets are generated - git objects inside the published tree
 * would make the repository unpublishable.
 */
export async function ensureFixture() {
  const envPath = join(FIXTURE_DIR, ".env");
  const gitDir = join(FIXTURE_DIR, ".git");

  if (existsSync(envPath) && existsSync(gitDir)) return FIXTURE_DIR;

  const s = buildSecrets();

  writeFileSync(envPath, envFile(s), "utf8");
  writeFileSync(join(FIXTURE_DIR, ".env.local"), envLocalFile(s), "utf8");

  const distDir = join(FIXTURE_DIR, "dist", "assets");
  mkdirSync(distDir, { recursive: true });
  writeFileSync(join(distDir, "index-a1b2c3.js"), bundleFile(s), "utf8");
  writeFileSync(join(distDir, "index-a1b2c3.js.map"), bundleMapFile(s), "utf8");

  // Initialise the fixture's own repository and commit the secrets to it.
  // Without git the scan still works - the .env is simply reported as
  // "present and not ignored" instead of "committed to git".
  if (!existsSync(gitDir)) {
    const init = await run("git", ["init", "-q", "-b", "main"], FIXTURE_DIR);
    if (init.ok) {
      await run("git", ["config", "user.email", "demo@vibeaudit.local"], FIXTURE_DIR);
      await run("git", ["config", "user.name", "vibeaudit demo"], FIXTURE_DIR);
      await run("git", ["add", "-A"], FIXTURE_DIR);
      await run(
        "git",
        ["commit", "-q", "-m", "Initial commit (this .env should not be here)"],
        FIXTURE_DIR
      );
    }
  }

  return FIXTURE_DIR;
}

// Allow running directly: node fixtures/build-fixture.mjs
if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  ensureFixture().then(
    () => console.log("fixture ready:", FIXTURE_DIR),
    (e) => {
      console.error("fixture build failed:", e && e.message);
      process.exit(1);
    }
  );
}
