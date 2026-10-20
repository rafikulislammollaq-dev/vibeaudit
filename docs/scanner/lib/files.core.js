/**
 * lib/files.core.js
 * ---------------------------------------------------------------------------
 * File classification for the browser scanner.
 *
 * PORTED from the CLI's `audit/lib/fs-walk.js` (the parts that decide what a
 * file IS), plus the browser-specific rules for what we are willing to read
 * into memory.
 *
 * The CLI walks a directory with .gitignore awareness. The browser cannot -
 * the File API hands us whatever the user picked, and we cannot ask git
 * anything - so the rules are simplified and the differences are stated in
 * the report ("What this does NOT check").
 */

(function (root) {
  'use strict';

  const S = (root.SCANNER = root.SCANNER || {});
  S.lib = S.lib || {};

  /** Directories that are never worth walking (dependencies, VCS, caches). */
  const SKIP_DIRS = new Set([
    '.git',
    '.svn',
    '.hg',
    '.bzr',
    'node_modules',
    'bower_components',
    'jspm_packages',
    '.yarn',
    '.pnpm-store',
    '.pnpm',
    'vendor',
    '.venv',
    'venv',
    '.tox',
    '__pycache__',
    '.pytest_cache',
    '.mypy_cache',
    '.ruff_cache',
    'coverage',
    '.nyc_output',
    '.cache',
    '.turbo',
    '.parcel-cache',
    '.sass-cache',
    '.gradle',
    '.m2',
    '.idea',
    '.vscode',
    'site-packages',
    'obj',
    'Pods',
    '.dart_tool',
    'DerivedData',
  ]);

  /** Build output folders - scanned on purpose (secrets ship in bundles). */
  const BUNDLE_DIRS = new Set(['dist', 'build', 'out', '.next', '.output', 'vercel', 'storybook-static']);

  /** File extensions we treat as text and therefore scan. */
  const TEXT_EXTENSIONS = new Set([
    '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.mts', '.cts',
    '.json', '.jsonc', '.json5', '.map', '.yaml', '.yml', '.toml', '.ini',
    '.conf', '.cfg', '.properties', '.env', '.sql', '.graphql', '.gql',
    '.html', '.htm', '.css', '.scss', '.sass', '.less', '.vue', '.svelte',
    '.astro', '.md', '.mdx', '.txt', '.sh', '.bash', '.zsh', '.ps1',
    '.py', '.rb', '.go', '.rs', '.php', '.java', '.kt', '.swift', '.cs',
    '.tf', '.tfvars', '.xml', '.svg', '.dockerfile', '.gitignore', '.npmrc',
    '.netrc', '.env.example', '.lock', '.prisma', '.drizzle',
  ]);

  /** Exact filenames that are always treated as text. */
  const TEXT_FILENAMES = new Set([
    'Dockerfile', 'Makefile', 'Procfile', 'docker-compose.yml', 'docker-compose.yaml',
    '.env', '.envrc', '.gitignore', '.npmrc', '.netrc', '.htpasswd', '.dockerignore',
  ]);

  /** Extensions that contain executable application code. */
  const CODE_EXTENSIONS = new Set([
    '.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.mts', '.cts',
  ]);

  /** Build-output path prefixes (always scanned). */
  const BUNDLE_PREFIXES = ['dist/', 'build/', 'out/', '.next/', '.output/', '.vercel/output/', 'public/build/'];

  /** Files larger than this are not read into memory (binary or generated). */
  const MAX_FILE_BYTES = 1_500_000;

  /** Hard ceiling on the number of files collected from one tree. */
  const MAX_FILES = 20_000;

  /**
   * Sensitive filenames that are always scanned even if a user excludes them.
   * A local `.env` holding a live Stripe key is still a live Stripe key.
   */
  const SENSITIVE_NAME_REGEX =
    /(^|\/)\.env($|\.)|\.(pem|key|p12|pfx|jks|keystore|asc)$|(^|\/)id_(rsa|dsa|ecdsa|ed25519)$|credential|secret/i;

  /**
   * Work out what a file "is" so checks can filter cheaply.
   * category: 'env' | 'sql' | 'bundle' | 'config' | 'source' | 'other'
   */
  function classifyFile(relPath, name) {
    const lower = String(name || '').toLowerCase();
    const posix = String(relPath || '').replace(/\\/g, '/');

    // Any `.env*` variant is treated as an environment file (including
    // .env.example). Examples are filtered out by the checks themselves, and
    // examples are still scanned for secrets: people paste real keys into
    // .env.example all the time.
    if (/^\.env($|\.)/.test(lower)) return 'env';
    if (lower.endsWith('.sql')) return 'sql';
    if (lower.endsWith('.map')) return 'bundle';

    const segments = posix.split('/');
    const inBundleDir = segments.some((seg, index) => index < segments.length - 1 && BUNDLE_DIRS.has(seg));
    if (inBundleDir) return 'bundle';
    if (BUNDLE_PREFIXES.some((prefix) => posix.startsWith(prefix))) return 'bundle';

    if (
      lower === 'package.json' ||
      lower.startsWith('next.config') ||
      lower.startsWith('vite.config') ||
      lower.startsWith('nuxt.config') ||
      lower.startsWith('svelte.config') ||
      lower.startsWith('astro.config') ||
      lower.startsWith('vercel.json') ||
      lower.startsWith('netlify.toml') ||
      lower === 'tsconfig.json' ||
      lower === 'tailwind.config.js' ||
      lower === 'tailwind.config.ts' ||
      lower === 'docker-compose.yml' ||
      lower === 'docker-compose.yaml' ||
      lower === 'Dockerfile'
    ) {
      return 'config';
    }

    const dot = lower.lastIndexOf('.');
    const ext = dot > 0 ? lower.slice(dot) : '';
    if (TEXT_EXTENSIONS.has(ext) || TEXT_FILENAMES.has(lower)) return 'source';
    return 'other';
  }

  /**
   * Is this record executable code (as opposed to documentation, data or
   * config)?
   *
   * WHY the distinction matters: a README that documents "alg: none" is not a
   * vulnerability, and a code checker that reports it teaches the client to
   * ignore the report.
   */
  function isCodeFile(record) {
    return CODE_EXTENSIONS.has(String(record.ext || '').toLowerCase());
  }

  /** Is this record a file we can safely read as text? */
  function isTextLike(record) {
    return (
      record.category === 'env' ||
      record.category === 'sql' ||
      record.category === 'source' ||
      record.category === 'bundle' ||
      record.category === 'config'
    );
  }

  /** Should this path always be scanned regardless of any user filter? */
  function isAlwaysScanned(relPath, name) {
    const posix = String(relPath || '').replace(/\\/g, '/');
    if (SENSITIVE_NAME_REGEX.test(posix)) return true;
    if (BUNDLE_PREFIXES.some((prefix) => posix.startsWith(prefix))) return true;
    const segments = posix.split('/');
    if (segments.some((seg) => BUNDLE_DIRS.has(seg))) return true;
    return false;
  }

  /** Build a file record from a browser File object. */
  function createFileRecord(input) {
    const relPath = String(input.relPath || '');
    const name = relPath.split('/').pop() || relPath;
    const dot = name.lastIndexOf('.');
    const ext = input.ext !== undefined ? input.ext : dot > 0 ? name.slice(dot) : '';
    return {
      relPath,
      name,
      ext: String(ext).toLowerCase(),
      size: input.size !== undefined ? input.size : (input.content || '').length,
      category: input.category || classifyFile(relPath, name),
      content: input.content === undefined ? null : input.content,
    };
  }

  /** Does this text look like a binary file that was mis-read as UTF-8? */
  function looksBinary(text) {
    if (!text) return false;
    const sample = text.slice(0, 8000);
    return sample.indexOf('\u0000') !== -1;
  }

  S.lib.files = {
    SKIP_DIRS,
    BUNDLE_DIRS,
    TEXT_EXTENSIONS,
    TEXT_FILENAMES,
    CODE_EXTENSIONS,
    BUNDLE_PREFIXES,
    MAX_FILE_BYTES,
    MAX_FILES,
    classifyFile,
    isCodeFile,
    isTextLike,
    isAlwaysScanned,
    createFileRecord,
    looksBinary,
  };
})(globalThis);
