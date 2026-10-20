/**
 * checks/debug-routes.js
 * ---------------------------------------------------------------------------
 * CHECK 6 - debug routes, exposed development files and dev-only settings.
 *
 * WHY THIS MATTERS: AI assistants happily add a "/api/debug" route while
 * building, and forget to remove it. Those routes usually dump the process
 * environment - which is exactly where the database admin key lives. They are
 * also a map for an attacker: they tell them which library and which version
 * of everything you are running.
 *
 * We look for:
 *  - debug / test / internal routes
 *  - serving the project folder (which publishes .env)
 *  - source maps in production builds
 *  - dev flags in next.config.js and friends
 *  - DEBUG=true defaults
 *  - GraphQL introspection left enabled
 */

import { makeFinding, makePass } from '../lib/findings.js';
import { countLines } from '../lib/secrets.js';
import { isCodeFile } from '../lib/fs-walk.js';
import { DEBUG_ROUTE } from './authz.js';

export const id = 'debug-routes';
export const title = 'Debug routes, exposed dev files and development settings';
export const severity = 'MEDIUM';

/** Keywords that suggest a debug route also exposes sensitive material. */
const SENSITIVE_HINTS = /(process\.env|secret|token|key|password|database|supabase|config|credentials|pool)/i;

export function run(context) {
  const findings = [];
  const codeFiles = context.files.filter(
    (file) => isCodeFile(file) && file.content,
  );

  for (const file of codeFiles) {
    const content = file.content;

    // ------------------------------------------------------ debug routes
    const routeRegex = new RegExp(DEBUG_ROUTE.source, 'gi');
    for (const match of content.matchAll(routeRegex)) {
      const route = match[1];
      const line = countLines(content, match.index);
      const window = content.slice(match.index, match.index + 900);
      const exposesSecrets = SENSITIVE_HINTS.test(window);
      findings.push(
        makeFinding({
          severity: exposesSecrets ? 'HIGH' : 'MEDIUM',
          title: `Debug or test route exposed: ${route}`,
          detail:
            `The route "${route}" is registered in your application.` +
            (exposesSecrets
              ? ' The handler also touches environment variables, keys or the database, so it can leak sensitive ' +
                'information to anybody who requests it.'
              : ' Debug routes are usually left over from development. They tell an attacker which libraries and ' +
                'versions you run, and they sometimes expose data.'),
          plain: exposesSecrets
            ? 'Your app has a hidden web page for testing that can show internal information to anyone who finds it.'
            : 'Your app still has a leftover testing web page that should not be on a live site.',
          location: `${file.relPath}:${line}`,
          remediation:
            'Delete the route before going live. If you still need it, protect it instead:\n\n' +
            '    app.get("/api/debug", (req, res) => {\n' +
            '      if (process.env.NODE_ENV === "production") return res.sendStatus(404);\n' +
            '      if (req.headers["x-debug-token"] !== process.env.DEBUG_TOKEN) return res.sendStatus(403);\n' +
            '      res.json({ ok: true });\n' +
            '    });\n\n' +
            'Never return process.env itself from a route - it contains your admin keys.',
          evidence: context.window(content, match.index, 10),
          cwe: 'CWE-489',
        }),
      );
    }

    // ------------------------------- serving the whole project folder
    const staticRegex = /express\s*\.\s*static\s*\(\s*([^)]{0,60})\)/g;
    for (const match of content.matchAll(staticRegex)) {
      const argument = match[1] || '';
      const servesProjectRoot =
        /^\s*['"]\.['"]\s*$/.test(argument) ||
        /__dirname\s*\)?\s*$/.test(argument) &&
          !/['"][^'"]*(public|static|dist|build|assets)['"]/i.test(argument);
      if (!servesProjectRoot) continue;
      const line = countLines(content, match.index);
      findings.push(
        makeFinding({
          severity: 'HIGH',
          title: `The whole project folder is served publicly (${file.relPath})`,
          detail:
            'express.static() is pointed at the project root, which means a request for "/.env" or "/package.json" ' +
            'returns those files. Your .env contains the database admin key and the payment keys.',
          plain:
            'Your app will hand out your secret password file to anyone who asks for the right web address.',
          location: `${file.relPath}:${line}`,
          remediation:
            'Serve only the folder that holds the public files:\n\n' +
            '    // instead of express.static(".")\n' +
            '    app.use(express.static(path.join(__dirname, "public")));\n' +
            '    // and if you must serve the project root, hide the sensitive files:\n' +
            '    // app.use(express.static(__dirname, { dotfiles: "deny" }));\n\n' +
            'Also add this guard so a leaked .env can never be served:\n\n' +
            '    app.use((req, res, next) => {\n' +
            '      if (/^\\/?\\.env/i.test(req.path)) return res.sendStatus(404);\n' +
            '      next();\n' +
            '    });',
          evidence: context.window(content, match.index, 6),
          cwe: 'CWE-548',
        }),
      );
    }

    // ------------------------------------------- .env served explicitly
    const envServe = /(?:sendFile|res\.send|createReadStream)\s*\([^)]*['"`][^'"`]*\.env/g;
    for (const match of content.matchAll(envServe)) {
      const line = countLines(content, match.index);
      findings.push(
        makeFinding({
          severity: 'CRITICAL',
          title: `Code serves a .env file over HTTP (${file.relPath})`,
          detail:
            'The application explicitly reads and sends your environment file. Everything in it - including the ' +
            'service_role key and payment keys - is downloadable by anyone.',
          plain: 'Your app publishes its own secret password file to the internet.',
          location: `${file.relPath}:${line}`,
          remediation: 'Delete this code path. Never send .env over HTTP.',
          evidence: context.window(content, match.index, 6),
          cwe: 'CWE-200',
        }),
      );
    }

    // ------------------------------------------------------ DEBUG = true
    const debugDefault =
      /(?:process\.env\.DEBUG\s*=\s*['"]true['"]|DEBUG\s*[:=]\s*true\b|['"]debug['"]\s*:\s*true)/gi;
    for (const match of content.matchAll(debugDefault)) {
      const line = countLines(content, match.index);
      findings.push(
        makeFinding({
          severity: 'LOW',
          title: `Debug output is switched on by default (${file.relPath})`,
          detail:
            'Debug logging left enabled in production often prints request details, SQL queries or user data into ' +
            'your logs, which are often less protected than the database itself.',
          plain: 'Your app writes extra debug information into its logs, which may include your users\' data.',
          location: `${file.relPath}:${line}`,
          remediation:
            'Make debug output opt-in and never enable it in production:\n\n' +
            '    const isDebug = process.env.DEBUG === "true" && process.env.NODE_ENV !== "production";',
          evidence: context.window(content, match.index, 4),
          cwe: 'CWE-532',
        }),
      );
    }

    // ------------------------------------------------ GraphQL introspection
    if (/\b(introspection|ApolloServer|makeExecutableSchema|buildSchema)\b/.test(content)) {
      const introspectionOff = /introspection\s*[:=]\s*false/i.test(content);
      const line = countLines(content, 0);
      if (!introspectionOff) {
        findings.push(
          makeFinding({
            severity: 'LOW',
            title: `GraphQL introspection appears to be enabled (${file.relPath})`,
            detail:
              'Introspection lets anybody list your entire API - every query, every field, every type. It makes ' +
              'reconnaissance trivial and is rarely needed by a production app.',
            plain:
              'Your API publishes a full map of everything it can do, which helps someone find the weak spots.',
            location: `${file.relPath}:${line}`,
            remediation:
              'Turn introspection off in production:\n\n' +
              '    const server = new ApolloServer({\n' +
              '      typeDefs,\n' +
              '      resolvers,\n' +
              '      introspection: process.env.NODE_ENV !== "production",\n' +
              '    });',
            evidence: 'GraphQL server detected without an explicit "introspection: false" setting.',
            cwe: 'CWE-200',
          }),
        );
      }
    }

    // ------------------------------------------- next.config dev settings
    if (/^next\.config\./i.test(file.name)) {
      const sourceMapFlag = /productionBrowserSourceMaps\s*:\s*true/i.test(content);
      if (sourceMapFlag) {
        const line = countLines(content, content.search(/productionBrowserSourceMaps/i));
        findings.push(
          makeFinding({
            severity: 'MEDIUM',
            title: 'next.config publishes browser source maps in production',
            detail:
              'Browser source maps let anyone reconstruct your original source code from the site, including any ' +
              'secrets or logic you did not intend to publish.',
            plain: 'Your website publishes a file that lets anyone rebuild a readable copy of your app\'s code.',
            location: `${file.relPath}:${line}`,
            remediation:
              'Remove the flag from next.config.js:\n\n' +
              '    // delete this line\n' +
              '    productionBrowserSourceMaps: true,\n\n' +
              'Then delete the .next folder and rebuild.',
            evidence: context.window(content, content.search(/productionBrowserSourceMaps/i), 4),
            cwe: 'CWE-540',
          }),
        );
      }
      const ignoreBuildErrors = /ignoreBuildErrors\s*:\s*true/i.test(content);
      if (ignoreBuildErrors) {
        const line = countLines(content, content.search(/ignoreBuildErrors/i));
        findings.push(
          makeFinding({
            severity: 'LOW',
            title: 'next.config ignores build errors',
            detail:
              'Skipping type and build errors lets the app ship with problems that would normally stop the build - ' +
              'including accidentally broken authorisation checks.',
            plain:
              'Your project is configured to ship even when the code has errors, so small problems can slip through.',
            location: `${file.relPath}:${line}`,
            remediation:
              'Remove "typescript: { ignoreBuildErrors: true }" and "eslint: { ignoreDuringBuilds: true }" and fix ' +
              'the reported errors before shipping.',
            evidence: context.window(content, content.search(/ignoreBuildErrors/i), 4),
            cwe: 'CWE-710',
          }),
        );
      }
    }
  }

  // --------------------------------------------------- source map files
  //
  // Two related symptoms, one finding: the .map files themselves, and the
  // "sourceMappingURL" comments in the built JavaScript that point at them.
  const mapFiles = context.files.filter((file) => file.ext === '.map');
  const mapReferences = context.files.filter(
    (file) => file.category === 'bundle' && file.content && file.content.includes('sourceMappingURL'),
  );
  if (mapFiles.length || mapReferences.length) {
    const locations = [
      ...mapFiles.map((f) => f.relPath),
      ...mapReferences.map((f) => f.relPath),
    ];
    findings.push(
      makeFinding({
        severity: 'MEDIUM',
        title: `Source maps are published with the build (${locations.length} file(s))`,
        detail:
          'Source maps contain the full original source of your application. If they are deployed, anybody can read ' +
          'your code, including secrets that were supposed to be server-side.',
        plain:
          'Your published website includes files that reveal the full original source code of your app.',
        location: locations.slice(0, 5).join(', '),
        remediation:
          'Stop shipping source maps to production (build.sourcemap = false in Vite, remove ' +
          'productionBrowserSourceMaps from next.config.js), delete the build folder and rebuild.',
        evidence: locations.slice(0, 20).join('\n'),
        cwe: 'CWE-540',
      }),
    );
  }

  if (!findings.length) {
    findings.push(
      makePass(
        'No debug routes or exposed development settings found',
        `Reviewed ${codeFiles.length} code file(s) for debug/test routes, public static folders, source maps, ` +
          'debug defaults and GraphQL introspection.',
        codeFiles.length ? '' : context.root,
      ),
    );
  }

  return findings;
}

export function status(context) {
  const codeFiles = context.files.filter((file) => file.category === 'source' && file.content);
  if (!codeFiles.length) {
    return { state: 'skip', notes: ['No source code files were found to review.'] };
  }
  return { state: 'unknown', notes: [] };
}
