/**
 * checks/authz.js
 * ---------------------------------------------------------------------------
 * CHECK 5 - authentication and authorisation smells in application code.
 *
 * WHY THIS MATTERS: AI assistants write the happy path. They call
 * `supabase.auth.getUser()`, take the result and use it - without checking
 * that it is not null. On the server they use `getSession()`, which reads a
 * cookie but does NOT re-validate the token, so a forged cookie is accepted.
 * And they trust a `user_id` or `role` that came from the request body or
 * from localStorage, which means any visitor can simply change it.
 *
 * We look for four things:
 *  1. `auth.getUser()` whose result is used without a null/error check
 *  2. `auth.getSession()` used in server-side code (should be getUser())
 *  3. Client code trusting a user_id / role that came from the request body
 *     or from browser storage
 *  4. Admin-looking endpoints with no role check
 */

import { makeFinding, makePass } from '../lib/findings.js';
import { countLines } from '../lib/secrets.js';
import { isCodeFile } from '../lib/fs-walk.js';

export const id = 'authz';
export const title = 'Authentication and authorisation mistakes in application code';
export const severity = 'HIGH';

/** A file is treated as server-side when it looks like backend code. */
export function isServerSideFile(relPath, content) {
  const path = String(relPath || '');
  if (/supabase\/functions|\/api\/|\/server\/|\/routes?\/|\/backend\/|\/controllers?\//i.test(path)) return true;
  if (/^(server|app|index|main)\.(js|mjs|ts)$/i.test(path)) return true;
  if (/\bDeno\./.test(content || '')) return true;
  if (/\bprocess\.env\b/.test(content || '') && /\b(express|fastify|koa|hono|req|res)\b/i.test(content || '')) return true;
  return false;
}

/** Does the file contain any guard that handles a missing/failed user? */
function hasUserGuard(content) {
  return (
    /if\s*\(\s*!\s*(user|data\s*\?\.\s*user|data\?\.\s*user)\b/i.test(content) ||
    /if\s*\(\s*error\b/i.test(content) ||
    /if\s*\(\s*!\s*error\b/i.test(content) ||
    /\bif\s*\(\s*user\s*===?\s*null/i.test(content) ||
    /\bif\s*\(\s*!session\b/i.test(content) ||
    /user\s*\?\.\s*id/.test(content) ||
    /throw\s+new\s+Error\s*\(\s*['"`]Unauthorized/i.test(content) ||
    /return\s+.*401/.test(content) ||
    /return\s+.*403/.test(content)
  );
}

/** Route registrations that look like they expose admin functionality. */
const ADMIN_ROUTE = /\b(?:app|router|server)\s*\.\s*(?:get|post|put|patch|delete|all|use)\s*\(\s*['"`]([^'"`]*admin[^'"`]*)['"`]/gi;

/** Route registrations that look like debug/test endpoints. */
export const DEBUG_ROUTE = /\b(?:app|router|server)\s*\.\s*(?:get|post|put|patch|delete|all|use)\s*\(\s*['"`]([^'"`]*(?:\/debug|\/__debug|\/_debug|\/debug\/|\/test|\/__test|\/dev-tools|\/internal|\/actuator|\/graphql-playground)[^'"`]*)['"`]/gi;

export function run(context) {
  const findings = [];
  const codeFiles = context.files.filter(
    (file) => isCodeFile(file) && file.content,
  );

  for (const file of codeFiles) {
    const content = file.content;
    const serverSide = isServerSideFile(file.relPath, content);

    // ---------------------------------------- 1. unchecked auth.getUser()
    const getUserRegex = /\.auth\s*\.\s*getUser\s*\(/g;
    for (const match of content.matchAll(getUserRegex)) {
      const line = countLines(content, match.index);
      const guarded = hasUserGuard(content);
      // Look at the immediate neighbourhood first: a guard directly after the
      // call counts even if the file has no other guard.
      const window = content.slice(match.index, match.index + 600);
      const localGuard =
        /if\s*\(\s*!\s*(user|data\s*\?\.\s*user|data\?\.\s*user|error)\b/i.test(window) ||
        /user\s*\?\.\s*id/.test(window) ||
        /\?\?\s*\{\s*\}/.test(window);
      if (guarded || localGuard) continue;

      findings.push(
        makeFinding({
          severity: 'HIGH',
          title: `auth.getUser() result is used without checking it succeeded (${file.relPath})`,
          detail:
            'getUser() returns { data, error }. If the request fails or the visitor is not signed in, data.user is ' +
            'null and data.user.id throws - or worse, the code continues with an undefined user and silently ' +
            'operates on the wrong account.',
          plain:
            'Your app uses the "who is this person" result without checking that the check actually succeeded, so ' +
            'the app can carry on with the wrong user or break in confusing ways.',
          location: `${file.relPath}:${line}`,
          remediation:
            'Always check the result before using it:\n\n' +
            '    const { data, error } = await supabase.auth.getUser();\n' +
            '    if (error || !data?.user) {\n' +
            '      return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401 });\n' +
            '    }\n' +
            '    const user = data.user;\n\n' +
            'Never use optional chaining on the user (user?.id) as the fix - that hides the failure instead of ' +
            'handling it.',
          evidence: context.window(content, match.index, 12),
          cwe: 'CWE-287',
        }),
      );
    }

    // --------------------------------------- 2. getSession() on the server
    if (serverSide) {
      const getSessionRegex = /\.auth\s*\.\s*getSession\s*\(/g;
      for (const match of content.matchAll(getSessionRegex)) {
        const line = countLines(content, match.index);
        findings.push(
          makeFinding({
            severity: 'HIGH',
            title: `auth.getSession() used in server-side code (${file.relPath})`,
            detail:
              'getSession() reads the session cookie but does NOT re-validate the signature of the token against ' +
              'your Supabase auth server. A modified cookie is accepted as valid. On the server you must use ' +
              'getUser(), which contacts the auth server and verifies the token.',
            plain:
              'This part of your app trusts a value that a visitor could have edited by hand, instead of asking the ' +
              'authentication service to verify it.',
            location: `${file.relPath}:${line}`,
            remediation:
              'Replace getSession() with getUser() in server-side code (Edge Functions, API routes, server actions):\n\n' +
              '    // Edge Function / API route / server action\n' +
              '    const { data: { user }, error } = await supabase.auth.getUser();\n' +
              '    if (error || !user) {\n' +
              '      return new Response("Unauthorized", { status: 401 });\n' +
              '    }\n\n' +
              'getSession() is only acceptable on the client, where it is only used to decide what to render.',
            evidence: context.window(content, match.index, 10),
            cwe: 'CWE-345',
          }),
        );
      }
    }

    // ------------------------- 3. trusting user_id / role from the client
    const bodyTrust =
      /\b(?:req|request)\s*\.\s*body\s*\.\s*(user_id|userId|role|is_admin|isAdmin|owner_id|account_id|org_id)\b/g;
    for (const match of content.matchAll(bodyTrust)) {
      const line = countLines(content, match.index);
      findings.push(
        makeFinding({
          severity: 'HIGH',
          title: `Server trusts a client-supplied "${match[1]}" value (${file.relPath})`,
          detail:
            'The value comes from the request body, which the caller controls. Any visitor can change it in the ' +
            'browser developer tools and send a request as a different user, or as an admin.',
          plain:
            'Your app believes a value that the visitor sends in, and a visitor can edit that value to act as ' +
            'somebody else.',
          location: `${file.relPath}:${line}`,
          remediation:
            'Ignore the client-supplied identifier and derive it from the verified session:\n\n' +
            '    const { data: { user }, error } = await supabase.auth.getUser();\n' +
            '    if (error || !user) return new Response("Unauthorized", { status: 401 });\n' +
            '    const userId = user.id;              // trusted, comes from the auth server\n' +
            '    // use userId in the query, never req.body.user_id\n\n' +
            'If the body value is genuinely needed as input, validate it and treat it as untrusted data.',
          evidence: context.window(content, match.index, 8),
          cwe: 'CWE-639',
        }),
      );
    }

    const storageTrust = /localStorage\s*\.\s*(?:getItem|get)\s*\(\s*['"`]([^'"`]*)/gi;
    for (const match of content.matchAll(storageTrust)) {
      const key = match[1];
      if (!/(role|user_id|userid|is_admin|isadmin|admin|owner|account_id|org_id)/i.test(key)) continue;
      const line = countLines(content, match.index);
      const after = content.slice(match.index, match.index + 400);
      if (/supabase\.auth|getUser\(|getSession\(/.test(after)) continue;
      findings.push(
        makeFinding({
          severity: 'HIGH',
          title: `Client-side code trusts "${key}" from browser storage (${file.relPath})`,
          detail:
            'Browser storage is completely under the control of the person using the browser. If a permission check ' +
            'is based on a value read from localStorage, anyone can edit it in developer tools and unlock the feature.',
          plain:
            'Your app decides what a visitor is allowed to do using a note they can change themselves.',
          location: `${file.relPath}:${line}`,
          remediation:
            'Never use browser storage for permissions. Ask the server instead - the server verifies the session and ' +
            'the row-level security rules decide what is visible:\n\n' +
            '    const { data: { user } } = await supabase.auth.getUser();\n' +
            '    // pass the session to the server; the server decides what to return\n' +
            '    const { data } = await supabase.from("profiles").select("*").eq("id", user.id).maybeSingle();\n\n' +
            'Remove the localStorage-based check entirely.',
          evidence: context.window(content, match.index, 8),
          cwe: 'CWE-602',
        }),
      );
    }

    // ------------------------------------ 4. admin endpoints without a check
    const adminRegex = new RegExp(ADMIN_ROUTE.source, 'gi');
    for (const match of content.matchAll(adminRegex)) {
      const route = match[1];
      const line = countLines(content, match.index);
      const window = content.slice(match.index, match.index + 1200);
      const hasRoleCheck =
        /\b(role|is_admin|isAdmin|is_admin_user|requireAdmin|requireRole|authorize|permission)\b/i.test(window);
      if (hasRoleCheck) continue;
      findings.push(
        makeFinding({
          severity: 'HIGH',
          title: `Admin endpoint "${route}" has no role check (${file.relPath})`,
          detail:
            'The route path says "admin" but nothing in the handler verifies that the caller is an admin. If the ' +
            'route is reachable, anybody who finds it can call it.',
          plain:
            'One of your admin features can be used by anyone who finds its web address, not just by you.',
          location: `${file.relPath}:${line}`,
          remediation:
            'Check the caller\'s role on the server before doing anything else:\n\n' +
            '    const { data: { user }, error } = await supabase.auth.getUser();\n' +
            '    if (error || !user) return new Response("Unauthorized", { status: 401 });\n\n' +
            '    const { data: profile } = await supabase\n' +
            '      .from("profiles")\n' +
            '      .select("role")\n' +
            '      .eq("id", user.id)\n' +
            '      .maybeSingle();\n\n' +
            '    if (profile?.role !== "admin") {\n' +
            '      return new Response("Forbidden", { status: 403 });\n' +
            '    }\n\n' +
            'Prefer putting the admin check in a Row Level Security policy so it applies everywhere, not just here.',
          evidence: context.window(content, match.index, 12),
          cwe: 'CWE-862',
        }),
      );
    }
  }

  if (!findings.length) {
    findings.push(
      makePass(
        'No obvious authentication or authorisation mistakes found',
        `Reviewed ${codeFiles.length} code file(s) for unchecked getUser() results, server-side getSession() usage, ` +
          'client-trusted user ids and roles, and admin routes without a role check.',
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
