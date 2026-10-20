/**
 * lib/http.js
 * ---------------------------------------------------------------------------
 * The ONLY place in this tool that touches the network.
 *
 * SAFETY CONTRACT (enforced here, documented in the README, and required by
 * the audit engagement rules):
 *  - A request is only ever made to a URL the operator explicitly passed on
 *    the command line with --url.
 *  - The operator must additionally pass --i-have-authorization.
 *  - We NEVER brute force, never enumerate paths, tables or endpoints, and
 *    never attempt to authenticate. There is no password guessing, no token
 *    replay, no directory listing.
 *  - The Supabase probe sends exactly ONE benign read with `limit=1` against
 *    ONE table name that we already know from the project's own SQL files.
 *  - The header check sends one HEAD-ish GET to the root URL.
 *
 * Everything else in the scanner is offline and static.
 */

import { setTimeout as delay } from 'node:timers/promises';

/** Default timeout for a single live request. */
export const DEFAULT_TIMEOUT_MS = 12_000;

/** Maximum response body we will read from a live URL (bytes). */
const MAX_BODY_BYTES = 64 * 1024;

/**
 * Normalise a user supplied URL.
 * Returns null for anything that is not http/https - we refuse to touch
 * other protocols outright.
 */
export function normalizeBaseUrl(input) {
  if (!input) return null;
  const raw = String(input).trim();
  if (!raw) return null;
  const withScheme = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;
  let parsed;
  try {
    parsed = new URL(withScheme);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
  parsed.hash = '';
  parsed.search = '';
  return parsed.toString().replace(/\/$/, '');
}

/** True when the host looks like a Supabase project URL. */
export function isSupabaseHost(url) {
  try {
    const host = new URL(url).hostname.toLowerCase();
    return host.endsWith('.supabase.co') || host === 'supabase.co';
  } catch {
    return false;
  }
}

/**
 * Perform a single HTTP request with a hard timeout.
 * Never throws - failures are returned as `{ ok: false, error }`.
 */
export async function httpRequest(url, options = {}) {
  const {
    method = 'GET',
    headers = {},
    timeoutMs = DEFAULT_TIMEOUT_MS,
    body = null,
    maxBodyBytes = MAX_BODY_BYTES,
  } = options;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const started = Date.now();

  try {
    const response = await fetch(url, {
      method,
      headers,
      body,
      redirect: 'follow',
      signal: controller.signal,
    });

    // Read at most a small slice of the body: a live probe must never
    // download an arbitrary amount of data from a client's server.
    let text = '';
    try {
      const reader = response.body?.getReader();
      if (reader) {
        const chunks = [];
        let received = 0;
        while (received < maxBodyBytes) {
          const { done, value } = await reader.read();
          if (done) break;
          chunks.push(value);
          received += value.length;
        }
        text = Buffer.concat(chunks.map((c) => Buffer.from(c))).toString('utf8');
        try {
          await reader.cancel();
        } catch {
          /* ignore */
        }
      }
    } catch {
      /* body read failure is not fatal for our purposes */
    }

    return {
      ok: true,
      status: response.status,
      statusText: response.statusText,
      url: response.url,
      headers: Object.fromEntries(response.headers.entries()),
      body: text,
      durationMs: Date.now() - started,
    };
  } catch (error) {
    return {
      ok: false,
      status: 0,
      error: error && error.name === 'AbortError' ? `Request timed out after ${timeoutMs}ms` : String(error?.message || error),
      durationMs: Date.now() - started,
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Fetch the root URL and read the security response headers.
 * One request only.
 */
export async function fetchSecurityHeaders(url) {
  const response = await httpRequest(url, { method: 'GET', timeoutMs: DEFAULT_TIMEOUT_MS });
  if (!response.ok) return { ok: false, error: response.error };
  return {
    ok: true,
    status: response.status,
    finalUrl: response.url,
    headers: response.headers,
    durationMs: response.durationMs,
  };
}

/**
 * THE SUPABASE PROBE.
 *
 * Sends exactly one request:
 *     GET {base}/rest/v1/{table}?select=*&limit=1
 * with the project's public anon key. If the server answers 200 with a row,
 * the table is readable by anyone on the internet - a critical broken
 * access control finding.
 *
 * `table` MUST be a name we already know from the project's own SQL files.
 * We never guess, never enumerate and never try more than one table.
 */
export async function probeSupabaseAnonRead(baseUrl, anonKey, table) {
  if (!baseUrl || !anonKey || !table) {
    return { ok: false, error: 'Missing base URL, anon key or table name.' };
  }
  const url = `${baseUrl}/rest/v1/${encodeURIComponent(table)}?select=*&limit=1`;
  const response = await httpRequest(url, {
    method: 'GET',
    headers: {
      apikey: anonKey,
      Authorization: `Bearer ${anonKey}`,
      Accept: 'application/json',
    },
    timeoutMs: DEFAULT_TIMEOUT_MS,
  });

  if (!response.ok) {
    return { ok: false, error: response.error, url };
  }

  let parsed = null;
  let rowCount = null;
  try {
    parsed = JSON.parse(response.body);
    if (Array.isArray(parsed)) rowCount = parsed.length;
  } catch {
    /* not JSON - leave parsed null */
  }

  return {
    ok: true,
    url,
    status: response.status,
    rows: rowCount,
    parsed,
    bodyPreview: response.body.slice(0, 400),
    durationMs: response.durationMs,
  };
}

/** Small helper used by the CLI to pause between the two live probes. */
export async function pause(ms = 150) {
  await delay(ms);
}
