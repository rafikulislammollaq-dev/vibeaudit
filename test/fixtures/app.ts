/**
 * test/fixtures/app.ts
 *
 * A small TypeScript file used by the unit tests. It contains the
 * authentication and authorisation mistakes the authz check looks for:
 *   - auth.getUser() whose result is never checked
 *   - auth.getSession() used in server-side code
 *   - a client that trusts a role from browser storage
 *   - a server that trusts a user id from the request body
 */

import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.VITE_SUPABASE_ANON_KEY,
);

export async function loadProfile() {
  const { data: { user } } = await supabase.auth.getUser();
  const userId = user.id;
  const email = user.email;
  return { userId, email };
}

export async function readServerSession() {
  const { data: { session } } = await supabase.auth.getSession();
  return session.user.id;
}

export function isAdmin() {
  return localStorage.getItem('role') === 'admin';
}

export async function handleProfileUpdate(request: Request) {
  const body = await request.json();
  const { user_id, full_name } = body;
  await supabase.from('profiles').update({ full_name }).eq('id', user_id);
  return { ok: true };
}
