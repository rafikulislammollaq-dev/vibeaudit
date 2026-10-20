/**
 * src/lib/auth.js - authentication helpers.
 *
 * DEMO FIXTURE: deliberately insecure.
 */

import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.VITE_SUPABASE_ANON_KEY,
);

/**
 * PROBLEM 1: the result of getUser() is never checked. If the request fails
 * or nobody is signed in, `user` is null and `user.id` throws - or the code
 * silently carries on with an undefined user.
 */
export async function getCurrentUser() {
  const { data: { user } } = await supabase.auth.getUser();
  const userId = user.id;
  const email = user.email;
  return { userId, email };
}

/**
 * PROBLEM 2: getSession() reads a cookie but does not re-validate the
 * signature with the auth server. A hand-edited cookie is accepted.
 */
export async function readSession() {
  const { data: { session } } = await supabase.auth.getSession();
  return session.user.id;
}

/**
 * PROBLEM 3: the role is read from browser storage, which the visitor can
 * edit in developer tools.
 */
export function isAdmin() {
  return localStorage.getItem('role') === 'admin';
}

/**
 * PROBLEM 4: the user id is taken from browser storage instead of from the
 * verified session.
 */
export function currentUserId() {
  return localStorage.getItem('user_id');
}
