/**
 * supabase/functions/delete-user/index.ts - Edge Function.
 *
 * DEMO FIXTURE: deliberately insecure.
 *
 * Edge Functions run with the service_role key, so Row Level Security does
 * NOT protect anything this function touches. getSession() does not
 * re-validate the token, so the "who is calling" question is answered by the
 * caller.
 */

import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

const supabaseAdmin = createClient(
  Deno.env.get('SUPABASE_URL')!,
  Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
);

Deno.serve(async (req) => {
  // PROBLEM 1: getSession() reads the cookie without verifying it.
  const { data: { session } } = await supabaseAdmin.auth.getSession();
  const userId = session.user.id;

  // PROBLEM 2: the target user id is taken from the request body.
  const { target_user_id } = await req.json();

  // PROBLEM 3: the profiles table has no Row Level Security, and this
  // function runs with the admin key, so nothing stops a caller from
  // deleting somebody else's account.
  const { error } = await supabaseAdmin
    .from('profiles')
    .delete()
    .eq('id', target_user_id);

  if (error) {
    return new Response(JSON.stringify({ error: error.message }), { status: 500 });
  }

  return new Response(JSON.stringify({ ok: true, deleted: target_user_id }), {
    headers: { 'Content-Type': 'application/json' },
  });
});
