/**
 * src/routes/admin.js - admin endpoints.
 *
 * DEMO FIXTURE: deliberately insecure.
 */

import express from 'express';
import { createClient } from '@supabase/supabase-js';

const router = express.Router();

const supabaseAdmin = createClient(
  process.env.VITE_SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
);

// PROBLEM 1: no role check. Anybody who finds /admin/users gets everything.
router.get('/admin/users', async (req, res) => {
  const { data } = await supabaseAdmin.from('profiles').select('*');
  res.json({ users: data });
});

// PROBLEM 2: the account id comes from the request body, so the caller
// decides whose account gets modified.
router.post('/admin/users/:id/role', async (req, res) => {
  const { user_id, role } = req.body;
  await supabaseAdmin.from('profiles').update({ role }).eq('id', user_id);
  res.json({ ok: true });
});

export default router;
