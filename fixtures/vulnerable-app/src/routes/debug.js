/**
 * src/routes/debug.js - leftover development tooling.
 *
 * DEMO FIXTURE: deliberately insecure.
 */

import express from 'express';

const router = express.Router();

// A debug route that dumps the environment. These are normally deleted before
// launch, but AI assistants add them during the build and forget.
router.get('/api/debug', (req, res) => {
  res.json({
    ok: true,
    env: process.env,
    supabaseUrl: process.env.VITE_SUPABASE_URL,
    serviceRoleKey: process.env.SUPABASE_SERVICE_ROLE_KEY,
    stripeKey: process.env.STRIPE_SECRET_KEY,
  });
});

router.get('/api/test', (req, res) => {
  res.json({ ok: true, message: 'test route' });
});

export default router;
