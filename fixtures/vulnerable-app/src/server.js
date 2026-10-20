/**
 * src/server.js - the Express entry point of the demo app.
 *
 * DEMO FIXTURE: deliberately insecure. Every problem here is a real mistake
 * an AI code generator makes when it writes a backend for you.
 */

import express from 'express';
import cors from 'cors';
import path from 'path';
import jwt from 'jsonwebtoken';
import { createClient } from '@supabase/supabase-js';
import { getCurrentUser } from './lib/auth.js';

const app = express();
const PORT = process.env.PORT || 3000;

// PROBLEM 1: the service_role key is read from the environment here, but the
// same variable name is also prefixed for the browser in the client bundle
// (see src/lib/supabaseClient.js). The admin key must be server-only.
const supabaseAdmin = createClient(
  process.env.VITE_SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
);

// PROBLEM 2: CORS allows every origin on the internet.
app.use(cors({ origin: '*' }));

// PROBLEM 3: credentials are allowed on top of the wildcard origin.
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
});

// PROBLEM 4: the whole project folder is served as static files, which means
// GET /.env returns the environment file with every secret in it.
app.use(express.static('.'));

// PROBLEM 5: a debug route that leaks the environment.
app.get('/api/debug', (req, res) => {
  res.json({
    ok: true,
    environment: process.env,
    database: process.env.DATABASE_URL,
    stripeKey: process.env.STRIPE_SECRET_KEY,
    timestamp: new Date().toISOString(),
  });
});

// PROBLEM 6: an admin endpoint with no role check at all.
app.get('/api/admin/users', async (req, res) => {
  const { data, error } = await supabaseAdmin
    .from('profiles')
    .select('*')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  return res.json({ users: data });
});

// PROBLEM 7: the server accepts unsigned tokens (alg: none).
app.get('/api/me', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET || 'dev-secret', {
      algorithms: ['none', 'HS256'],
    });
    return res.json({ user: payload });
  } catch (error) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
});

// PROBLEM 8: the server trusts a user id that the caller supplied.
app.post('/api/profile', async (req, res) => {
  const { user_id, full_name } = req.body;
  const { error } = await supabaseAdmin
    .from('profiles')
    .update({ full_name })
    .eq('id', user_id);
  if (error) return res.status(500).json({ error: error.message });
  return res.json({ ok: true });
});

// PROBLEM 9: the helper that reads the current user never checks whether the
// lookup actually succeeded.
app.get('/api/my-orders', async (req, res) => {
  const { userId } = await getCurrentUser();
  const { data } = await supabaseAdmin.from('orders').select('*').eq('user_id', userId);
  return res.json({ orders: data });
});

app.listen(PORT, () => {
  console.log(`Server listening on http://localhost:${PORT}`);
});
