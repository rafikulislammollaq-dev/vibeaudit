/**
 * test/fixtures/server.js
 *
 * A small Express-shaped file used by the unit tests. It contains:
 *   - a wildcard CORS origin combined with credentials
 *   - a debug route
 *   - an admin route with no role check
 *   - a token check that accepts alg: "none"
 */

import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';

const app = express();

app.use(cors({ origin: '*' }));

app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
});

app.get('/api/debug', (req, res) => {
  res.json({ ok: true, env: process.env });
});

app.get('/api/admin/users', async (req, res) => {
  res.json({ users: [] });
});

app.get('/api/me', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  const payload = jwt.verify(token, process.env.JWT_SECRET || 'dev-secret', {
    algorithms: ['none', 'HS256'],
  });
  res.json({ user: payload });
});

export default app;
