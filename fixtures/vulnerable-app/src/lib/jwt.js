/**
 * src/lib/jwt.js - token handling.
 *
 * DEMO FIXTURE: deliberately insecure.
 */

import jwt from 'jsonwebtoken';

// PROBLEM 1: the signing secret falls back to a hard-coded value, so a
// missing environment variable silently downgrades the security of every
// token in the app.
const SECRET = process.env.JWT_SECRET || 'change-me-in-production';

export function issueToken(userId, role) {
  return jwt.sign({ sub: userId, role }, SECRET, { expiresIn: '7d' });
}

// PROBLEM 2: unsigned tokens are explicitly accepted.
export function verifyToken(token) {
  return jwt.verify(token, SECRET, { algorithms: ['none', 'HS256'] });
}

// PROBLEM 3: decode() is used instead of verify(), so the token contents are
// trusted without any signature check.
export function readToken(token) {
  return jwt.decode(token);
}
