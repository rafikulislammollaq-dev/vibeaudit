/**
 * dev/serve.js
 * ---------------------------------------------------------------------------
 * A tiny static file server for local testing.
 *
 *   node dev/serve.js [port]
 *
 * It serves the scanner folder over http://localhost so you can click through
 * the UI the same way a visitor would. It is a development convenience only -
 * the scanner itself never talks to a server, and the deployed tool is a
 * folder of static files with no server at all.
 */

import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');
const port = Number(process.argv[2]) || 8123;

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.md': 'text/markdown; charset=utf-8',
};

const server = createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://localhost:${port}`);
    let rel = decodeURIComponent(url.pathname);
    if (rel === '/') rel = '/index.html';
    const target = path.join(root, rel.replace(/^\/+/, ''));
    if (!target.startsWith(root)) {
      res.writeHead(403).end('Forbidden');
      return;
    }
    const info = await stat(target);
    if (info.isDirectory()) {
      res.writeHead(302, { Location: `${rel.replace(/\/$/, '')}/index.html` }).end();
      return;
    }
    const body = await readFile(target);
    res.writeHead(200, {
      'Content-Type': TYPES[path.extname(target).toLowerCase()] || 'application/octet-stream',
      'Cache-Control': 'no-store',
    });
    res.end(body);
  } catch {
    res.writeHead(404, { 'Content-Type': 'text/plain' }).end('Not found');
  }
});

server.listen(port, () => {
  console.log(`scanner served at http://localhost:${port}/  (Ctrl+C to stop)`);
});
