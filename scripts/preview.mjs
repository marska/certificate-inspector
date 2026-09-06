#!/usr/bin/env node
/**
 * Serves the static export the way the container does, so `npm run build` can
 * be checked locally without Docker.
 *
 * The security headers are parsed out of docker/security-headers.conf rather
 * than duplicated here — if the two ever disagreed, this preview would stop
 * being evidence of anything.
 *
 * This is a development convenience. The published image serves the same files
 * with nginx; nothing in here ships.
 */
import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { dirname, extname, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(ROOT, 'out');
const PORT = Number(process.env.PORT ?? 3000);

const CONTENT_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.png': 'image/png',
  '.woff2': 'font/woff2',
};

/** Reads `add_header Name "value" always;` lines from the nginx snippet. */
function securityHeaders() {
  const conf = readFileSync(join(ROOT, 'docker', 'security-headers.conf'), 'utf8');
  const headers = {};
  for (const line of conf.split('\n')) {
    const match = line.match(/^\s*add_header\s+(\S+)\s+"([^"]*)"/);
    if (match) headers[match[1]] = match[2];
  }
  return headers;
}

const HEADERS = securityHeaders();

async function findFile(pathname) {
  const safe = normalize(decodeURIComponent(pathname)).replace(/^(\.\.[/\\])+/, '');
  for (const candidate of [safe, `${safe}/index.html`, `${safe}.html`]) {
    const file = join(OUT, candidate);
    if (!file.startsWith(OUT)) continue; // no escaping the export directory
    try {
      if ((await stat(file)).isFile()) return file;
    } catch {
      /* try the next shape, mirroring nginx try_files */
    }
  }
  return undefined;
}

const server = createServer(async (request, response) => {
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    response.writeHead(405, HEADERS).end();
    return;
  }

  const { pathname } = new URL(request.url ?? '/', 'http://localhost');

  if (pathname === '/healthz') {
    response
      .writeHead(200, { ...HEADERS, 'Content-Type': 'text/plain' })
      .end('ok\n');
    return;
  }

  const file = await findFile(pathname);
  const immutable = pathname.startsWith('/_next/static/');

  if (!file) {
    const notFound = await findFile('/404.html');
    response.writeHead(404, {
      ...HEADERS,
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-cache',
    });
    response.end(notFound ? await readFile(notFound) : 'Not found');
    return;
  }

  response.writeHead(200, {
    ...HEADERS,
    'Content-Type': CONTENT_TYPES[extname(file)] ?? 'application/octet-stream',
    'Cache-Control': immutable
      ? 'public, max-age=31536000, immutable'
      : 'no-cache',
  });
  response.end(request.method === 'HEAD' ? undefined : await readFile(file));
});

try {
  await stat(OUT);
} catch {
  console.error('No ./out directory. Run `npm run build` first.');
  process.exit(1);
}

server.listen(PORT, () => {
  console.log(`Certificate Inspector (static export) on http://localhost:${PORT}`);
  console.log(`Serving ${OUT} with the headers from docker/security-headers.conf`);
});
