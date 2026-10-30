// Post-build smoke check: run after `npm run build`.
import { existsSync } from 'node:fs';
import { join } from 'node:path';

const dist = new URL('../dist/', import.meta.url);
for (const entry of ['index', 'express/index', 'next/index', 'hono/index', 'fastify/index', 'pg/index']) {
  for (const ext of ['js', 'd.ts']) {
    if (!existsSync(new URL(`${entry}.${ext}`, dist))) throw new Error(`dist/${entry}.${ext} is missing`);
  }
}
const pg = await import(new URL('pg/index.js', dist).href);
if (typeof pg.pgAuthStore !== 'function') throw new Error('dist/pg/index.js does not export pgAuthStore');
if (!existsSync(join(pg.migrationsDir, '001_auth.sql'))) throw new Error('migrationsDir does not contain 001_auth.sql');
const core = await import(new URL('index.js', dist).href);
if (typeof core.createAuth !== 'function') throw new Error('dist/index.js does not export createAuth');
for (const [entry, names] of [['next', ['authRouteHandlers', 'getSessionFromRequest', 'requireSession']], ['hono', ['authHandler', 'requireSession']], ['fastify', ['authPlugin', 'requireSession']]]) {
  const mod = await import(new URL(`${entry}/index.js`, dist).href);
  for (const name of names) {
    if (typeof mod[name] !== 'function') throw new Error(`dist/${entry}/index.js does not export ${name}`);
  }
}
console.log('dist ok');
