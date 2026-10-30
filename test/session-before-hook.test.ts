import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import pg from 'pg';
import { afterAll, describe, expect, it } from 'vitest';
import { createAuth, type AuthStore, type ProviderName, type ProviderProfile } from '../src/index.js';
import { migrationsDir, pgAuthStore } from '../src/pg/index.js';
import { fakeProvider } from './helpers/fake-provider.js';
import { createMemoryStore } from './helpers/memory-store.js';
import { req, setCookie } from './helpers/request.js';

const FRONT = 'https://app.example.test';
const URL_ENV = process.env.VENTRICAL_TEST_DATABASE_URL;

interface Harness { store: AuthStore<any>; suspend(userId: string): Promise<void>; sessionCount(): Promise<number>; close?(): Promise<void> }

function setup(profile: ProviderProfile, store: AuthStore<any>, afterSignIn?: (ctx: any) => Promise<void>) {
  return createAuth<any>({
    providers: { google: { clientId: 'a', clientSecret: 'b' } },
    publicUrl: 'https://api.example.test', frontendUrl: FRONT, encryptionKey: Buffer.alloc(32, 7), store,
    providerOverrides: { google: fakeProvider('google' as ProviderName, profile) },
    ...(afterSignIn ? { hooks: { afterSignIn } } : {}),
  });
}
type Auth = ReturnType<typeof setup>;

async function flow(auth: Auth) {
  const start = (await auth.handle(req('GET', '/auth/google/start', {})))!;
  const oauth = `__Host-ventrical_oauth=${encodeURIComponent(setCookie(start, '__Host-ventrical_oauth')!.value)}`;
  const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
  return (await auth.handle(req('GET', `/auth/google/callback?code=c&state=${encodeURIComponent(state)}`, { cookie: oauth })))!;
}

function suite(name: string, make: () => Promise<Harness>) {
  describe(`${name}: the session is created before afterSignIn`, () => {
    const profile = (): ProviderProfile => ({ subject: 'g1', email: 'g1@example.test', emailVerified: true });

    it('calls createSessionUnlessSuspended before the hook, for new and returning users', async () => {
      const h = await make();
      try {
        const order: string[] = [];
        const orig = h.store.createSessionUnlessSuspended.bind(h.store);
        h.store.createSessionUnlessSuspended = (...a) => { order.push('session'); return orig(...a); };
        const auth = setup(profile(), h.store, async () => { order.push('hook'); });
        expect((await flow(auth)).headers.get('location')).toBe(`${FRONT}/`);
        expect((await flow(auth)).headers.get('location')).toBe(`${FRONT}/`);
        expect(order).toEqual(['session', 'hook', 'session', 'hook']);
      } finally { await h.close?.(); }
    });

    it('does not call the hook for a suspended returning user', async () => {
      const h = await make();
      try {
        let hooks = 0;
        const auth = setup(profile(), h.store, async () => { hooks++; });
        await flow(auth);
        expect(hooks).toBe(1);
        await h.suspend((await h.store.findUserByIdentity('google', 'g1'))!.id);
        const res = await flow(auth);
        expect(res.headers.get('location')).toBe(`${FRONT}/signin?error=suspended`);
        expect(setCookie(res, '__Host-ventrical_session')).toBeUndefined();
        expect(hooks).toBe(1);
      } finally { await h.close?.(); }
    });

    it('a throwing hook leaves no user and no session row', async () => {
      const h = await make();
      try {
        const auth = setup(profile(), h.store, async () => { throw new Error('boom'); });
        const res = await flow(auth);
        expect(res.headers.get('location')).toBe(`${FRONT}/signin?error=sign_in_failed`);
        expect(setCookie(res, '__Host-ventrical_session')).toBeUndefined();
        expect(await h.sessionCount()).toBe(0);
        expect(await h.store.findUserByIdentity('google', 'g1')).toBeUndefined();
      } finally { await h.close?.(); }
    });

    it('a throwing hook for a returning user adds no session row', async () => {
      const h = await make();
      try {
        let boom = false;
        const auth = setup(profile(), h.store, async () => { if (boom) throw new Error('boom'); });
        await flow(auth);
        expect(await h.sessionCount()).toBe(1);
        boom = true;
        expect((await flow(auth)).headers.get('location')).toBe(`${FRONT}/signin?error=sign_in_failed`);
        expect(await h.sessionCount()).toBe(1);
      } finally { await h.close?.(); }
    });
  });
}

suite('memory', async () => {
  const store = createMemoryStore();
  return { store, suspend: async (id) => store.suspend(id), sessionCount: async () => store.sessions.size };
});

describe.skipIf(!URL_ENV)('pg', () => {
  const admin = new pg.Pool({ connectionString: URL_ENV, max: 2 });
  afterAll(async () => { await admin.end(); });
  suite('postgres', async () => {
    const schema = `auth_test_${Math.random().toString(36).slice(2, 10)}`;
    await admin.query(`create schema ${schema}`);
    const pool = new pg.Pool({ connectionString: URL_ENV, max: 4, options: `-c search_path=${schema}` });
    for (const f of readdirSync(migrationsDir).filter((n) => n.endsWith('.sql')).sort()) await pool.query(readFileSync(join(migrationsDir, f), 'utf8'));
    return {
      store: pgAuthStore(pool),
      suspend: async (id) => { await pool.query('update users set suspended_at = now() where id = $1', [id]); },
      sessionCount: async () => Number((await pool.query('select count(*) from sessions')).rows[0].count),
      close: async () => { await pool.end(); await admin.query(`drop schema ${schema} cascade`); },
    };
  });
});
