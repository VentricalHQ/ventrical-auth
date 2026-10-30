import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import pg from 'pg';
import { afterAll, describe, expect, it } from 'vitest';
import { hashToken } from '../src/crypto.js';
import { createAuth, type AuthStore, type ProviderName, type ProviderProfile } from '../src/index.js';
import { migrationsDir, pgAuthStore } from '../src/pg/index.js';
import { fakeProvider } from './helpers/fake-provider.js';
import { createMemoryStore } from './helpers/memory-store.js';
import { req, setCookie } from './helpers/request.js';

const FRONT = 'https://app.example.test';
const URL_ENV = process.env.VENTRICAL_TEST_DATABASE_URL;
const DAY = 24 * 60 * 60 * 1000;
const SESSION = '__Host-ventrical_session';

interface Harness {
  store: AuthStore<any>;
  clock: { now: Date };
  suspend(userId: string): Promise<void>;
  setCreatedAt(idHash: string, d: Date): Promise<void>;
  close?(): Promise<void>;
}

function setup(h: Harness, profiles: Partial<Record<ProviderName, ProviderProfile>>, extra: { sessionMaxAgeMs?: number; sessionTtlMs?: number; store?: AuthStore<any> } = {}) {
  const overrides: Partial<Record<ProviderName, ReturnType<typeof fakeProvider>>> = {};
  for (const [n, p] of Object.entries(profiles)) overrides[n as ProviderName] = fakeProvider(n as ProviderName, p!);
  return createAuth<any>({
    providers: { google: { clientId: 'a', clientSecret: 'b' }, github: { clientId: 'a', clientSecret: 'b' } },
    publicUrl: 'https://api.example.test', frontendUrl: FRONT, encryptionKey: Buffer.alloc(32, 7), store: extra.store ?? h.store,
    providerOverrides: overrides, clock: () => h.clock.now,
    ...(extra.sessionMaxAgeMs !== undefined ? { sessionMaxAgeMs: extra.sessionMaxAgeMs } : {}),
    ...(extra.sessionTtlMs !== undefined ? { sessionTtlMs: extra.sessionTtlMs } : {}),
  });
}
type Auth = ReturnType<typeof setup>;

/** The OAuth flow. `startCookie` rides on /start (binds a link), `cbCookie` on the callback. */
async function flow(auth: Auth, provider: string, opts: { startCookie?: string; cbCookie?: string } = {}) {
  const start = (await auth.handle(req('GET', `/auth/${provider}/start`, opts.startCookie ? { cookie: opts.startCookie } : {})))!;
  const oauth = `__Host-ventrical_oauth=${encodeURIComponent(setCookie(start, '__Host-ventrical_oauth')!.value)}`;
  const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
  return (await auth.handle(req('GET', `/auth/${provider}/callback?code=c&state=${encodeURIComponent(state)}`, { cookie: [oauth, opts.cbCookie].filter(Boolean).join('; ') })))!;
}
const cookieOf = (res: Response) => `${SESSION}=${setCookie(res, SESSION)!.value}`;
const idOf = (cookie: string) => cookie.slice(SESSION.length + 1);
const G1: ProviderProfile = { subject: 'g1', emailVerified: true, email: 'g1@example.test' };

function suite(name: string, make: () => Promise<Harness>) {
  describe(`${name}: sessionMaxAgeMs`, () => {
    /** Signs in at the harness clock and pins created_at to it. */
    async function signIn(h: Harness, auth: Auth, profile = 'google') {
      const res = await flow(auth, profile);
      const cookie = cookieOf(res);
      await h.setCreatedAt(hashToken(idOf(cookie)), h.clock.now);
      return { res, cookie };
    }
    const expiryOf = async (h: Harness, cookie: string) => (await h.store.getSessionWithExpiry(hashToken(idOf(cookie)), new Date(0)))?.expiresAt.getTime();

    it('a new session expires at min(now + ttl, now + cap), and so does the cookie Max-Age', async () => {
      const h = await make();
      try {
        const t0 = h.clock.now;
        const auth = setup(h, { google: G1 }, { sessionTtlMs: 30 * DAY, sessionMaxAgeMs: 10 * DAY });
        const { res, cookie } = await signIn(h, auth);
        expect(await expiryOf(h, cookie)).toBe(t0.getTime() + 10 * DAY);
        expect(setCookie(res, SESSION)!.attrs['max-age']).toBe(String(10 * 86400));
      } finally { await h.close?.(); }
    });

    it('defaults the cap to 90 days (longer than the ttl, so the ttl still decides)', async () => {
      const h = await make();
      try {
        const t0 = h.clock.now;
        const auth = setup(h, { google: G1 }, { sessionTtlMs: 120 * DAY });
        const { cookie } = await signIn(h, auth);
        expect(await expiryOf(h, cookie)).toBe(t0.getTime() + 90 * DAY);
      } finally { await h.close?.(); }
    });

    it('refresh never extends past created_at + cap, and the refresh cookie Max-Age is clamped likewise', async () => {
      const h = await make();
      try {
        const t0 = h.clock.now;
        const auth = setup(h, { google: G1 }, { sessionTtlMs: 30 * DAY, sessionMaxAgeMs: 40 * DAY });
        const { cookie } = await signIn(h, auth);
        h.clock.now = new Date(t0.getTime() + 20 * DAY); // 10 days left: refreshes
        const s = await auth.getSession(req('GET', '/x', { cookie }));
        expect(s?.user).toBeDefined();
        expect(await expiryOf(h, cookie)).toBe(t0.getTime() + 40 * DAY); // not 50
        expect(s?.setCookie).toContain(`Max-Age=${20 * 86400}`);
      } finally { await h.close?.(); }
    });

    it('a refresh well inside the cap still extends by the full ttl', async () => {
      const h = await make();
      try {
        const t0 = h.clock.now;
        const auth = setup(h, { google: G1 }, { sessionTtlMs: 30 * DAY, sessionMaxAgeMs: 90 * DAY });
        const { cookie } = await signIn(h, auth);
        h.clock.now = new Date(t0.getTime() + 5 * DAY);
        const s = await auth.getSession(req('GET', '/x', { cookie }));
        expect(await expiryOf(h, cookie)).toBe(t0.getTime() + 35 * DAY);
        expect(s?.setCookie).toContain(`Max-Age=${30 * 86400}`);
      } finally { await h.close?.(); }
    });

    it('a session at or past created_at + cap is signed out and deleted, even if its expires_at is later', async () => {
      const h = await make();
      try {
        const t0 = h.clock.now;
        const long = setup(h, { google: G1 }, { sessionTtlMs: 30 * DAY, sessionMaxAgeMs: 90 * DAY });
        const { cookie } = await signIn(h, long);
        const strict = setup(h, { google: G1 }, { sessionTtlMs: 30 * DAY, sessionMaxAgeMs: 10 * DAY });
        h.clock.now = new Date(t0.getTime() + 10 * DAY - 1);
        expect(await strict.getSession(req('GET', '/x', { cookie }))).toBeDefined();
        h.clock.now = new Date(t0.getTime() + 10 * DAY);
        expect(await strict.getSession(req('GET', '/x', { cookie }))).toBeUndefined();
        const err = await strict.requireSession(req('GET', '/x', { cookie })).catch((e) => e);
        expect(err).toMatchObject({ status: 401, code: 'unauthenticated' });
        // Gone from the store, not only hidden (the longer-cap instance cannot see it either).
        expect(await h.store.getSessionWithExpiry(hashToken(idOf(cookie)), new Date(0))).toBeUndefined();
      } finally { await h.close?.(); }
    });

    it('a failing best-effort delete does not break the signed-out answer', async () => {
      const h = await make();
      try {
        const t0 = h.clock.now;
        const long = setup(h, { google: G1 }, { sessionMaxAgeMs: 90 * DAY });
        const { cookie } = await signIn(h, long);
        const broken = { ...h.store, transaction: h.store.transaction.bind(h.store), getSessionWithExpiry: h.store.getSessionWithExpiry.bind(h.store), deleteSession: async () => { throw new Error('db down'); } } as AuthStore<any>;
        const strict = setup(h, { google: G1 }, { sessionMaxAgeMs: 10 * DAY, store: broken });
        h.clock.now = new Date(t0.getTime() + 11 * DAY);
        expect(await strict.getSession(req('GET', '/x', { cookie }))).toBeUndefined();
      } finally { await h.close?.(); }
    });

    it('a store that omits createdAt skips cap enforcement', async () => {
      const h = await make();
      try {
        const t0 = h.clock.now;
        const long = setup(h, { google: G1 }, { sessionMaxAgeMs: 90 * DAY });
        const { cookie } = await signIn(h, long);
        const legacy = {
          ...h.store, transaction: h.store.transaction.bind(h.store), touchSession: h.store.touchSession.bind(h.store),
          getSessionWithExpiry: async (i: string, n: Date) => { const { createdAt: _c, ...rest } = (await h.store.getSessionWithExpiry(i, n))!; return rest; },
        } as AuthStore<any>;
        const strict = setup(h, { google: G1 }, { sessionMaxAgeMs: 1 * DAY, store: legacy });
        h.clock.now = new Date(t0.getTime() + 5 * DAY);
        expect(await strict.getSession(req('GET', '/x', { cookie }))).toBeDefined();
      } finally { await h.close?.(); }
    });
  });

  describe(`${name}: signing in deletes the session the request carried`, () => {
    const alive = async (h: Harness, cookie: string) => !!(await h.store.getSessionWithExpiry(hashToken(idOf(cookie)), h.clock.now));

    it('the old session is gone after a sign-in, and the new one works', async () => {
      const h = await make();
      try {
        const auth = setup(h, { google: G1, github: { subject: 'h1', emailVerified: true, email: 'h1@example.test' } });
        const old = cookieOf(await flow(auth, 'google'));
        expect(await alive(h, old)).toBe(true);
        const res = await flow(auth, 'github', { cbCookie: old }); // a different account signs in over the old cookie
        const fresh = cookieOf(res);
        expect(fresh).not.toBe(old);
        expect(await alive(h, old)).toBe(false);
        expect(await auth.getSession(req('GET', '/x', { cookie: old }))).toBeUndefined();
        expect((await auth.getSession(req('GET', '/x', { cookie: fresh })))?.user.email).toBe('h1@example.test');
      } finally { await h.close?.(); }
    });

    it('signing in again as the same user also drops the old session', async () => {
      const h = await make();
      try {
        const auth = setup(h, { google: G1 });
        const old = cookieOf(await flow(auth, 'google'));
        const fresh = cookieOf(await flow(auth, 'google', { cbCookie: old }));
        expect(await alive(h, old)).toBe(false);
        expect(await alive(h, fresh)).toBe(true);
      } finally { await h.close?.(); }
    });

    it('a sign-in that rolls back (suspended) keeps the old session', async () => {
      const h = await make();
      try {
        const auth = setup(h, { google: G1, github: { subject: 'h1', emailVerified: true, email: 'h1@example.test' } });
        const old = cookieOf(await flow(auth, 'google'));
        await flow(auth, 'github'); // creates user h1 (and a session we ignore)
        await h.suspend((await h.store.findUserByIdentity('github', 'h1'))!.id);
        const res = await flow(auth, 'github', { cbCookie: old });
        expect(res.headers.get('location')).toBe(`${FRONT}/signin?error=suspended`);
        expect(setCookie(res, SESSION)).toBeUndefined();
        expect(await alive(h, old)).toBe(true);
      } finally { await h.close?.(); }
    });

    it('the link path does not delete the session', async () => {
      const h = await make();
      try {
        const auth = setup(h, { google: G1, github: { subject: 'h1', emailVerified: true, email: 'h1@example.test' } });
        const cur = cookieOf(await flow(auth, 'google'));
        const res = await flow(auth, 'github', { startCookie: cur, cbCookie: cur });
        expect(res.headers.get('location')).toBe(`${FRONT}/`);
        expect(setCookie(res, SESSION)).toBeUndefined();
        expect(await alive(h, cur)).toBe(true);
      } finally { await h.close?.(); }
    });
  });
}

suite('memory', async () => {
  const clock = { now: new Date('2030-01-01T00:00:00Z') };
  const store = createMemoryStore(() => clock.now);
  return {
    store, clock,
    suspend: async (id) => store.suspend(id),
    setCreatedAt: async (h, d) => { store.sessions.get(h)!.createdAt = d; },
  };
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
      // Real time: the database stamps created_at itself, so a far-off fake clock would trip the cap.
      clock: { now: new Date() },
      suspend: async (id) => { await pool.query('update users set suspended_at = now() where id = $1', [id]); },
      setCreatedAt: async (h, d) => { await pool.query('update sessions set created_at = $2 where id_hash = $1', [h, d]); },
      close: async () => { await pool.end(); await admin.query(`drop schema ${schema} cascade`); },
    };
  });
});
