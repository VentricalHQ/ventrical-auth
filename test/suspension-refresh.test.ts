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

interface Harness { store: AuthStore<any>; suspend(userId: string): Promise<void>; close?(): Promise<void> }

function setup(profiles: Partial<Record<ProviderName, ProviderProfile>>, store: AuthStore<any>, errors: { stage: string; code: string }[] = []) {
  const overrides: Partial<Record<ProviderName, ReturnType<typeof fakeProvider>>> = {};
  for (const [n, p] of Object.entries(profiles)) overrides[n as ProviderName] = fakeProvider(n as ProviderName, p!);
  return createAuth<any>({
    providers: { google: { clientId: 'a', clientSecret: 'b' }, github: { clientId: 'a', clientSecret: 'b' } },
    publicUrl: 'https://api.example.test', frontendUrl: FRONT, encryptionKey: Buffer.alloc(32, 7), store, providerOverrides: overrides,
    hooks: { onError: (e) => { errors.push({ stage: e.stage, code: e.code }); } },
  });
}
type Auth = ReturnType<typeof setup>;

async function flow(auth: Auth, provider: string, session?: string) {
  const start = (await auth.handle(req('GET', `/auth/${provider}/start`, session ? { cookie: session } : {})))!;
  const oauth = `__Host-ventrical_oauth=${encodeURIComponent(setCookie(start, '__Host-ventrical_oauth')!.value)}`;
  const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
  return (await auth.handle(req('GET', `/auth/${provider}/callback?code=c&state=${encodeURIComponent(state)}`, { cookie: [oauth, session].filter(Boolean).join('; ') })))!;
}
const sessionOf = (res: Response) => `__Host-ventrical_session=${setCookie(res, '__Host-ventrical_session')!.value}`;
const identityOf = async (s: AuthStore<any>, p: ProviderName, sub: string) => (await s.findUserByIdentity(p, sub))?.identity;
const userId = async (s: AuthStore<any>, p: ProviderName, sub: string) => (await s.findUserByIdentity(p, sub))!.id;

function suite(name: string, make: () => Promise<Harness>) {
  describe(`${name}: suspended email cannot be re-acquired through an identity refresh`, () => {
    /** User A (verified e1 on google) is suspended; an attacker signs up on github with e2. */
    async function world() {
      const h = await make();
      const e1 = 'victim@example.test';
      const a = setup({ google: { subject: 'g-a', email: e1, emailVerified: true } }, h.store);
      await flow(a, 'google');
      await h.suspend(await userId(h.store, 'google', 'g-a'));
      const gh: ProviderProfile = { subject: 'h-evil', email: 'evil@example.test', emailVerified: true };
      const errors: { stage: string; code: string }[] = [];
      const auth = setup({ github: gh }, h.store, errors);
      const first = await flow(auth, 'github');
      expect(first.headers.get('location')).toBe(`${FRONT}/`);
      return { h, e1, gh, auth, errors, session: sessionOf(first) };
    }

    it('sign-in: a verified email changed to a suspended one is refused and not stored', async () => {
      const { h, e1, gh, auth, errors } = await world();
      try {
        gh.email = e1;
        const res = await flow(auth, 'github');
        expect(res.headers.get('location')).toBe(`${FRONT}/signin?error=suspended`);
        expect(setCookie(res, '__Host-ventrical_session')).toBeUndefined();
        expect(await identityOf(h.store, 'github', 'h-evil')).toEqual({ email: 'evil@example.test', emailVerified: true });
        expect(errors).toContainEqual({ stage: 'callback', code: 'suspended' });
      } finally { await h.close?.(); }
    });

    it('link: a signed-in user linking a provider whose verified email is suspended is refused', async () => {
      const { h, e1, errors, session } = await world();
      try {
        const linker = setup({ google: { subject: 'g-new', email: e1, emailVerified: true } }, h.store, errors);
        const res = await flow(linker, 'google', session);
        expect(res.headers.get('location')).toBe(`${FRONT}/settings?error=suspended`);
        expect(await identityOf(h.store, 'google', 'g-new')).toBeUndefined();
        expect(errors).toContainEqual({ stage: 'link', code: 'suspended' });
      } finally { await h.close?.(); }
    });

    it('an unverified suspended email does not trigger the check and is stored unverified', async () => {
      const { h, e1, gh, auth } = await world();
      try {
        gh.email = e1;
        gh.emailVerified = false;
        const res = await flow(auth, 'github');
        expect(res.headers.get('location')).toBe(`${FRONT}/`);
        expect(setCookie(res, '__Host-ventrical_session')).toBeDefined();
        expect(await identityOf(h.store, 'github', 'h-evil')).toEqual({ email: e1, emailVerified: false });
      } finally { await h.close?.(); }
    });

    it('a previously unverified identity that becomes verified with a suspended email is refused', async () => {
      const { h, e1, gh, auth } = await world();
      try {
        gh.email = e1; gh.emailVerified = false;
        await flow(auth, 'github');
        gh.emailVerified = true; // same email as stored, but the stored identity was unverified
        const res = await flow(auth, 'github');
        expect(res.headers.get('location')).toBe(`${FRONT}/signin?error=suspended`);
        expect(await identityOf(h.store, 'github', 'h-evil')).toEqual({ email: e1, emailVerified: false });
      } finally { await h.close?.(); }
    });

    it('an unrelated verified email change still updates the identity and signs in', async () => {
      const { h, gh, auth } = await world();
      try {
        gh.email = 'e3@example.test';
        const res = await flow(auth, 'github');
        expect(res.headers.get('location')).toBe(`${FRONT}/`);
        expect(setCookie(res, '__Host-ventrical_session')).toBeDefined();
        expect(await identityOf(h.store, 'github', 'h-evil')).toEqual({ email: 'e3@example.test', emailVerified: true });
      } finally { await h.close?.(); }
    });

    /** Two users who each verified the same email on different providers (never linked), before one is suspended. */
    async function twin() {
      const h = await make();
      const email = 'shared@example.test';
      const errors: { stage: string; code: string }[] = [];
      const ga: ProviderProfile = { subject: 'g-twin', email, emailVerified: true };
      const gh: ProviderProfile = { subject: 'h-twin', email, emailVerified: true };
      const auth = setup({ google: ga, github: gh }, h.store, errors);
      expect((await flow(auth, 'google')).headers.get('location')).toBe(`${FRONT}/`);
      expect((await flow(auth, 'github')).headers.get('location')).toBe(`${FRONT}/`);
      return { h, email, ga, gh, auth, errors };
    }

    it('sign-in: a returning user whose stored email is unchanged is refused when another user with that verified email is suspended', async () => {
      const { h, auth, errors } = await twin();
      try {
        await h.suspend(await userId(h.store, 'google', 'g-twin'));
        errors.length = 0;
        const res = await flow(auth, 'github');
        expect(res.headers.get('location')).toBe(`${FRONT}/signin?error=suspended`);
        expect(setCookie(res, '__Host-ventrical_session')).toBeUndefined();
        expect(errors).toContainEqual({ stage: 'callback', code: 'suspended' });
      } finally { await h.close?.(); }
    });

    it('sign-in: a returning user sharing a verified email with an unsuspended twin signs in normally', async () => {
      const { h, auth } = await twin();
      try {
        const res = await flow(auth, 'github');
        expect(res.headers.get('location')).toBe(`${FRONT}/`);
        expect(setCookie(res, '__Host-ventrical_session')).toBeDefined();
      } finally { await h.close?.(); }
    });

    it('sign-in: a returning user with an unrelated verified email is unaffected by the suspension', async () => {
      const { h, gh, auth } = await twin();
      try {
        await h.suspend(await userId(h.store, 'google', 'g-twin'));
        gh.email = 'else@example.test';
        const res = await flow(auth, 'github');
        expect(res.headers.get('location')).toBe(`${FRONT}/`);
        expect(setCookie(res, '__Host-ventrical_session')).toBeDefined();
      } finally { await h.close?.(); }
    });

    it('sign-in: the handler passes the returning user id as exceptUserId, and none for a new user', async () => {
      const { h, auth } = await twin();
      try {
        const calls: (string | undefined)[] = [];
        const orig = h.store.emailBelongsToSuspendedUser.bind(h.store);
        h.store.emailBelongsToSuspendedUser = (email, tx, opts) => { if (tx) calls.push(opts?.exceptUserId); return orig(email, tx, opts); };
        await flow(auth, 'github');
        expect(calls).toEqual([await userId(h.store, 'github', 'h-twin')]);
        calls.length = 0;
        const fresh = setup({ google: { subject: 'g-new', email: 'new@example.test', emailVerified: true } }, h.store);
        await flow(fresh, 'google');
        expect(calls).toEqual([undefined]);
      } finally { await h.close?.(); }
    });

    it('sign-in: an unverified email is not checked for a returning user', async () => {
      const { h, gh, auth } = await twin();
      try {
        await h.suspend(await userId(h.store, 'google', 'g-twin'));
        gh.emailVerified = false;
        const res = await flow(auth, 'github');
        expect(res.headers.get('location')).toBe(`${FRONT}/`);
        expect(setCookie(res, '__Host-ventrical_session')).toBeDefined();
      } finally { await h.close?.(); }
    });

    it('sign-in: a new identity whose verified email belongs to a suspended user is refused and creates nothing', async () => {
      const { h, e1, errors } = await world();
      try {
        const fresh = setup({ google: { subject: 'g-fresh', email: e1, emailVerified: true } }, h.store, errors);
        errors.length = 0;
        const res = await flow(fresh, 'google');
        expect(res.headers.get('location')).toBe(`${FRONT}/signin?error=suspended`);
        expect(setCookie(res, '__Host-ventrical_session')).toBeUndefined();
        expect(await h.store.findUserByIdentity('google', 'g-fresh')).toBeUndefined();
        expect(errors).toContainEqual({ stage: 'callback', code: 'suspended' });
      } finally { await h.close?.(); }
    });

    it('a profile email with stray whitespace and case is stored normalised and matches a suspended mixed-case email', async () => {
      const h = await make();
      try {
        const a = setup({ google: { subject: 'g-a', email: 'ANN@example.test', emailVerified: true } }, h.store);
        await flow(a, 'google');
        expect(await identityOf(h.store, 'google', 'g-a')).toEqual({ email: 'ann@example.test', emailVerified: true });
        await h.suspend(await userId(h.store, 'google', 'g-a'));
        const b = setup({ github: { subject: 'h-b', email: ' Ann@Example.test ', emailVerified: true } }, h.store);
        const res = await flow(b, 'github');
        expect(res.headers.get('location')).toBe(`${FRONT}/signin?error=suspended`);
        expect(await h.store.findUserByIdentity('github', 'h-b')).toBeUndefined();
        const c = setup({ github: { subject: 'h-c', email: ' Fresh@Example.test ', emailVerified: true } }, h.store);
        await flow(c, 'github');
        expect(await identityOf(h.store, 'github', 'h-c')).toEqual({ email: 'fresh@example.test', emailVerified: true });
        expect((await h.store.findUserByIdentity('github', 'h-c'))!.email).toBe('fresh@example.test');
      } finally { await h.close?.(); }
    });

    it('a returning sign-in whose email differs only by case or whitespace does not rewrite the identity', async () => {
      const h = await make();
      try {
        const gh: ProviderProfile = { subject: 'h-r', email: 'r@example.test', emailVerified: true };
        const auth = setup({ github: gh }, h.store);
        await flow(auth, 'github');
        const calls: unknown[] = [];
        const orig = h.store.updateIdentity!.bind(h.store);
        h.store.updateIdentity = (...args) => { calls.push(args); return orig(...args); };
        gh.email = '  R@Example.TEST ';
        expect((await flow(auth, 'github')).headers.get('location')).toBe(`${FRONT}/`);
        expect(calls).toEqual([]);
        expect(await identityOf(h.store, 'github', 'h-r')).toEqual({ email: 'r@example.test', emailVerified: true });
      } finally { await h.close?.(); }
    });

    it('a profile email that is empty after trimming counts as no email', async () => {
      const h = await make();
      try {
        const seen: (string | undefined)[] = [];
        const orig = h.store.emailBelongsToSuspendedUser.bind(h.store);
        h.store.emailBelongsToSuspendedUser = (email, tx, opts) => { seen.push(email); return orig(email, tx, opts); };
        const auth = setup({ github: { subject: 'h-e', email: '   ', emailVerified: true } }, h.store);
        expect((await flow(auth, 'github')).headers.get('location')).toBe(`${FRONT}/`);
        expect(seen).toEqual([]);
        const u = (await h.store.findUserByIdentity('github', 'h-e'))!;
        expect(u.email).toBeNull();
        expect(u.identity?.email ?? null).toBeNull();
      } finally { await h.close?.(); }
    });

    it('link: an unverified suspended email links unverified, and a later verified sign-in with it is refused', async () => {
      const { h, e1, session } = await world();
      try {
        const profile: ProviderProfile = { subject: 'g-unv', email: e1, emailVerified: false };
        const linker = setup({ google: profile }, h.store);
        const res = await flow(linker, 'google', session);
        expect(res.headers.get('location')).toBe(`${FRONT}/`);
        expect(await identityOf(h.store, 'google', 'g-unv')).toEqual({ email: e1, emailVerified: false });
        profile.emailVerified = true;
        const again = await flow(linker, 'google');
        expect(again.headers.get('location')).toBe(`${FRONT}/signin?error=suspended`);
        expect(setCookie(again, '__Host-ventrical_session')).toBeUndefined();
        expect(await identityOf(h.store, 'google', 'g-unv')).toEqual({ email: e1, emailVerified: false });
      } finally { await h.close?.(); }
    });

    it('link: an unrelated verified email links normally', async () => {
      const { h, session } = await world();
      try {
        const linker = setup({ google: { subject: 'g-ok', email: 'e3@example.test', emailVerified: true } }, h.store);
        const res = await flow(linker, 'google', session);
        expect(res.headers.get('location')).toBe(`${FRONT}/`);
        expect(await identityOf(h.store, 'google', 'g-ok')).toEqual({ email: 'e3@example.test', emailVerified: true });
      } finally { await h.close?.(); }
    });
  });
}

suite('memory', async () => {
  const store = createMemoryStore();
  return { store, suspend: async (id) => store.suspend(id) };
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
      close: async () => { await pool.end(); await admin.query(`drop schema ${schema} cascade`); },
    };
  });
});
