import { describe, expect, it } from 'vitest';
import { createAuth, type AuthConfig } from '../src/index.js';
import { hashToken } from '../src/crypto.js';
import { DuplicateIdentityError } from '../src/errors.js';
import { fakeProvider } from './helpers/fake-provider.js';
import { createMemoryStore, type MemoryStore, type MemoryTx } from './helpers/memory-store.js';
import { cookieHeaderFrom, req, setCookie } from './helpers/request.js';
import type { ProviderName, ProviderProfile } from '../src/types.js';

const KEY = Buffer.alloc(32, 7);
const FRONT = 'https://app.example.test';
const PUBLIC = 'https://api.example.test';
const prof = (subject: string, over: Partial<ProviderProfile> = {}): ProviderProfile => ({ subject, emailVerified: true, email: `${subject}@example.test`, ...over });

function setup(profiles: Partial<Record<ProviderName, ProviderProfile | Error>>, over: Partial<AuthConfig<MemoryTx>> = {}) {
  const store = createMemoryStore();
  const overrides: Partial<Record<ProviderName, ReturnType<typeof fakeProvider>>> = {};
  for (const [n, p] of Object.entries(profiles)) overrides[n as ProviderName] = fakeProvider(n as ProviderName, p!);
  const auth = createAuth<MemoryTx>({
    providers: { google: { clientId: 'fake-id', clientSecret: 'fake-secret' }, github: { clientId: 'fake-id', clientSecret: 'fake-secret' } },
    publicUrl: PUBLIC,
    frontendUrl: FRONT,
    encryptionKey: KEY,
    store,
    providerOverrides: overrides,
    ...over,
  });
  return { store, auth };
}

type Auth = ReturnType<typeof setup>['auth'];

/** Runs /start then the callback; `session` is a session cookie header sent to both. */
async function flow(auth: Auth, provider: string, o: { session?: string; startSession?: string; redirect?: string; query?: string } = {}) {
  const startSession = o.startSession ?? o.session;
  const start = (await auth.handle(req('GET', `/auth/${provider}/start${o.redirect ? `?redirect=${encodeURIComponent(o.redirect)}` : ''}`, startSession ? { cookie: startSession } : {})))!;
  const oauthCookie = `ventrical_oauth=${encodeURIComponent(setCookie(start, 'ventrical_oauth')!.value)}`;
  const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
  const cookie = [oauthCookie, o.session].filter(Boolean).join('; ');
  const path = `/auth/${provider}/callback?${(o.query ?? 'code=fake-code&state={state}').replace('{state}', encodeURIComponent(state))}`;
  const res = (await auth.handle(req('GET', path, { cookie })))!;
  return { res, cookie, oauthCookie, state, path };
}

const sessionCookieOf = (res: Response) => setCookie(res, 'ventrical_session');
const loc = (res: Response) => res.headers.get('location');
const count = (store: MemoryStore) => store.sessions.size;

describe('GET /auth/:provider/callback', () => {
  it('new user is created and signed in', async () => {
    const { auth, store } = setup({ google: prof('g1', { name: 'Gee' }) });
    const { res } = await flow(auth, 'google', { redirect: '/memories' });
    expect(res.status).toBe(302);
    expect(loc(res)).toBe(`${FRONT}/memories`);
    const sc = sessionCookieOf(res)!;
    expect(sc.attrs.httponly).toBe(true);
    expect(store.sessions.has(hashToken(sc.value))).toBe(true);
    const user = await store.findUserByIdentity('google', 'g1');
    expect(user).toMatchObject({ email: 'g1@example.test', name: 'Gee' });
    const me = await auth.getSession(req('GET', '/x', { cookie: `ventrical_session=${sc.value}` }));
    expect(me?.user.id).toBe(user!.id);
  });

  it('returning user is signed in without a new user', async () => {
    const { auth, store } = setup({ google: prof('g1') });
    await flow(auth, 'google');
    const first = (await store.findUserByIdentity('google', 'g1'))!;
    const { res } = await flow(auth, 'google');
    expect(res.status).toBe(302);
    expect(sessionCookieOf(res)).toBeDefined();
    expect((await store.findUserByIdentity('google', 'g1'))!.id).toBe(first.id);
    expect(count(store)).toBe(2);
  });

  it('never links by email: a second provider with the same verified email creates no link', async () => {
    const { auth, store } = setup({ google: prof('g1', { email: 'same@example.test' }), github: prof('h1', { email: 'same@example.test' }) });
    await flow(auth, 'google');
    const { res } = await flow(auth, 'github');
    const a = (await store.findUserByIdentity('google', 'g1'))!;
    const b = (await store.findUserByIdentity('github', 'h1'))!;
    expect(b.id).not.toBe(a.id);
    const me = await auth.getSession(req('GET', '/x', { cookie: `ventrical_session=${sessionCookieOf(res)!.value}` }));
    expect(me!.user.id).toBe(b.id);
  });

  async function signedIn(auth: Auth, p: string) {
    const { res } = await flow(auth, p);
    return `ventrical_session=${sessionCookieOf(res)!.value}`;
  }

  it('link works only in the session that started the flow', async () => {
    const { auth, store } = setup({ google: prof('g1'), github: prof('h1') });
    const sessA = await signedIn(auth, 'google');
    // Same session: links, no new user, no new session.
    const ok = await flow(auth, 'github', { session: sessA });
    expect(ok.res.status).toBe(302);
    expect(sessionCookieOf(ok.res)).toBeUndefined();
    const a = (await store.findUserByIdentity('google', 'g1'))!;
    expect((await store.findUserByIdentity('github', 'h1'))!.id).toBe(a.id);

    // Flow started signed out, finished inside someone's session: no link; signs in as its own user.
    const { auth: auth2, store: store2 } = setup({ google: prof('g1'), github: prof('h2', { email: 'g1@example.test' }) });
    const sessB = await signedIn(auth2, 'google');
    const r = await flow(auth2, 'github', { startSession: undefined, session: undefined });
    const cookie2 = `${r.oauthCookie}; ${sessB}`;
    const res2 = (await auth2.handle(req('GET', r.path, { cookie: cookie2 })))!;
    const g = (await store2.findUserByIdentity('google', 'g1'))!;
    const h = (await store2.findUserByIdentity('github', 'h2'))!;
    expect(h.id).not.toBe(g.id);
    expect(sessionCookieOf(res2)).toBeDefined();

    // Flow bound to user A, finished while signed in as user B: no link to either.
    const { auth: auth3, store: store3 } = setup({ google: prof('ga'), github: prof('hx') });
    const sA = await signedIn(auth3, 'google');
    const start = (await auth3.handle(req('GET', '/auth/github/start', { cookie: sA })))!;
    const { auth: _unused } = { auth: auth3 };
    const other = await store3.createUserWithIdentity({ provider: 'google', subject: 'gb', emailVerified: true });
    const sessOther = `ventrical_session=sess-other`;
    await store3.transaction((tx) => store3.createSessionUnlessSuspended(other.id, hashToken('sess-other'), new Date(Date.now() + 864e5), { provider: 'google', subject: 'gb' }, tx));
    const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
    const res3 = (await auth3.handle(req('GET', `/auth/github/callback?code=c&state=${state}`, {
      cookie: `ventrical_oauth=${encodeURIComponent(setCookie(start, 'ventrical_oauth')!.value)}; ${sessOther}`,
    })))!;
    const hx = (await store3.findUserByIdentity('github', 'hx'))!;
    const ga = (await store3.findUserByIdentity('google', 'ga'))!;
    expect(hx.id).not.toBe(ga.id);
    expect(hx.id).not.toBe(other.id);
    expect(sessionCookieOf(res3)).toBeDefined();
  });

  it('identity owned by another user redirects identity_in_use', async () => {
    const { auth, store } = setup({ google: prof('g1'), github: prof('h1') });
    await flow(auth, 'github'); // user H owns github h1
    const sessG = await signedIn(auth, 'google');
    const { res } = await flow(auth, 'github', { session: sessG });
    expect(res.status).toBe(302);
    expect(loc(res)).toBe(`${FRONT}/settings?error=identity_in_use`);
    const g = (await store.findUserByIdentity('google', 'g1'))!;
    expect((await store.findUserByIdentity('github', 'h1'))!.id).not.toBe(g.id);
  });

  it('a suspended user is refused through any provider with the same verified email', async () => {
    const { auth, store } = setup({ google: prof('g1', { email: 'Same@Example.test' }), github: prof('h1', { email: 'same@example.TEST' }) });
    await flow(auth, 'google');
    store.suspend((await store.findUserByIdentity('google', 'g1'))!.id);
    const before = count(store);
    const { res } = await flow(auth, 'github');
    expect(loc(res)).toBe(`${FRONT}/signin?error=suspended`);
    expect(sessionCookieOf(res)).toBeUndefined();
    expect(await store.findUserByIdentity('github', 'h1')).toBeUndefined();
    expect(count(store)).toBe(before);
  });

  it('an unverified email does not trigger the suspended-email check', async () => {
    const { auth, store } = setup({ google: prof('g1', { email: 'same@example.test' }), github: prof('h1', { email: 'same@example.test', emailVerified: false }) });
    await flow(auth, 'google');
    store.suspend((await store.findUserByIdentity('google', 'g1'))!.id);
    const { res } = await flow(auth, 'github');
    expect(loc(res)).toBe(`${FRONT}/`);
    expect(await store.findUserByIdentity('github', 'h1')).toBeDefined();
  });

  it('the in-transaction suspended-email check catches a suspension after the pre-check', async () => {
    const { auth, store } = setup({ google: prof('g1', { email: 'o@example.test' }), github: prof('h1', { email: 'o@example.test' }) }, {
      hooks: {
        // Runs after the pre-check and before the transaction.
        canCreateAccount: async () => {
          const owner = await store.findUserByIdentity('google', 'g1');
          if (owner) store.suspend(owner.id);
          return { allow: true };
        },
      },
    });
    await flow(auth, 'google'); // creates the owner (hook finds no owner yet)
    const before = count(store);
    const { res } = await flow(auth, 'github');
    expect(loc(res)).toBe(`${FRONT}/signin?error=suspended`);
    expect(sessionCookieOf(res)).toBeUndefined();
    expect(await store.findUserByIdentity('github', 'h1')).toBeUndefined();
    expect(count(store)).toBe(before);
  });

  it('a non-ASCII redirect signs in with a percent-encoded Location', async () => {
    const { auth, store } = setup({ google: prof('g1') });
    const { res } = await flow(auth, 'google', { redirect: '/日本?q=é' });
    expect(res.status).toBe(302);
    expect(loc(res)).toBe(`${FRONT}/%E6%97%A5%E6%9C%AC?q=%C3%A9`);
    expect(sessionCookieOf(res)).toBeDefined();
    expect(await store.findUserByIdentity('google', 'g1')).toBeDefined();
  });

  it('a non-ASCII redirect on link ends with a percent-encoded Location', async () => {
    const { auth, store } = setup({ google: prof('g1'), github: prof('h1') });
    const sess = `ventrical_session=${sessionCookieOf((await flow(auth, 'google')).res)!.value}`;
    const { res } = await flow(auth, 'github', { session: sess, redirect: '/日本' });
    expect(res.status).toBe(302);
    expect(loc(res)).toBe(`${FRONT}/%E6%97%A5%E6%9C%AC`);
    const a = (await store.findUserByIdentity('google', 'g1'))!;
    expect((await store.findUserByIdentity('github', 'h1'))!.id).toBe(a.id);
  });

  it('a hook path that is not a valid URL never makes the response throw', async () => {
    const { auth } = setup({ google: prof('g1') }, { hooks: { resolveRedirect: () => ({ target: 'frontend', path: '/\u0000\ud800x' }) } });
    const { res } = await flow(auth, 'google');
    expect(res.status).toBe(302);
    expect(sessionCookieOf(res)).toBeDefined();
    expect(loc(res)!.startsWith(`${FRONT}/`)).toBe(true);
  });

  it('a duplicate on link with no owner found redirects link_failed', async () => {
    const store = createMemoryStore();
    const dup = Object.assign(Object.create(store) as typeof store, {
      linkIdentity: async () => { throw new DuplicateIdentityError(); },
    });
    const { auth } = setup({ google: prof('g1'), github: prof('h1') }, { store: dup });
    const sess = `ventrical_session=${sessionCookieOf((await flow(auth, 'google')).res)!.value}`;
    const { res } = await flow(auth, 'github', { session: sess });
    expect(loc(res)).toBe(`${FRONT}/settings?error=link_failed`);
  });

  it('suspension between lookup and session insert leaves no session', async () => {
    const store = createMemoryStore();
    const racing = Object.assign(Object.create(store) as typeof store, {
      createSessionUnlessSuspended: async (...a: Parameters<typeof store.createSessionUnlessSuspended>) => {
        store.suspend(a[0]);
        return store.createSessionUnlessSuspended(...a);
      },
    });
    const { auth } = setup({ google: prof('g1') }, { store: racing });
    const { res } = await flow(auth, 'google');
    expect(loc(res)).toBe(`${FRONT}/signin?error=suspended`);
    expect(sessionCookieOf(res)).toBeUndefined();
    expect(store.sessions.size).toBe(0);
  });

  it('canCreateAccount deny redirects with the reason and creates nothing', async () => {
    const seen: unknown[] = [];
    const { auth, store } = setup({ google: prof('g1') }, {
      hooks: { canCreateAccount: async (p) => { seen.push(p); return { allow: false, reason: 'a&b#c%0d%0a' }; } },
    });
    const { res } = await flow(auth, 'google');
    expect(loc(res)).toBe(`${FRONT}/signin?error=${encodeURIComponent('a&b#c%0d%0a')}`);
    expect(sessionCookieOf(res)).toBeUndefined();
    expect(await store.findUserByIdentity('google', 'g1')).toBeUndefined();
    expect(count(store)).toBe(0);
    expect(seen).toEqual([{ provider: 'google', subject: 'g1', email: 'g1@example.test', emailVerified: true }]);
  });

  it('canCreateAccount is not called for a returning user or a link', async () => {
    let calls = 0;
    const { auth } = setup({ google: prof('g1'), github: prof('h1') }, {
      hooks: { canCreateAccount: async () => { calls++; return { allow: true }; } },
    });
    const { res } = await flow(auth, 'google');
    expect(calls).toBe(1);
    await flow(auth, 'google');
    expect(calls).toBe(1);
    await flow(auth, 'github', { session: `ventrical_session=${sessionCookieOf(res)!.value}` });
    expect(calls).toBe(1);
  });

  it('afterSignIn throwing rolls back the user and the session and redirects sign_in_failed', async () => {
    const { auth, store } = setup({ google: prof('g1') }, {
      hooks: { afterSignIn: async () => { throw new Error('secret db detail'); } },
    });
    const { res } = await flow(auth, 'google');
    expect(res.status).toBe(302);
    expect(loc(res)).toBe(`${FRONT}/signin?error=sign_in_failed`);
    expect(sessionCookieOf(res)).toBeUndefined();
    expect(await store.findUserByIdentity('google', 'g1')).toBeUndefined();
    expect(count(store)).toBe(0);
    expect(JSON.stringify([...res.headers])).not.toContain('secret db detail');
  });

  it('afterSignIn receives isNew true then false, the same tx as the store calls, and runs before the session cookie is set', async () => {
    const calls: { isNew: boolean; tx: MemoryTx; provider: string; sessionsAtCall: number }[] = [];
    const store = createMemoryStore();
    const txSeen: (MemoryTx | undefined)[] = [];
    const spy = Object.assign(Object.create(store) as typeof store, {
      createUserWithIdentity: async (p: any, tx?: MemoryTx) => { txSeen.push(tx); return store.createUserWithIdentity(p, tx); },
      createSessionUnlessSuspended: async (...a: Parameters<typeof store.createSessionUnlessSuspended>) => { txSeen.push(a[4]); return store.createSessionUnlessSuspended(...a); },
    });
    const { auth } = setup({ google: prof('g1') }, {
      store: spy,
      hooks: { afterSignIn: async (c) => { calls.push({ isNew: c.isNew, tx: c.tx, provider: c.provider, sessionsAtCall: store.sessions.size }); } },
    });
    await flow(auth, 'google');
    await flow(auth, 'google');
    expect(calls.map((c) => c.isNew)).toEqual([true, false]);
    expect(calls.map((c) => c.provider)).toEqual(['google', 'google']);
    expect(calls.map((c) => c.sessionsAtCall)).toEqual([0, 1]);
    expect(txSeen[0]).toBeDefined();
    expect(txSeen[0]).toBe(calls[0]!.tx);
    expect(txSeen[1]).toBe(calls[0]!.tx);
    expect(txSeen[2]).toBe(calls[1]!.tx);
  });

  it('a provider error message never reaches the response', async () => {
    const { auth } = setup({ google: new Error('token=abc123 code=zzz body={"error":"leak"}') });
    const { res } = await flow(auth, 'google');
    expect(res.status).toBe(400);
    const text = await res.text();
    expect(JSON.parse(text)).toEqual({ error: { code: 'oauth_error', message: 'Sign-in failed' } });
    expect(text + JSON.stringify([...res.headers])).not.toMatch(/abc123|zzz|leak|fake-code/);
  });

  it('a profile with no email signs in and canCreateAccount sees no email', async () => {
    let seen: object | undefined;
    const { auth, store } = setup({ google: { subject: 'g1', emailVerified: false } }, {
      hooks: { canCreateAccount: async (p) => { seen = p; return { allow: true }; } },
    });
    const { res } = await flow(auth, 'google');
    expect(res.status).toBe(302);
    expect(sessionCookieOf(res)).toBeDefined();
    expect(seen).toEqual({ provider: 'google', subject: 'g1', emailVerified: false });
    expect(seen).not.toHaveProperty('email');
    expect((await store.findUserByIdentity('google', 'g1'))!.email).toBeNull();
  });

  it('replaying the state cookie after a successful callback fails with invalid_state', async () => {
    const { auth, store } = setup({ google: prof('g1') });
    const first = await flow(auth, 'google');
    expect(first.res.status).toBe(302);
    const cleared = setCookie(first.res, 'ventrical_oauth')!;
    expect(cleared.value).toBe('');
    expect(cleared.attrs['max-age']).toBe('0');
    // Proves: the state cookie is cleared with Max-Age=0, and a callback arriving without it fails with invalid_state.
    const noCookie = (await auth.handle(req('GET', first.path)))!;
    expect(noCookie.status).toBe(400);
    expect((await noCookie.json() as any).error.code).toBe('invalid_state');
    const before = count(store);
    const replay = (await auth.handle(req('GET', first.path, { cookie: cookieHeaderFrom(first.res) })))!;
    expect(replay.status).toBe(400);
    expect((await replay.json() as any).error.code).toBe('invalid_state');
    expect(count(store)).toBe(before);
  });

  it('a tampered state cookie gives invalid_state', async () => {
    const { auth, store } = setup({ google: prof('g1') });
    const start = (await auth.handle(req('GET', '/auth/google/start')))!;
    const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
    const v = setCookie(start, 'ventrical_oauth')!.value;
    const flipped = v.slice(0, -2) + (v.endsWith('A') ? 'B' : 'A') + v.slice(-1);
    for (const bad of [flipped, 'garbage', v.slice(0, 10)]) {
      const res = (await auth.handle(req('GET', `/auth/google/callback?code=c&state=${state}`, { cookie: `ventrical_oauth=${encodeURIComponent(bad)}` })))!;
      expect(res.status).toBe(400);
      expect((await res.json() as any).error.code).toBe('invalid_state');
    }
    expect(count(store)).toBe(0);
  });

  it('the state cookie is cleared on every response path', async () => {
    const { auth } = setup({ google: prof('g1') });
    const bad = (await auth.handle(req('GET', '/auth/google/callback?code=c&state=nope')))!;
    expect(setCookie(bad, 'ventrical_oauth')!.attrs['max-age']).toBe('0');
    const unknown = (await auth.handle(req('GET', '/auth/nope/callback?code=c&state=nope')))!;
    expect(unknown.status).toBe(404);
    expect(setCookie(unknown, 'ventrical_oauth')!.attrs['max-age']).toBe('0');
    const denied = await flow(auth, 'google', { query: 'error=access_denied&error_description=leak&state={state}' });
    expect(denied.res.status).toBe(400);
    expect((await denied.res.json() as any).error.code).toBe('oauth_error');
    expect(setCookie(denied.res, 'ventrical_oauth')!.attrs['max-age']).toBe('0');
    const noCode = await flow(auth, 'google', { query: 'state={state}' });
    expect(noCode.res.status).toBe(400);
    expect((await noCode.res.json() as any).error.code).toBe('oauth_error');
    expect(setCookie(noCode.res, 'ventrical_oauth')!.attrs['max-age']).toBe('0');
    const failed = setup({ google: new Error('x') });
    const f = await flow(failed.auth, 'google');
    expect(setCookie(f.res, 'ventrical_oauth')!.attrs['max-age']).toBe('0');
    const rollback = setup({ google: prof('g1') }, { hooks: { afterSignIn: async () => { throw new Error('x'); } } });
    const r = await flow(rollback.auth, 'google');
    expect(setCookie(r.res, 'ventrical_oauth')!.attrs['max-age']).toBe('0');
  });

  it('a wrong state, another provider\'s cookie, a missing code or an error parameter are rejected', async () => {
    const { auth } = setup({ google: prof('g1'), github: prof('h1') });
    const wrong = await flow(auth, 'google', { query: 'code=c&state=wrong' });
    expect((await wrong.res.json() as any).error.code).toBe('invalid_state');
    // Cookie from a google /start used on the github callback.
    const g = await flow(auth, 'google', { query: 'x=1' });
    const cross = (await auth.handle(req('GET', `/auth/github/callback?code=c&state=${g.state}`, { cookie: g.oauthCookie })))!;
    expect((await cross.json() as any).error.code).toBe('invalid_state');
    // error param with a valid state
    const start = (await auth.handle(req('GET', '/auth/google/start')))!;
    const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
    const oc = `ventrical_oauth=${encodeURIComponent(setCookie(start, 'ventrical_oauth')!.value)}`;
    const e = (await auth.handle(req('GET', `/auth/google/callback?error=access_denied&state=${state}`, { cookie: oc })))!;
    expect(e.status).toBe(400);
    expect((await e.json() as any).error.code).toBe('oauth_error');
    const nc = (await auth.handle(req('GET', `/auth/google/callback?state=${state}`, { cookie: oc })))!;
    expect((await nc.json() as any).error.code).toBe('oauth_error');
  });

  it('redirects through safeRedirect and hooks.resolveRedirect, using only configured URLs', async () => {
    const { auth } = setup({ google: prof('g1') }, {
      hooks: { resolveRedirect: (p) => (p.startsWith('/authorize') ? { target: 'backend', path: p } : { target: 'frontend', path: p }) },
    });
    const a = await flow(auth, 'google', { redirect: '/authorize?x=1' });
    expect(loc(a.res)).toBe(`${PUBLIC}/authorize?x=1`);
    const b = await flow(auth, 'google', { redirect: '//evil.example.test' });
    expect(loc(b.res)).toBe(`${FRONT}/`);
    const c = await flow(auth, 'google', { redirect: '/a' });
    expect(loc(c.res)).toBe(`${FRONT}/a`);
    // A hostile Host header does not influence the location.
    const start = (await auth.handle(req('GET', '/auth/google/start')))!;
    const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
    const res = (await auth.handle(new Request(`https://evil.example.test/auth/google/callback?code=c&state=${state}`, {
      headers: { cookie: `ventrical_oauth=${encodeURIComponent(setCookie(start, 'ventrical_oauth')!.value)}`, host: 'evil.example.test' },
      redirect: 'manual',
    })))!;
    expect(loc(res)).toBe(`${FRONT}/`);
  });

  it('two concurrent first sign-ins for one identity end signed in as the same user with no 500', async () => {
    const newFlags: boolean[] = [];
    let arrived = 0;
    let release!: () => void;
    const gate = new Promise<void>((r) => { release = r; });
    const { auth, store } = setup({ google: prof('g1') }, {
      hooks: {
        // Both requests have found no identity before either creates one.
        canCreateAccount: async () => { if (++arrived === 2) release(); await gate; return { allow: true }; },
        afterSignIn: async (c) => { newFlags.push(c.isNew); },
      },
    });
    const [a, b] = await Promise.all([flow(auth, 'google'), flow(auth, 'google')]);
    for (const { res } of [a, b]) {
      expect(res.status).toBe(302);
      expect(loc(res)).toBe(`${FRONT}/`);
      expect(sessionCookieOf(res)).toBeDefined();
    }
    const uid = (await store.findUserByIdentity('google', 'g1'))!.id;
    const ids = await Promise.all([a, b].map(async ({ res }) =>
      (await auth.getSession(req('GET', '/x', { cookie: `ventrical_session=${sessionCookieOf(res)!.value}` })))!.user.id));
    expect(ids).toEqual([uid, uid]);
    expect(newFlags.sort()).toEqual([false, true]);
  });

  it('a duplicate whose retry also fails ends in sign_in_failed with nothing kept', async () => {
    const store = createMemoryStore();
    const dup = Object.assign(Object.create(store) as typeof store, {
      createUserWithIdentity: async () => { throw new DuplicateIdentityError(); },
    });
    const { auth } = setup({ google: prof('g1') }, { store: dup });
    const { res } = await flow(auth, 'google');
    expect(loc(res)).toBe(`${FRONT}/signin?error=sign_in_failed`);
    expect(sessionCookieOf(res)).toBeUndefined();
    expect(store.sessions.size).toBe(0);
  });

  it('a non-duplicate create failure is sign_in_failed, not a 500', async () => {
    const store = createMemoryStore();
    const bad = Object.assign(Object.create(store) as typeof store, {
      createUserWithIdentity: async () => { throw new Error('db down'); },
    });
    const { auth } = setup({ google: prof('g1') }, { store: bad });
    const { res } = await flow(auth, 'google');
    expect(loc(res)).toBe(`${FRONT}/signin?error=sign_in_failed`);
  });
});
