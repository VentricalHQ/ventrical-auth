import { describe, expect, it } from 'vitest';
import { openOAuthState } from '../src/cookies.js';
import { createAuth, type AuthConfig } from '../src/index.js';
import { newSessionId } from '../src/session.js';
import { fakeProvider } from './helpers/fake-provider.js';
import { createMemoryStore, type MemoryTx } from './helpers/memory-store.js';
import { cookieHeaderFrom, req, setCookie } from './helpers/request.js';

const KEY = Buffer.alloc(32, 7);
const FRONT = 'https://app.example.test';
const profile = { subject: 's', emailVerified: true };

function setup(over: Partial<AuthConfig<MemoryTx>> = {}) {
  const store = createMemoryStore();
  const auth = createAuth<MemoryTx>({
    providers: { google: { clientId: 'fake-id', clientSecret: 'fake-secret' } },
    publicUrl: 'https://api.example.test',
    frontendUrl: FRONT,
    encryptionKey: KEY,
    store,
    providerOverrides: { google: fakeProvider('google', profile), github: fakeProvider('github', profile) },
    ...over,
  });
  return { store, auth };
}

async function withSession(store: ReturnType<typeof createMemoryStore>, email = 'a@example.test') {
  const user = await store.createUserWithIdentity({ provider: 'github', subject: email, email, emailVerified: true });
  const { id, idHash } = newSessionId();
  await store.transaction((tx) => store.createSessionUnlessSuspended(user.id, idHash, new Date(Date.now() + 30 * 864e5), { provider: 'github', subject: email }, tx));
  return { user, id, idHash, cookie: `ventrical_session=${id}` };
}

describe('GET /auth/providers', () => {
  it('lists only configured providers in order', async () => {
    const { auth } = setup({
      providers: { microsoft: { clientId: 'i', clientSecret: 's', tenant: 't' }, google: { clientId: 'i', clientSecret: 's' } },
      providerOverrides: { microsoft: fakeProvider('microsoft', profile), google: fakeProvider('google', profile) },
    });
    const res = (await auth.handle(req('GET', '/auth/providers')))!;
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ providers: ['google', 'microsoft'] });
  });
  it('lists only google when only google is configured', async () => {
    const { auth } = setup({ providerOverrides: { google: fakeProvider('google', profile) } });
    expect(await (await auth.handle(req('GET', '/auth/providers')))!.json()).toEqual({ providers: ['google'] });
  });
});

describe('an unrelated path', () => {
  it('returns undefined', async () => {
    const { auth } = setup();
    expect(await auth.handle(req('GET', '/api/me'))).toBeUndefined();
    expect(await auth.handle(req('GET', '/auth'))).toBeUndefined();
    expect(await auth.handle(req('GET', '/auth/google/other'))).toBeUndefined();
  });
});

describe('GET /auth/:provider/start', () => {
  it('unknown provider is 404 not_found', async () => {
    const res = (await setup().auth.handle(req('GET', '/auth/unknown/start')))!;
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: { code: 'not_found', message: 'Not found' } });
  });
  it('unconfigured provider is 404 provider_disabled', async () => {
    const { auth } = setup({ providerOverrides: { google: fakeProvider('google', profile) } });
    const res = (await auth.handle(req('GET', '/auth/github/start')))!;
    expect(res.status).toBe(404);
    expect((await res.json() as any).error.code).toBe('provider_disabled');
  });
  it('prototype-ish names are not_found', async () => {
    const res = (await setup().auth.handle(req('GET', '/auth/constructor/start')))!;
    expect((await res.json() as any).error.code).toBe('not_found');
  });

  it('redirects 302 to the provider with state and sets a sealed oauth cookie', async () => {
    const { auth } = setup();
    const res = (await auth.handle(req('GET', '/auth/google/start?redirect=/memories')))!;
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get('location')!);
    expect(loc.origin).toBe('https://idp.example.test');
    const c = setCookie(res, 'ventrical_oauth')!;
    expect(c.attrs['max-age']).toBe('600');
    expect(c.attrs.httponly).toBe(true);
    expect(c.attrs.secure).toBe(true);
    expect(c.attrs.samesite).toBe('Lax');
    expect(c.raw).not.toContain('/memories');
    const st = openOAuthState(c.value, KEY)!;
    expect(st.provider).toBe('google');
    expect(st.state).toBe(loc.searchParams.get('state'));
    expect(st.redirect).toBe('/memories');
    expect(st.codeVerifier).not.toBe('');
    expect(st.nonce).toBeTruthy();
    expect(st.linkUserId).toBeUndefined();
  });

  it('uses custom cookie names', async () => {
    const { auth } = setup({ cookieNames: { oauth: 'my_oauth' } });
    const res = (await auth.handle(req('GET', '/auth/google/start')))!;
    expect(setCookie(res, 'my_oauth')).toBeDefined();
    expect(setCookie(res, 'ventrical_oauth')).toBeUndefined();
  });

  it('binds linkUserId when a session exists', async () => {
    const { auth, store } = setup();
    const s = await withSession(store);
    const res = (await auth.handle(req('GET', '/auth/google/start', { cookie: s.cookie })))!;
    expect(openOAuthState(setCookie(res, 'ventrical_oauth')!.value, KEY)!.linkUserId).toBe(s.user.id);
  });

  it('does not bind linkUserId for an unknown session cookie', async () => {
    const { auth } = setup();
    const res = (await auth.handle(req('GET', '/auth/google/start', { cookie: 'ventrical_session=nope' })))!;
    expect(openOAuthState(setCookie(res, 'ventrical_oauth')!.value, KEY)!.linkUserId).toBeUndefined();
  });

  it('keeps only a safe redirect', async () => {
    const { auth } = setup();
    for (const bad of ['https://evil.test', '//evil.test', '/\\evil.test', 'relative']) {
      const res = (await auth.handle(req('GET', `/auth/google/start?redirect=${encodeURIComponent(bad)}`)))!;
      expect(openOAuthState(setCookie(res, 'ventrical_oauth')!.value, KEY)!.redirect).toBe('/');
    }
    const ok = (await auth.handle(req('GET', '/auth/google/start?redirect=%2Fa%3Fb%3D1')))!;
    expect(openOAuthState(setCookie(ok, 'ventrical_oauth')!.value, KEY)!.redirect).toBe('/a?b=1');
  });

  it('maps a provider failure to a generic 500 with no detail and no logging', async () => {
    const secret = 'planted-secret-abc123';
    const bad = { name: 'google' as const, authorizeUrl: () => { throw new Error(secret); }, exchange: async () => ({ subject: 's', emailVerified: true }) };
    const spies = (['log', 'error', 'warn', 'info', 'debug'] as const).map((k) => {
      const orig = console[k];
      const calls: unknown[][] = [];
      console[k] = (...a: unknown[]) => { calls.push(a); };
      return { k, orig, calls };
    });
    let res: Response;
    try {
      res = (await setup({ providerOverrides: { google: bad } }).auth.handle(req('GET', '/auth/google/start')))!;
    } finally {
      for (const s of spies) console[s.k] = s.orig;
    }
    expect(res.status).toBe(500);
    const text = await res.text();
    expect(JSON.parse(text)).toEqual({ error: { code: 'internal_error', message: 'Internal error' } });
    expect(text).not.toContain(secret);
    expect(spies.flatMap((s) => s.calls)).toEqual([]);
    expect(res.headers.getSetCookie()).toEqual([]);
  });
});

describe('POST /auth/logout', () => {
  it('deletes the session and clears the cookie', async () => {
    const { auth, store } = setup();
    const s = await withSession(store);
    const res = (await auth.handle(req('POST', '/auth/logout', { cookie: s.cookie, origin: FRONT })))!;
    expect(res.status).toBe(204);
    expect(store.sessions.has(s.idHash)).toBe(false);
    const c = setCookie(res, 'ventrical_session')!;
    expect(c.value).toBe('');
    expect(c.attrs['max-age']).toBe('0');
    expect(await auth.getSession(req('GET', '/', { cookie: s.cookie }))).toBeUndefined();
  });
  it('without a session cookie is still 204', async () => {
    const res = (await setup().auth.handle(req('POST', '/auth/logout', { origin: FRONT })))!;
    expect(res.status).toBe(204);
  });
  it('accepts the public origin and a same-origin Referer', async () => {
    const { auth } = setup();
    expect((await auth.handle(req('POST', '/auth/logout', { origin: 'https://api.example.test' })))!.status).toBe(204);
    expect((await auth.handle(req('POST', '/auth/logout', { referer: `${FRONT}/page` })))!.status).toBe(204);
  });
  it('GET is not handled', async () => {
    expect(await setup().auth.handle(req('GET', '/auth/logout'))).toBeUndefined();
  });
});

describe('POST /auth/logout-everywhere', () => {
  it('requires a session', async () => {
    const res = (await setup().auth.handle(req('POST', '/auth/logout-everywhere', { origin: FRONT })))!;
    expect(res.status).toBe(401);
    expect((await res.json() as any).error.code).toBe('unauthenticated');
  });

  it('calls onLogoutEverywhere with the same tx as the delete, in one transaction, then clears the cookie', async () => {
    const store = createMemoryStore();
    const calls: string[] = [];
    let hookTx: MemoryTx | undefined;
    let deleteTx: MemoryTx | undefined;
    const wrapped = Object.assign(Object.create(store) as typeof store, {
      transaction: <T>(fn: (tx: MemoryTx) => Promise<T>) => { calls.push('transaction'); return store.transaction(fn); },
      deleteSessionsForUser: (uid: string, tx?: MemoryTx) => { calls.push('delete'); deleteTx = tx; return store.deleteSessionsForUser(uid, tx); },
    });
    const { auth } = setup({
      store: wrapped,
      hooks: { onLogoutEverywhere: async (_uid, tx) => { calls.push('hook'); hookTx = tx; } },
    });
    const s = await withSession(store);
    const other = await withSession(store, 'b@example.test');
    const second = newSessionId();
    await store.transaction((tx) => store.createSessionUnlessSuspended(s.user.id, second.idHash, new Date(Date.now() + 864e5), { provider: 'github', subject: 'x' }, tx));
    const res = (await auth.handle(req('POST', '/auth/logout-everywhere', { cookie: s.cookie, origin: FRONT })))!;
    expect(res.status).toBe(204);
    expect(calls).toEqual(['transaction', 'hook', 'delete']);
    expect(hookTx).toBeDefined();
    expect(deleteTx).toBe(hookTx);
    expect(store.sessions.has(s.idHash)).toBe(false);
    expect(store.sessions.has(second.idHash)).toBe(false);
    expect(store.sessions.has(other.idHash)).toBe(true);
    expect(setCookie(res, 'ventrical_session')!.value).toBe('');
  });

  it('the memory store hands out a distinct tx per transaction', async () => {
    const store = createMemoryStore();
    const a = await store.transaction(async (tx) => tx);
    const b = await store.transaction(async (tx) => tx);
    expect(a).not.toBe(b);
  });

  it('a hook failure leaves the sessions in place and returns a generic 500', async () => {
    const store = createMemoryStore();
    const { auth } = setup({ store, hooks: { onLogoutEverywhere: async () => { throw new Error('planted-secret-xyz'); } } });
    const s = await withSession(store);
    const res = (await auth.handle(req('POST', '/auth/logout-everywhere', { cookie: s.cookie, origin: FRONT })))!;
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: { code: 'internal_error', message: 'Internal error' } });
    expect(store.sessions.has(s.idHash)).toBe(true);
    expect(res.headers.getSetCookie()).toEqual([]);
  });

  it('a delete failure rolls back the hook\'s writes and keeps every session', async () => {
    const store = createMemoryStore();
    const failing = Object.assign(Object.create(store) as typeof store, {
      deleteSessionsForUser: async () => { throw new Error('boom'); },
    });
    const planted = newSessionId();
    let hookRan = false;
    const { auth } = setup({
      store: failing,
      hooks: {
        onLogoutEverywhere: async (uid, tx) => {
          // The hook's write goes through the tx; the failed delete must undo it.
          await store.createSessionUnlessSuspended(uid, planted.idHash, new Date(Date.now() + 864e5), { provider: 'github', subject: 'hook' }, tx);
          hookRan = true;
        },
      },
    });
    const s = await withSession(store);
    const other = await withSession(store, 'b@example.test');
    const res = (await auth.handle(req('POST', '/auth/logout-everywhere', { cookie: s.cookie, origin: FRONT })))!;
    expect(res.status).toBe(500);
    expect(hookRan).toBe(true);
    expect(store.sessions.has(planted.idHash)).toBe(false);
    expect(store.sessions.has(s.idHash)).toBe(true);
    expect(store.sessions.has(other.idHash)).toBe(true);
    expect(res.headers.getSetCookie()).toEqual([]);
  });
});

describe('POST origin check', () => {
  it.each(['/auth/logout', '/auth/logout-everywhere'])('%s without Origin/Referer or with another origin is 403 and deletes nothing', async (path) => {
    const { auth, store } = setup();
    const s = await withSession(store);
    for (const o of [{}, { origin: 'https://evil.test' }, { referer: 'https://evil.test/x' }, { origin: 'null' }]) {
      const res = (await auth.handle(req('POST', path, { cookie: s.cookie, ...o })))!;
      expect(res.status).toBe(403);
      expect((await res.json() as any).error.code).toBe('forbidden');
      expect(res.headers.getSetCookie()).toEqual([]);
      expect(store.sessions.has(s.idHash)).toBe(true);
    }
  });
});

describe('createAuth surface', () => {
  it('returns handle, getSession and requireSession', async () => {
    const { auth, store } = setup();
    const s = await withSession(store);
    expect(typeof auth.handle).toBe('function');
    expect((await auth.getSession(req('GET', '/', { cookie: s.cookie })))!.user.id).toBe(s.user.id);
    await expect(auth.requireSession(req('GET', '/'))).rejects.toMatchObject({ status: 401 });
  });
  it('a refreshed session cookie is forwarded on /start', async () => {
    const now = new Date('2026-01-01T00:00:00Z');
    const store = createMemoryStore();
    const { auth } = setup({ store, clock: () => now });
    const user = await store.createUserWithIdentity({ provider: 'github', subject: 'q', emailVerified: true });
    const { id, idHash } = newSessionId();
    await store.transaction((tx) => store.createSessionUnlessSuspended(user.id, idHash, new Date(now.getTime() + 10 * 864e5), { provider: 'github', subject: 'q' }, tx));
    const res = (await auth.handle(req('GET', '/auth/google/start', { cookie: `ventrical_session=${id}` })))!;
    expect(setCookie(res, 'ventrical_session')!.value).toBe(id);
    expect(cookieHeaderFrom(res)).toContain('ventrical_oauth=');
  });
});

describe('origin check runs before everything else', () => {
  const paths = ['/auth/logout', '/auth/logout-everywhere'];
  const bad = [{}, { origin: 'https://evil.test' }, { referer: 'https://evil.test/x' }];

  it.each(paths)('%s: an unauthenticated request with a bad Origin is 403, not 401', async (path) => {
    const { auth } = setup();
    for (const o of bad) {
      const res = (await auth.handle(req('POST', path, o)))!;
      expect(res.status).toBe(403);
      expect((await res.json() as any).error.code).toBe('forbidden');
    }
  });

  it.each(paths)('%s: a 403 makes zero store and hook calls', async (path) => {
    const store = createMemoryStore();
    const s = await withSession(store);
    const calls: string[] = [];
    const spy = <K extends keyof typeof store>(k: K) => (...a: unknown[]) => { calls.push(String(k)); return (store[k] as (...x: unknown[]) => unknown)(...a); };
    const wrapped = Object.assign(Object.create(store) as typeof store, {
      getSessionWithExpiry: spy('getSessionWithExpiry'), touchSession: spy('touchSession'), deleteSession: spy('deleteSession'),
      deleteSessionsForUser: spy('deleteSessionsForUser'), transaction: spy('transaction'),
      isSuspendedCredential: spy('isSuspendedCredential'),
    });
    const { auth } = setup({ store: wrapped, hooks: { onLogoutEverywhere: async () => { calls.push('hook'); } } });
    for (const o of bad) {
      expect((await auth.handle(req('POST', path, { cookie: s.cookie, ...o })))!.status).toBe(403);
    }
    expect(calls).toEqual([]);
  });
});

describe('path and scheme handling', () => {
  it('a malformed percent-escape in the provider segment is 404 not_found', async () => {
    const res = (await setup().auth.handle(req('GET', '/auth/%E0%A4%A/start')))!;
    expect(res.status).toBe(404);
    expect((await res.json() as any).error.code).toBe('not_found');
  });

  it('an upper-case HTTPS:// publicUrl still yields Secure cookies', async () => {
    const { auth } = setup({ publicUrl: 'HTTPS://api.example.test' });
    const res = (await auth.handle(req('GET', '/auth/google/start')))!;
    expect(setCookie(res, 'ventrical_oauth')!.attrs.secure).toBe(true);
    const out = (await auth.handle(req('POST', '/auth/logout', { origin: FRONT })))!;
    expect(setCookie(out, 'ventrical_session')!.attrs.secure).toBe(true);
  });

  it('an http publicUrl yields no Secure attribute', async () => {
    const { auth } = setup({ publicUrl: 'http://localhost:3000' });
    const res = (await auth.handle(req('GET', '/auth/google/start')))!;
    expect(setCookie(res, 'ventrical_oauth')!.attrs.secure).toBeUndefined();
  });
});
