import { describe, expect, it, vi } from 'vitest';
import { createAuth, type AuthConfig, type AuthErrorEvent, type ProviderName, type ProviderProfile } from '../src/index.js';
import { DuplicateIdentityError } from '../src/errors.js';
import { fakeProvider } from './helpers/fake-provider.js';
import { createMemoryStore, type MemoryTx } from './helpers/memory-store.js';
import { req, setCookie } from './helpers/request.js';

const FRONT = 'https://app.example.test';
const prof = (subject: string, over: Partial<ProviderProfile> = {}): ProviderProfile => ({ subject, emailVerified: true, email: `${subject}@example.test`, ...over });

function setup(profiles: Partial<Record<ProviderName, ProviderProfile | Error>>, over: Partial<AuthConfig<MemoryTx>> = {}) {
  const store = createMemoryStore();
  const overrides: Partial<Record<ProviderName, ReturnType<typeof fakeProvider>>> = {};
  for (const [n, p] of Object.entries(profiles)) overrides[n as ProviderName] = fakeProvider(n as ProviderName, p!);
  const events: AuthErrorEvent[] = [];
  const auth = createAuth<MemoryTx>({
    providers: { google: { clientId: 'fake-id', clientSecret: 'fake-secret' }, github: { clientId: 'fake-id', clientSecret: 'fake-secret' } },
    publicUrl: 'https://api.example.test', frontendUrl: FRONT, encryptionKey: Buffer.alloc(32, 7), store,
    providerOverrides: overrides, ...over,
    hooks: { ...over.hooks, onError: over.hooks?.onError ?? ((e) => { events.push(e); }) },
  });
  return { auth, store, events };
}
type Auth = ReturnType<typeof setup>['auth'];

async function flow(auth: Auth, provider: string, o: { session?: string; query?: string } = {}) {
  const start = (await auth.handle(req('GET', `/auth/${provider}/start`, o.session ? { cookie: o.session } : {})))!;
  const oauth = `__Host-ventrical_oauth=${encodeURIComponent(setCookie(start, '__Host-ventrical_oauth')!.value)}`;
  const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
  const path = `/auth/${provider}/callback?${(o.query ?? 'code=fake-code&state={state}').replace('{state}', encodeURIComponent(state))}`;
  return (await auth.handle(req('GET', path, { cookie: [oauth, o.session].filter(Boolean).join('; ') })))!;
}
const signedIn = async (auth: Auth, p: string) => `__Host-ventrical_session=${setCookie(await flow(auth, p), '__Host-ventrical_session')!.value}`;
const snap = async (r: Response) => JSON.stringify([r.status, [...r.headers].filter(([k]) => k !== 'set-cookie'), r.headers.getSetCookie().map((c) => c.replace(/=[^;]*/, '=')), await r.clone().text()]);

describe('hooks.onError events', () => {
  it('invalid_state', async () => {
    const { auth, events } = setup({ google: prof('g1') });
    const res = (await auth.handle(req('GET', '/auth/google/callback?code=c&state=nope')))!;
    expect(res.status).toBe(400);
    expect(events).toEqual([]);
  });

  it('invalid_state is never reported (attacker-triggerable), while the response is unchanged', async () => {
    const { auth, events } = setup({ google: prof('g1') });
    const noCookie = (await auth.handle(req('GET', '/auth/google/callback?code=c&state=nope')))!;
    const tampered = (await auth.handle(req('GET', '/auth/google/callback?code=c&state=x', { cookie: '__Host-ventrical_oauth=garbage' })))!;
    for (const r of [noCookie, tampered]) {
      expect(r.status).toBe(400);
      expect((await r.json() as any).error.code).toBe('invalid_state');
    }
    expect(events).toEqual([]);
  });

  it('a GitHub exchange that times out is reported as exchange_failed with a plain 400 oauth_error', async () => {
    const ctl = new AbortController();
    const spy = vi.spyOn(AbortSignal, 'timeout').mockImplementation(() => ctl.signal);
    try {
      const fetchFn = (async (_u: string | URL | Request, init?: RequestInit) => new Promise<Response>((_, reject) => {
        init?.signal?.addEventListener('abort', () => reject(init.signal!.reason));
      })) as typeof fetch;
      const { auth, events } = setup({}, { fetch: fetchFn });
      const start = (await auth.handle(req('GET', '/auth/github/start')))!;
      const oauth = `__Host-ventrical_oauth=${encodeURIComponent(setCookie(start, '__Host-ventrical_oauth')!.value)}`;
      const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
      const pending = auth.handle(req('GET', `/auth/github/callback?code=c&state=${encodeURIComponent(state)}`, { cookie: oauth }));
      await new Promise((r) => setTimeout(r, 10));
      ctl.abort(new DOMException('timed out', 'TimeoutError'));
      const res = (await pending)!;
      expect(res.status).toBe(400);
      expect(await res.text()).not.toMatch(/timed out|TimeoutError/);
      expect(events).toEqual([{ stage: 'callback', code: 'exchange_failed', provider: 'github', errorName: expect.any(String) }]);
    } finally { spy.mockRestore(); }
  });

  it('oauth_error when the provider returned an error or no code', async () => {
    const { auth, events } = setup({ google: prof('g1') });
    await flow(auth, 'google', { query: 'error=access_denied&state={state}' });
    await flow(auth, 'google', { query: 'state={state}' });
    const e = { stage: 'callback', code: 'oauth_error', provider: 'google', errorName: 'AuthHttpError' };
    expect(events).toEqual([e, e]);
  });

  it('exchange failure (including an id-token signature failure) is exchange_failed with only the class name', async () => {
    class TokenSignatureError extends Error {}
    const { auth, events } = setup({ google: new TokenSignatureError('token=abc123') });
    const res = await flow(auth, 'google');
    expect(res.status).toBe(400);
    expect(events).toEqual([{ stage: 'callback', code: 'exchange_failed', provider: 'google', errorName: 'TokenSignatureError' }]);
  });

  it('suspended (pre-check and in-transaction)', async () => {
    const a = setup({ google: prof('g1', { email: 'o@example.test' }), github: prof('h1', { email: 'o@example.test' }) });
    await flow(a.auth, 'google');
    a.store.suspend((await a.store.findUserByIdentity('google', 'g1'))!.id);
    await flow(a.auth, 'github');
    expect(a.events).toEqual([{ stage: 'callback', code: 'suspended', provider: 'github' }]);

    const store = createMemoryStore();
    const racing = Object.assign(Object.create(store) as typeof store, {
      createSessionUnlessSuspended: async (...x: Parameters<typeof store.createSessionUnlessSuspended>) => { store.suspend(x[0]); return store.createSessionUnlessSuspended(...x); },
    });
    const b = setup({ google: prof('g1') }, { store: racing });
    await flow(b.auth, 'google');
    expect(b.events).toEqual([{ stage: 'callback', code: 'suspended', provider: 'google' }]);
  });

  it('canCreateAccount deny uses the reason as code', async () => {
    const { auth, events } = setup({ google: prof('g1') }, { hooks: { canCreateAccount: async () => ({ allow: false, reason: 'waitlist' }) } });
    await flow(auth, 'google');
    expect(events).toEqual([{ stage: 'callback', code: 'waitlist', provider: 'google' }]);
  });

  it('canCreateAccount throwing is internal_error with the class name', async () => {
    const { auth, events } = setup({ google: prof('g1') }, { hooks: { canCreateAccount: async () => { throw new TypeError('x'); } } });
    const res = await flow(auth, 'google');
    expect(res.status).toBe(500);
    expect(events).toEqual([{ stage: 'callback', code: 'internal_error', provider: 'google', errorName: 'TypeError' }]);
  });

  it('sign_in_failed when afterSignIn throws', async () => {
    const { auth, events } = setup({ google: prof('g1') }, { hooks: { afterSignIn: async () => { throw new RangeError('boom'); } } });
    await flow(auth, 'google');
    expect(events).toEqual([{ stage: 'callback', code: 'sign_in_failed', provider: 'google', errorName: 'RangeError' }]);
  });

  it('sign_in_failed on a second duplicate-identity failure', async () => {
    const store = createMemoryStore();
    const dup = Object.assign(Object.create(store) as typeof store, {
      createUserWithIdentity: async () => { throw new DuplicateIdentityError(); },
      findUserByIdentity: async () => ({ id: 'u-other', email: null, name: null }),
      createSessionUnlessSuspended: async () => { throw new DuplicateIdentityError(); },
    });
    const { auth, events } = setup({ google: prof('g1') }, { store: dup });
    await flow(auth, 'google');
    expect(events).toEqual([{ stage: 'callback', code: 'sign_in_failed', provider: 'google', errorName: 'DuplicateIdentityError' }]);
  });

  it('store errors are sign_in_failed (transaction) or internal_error (lookup)', async () => {
    const store = createMemoryStore();
    const failTx = { ...store, transaction: async () => { throw new EvalError('db'); } } as typeof store;
    const a = setup({ google: prof('g1') }, { store: failTx });
    await flow(a.auth, 'google');
    expect(a.events).toEqual([{ stage: 'callback', code: 'sign_in_failed', provider: 'google', errorName: 'EvalError' }]);
    const failFind = { ...store, findUserByIdentity: async () => { throw new URIError('db'); } } as typeof store;
    const b = setup({ google: prof('g1') }, { store: failFind });
    const res = await flow(b.auth, 'google');
    expect(res.status).toBe(500);
    expect(b.events).toEqual([{ stage: 'callback', code: 'internal_error', provider: 'google', errorName: 'URIError' }]);
  });

  it('link: identity_in_use, link_failed and a store error', async () => {
    const a = setup({ google: prof('g1'), github: prof('h1') });
    await flow(a.auth, 'github');
    const sess = await signedIn(a.auth, 'google');
    a.events.length = 0;
    await flow(a.auth, 'github', { session: sess });
    expect(a.events).toEqual([{ stage: 'link', code: 'identity_in_use', provider: 'github' }]);

    const store = createMemoryStore();
    const dup = Object.assign(Object.create(store) as typeof store, { linkIdentity: async () => { throw new DuplicateIdentityError(); } });
    const b = setup({ google: prof('g1'), github: prof('h1') }, { store: dup });
    const sb = await signedIn(b.auth, 'google');
    await flow(b.auth, 'github', { session: sb });
    expect(b.events).toEqual([{ stage: 'link', code: 'link_failed', provider: 'github' }]);

    const bad = Object.assign(Object.create(store) as typeof store, { linkIdentity: async () => { throw new SyntaxError('db'); } });
    const c = setup({ google: prof('g1'), github: prof('h1') }, { store: bad });
    const sc = await signedIn(c.auth, 'google');
    const res = await flow(c.auth, 'github', { session: sc });
    expect(res.status).toBe(500);
    expect(c.events).toEqual([{ stage: 'link', code: 'internal_error', provider: 'github', errorName: 'SyntaxError' }]);
  });

  it('start: a disabled provider; an unknown provider is not reported', async () => {
    const { auth, events } = setup({ google: prof('g1') });
    const off = (await auth.handle(req('GET', '/auth/microsoft/start')))!;
    expect(off.status).toBe(404);
    expect(events).toEqual([{ stage: 'start', code: 'provider_disabled', provider: 'microsoft', errorName: 'AuthHttpError' }]);
    events.length = 0;
    await auth.handle(req('GET', '/auth/nope/start'));
    expect(events).toEqual([]);
  });

  it('start: an internal failure', async () => {
    const store = createMemoryStore();
    const bad = { ...store, getSessionWithExpiry: async () => { throw new TypeError('db'); } } as typeof store;
    const { auth, events } = setup({ google: prof('g1') }, { store: bad });
    const res = (await auth.handle(req('GET', '/auth/google/start', { cookie: '__Host-ventrical_session=x' })))!;
    expect(res.status).toBe(500);
    expect(events).toEqual([{ stage: 'start', code: 'internal_error', provider: 'google', errorName: 'TypeError' }]);
  });

  it('logout: forbidden and unauthenticated', async () => {
    const { auth, events } = setup({ google: prof('g1') });
    await auth.handle(req('POST', '/auth/logout'));
    await auth.handle(req('POST', '/auth/logout-everywhere', { origin: FRONT }));
    expect(events).toEqual([
      { stage: 'logout', code: 'forbidden', errorName: 'AuthHttpError' },
      { stage: 'logout', code: 'unauthenticated', errorName: 'AuthHttpError' },
    ]);
  });

  it('logout-everywhere for a suspended user is account_suspended', async () => {
    const { auth, store, events } = setup({ google: prof('g1') });
    const sess = await signedIn(auth, 'google');
    store.suspend((await store.findUserByIdentity('google', 'g1'))!.id);
    const res = (await auth.handle(req('POST', '/auth/logout-everywhere', { origin: FRONT, cookie: sess })))!;
    expect(res.status).toBe(403);
    expect(events).toEqual([{ stage: 'logout', code: 'account_suspended', errorName: 'AuthHttpError' }]);
  });

  it('logout store errors are internal_error (deleteSession and deleteSessionsForUser)', async () => {
    const store = createMemoryStore();
    const badDelete = Object.assign(Object.create(store) as typeof store, { deleteSession: async () => { throw new EvalError('db'); } });
    const a = setup({ google: prof('g1') }, { store: badDelete });
    const res = (await a.auth.handle(req('POST', '/auth/logout', { origin: FRONT, cookie: '__Host-ventrical_session=x' })))!;
    expect(res.status).toBe(500);
    expect(a.events).toEqual([{ stage: 'logout', code: 'internal_error', errorName: 'EvalError' }]);

    const badAll = Object.assign(Object.create(store) as typeof store, { deleteSessionsForUser: async () => { throw new RangeError('db'); } });
    const b = setup({ google: prof('g1') }, { store: badAll });
    const sess = await signedIn(b.auth, 'google');
    b.events.length = 0;
    const res2 = (await b.auth.handle(req('POST', '/auth/logout-everywhere', { origin: FRONT, cookie: sess })))!;
    expect(res2.status).toBe(500);
    expect(b.events).toEqual([{ stage: 'logout', code: 'internal_error', errorName: 'RangeError' }]);
  });

  it('a duplicate-identity failure with no owner on retry is sign_in_failed', async () => {
    const store = createMemoryStore();
    let finds = 0;
    const dup = Object.assign(Object.create(store) as typeof store, {
      findUserByIdentity: async () => { finds++; return undefined; },
      createUserWithIdentity: async () => { throw new DuplicateIdentityError(); },
    });
    const { auth, events } = setup({ google: prof('g1') }, { store: dup });
    const res = await flow(auth, 'google');
    expect(res.status).toBe(302);
    expect(res.headers.get('location')).toBe(`${FRONT}/signin?error=sign_in_failed`);
    expect(finds).toBe(2);
    expect(events).toEqual([{ stage: 'callback', code: 'sign_in_failed', provider: 'google', errorName: 'DuplicateIdentityError' }]);
  });

  it('an error whose class name cannot be read still yields the normal response', async () => {
    const hostile = new Proxy({}, { get() { throw new Error('nope'); } });
    const store = createMemoryStore();
    const bad = Object.assign(Object.create(store) as typeof store, { deleteSession: async () => { throw hostile; } });
    const { auth, events } = setup({ google: prof('g1') }, { store: bad });
    const res = (await auth.handle(req('POST', '/auth/logout', { origin: FRONT, cookie: '__Host-ventrical_session=x' })))!;
    expect(res.status).toBe(500);
    expect(await res.json()).toEqual({ error: { code: 'internal_error', message: 'Internal error' } });
    expect(events).toEqual([]);
  });

  it('success paths and a provider-less 404 report nothing', async () => {
    const { auth, events } = setup({ google: prof('g1') });
    await flow(auth, 'google');
    await auth.handle(req('GET', '/auth/providers'));
    expect(events).toEqual([]);
  });
});

describe('a misbehaving onError hook changes nothing', () => {
  const scenarios: Array<[string, (over: Partial<AuthConfig<MemoryTx>>) => Promise<Response>]> = [
    ['oauth_error', async (o) => flow(setup({ google: prof('g1') }, o).auth, 'google', { query: 'error=access_denied&state={state}' })],
    ['sign_in_failed', async (o) => flow(setup({ google: prof('g1') }, { ...o, hooks: { ...o.hooks, afterSignIn: async () => { throw new Error('x'); } } }).auth, 'google')],
    ['logout forbidden', async (o) => (await setup({ google: prof('g1') }, o).auth.handle(req('POST', '/auth/logout')))!],
    ['start provider_disabled', async (o) => (await setup({ google: prof('g1') }, o).auth.handle(req('GET', '/auth/microsoft/start')))!],
    ['internal_error', async (o) => flow(setup({ google: prof('g1') }, { ...o, hooks: { ...o.hooks, canCreateAccount: async () => { throw new Error('x'); } } }).auth, 'google')],
  ];
  const variants: Array<[string, () => unknown]> = [
    ['sync throw', () => { throw new Error('hook'); }],
    ['async reject', () => Promise.reject(new Error('hook'))],
  ];
  for (const [sname, run] of scenarios) {
    for (const [vname, behave] of variants) {
      it(`${sname}: ${vname}`, async () => {
        const ok = await run({});
        const unhandled: unknown[] = [];
        const onUnhandled = (e: unknown) => unhandled.push(e);
        process.on('unhandledRejection', onUnhandled);
        let calls = 0;
        const bad = await run({ hooks: { onError: (() => { calls++; return behave(); }) as never } } as never);
        await new Promise((r) => setTimeout(r, 20));
        process.off('unhandledRejection', onUnhandled);
        expect(await snap(bad)).toBe(await snap(ok));
        expect(calls).toBeGreaterThan(0);
        expect(unhandled).toEqual([]);
      });
    }
  }
});

describe('config validation', () => {
  it('onError must be a function and the error never echoes the value', () => {
    const mk = (onError: unknown) => () => createAuth({
      providers: { google: { clientId: 'a', clientSecret: 'b' } }, publicUrl: 'https://api.example.test', frontendUrl: FRONT,
      encryptionKey: Buffer.alloc(32, 1), store: createMemoryStore(), hooks: { onError } as never,
    });
    expect(mk('SECRET-VALUE')).toThrow('hooks.onError must be a function');
    expect(mk('SECRET-VALUE')).not.toThrow(/SECRET-VALUE/);
    expect(mk(undefined)).not.toThrow();
    expect(mk(() => {})).not.toThrow();
  });
});
