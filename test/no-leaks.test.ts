import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createAuth, type AuthConfig, type ProviderName, type ProviderProfile } from '../src/index.js';
import { fakeIdp, type SignOptions } from './helpers/fake-fetch.js';
import { fakeProvider } from './helpers/fake-provider.js';
import { createMemoryStore, type MemoryTx } from './helpers/memory-store.js';
import { cookieHeaderFrom, req, setCookie } from './helpers/request.js';

/** Planted wherever a secret could sit: it must never come out. */
const PLANT = 'SECRET-PLANT-1234';
const FRONT = 'https://app.example.test';
const PUBLIC = 'https://api.example.test';
const G_ISSUER = 'https://accounts.google.com';
const G_DISCOVERY = `${G_ISSUER}/.well-known/openid-configuration`;
const KEY = Buffer.alloc(32, 9);

const forms = [PLANT, Buffer.from(PLANT).toString('base64'), Buffer.from(PLANT).toString('base64url'), Buffer.from(PLANT).toString('hex')];
const leaksIn = (text: string): string[] => forms.filter((f) => text.includes(f) || text.includes(encodeURIComponent(f)));

/** Everything a caller can see in a response: status line, every header and the body. */
async function dump(res: Response): Promise<string> {
  const headers = [...res.headers].map(([k, v]) => `${k}: ${v}`).concat(res.headers.getSetCookie().map((c) => `set-cookie: ${c}`));
  return [`${res.status}`, ...headers, await res.clone().text()].join('\n');
}

let output: string[] = [];
const spies: Array<{ mockRestore(): void }> = [];
beforeEach(() => {
  output = [];
  const record = (...a: unknown[]) => { output.push(a.map((x) => (typeof x === 'string' ? x : safeJson(x))).join(' ')); };
  for (const m of ['log', 'info', 'warn', 'error', 'debug', 'trace', 'dir', 'table', 'group', 'groupEnd', 'assert'] as const) {
    spies.push(vi.spyOn(console, m).mockImplementation(record as never));
  }
  const write = ((chunk: unknown) => { output.push(String(chunk)); return true; }) as never;
  spies.push(vi.spyOn(process.stdout, 'write').mockImplementation(write));
  spies.push(vi.spyOn(process.stderr, 'write').mockImplementation(write));
});
afterEach(() => { for (const s of spies.splice(0)) s.mockRestore(); });
function safeJson(x: unknown): string {
  try { return x instanceof Error ? `${x.name}: ${x.message}\n${x.stack ?? ''}` : JSON.stringify(x); } catch { return String(x); }
}

/** Asserts the plant is in no response dump and no captured console or stdout/stderr output. */
async function expectNoLeak(label: string, ...responses: Response[]): Promise<void> {
  for (const r of responses) expect(leaksIn(await dump(r)), `${label}: response`).toEqual([]);
  expect(leaksIn(output.join('\n')), `${label}: console/stdout/stderr`).toEqual([]);
}

function base(over: Partial<AuthConfig<MemoryTx>> = {}) {
  const store = createMemoryStore();
  const auth = createAuth<MemoryTx>({
    providers: { google: { clientId: 'gid', clientSecret: PLANT }, github: { clientId: 'ghid', clientSecret: PLANT } },
    publicUrl: PUBLIC, frontendUrl: FRONT, encryptionKey: KEY, store, ...over,
  });
  return { auth, store };
}

type Auth = ReturnType<typeof base>['auth'];

async function start(auth: Auth, provider: string) {
  const res = (await auth.handle(req('GET', `/auth/${provider}/start?redirect=%2Fhome`)))!;
  const url = new URL(res.headers.get('location')!);
  return { res, state: url.searchParams.get('state')!, nonce: url.searchParams.get('nonce') ?? '', cookie: cookieHeaderFrom(res) };
}
const callback = async (auth: Auth, provider: string, s: { state: string; cookie: string }, code = PLANT) =>
  (await auth.handle(req('GET', `/auth/${provider}/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(s.state)}`, { cookie: s.cookie })))!;

const ok = (p: Partial<ProviderProfile> = {}): ProviderProfile => ({ subject: 'u1', emailVerified: true, email: 'u1@example.test', ...p });

describe('planted secret never leaves (provider override)', () => {
  const run = async (result: ProviderProfile | Error) => {
    const { auth } = base({ providerOverrides: { google: fakeProvider('google', result) } as Partial<Record<ProviderName, ReturnType<typeof fakeProvider>>> });
    const s = await start(auth, 'google');
    const cb = await callback(auth, 'google', s);
    return { s, cb, auth };
  };

  it('start: the authorize redirect and state cookie hold no client secret', async () => {
    const { auth } = base();
    const idp = await fakeIdp(G_ISSUER, G_DISCOVERY);
    const { auth: real } = base({ fetch: idp.fetchFn });
    const s = await start(real, 'google');
    expect(s.res.status).toBe(302);
    await expectNoLeak('google start', s.res);
    const gh = await start(auth, 'github');
    expect(gh.res.status).toBe(302);
    await expectNoLeak('github start', gh.res);
  });

  it('failing callback: a provider error carrying the planted string', async () => {
    const { s, cb } = await run(new Error(`upstream said code=${PLANT} token=${PLANT} secret=${PLANT}`));
    expect(cb.status).toBe(400);
    await expectNoLeak('thrown provider error', s.res, cb);
  });

  it('failing callback: an error whose own properties carry the plant', async () => {
    const err = Object.assign(new Error('failed'), { body: PLANT, cause: new Error(PLANT), response: { text: PLANT } });
    const { s, cb } = await run(err);
    expect(cb.status).toBe(400);
    await expectNoLeak('error properties', s.res, cb);
  });

  it('successful callback with a planted code', async () => {
    const { s, cb } = await run(ok());
    expect(cb.status).toBe(302);
    expect(setCookie(cb, 'ventrical_session')).toBeDefined();
    await expectNoLeak('success', s.res, cb);
  });

  it('a profile whose fields are the plant stays out of the response', async () => {
    // The email and name are stored, never echoed: the redirect, cookies and body hold none of it.
    const { s, cb } = await run(ok({ subject: 'p1', name: PLANT, email: `${PLANT.toLowerCase()}@example.test` }));
    expect(cb.status).toBe(302);
    await expectNoLeak('profile fields', s.res, cb);
  });

  it('a store error carrying the plant does not reach the response', async () => {
    const store = createMemoryStore();
    const failing = { ...store, transaction: async () => { throw new Error(`db ${PLANT}`); } } as typeof store;
    const { auth } = base({ store: failing, providerOverrides: { google: fakeProvider('google', ok()) } as never });
    const s = await start(auth, 'google');
    const cb = await callback(auth, 'google', s);
    await expectNoLeak('store error', s.res, cb);
  });

  it('a hook error carrying the plant does not reach the response', async () => {
    const { auth } = base({
      providerOverrides: { google: fakeProvider('google', ok()) } as never,
      hooks: { afterSignIn: async () => { throw new Error(PLANT); }, canCreateAccount: async () => ({ allow: true }) },
    });
    const s = await start(auth, 'google');
    const cb = await callback(auth, 'google', s);
    expect(cb.status).toBe(302);
    expect(cb.headers.get('location')).toContain('error=sign_in_failed');
    await expectNoLeak('hook error', s.res, cb);
  });
});

describe('planted secret never leaves (github over a fake fetch)', () => {
  const ghFetch = (o: { tokenStatus?: number; userStatus?: number }) => (async (input: string | URL | Request) => {
    const url = String(input instanceof Request ? input.url : input);
    const json = (b: unknown, status = 200) => new Response(JSON.stringify(b), { status, headers: { 'content-type': 'application/json' } });
    if (url === 'https://github.com/login/oauth/access_token') {
      return o.tokenStatus ? json({ error: 'bad_verification_code', error_description: PLANT }, o.tokenStatus) : json({ access_token: PLANT, token_type: 'bearer' });
    }
    if (url === 'https://api.github.com/user') return o.userStatus ? new Response(`<html>${PLANT}</html>`, { status: o.userStatus }) : json({ id: 77, login: 'gh' });
    if (url === 'https://api.github.com/user/emails') return json([{ email: 'gh@example.test', primary: true, verified: true }]);
    throw new Error(`unexpected fetch ${PLANT}`);
  }) as typeof fetch;

  it('token exchange rejected with the plant in the provider body', async () => {
    const { auth } = base({ fetch: ghFetch({ tokenStatus: 400 }) });
    const s = await start(auth, 'github');
    const cb = await callback(auth, 'github', s);
    expect(cb.status).toBe(400);
    await expectNoLeak('github token error', s.res, cb);
  });

  it('profile request failing with the plant in the body', async () => {
    const { auth } = base({ fetch: ghFetch({ userStatus: 500 }) });
    const s = await start(auth, 'github');
    const cb = await callback(auth, 'github', s);
    expect(cb.status).toBe(400);
    await expectNoLeak('github profile error', s.res, cb);
  });

  it('success with the plant as the access token', async () => {
    const { auth, store } = base({ fetch: ghFetch({}) });
    const s = await start(auth, 'github');
    const cb = await callback(auth, 'github', s);
    expect(cb.status).toBe(302);
    expect(await store.findUserByIdentity('github', '77')).toBeDefined();
    await expectNoLeak('github success', s.res, cb);
  });
});

describe('planted secret never leaves (ID token signature check)', () => {
  type Mut = (idp: Awaited<ReturnType<typeof fakeIdp>>) => void;
  /** Google over a fake IdP whose JWKS, token and key material all carry the plant. */
  async function google(opts: { sign?: SignOptions; mutate?: Mut; failJwks?: boolean; tokenError?: boolean } = {}) {
    const idp = await fakeIdp(G_ISSUER, G_DISCOVERY);
    idp.jwks.keys = [{ ...idp.mainKey.jwk, note: PLANT, x5t: PLANT }]; // key material
    opts.mutate?.(idp);
    const fetchFn = (async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input instanceof Request ? input.url : input);
      if (opts.failJwks && url === 'https://idp.test/jwks') throw new Error(`connect failed ${PLANT}`);
      if (opts.tokenError && url === 'https://idp.test/token') {
        return new Response(JSON.stringify({ error: 'invalid_grant', error_description: PLANT }), { status: 400, headers: { 'content-type': 'application/json' } });
      }
      return idp.fetchFn(input, init);
    }) as typeof fetch;
    const { auth, store } = base({ fetch: fetchFn });
    const s = await start(auth, 'google');
    await idp.sign({ iss: G_ISSUER, aud: 'gid', sub: 'g1', email: 'g1@example.test', email_verified: true, name: 'G', nonce: s.nonce, planted: PLANT, picture: PLANT }, opts.sign);
    const cb = await callback(auth, 'google', s);
    return { s, cb, idp, store };
  }

  const failing: Array<[string, Parameters<typeof google>[0]]> = [
    ['bad signature (a key the JWKS does not publish)', { sign: { wrongKey: true } }],
    ['payload tampered after signing', { sign: { tamper: true } }],
    ['unknown kid, which is the plant', { sign: { kid: PLANT } }],
    ['JWKS fetch failure, with the plant in the error', { failJwks: true }],
    ['non-JSON JWKS body holding the plant', { mutate: (i) => { i.jwks.body = `<html>${PLANT}</html>`; } }],
    ['non-OK JWKS holding the plant', { mutate: (i) => { i.jwks.status = 503; i.jwks.body = JSON.stringify({ error: PLANT }); } }],
    ['JWKS of the wrong shape holding the plant', { mutate: (i) => { i.jwks.body = JSON.stringify({ keys: PLANT }); } }],
    ['alg none', { sign: { alg: 'none' } }],
    ['token endpoint error body holding the plant', { tokenError: true }],
  ];
  for (const [name, opts] of failing) {
    it(`fails closed without leaking: ${name}`, async () => {
      const { s, cb, store } = await google(opts);
      expect(cb.status).toBe(400);
      expect(await store.findUserByIdentity('google', 'g1')).toBeUndefined();
      expect(setCookie(cb, 'ventrical_session')).toBeUndefined();
      await expectNoLeak(name, s.res, cb);
    });
  }

  it('a valid token whose JWKS entry and claims carry the plant signs in and still leaks nothing', async () => {
    const { s, cb, store } = await google();
    expect(cb.status).toBe(302);
    expect(await store.findUserByIdentity('google', 'g1')).toBeDefined();
    await expectNoLeak('valid token', s.res, cb);
  });
});

describe('the detector itself', () => {
  it('flags a plant in a body, a header, a cookie, or captured output', async () => {
    expect(leaksIn(await dump(new Response(`x ${PLANT} y`)))).toContain(PLANT);
    expect(leaksIn(await dump(new Response('x', { headers: { location: `/?q=${PLANT}` } })))).toContain(PLANT);
    const h = new Headers(); h.append('set-cookie', `a=${Buffer.from(PLANT).toString('base64')}`);
    expect(leaksIn(await dump(new Response('x', { headers: h })))).not.toEqual([]);
    console.error(`oops ${PLANT}`);
    process.stderr.write(`oops ${PLANT}`);
    expect(leaksIn(output.join('\n'))).toContain(PLANT);
    expect(output.length).toBeGreaterThanOrEqual(2);
  });
});
