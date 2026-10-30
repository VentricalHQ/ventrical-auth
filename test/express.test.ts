import express from 'express';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { createAuth, AuthHttpError, type ProviderName, type ProviderProfile } from '../src/index.js';
import { authRouter, requireSession } from '../src/express/index.js';
import { fakeProvider } from './helpers/fake-provider.js';
import { createMemoryStore, type MemoryTx } from './helpers/memory-store.js';

const FRONT = 'https://app.example.test';
const PUBLIC = 'https://api.example.test';
const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise<void>((r) => { s.close(() => r()); s.closeAllConnections(); })));
});

function setup(profile: ProviderProfile = { subject: 'g1', emailVerified: true, email: 'g1@example.test' }) {
  const store = createMemoryStore();
  const overrides: Partial<Record<ProviderName, ReturnType<typeof fakeProvider>>> = { google: fakeProvider('google', profile) };
  const auth = createAuth<MemoryTx>({
    providers: { google: { clientId: 'fake-id', clientSecret: 'fake-secret' } },
    publicUrl: PUBLIC, frontendUrl: FRONT, encryptionKey: Buffer.alloc(32, 7), store, providerOverrides: overrides,
  });
  return { auth, store };
}

async function listen(mount: (app: express.Express, auth: ReturnType<typeof setup>['auth']) => void, auth = setup().auth) {
  const app = express();
  mount(app, auth);
  app.use((err: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    if (err instanceof AuthHttpError) res.status(err.status).json({ error: { code: err.code, message: err.message } });
    else res.status(500).json({ error: { code: 'internal_error', message: 'Internal error' } });
  });
  const server = await new Promise<Server>((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  servers.push(server);
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

const get = (url: string, headers: Record<string, string> = {}) => fetch(url, { redirect: 'manual', headers });
const cookieOf = (res: Response, name: string) => {
  const raw = res.headers.getSetCookie().find((c) => c.startsWith(`${name}=`));
  return raw ? raw.split(';')[0]! : undefined;
};

describe('express adapter', () => {
  it('start, callback and logout work end to end', async () => {
    const { auth, store } = setup();
    const base = await listen((app, a) => app.use(authRouter(a)), auth);

    const start = await get(`${base}/auth/google/start`);
    expect(start.status).toBe(302);
    const oauth = cookieOf(start, 'ventrical_oauth')!;
    const state = new URL(start.headers.get('location')!).searchParams.get('state')!;

    const cb = await get(`${base}/auth/google/callback?code=fake-code&state=${encodeURIComponent(state)}`, { cookie: oauth });
    expect(cb.status).toBe(302);
    expect(cb.headers.get('location')!.startsWith(FRONT)).toBe(true);
    const session = cookieOf(cb, 'ventrical_session')!;
    expect(session).toBeDefined();
    expect(store.sessions.size).toBe(1);

    const out = await fetch(`${base}/auth/logout`, { method: 'POST', headers: { cookie: session, origin: FRONT } });
    expect(out.status).toBe(204);
    expect(store.sessions.size).toBe(0);
    expect(out.headers.getSetCookie().some((c) => /^ventrical_session=;/.test(c))).toBe(true);
  });

  it('an unrelated route still reaches the app\'s own handlers', async () => {
    const base = await listen((app, a) => {
      app.use(authRouter(a));
      app.get('/hello', (_req, res) => { res.send('hi'); });
    });
    const res = await get(`${base}/hello`);
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('hi');
    expect((await get(`${base}/nope`)).status).toBe(404);
  });

  it('requireSession sets req.user and returns 401 JSON without a cookie', async () => {
    const { auth, store } = setup();
    const base = await listen((app, a) => {
      app.get('/me', requireSession(a), (req, res) => { res.json({ id: req.user!.id }); });
    }, auth);

    const anon = await get(`${base}/me`);
    expect(anon.status).toBe(401);
    expect((await anon.json() as any).error.code).toBe('unauthenticated');

    const user = await store.createUserWithIdentity({ provider: 'google', subject: 'g9', emailVerified: true });
    const { newSessionId } = await import('../src/session.js');
    const sid = newSessionId();
    await store.transaction((tx) => store.createSessionUnlessSuspended(user.id, sid.idHash, new Date(Date.now() + 864e5), { provider: 'google', subject: 'g9' }, tx));
    const ok = await get(`${base}/me`, { cookie: `ventrical_session=${sid.id}` });
    expect(ok.status).toBe(200);
    expect(await ok.json()).toEqual({ id: user.id });
  });

  it('multiple Set-Cookie headers all reach the client', async () => {
    const base = await listen((app, a) => {
      const original = a.handle;
      app.use(authRouter({
        ...a,
        handle: async (r) => {
          const res = await original(r);
          if (!res) return res;
          const headers = new Headers(res.headers);
          headers.append('set-cookie', 'a=1; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT');
          headers.append('set-cookie', 'b=2; Path=/');
          return new Response(res.body, { status: res.status, headers });
        },
      }));
    });
    const res = await get(`${base}/auth/google/start`);
    const cookies = res.headers.getSetCookie();
    expect(cookies.some((c) => c.startsWith('ventrical_oauth='))).toBe(true);
    expect(cookies).toContain('a=1; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT');
    expect(cookies).toContain('b=2; Path=/');
    expect(cookies.length).toBe(3);
  });

  it('builds the request URL from publicUrl and keeps mounted paths', async () => {
    const seen: string[] = [];
    const base = await listen((app, a) => {
      app.use('/api', authRouter({ ...a, handle: async (r) => { seen.push(r.url); return a.handle(r); } }));
    });
    const res = await get(`${base}/api/auth/providers`, { host: 'evil.example.test' });
    // Mounted under /api, the auth route is /api/auth/providers, which the core does not serve.
    expect(res.status).toBe(404);
    expect(seen).toEqual([`${PUBLIC}/api/auth/providers`]);
  });

  it('thrown errors go to next() without exposing details', async () => {
    const base = await listen((app, a) => {
      app.use(authRouter({ ...a, handle: async () => { throw new Error('secret-detail'); } }));
    });
    const res = await get(`${base}/auth/providers`);
    expect(res.status).toBe(500);
    expect(await res.text()).not.toContain('secret-detail');
  });
});
