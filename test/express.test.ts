import express from 'express';
import type { Server } from 'node:http';
import net from 'node:net';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { createAuth, AuthHttpError, type ProviderName, type ProviderProfile } from '../src/index.js';
import { authRouter, currentSession, requireSession } from '../src/express/index.js';
import { newSessionId } from '../src/session.js';
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
    const oauth = cookieOf(start, '__Host-ventrical_oauth')!;
    const state = new URL(start.headers.get('location')!).searchParams.get('state')!;

    const cb = await get(`${base}/auth/google/callback?code=fake-code&state=${encodeURIComponent(state)}`, { cookie: oauth });
    expect(cb.status).toBe(302);
    expect(cb.headers.get('location')!.startsWith(FRONT)).toBe(true);
    const session = cookieOf(cb, '__Host-ventrical_session')!;
    expect(session).toBeDefined();
    expect(store.sessions.size).toBe(1);

    const out = await fetch(`${base}/auth/logout`, { method: 'POST', headers: { cookie: session, origin: FRONT } });
    expect(out.status).toBe(204);
    expect(store.sessions.size).toBe(0);
    expect(out.headers.getSetCookie().some((c) => /^__Host-ventrical_session=;/.test(c))).toBe(true);
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
      app.get('/me', requireSession(a), (req, res) => { res.json({ id: req.user!.id, verifiedEmail: req.user!.verifiedEmail }); });
    }, auth);

    const anon = await get(`${base}/me`);
    expect(anon.status).toBe(401);
    expect((await anon.json() as any).error.code).toBe('unauthenticated');

    const user = await store.createUserWithIdentity({ provider: 'google', subject: 'g9', email: 'nine@example.test', emailVerified: true });
    const sid = newSessionId();
    await store.transaction((tx) => store.createSessionUnlessSuspended(user.id, sid.idHash, new Date(Date.now() + 864e5), { provider: 'google', subject: 'g9' }, tx));
    const ok = await get(`${base}/me`, { cookie: `__Host-ventrical_session=${sid.id}` });
    expect(ok.status).toBe(200);
    expect(await ok.json()).toEqual({ id: user.id, verifiedEmail: 'nine@example.test' });
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
    expect(cookies.some((c) => c.startsWith('__Host-ventrical_oauth='))).toBe(true);
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

  async function seedSession(store: ReturnType<typeof setup>['store'], expiresAt: Date, subject = 'g5') {
    const user = await store.createUserWithIdentity({ provider: 'google', subject, emailVerified: true });
    const sid = newSessionId();
    await store.transaction((tx) => store.createSessionUnlessSuspended(user.id, sid.idHash, expiresAt, { provider: 'google', subject }, tx));
    return sid;
  }

  it('logout over HTTP with a missing or wrong Origin is 403 and the session survives', async () => {
    const { auth, store } = setup();
    const base = await listen((app, a) => app.use(authRouter(a)), auth);
    const sid = await seedSession(store, new Date(Date.now() + 864e5));
    const cookie = `__Host-ventrical_session=${sid.id}`;
    expect((await fetch(`${base}/auth/logout`, { method: 'POST', headers: { cookie } })).status).toBe(403);
    expect((await fetch(`${base}/auth/logout`, { method: 'POST', headers: { cookie, origin: 'https://evil.example.test' } })).status).toBe(403);
    expect(store.sessions.size).toBe(1);
  });

  it('requireSession returns the refreshed Set-Cookie when the session is under 29 days from expiry', async () => {
    const { auth, store } = setup();
    const base = await listen((app, a) => {
      app.get('/me', requireSession(a), (req, res) => { res.json({ id: req.user!.id }); });
    }, auth);
    const old = await seedSession(store, new Date(Date.now() + 10 * 864e5));
    const res = await get(`${base}/me`, { cookie: `__Host-ventrical_session=${old.id}` });
    expect(res.status).toBe(200);
    expect(cookieOf(res, '__Host-ventrical_session')).toBe(`__Host-ventrical_session=${old.id}`);
    const fresh = await seedSession(store, new Date(Date.now() + 30 * 864e5 - 1000), 'g6');
    const res2 = await get(`${base}/me`, { cookie: `__Host-ventrical_session=${fresh.id}` });
    expect(res2.status).toBe(200);
    expect(cookieOf(res2, '__Host-ventrical_session')).toBeUndefined();
  });

  it('absolute-form and asterisk request targets call next() instead of building a URL', async () => {
    const seen: string[] = [];
    const base = await listen((app, a) => {
      app.use(authRouter({ ...a, handle: async (r) => { seen.push(r.url); return a.handle(r); } }));
      app.use((_req, res) => { res.status(418).end(); });
    });
    const port = Number(new URL(base).port);
    const raw = (target: string, method: string) => new Promise<string>((resolve, reject) => {
      const sock = net.connect(port, '127.0.0.1', () => sock.write(`${method} ${target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`));
      let out = '';
      sock.on('data', (d) => { out += d.toString(); });
      sock.on('end', () => resolve(out));
      sock.on('error', reject);
    });
    expect(await raw('http://evil.example.test/auth/providers', 'GET')).toMatch(/^HTTP\/1.1 418/);
    expect(await raw('*', 'OPTIONS')).toMatch(/^HTTP\/1.1 418/);
    expect(seen).toEqual([]);
  });

  it('requireSession answers 401 and skips the handler for absolute-form and asterisk request targets', async () => {
    let ran = 0;
    const base = await listen((app, a) => {
      app.use(requireSession(a));
      app.use((_req, res) => { ran++; res.status(200).end(); });
    });
    const port = Number(new URL(base).port);
    const raw = (target: string, method: string) => new Promise<string>((resolve, reject) => {
      const sock = net.connect(port, '127.0.0.1', () => sock.write(`${method} ${target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`));
      let out = '';
      sock.on('data', (d) => { out += d.toString(); });
      sock.on('end', () => resolve(out));
      sock.on('error', reject);
    });
    expect(await raw('http://evil.example.test/me', 'GET')).toMatch(/^HTTP\/1.1 401/);
    expect(await raw('*', 'OPTIONS')).toMatch(/^HTTP\/1.1 401/);
    expect(ran).toBe(0);
  });
  it('currentSession resolves the session or undefined, sets req.user, and never rejects an anonymous caller', async () => {
    const { auth, store } = setup();
    const base = await listen((app, a) => {
      const current = currentSession(a);
      app.get('/who', async (req, res, next) => {
        try {
          const s = await current(req, res);
          res.json({ id: s?.user.id ?? null, reqUser: req.user?.id ?? null });
        } catch (e) { next(e); }
      });
    }, auth);
    const anon = await get(`${base}/who`);
    expect(anon.status).toBe(200);
    expect(await anon.json()).toEqual({ id: null, reqUser: null });
    expect((await get(`${base}/who`, { cookie: '__Host-ventrical_session=garbage' })).status).toBe(200);

    const old = await seedSession(store, new Date(Date.now() + 10 * 864e5), 'g7');
    const res = await get(`${base}/who`, { cookie: `__Host-ventrical_session=${old.id}` });
    const body = await res.json() as { id: string; reqUser: string };
    expect(body.id).toBe(body.reqUser);
    expect(body.id).toBeTruthy();
    expect(cookieOf(res, '__Host-ventrical_session')).toBe(`__Host-ventrical_session=${old.id}`); // refreshed cookie forwarded
  });

  it('currentSession returns undefined for absolute-form targets without building a URL', async () => {
    const base = await listen((app, a) => {
      const current = currentSession({ ...a, getSession: async () => { throw new Error('must not be called'); } });
      app.use(async (req, res) => { res.status((await current(req, res)) === undefined ? 418 : 200).end(); });
    });
    const port = Number(new URL(base).port);
    const out = await new Promise<string>((resolve, reject) => {
      const sock = net.connect(port, '127.0.0.1', () => sock.write('GET http://evil.example.test/x HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n'));
      let o = '';
      sock.on('data', (d) => { o += d.toString(); });
      sock.on('end', () => resolve(o));
      sock.on('error', reject);
    });
    expect(out).toMatch(/^HTTP\/1.1 418/);
  });
});
