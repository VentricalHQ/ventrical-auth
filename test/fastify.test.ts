import Fastify from 'fastify';
import net from 'node:net';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { authPlugin, requireSession } from '../src/fastify/index.js';
import { SUSPENDED_MESSAGE } from '../src/errors.js';
import { FRONT, PUBLIC, cookieNamed, seedSession, setup } from './helpers/adapter-setup.js';

const apps: ReturnType<typeof Fastify>[] = [];
afterEach(async () => { await Promise.all(apps.splice(0).map((a) => a.close())); });
const build = () => { const a = Fastify(); apps.push(a); return a; };
const setCookies = (res: { headers: Record<string, unknown> }) => {
  const v = res.headers['set-cookie'];
  return v === undefined ? [] : Array.isArray(v) ? v as string[] : [v as string];
};

describe('fastify adapter', () => {
  it('start, callback and logout work end to end', async () => {
    const { auth, store } = setup();
    const app = build();
    await app.register(authPlugin(auth));
    const start = await app.inject({ method: 'GET', url: '/auth/google/start' });
    expect(start.statusCode).toBe(302);
    const oauth = cookieNamed(setCookies(start), '__Host-ventrical_oauth')!;
    const state = new URL(start.headers.location as string).searchParams.get('state')!;
    const cb = await app.inject({ method: 'GET', url: `/auth/google/callback?code=fake-code&state=${encodeURIComponent(state)}`, headers: { cookie: oauth } });
    expect(cb.statusCode).toBe(302);
    expect((cb.headers.location as string).startsWith(FRONT)).toBe(true);
    const session = cookieNamed(setCookies(cb), '__Host-ventrical_session')!;
    expect(store.sessions.size).toBe(1);

    expect((await app.inject({ method: 'POST', url: '/auth/logout', headers: { cookie: session } })).statusCode).toBe(403);
    expect((await app.inject({ method: 'POST', url: '/auth/logout', headers: { cookie: session, origin: 'https://evil.example.test' } })).statusCode).toBe(403);
    expect(store.sessions.size).toBe(1);
    const out = await app.inject({ method: 'POST', url: '/auth/logout', headers: { cookie: session, origin: FRONT } });
    expect(out.statusCode).toBe(204);
    expect(store.sessions.size).toBe(0);
    expect(setCookies(out).some((c) => /^__Host-ventrical_session=;/.test(c))).toBe(true);
  });

  it('unowned paths fall through to the app', async () => {
    const app = build();
    await app.register(authPlugin(setup().auth));
    app.get('/hello', async () => 'hi');
    expect((await app.inject({ method: 'GET', url: '/hello' })).body).toBe('hi');
    expect((await app.inject({ method: 'GET', url: '/nope' })).statusCode).toBe(404);
  });

  it('builds the URL from publicUrl, not the Host header', async () => {
    const { auth } = setup();
    const seen: string[] = [];
    const app = build();
    await app.register(authPlugin({ ...auth, handle: async (q) => { seen.push(q.url); return auth.handle(q); } }));
    await app.inject({ method: 'GET', url: '/auth/providers?x=1', headers: { host: 'evil.example.test' } });
    expect(seen).toEqual([`${PUBLIC}/auth/providers?x=1`]);
  });

  const rawRequest = (port: number, target: string, method: string, extra = '', body = '') => new Promise<string>((resolve, reject) => {
    const sock = net.connect(port, '127.0.0.1', () => sock.write(`${method} ${target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n${extra}\r\n${body}`));
    let out = '';
    sock.on('data', (d) => { out += d.toString(); });
    sock.on('end', () => resolve(out));
    sock.on('error', reject);
  });
  const listen = async (app: ReturnType<typeof Fastify>) => {
    await app.listen({ port: 0, host: '127.0.0.1' });
    return (app.server.address() as AddressInfo).port;
  };

  it('absolute-form and asterisk request targets never reach the auth core and never answer 500', async () => {
    const { auth } = setup();
    let calls = 0;
    const app = build();
    await app.register(authPlugin({ ...auth, handle: async (q) => { calls++; return auth.handle(q); } }));
    app.setNotFoundHandler(async (_req, reply) => reply.code(418).send());
    const port = await listen(app);
    const abs = await rawRequest(port, 'http://evil.example.test/auth/providers', 'GET');
    const star = await rawRequest(port, '*', 'OPTIONS');
    expect(abs).not.toMatch(/^HTTP\/1.1 500/);
    expect(star).not.toMatch(/^HTTP\/1.1 500/);
    expect(abs).toMatch(/^HTTP\/1.1 (418|404|400)/);
    expect(star).toMatch(/^HTTP\/1.1 (418|404|400)/);
    expect(calls).toBe(0);
    expect(await rawRequest(port, '/auth/providers', 'GET')).toMatch(/^HTTP\/1.1 200/);
    expect(calls).toBe(1);
  });

  it('requireSession answers 401 and skips the handler for absolute-form and asterisk targets', async () => {
    const { auth } = setup();
    let ran = 0;
    const app = build();
    app.route({ method: ['GET', 'OPTIONS'], url: '/*', preHandler: requireSession(auth), handler: async () => { ran++; return 'ok'; } });
    const port = await listen(app);
    const abs = await rawRequest(port, 'http://evil.example.test/me', 'GET');
    const star = await rawRequest(port, '*', 'OPTIONS');
    expect(abs).not.toMatch(/^HTTP\/1.1 200/);
    expect(star).not.toMatch(/^HTTP\/1.1 200/);
    expect(abs).not.toMatch(/^HTTP\/1.1 500/);
    expect(ran).toBe(0);
    let coreCalls = 0;
    const direct = requireSession({ ...auth, requireSession: async (q) => { coreCalls++; return auth.requireSession(q); } });
    const reply = { code: (c: number) => ({ send: (b: unknown) => ({ c, b }) }), header: () => undefined };
    const out = await (direct as any)({ raw: { url: 'http://evil.example.test/me' }, headers: {}, method: 'GET' }, reply);
    expect(out).toEqual({ c: 401, b: { error: { code: 'unauthenticated', message: 'Sign in required' } } });
    expect(coreCalls).toBe(0);
  });

  it('logout with a JSON body or an odd content-type still reaches the core (403 without origin, 204 with)', async () => {
    const { auth, store } = setup();
    const app = build();
    await app.register(authPlugin(auth));
    const port = await listen(app);
    const { sid } = await seedSession(store, new Date(Date.now() + 864e5));
    const cookie = `Cookie: __Host-ventrical_session=${sid.id}\r\n`;
    for (const ct of ['application/json', 'application/x-weird']) {
      const body = '{"a":1}';
      const head = `${cookie}Content-Type: ${ct}\r\nContent-Length: ${body.length}\r\n`;
      expect(await rawRequest(port, '/auth/logout', 'POST', head, body)).toMatch(/^HTTP\/1.1 403/);
    }
    expect(store.sessions.size).toBe(1);
    const body = '{"a":1}';
    const ok = await rawRequest(port, '/auth/logout', 'POST', `${cookie}Origin: ${FRONT}\r\nContent-Type: application/x-weird\r\nContent-Length: ${body.length}\r\n`, body);
    expect(ok).toMatch(/^HTTP\/1.1 204/);
    expect(store.sessions.size).toBe(0);
  });

  it('preserves multiple Set-Cookie headers', async () => {
    const { auth } = setup();
    const app = build();
    await app.register(authPlugin({
      ...auth,
      handle: async (q) => {
        const res = (await auth.handle(q))!;
        const headers = new Headers(res.headers);
        headers.append('set-cookie', 'a=1; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT');
        headers.append('set-cookie', 'b=2; Path=/');
        return new Response(res.body, { status: res.status, headers });
      },
    }));
    const cookies = setCookies(await app.inject({ method: 'GET', url: '/auth/google/start' }));
    expect(cookies.length).toBe(3);
    expect(cookies).toContain('a=1; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT');
  });

  it('requireSession sets request.user, answers 401 and 403 account_suspended, forwards refreshed cookie', async () => {
    const { auth, store } = setup();
    const app = build();
    app.get('/me', { preHandler: requireSession(auth) }, async (req) => ({ id: req.user!.id }));
    const anon = await app.inject({ method: 'GET', url: '/me' });
    expect(anon.statusCode).toBe(401);
    expect(anon.json()).toEqual({ error: { code: 'unauthenticated', message: 'Sign in required' } });

    const { user, sid } = await seedSession(store, new Date(Date.now() + 10 * 864e5));
    const ok = await app.inject({ method: 'GET', url: '/me', headers: { cookie: `__Host-ventrical_session=${sid.id}` } });
    expect(ok.statusCode).toBe(200);
    expect(ok.json()).toEqual({ id: user.id });
    expect(cookieNamed(setCookies(ok), '__Host-ventrical_session')).toBe(`__Host-ventrical_session=${sid.id}`);

    store.suspend(user.id);
    const sus = await app.inject({ method: 'GET', url: '/me', headers: { cookie: `__Host-ventrical_session=${sid.id}` } });
    expect(sus.statusCode).toBe(403);
    expect(sus.json()).toEqual({ error: { code: 'account_suspended', message: SUSPENDED_MESSAGE } });
  });

  it('thrown errors become a fixed 500 without details', async () => {
    const { auth } = setup();
    const app = build();
    await app.register(authPlugin({ ...auth, handle: async () => { throw new Error('secret-detail'); } }));
    const res = await app.inject({ method: 'GET', url: '/auth/providers' });
    expect(res.statusCode).toBe(500);
    expect(res.body).not.toContain('secret-detail');
  });
});
