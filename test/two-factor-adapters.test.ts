import express from 'express';
import Fastify from 'fastify';
import { Hono } from 'hono';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { authRouter, getPendingSession as expressPending } from '../src/express/index.js';
import { authPlugin, getPendingSession as fastifyPending } from '../src/fastify/index.js';
import { authHandler, getPendingSession as honoPending } from '../src/hono/index.js';
import { authRouteHandlers, getPendingSession as nextPending } from '../src/next/index.js';
import { FRONT, SESSION_COOKIE, req, setCookie, tfSetup, type Tf } from './helpers/two-factor.js';

const servers: Server[] = [];
const apps: Array<{ close(): Promise<unknown> }> = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise<void>((r) => { s.close(() => r()); s.closeAllConnections(); })));
  await Promise.all(apps.splice(0).map((a) => a.close()));
});

/** An enrolled user with a pending session, plus a fresh code for the next step. */
async function pendingUser() {
  const t = tfSetup();
  const { secret } = await t.enrol();
  const { cookie } = await t.signIn();
  t.nextStep();
  return { t, cookie: cookie!, code: t.codeFor(secret) };
}
const headers = (cookie: string, extra: Record<string, string> = {}) => ({ cookie, origin: FRONT, 'content-type': 'application/json', ...extra });
const verifiedCookie = (res: { headers: Headers }) => setCookie(res as Response, SESSION_COOKIE);

async function listen(app: express.Express) {
  const server = await new Promise<Server>((r) => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
  servers.push(server);
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

describe('express adapter', () => {
  it('forwards the JSON body of a 2FA POST and reports the pending session', async () => {
    const { t, cookie, code } = await pendingUser();
    const app = express();
    app.get('/state', async (rq, rs) => { rs.json((await expressPending(t.auth)(rq)) ?? null); });
    app.use(authRouter(t.auth));
    const base = await listen(app);
    expect(await (await fetch(`${base}/state`, { headers: { cookie } })).json()).toEqual({ state: 'verify' });
    const res = await fetch(`${base}/auth/2fa/verify`, { method: 'POST', headers: headers(cookie), body: JSON.stringify({ code }) });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, redirect: `${FRONT}/` });
    expect(verifiedCookie(res)).toBeDefined();
    expect(await (await fetch(`${base}/state`, { headers: { cookie } })).json()).toBeNull();
  });

  it('works when express.json() already parsed the body', async () => {
    const { t, cookie, code } = await pendingUser();
    const app = express();
    app.use(express.json());
    app.use(authRouter(t.auth));
    const base = await listen(app);
    const res = await fetch(`${base}/auth/2fa/verify`, { method: 'POST', headers: headers(cookie), body: JSON.stringify({ code }) });
    expect(res.status).toBe(200);
  });

  it('works when the router is mounted under a prefix of the app', async () => {
    const { t, cookie, code } = await pendingUser();
    const app = express();
    app.use((rq, _rs, next) => next());
    app.use(authRouter(t.auth));
    const base = await listen(app);
    expect((await fetch(`${base}/auth/2fa/verify?x=1`, { method: 'POST', headers: headers(cookie), body: JSON.stringify({ code }) })).status).toBe(200);
  });

  it('answers 400 for an oversized body and does not count it', async () => {
    const { t, cookie } = await pendingUser();
    const app = express();
    app.use(authRouter(t.auth));
    const base = await listen(app);
    const res = await fetch(`${base}/auth/2fa/verify`, { method: 'POST', headers: headers(cookie), body: JSON.stringify({ code: 'x'.repeat(50_000) }) });
    expect(res.status).toBe(400);
    expect((await res.json()).error.code).toBe('invalid_request');
  });

  it('a very large body gets a 400, not a dropped connection', async () => {
    const { t, cookie } = await pendingUser();
    const app = express();
    app.use(authRouter(t.auth));
    const base = await listen(app);
    const res = await fetch(`${base}/auth/2fa/verify`, { method: 'POST', headers: headers(cookie), body: JSON.stringify({ code: 'x'.repeat(8_000_000) }) });
    expect(res.status).toBe(400);
  });

  it('GET /auth/2fa/status and unknown 2FA paths behave', async () => {
    const { t, cookie } = await pendingUser();
    const app = express();
    app.use(authRouter(t.auth));
    const base = await listen(app);
    expect((await fetch(`${base}/auth/2fa/status`, { headers: { cookie } })).status).toBe(401);
    expect((await fetch(`${base}/auth/2fa/nothing`, { method: 'POST', headers: headers(cookie), body: '{}' })).status).toBe(404);
  });

  it('does not touch the body of a POST to the same path when twoFactor is not configured', async () => {
    const t = tfSetup({ twoFactor: false });
    const app = express();
    app.use(authRouter(t.auth));
    app.post('/auth/2fa/verify', express.text({ type: '*/*' }), (rq, rs) => { rs.json({ echoed: rq.body }); });
    const base = await listen(app);
    const res = await fetch(`${base}/auth/2fa/verify`, { method: 'POST', headers: { 'content-type': 'text/plain' }, body: 'hello' });
    expect(await res.json()).toEqual({ echoed: 'hello' });
  });
});

describe('next adapter', () => {
  it('forwards the body and reports the pending session', async () => {
    const { t, cookie, code } = await pendingUser();
    const { POST, GET } = authRouteHandlers(t.auth);
    expect(await nextPending(t.auth)(req('GET', '/x', { cookie }))).toEqual({ state: 'verify' });
    const res = await POST(new Request('http://localhost:3000/auth/2fa/verify', { method: 'POST', headers: headers(cookie), body: JSON.stringify({ code }) }));
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, redirect: `${FRONT}/` });
    expect(verifiedCookie(res)).toBeDefined();
    expect((await GET(new Request('http://localhost:3000/auth/2fa/status', { headers: { cookie } }))).status).toBe(200);
    expect(await nextPending(t.auth)(req('GET', '/x', { cookie }))).toBeUndefined();
  });

  it('answers 400 for an oversized body', async () => {
    const { t, cookie } = await pendingUser();
    const { POST } = authRouteHandlers(t.auth);
    const res = await POST(new Request('http://localhost:3000/auth/2fa/verify', { method: 'POST', headers: headers(cookie), body: JSON.stringify({ code: 'x'.repeat(50_000) }) }));
    expect(res.status).toBe(400);
  });
});

describe('hono adapter', () => {
  it('forwards the body and reports the pending session', async () => {
    const { t, cookie, code } = await pendingUser();
    const app = new Hono();
    app.get('/state', async (c) => c.json((await honoPending(t.auth)(c)) ?? null));
    app.use(authHandler(t.auth));
    expect(await (await app.request('/state', { headers: { cookie } })).json()).toEqual({ state: 'verify' });
    const res = await app.request('/auth/2fa/verify', { method: 'POST', headers: headers(cookie), body: JSON.stringify({ code }) });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, redirect: `${FRONT}/` });
    expect(verifiedCookie(res)).toBeDefined();
    expect(await (await app.request('/state', { headers: { cookie } })).json()).toBeNull();
  });

  it('leaves the body readable for the app when twoFactor is not configured', async () => {
    const t = tfSetup({ twoFactor: false });
    const app = new Hono();
    app.use(authHandler(t.auth));
    app.post('/auth/2fa/verify', async (c) => c.json({ echoed: await c.req.text() }));
    const res = await app.request('/auth/2fa/verify', { method: 'POST', body: 'hello' });
    expect(await res.json()).toEqual({ echoed: 'hello' });
  });
});

describe('fastify adapter', () => {
  it('forwards the body and reports the pending session', async () => {
    const { t, cookie, code } = await pendingUser();
    const app = Fastify();
    apps.push(app);
    await app.register(authPlugin(t.auth));
    app.get('/state', async (rq) => (await fastifyPending(t.auth)(rq)) ?? null);
    expect(JSON.parse((await app.inject({ method: 'GET', url: '/state', headers: { cookie } })).body)).toEqual({ state: 'verify' });
    const res = await app.inject({ method: 'POST', url: '/auth/2fa/verify', headers: headers(cookie), payload: JSON.stringify({ code }) });
    expect(res.statusCode).toBe(200);
    expect(JSON.parse(res.body)).toEqual({ ok: true, redirect: `${FRONT}/` });
    const raw = ([] as string[]).concat(res.headers['set-cookie'] as string | string[] ?? []);
    expect(raw.some((c) => c.startsWith(`${SESSION_COOKIE}=`))).toBe(true);
    expect(JSON.parse((await app.inject({ method: 'GET', url: '/state', headers: { cookie } })).body)).toBeNull();
  });

  it('answers 400 for an oversized body', async () => {
    const { t, cookie } = await pendingUser();
    const app = Fastify();
    apps.push(app);
    await app.register(authPlugin(t.auth));
    const res = await app.inject({ method: 'POST', url: '/auth/2fa/verify', headers: headers(cookie), payload: JSON.stringify({ code: 'x'.repeat(50_000) }) });
    expect(res.statusCode).toBe(400);
  });
});

void (null as unknown as Tf);
