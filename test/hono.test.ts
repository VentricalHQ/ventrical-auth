import { Hono } from 'hono';
import { describe, expect, it } from 'vitest';
import { authHandler, requireSession, type AuthVariables } from '../src/hono/index.js';
import { SUSPENDED_MESSAGE } from '../src/errors.js';
import { FRONT, PUBLIC, cookieNamed, seedSession, setup } from './helpers/adapter-setup.js';

describe('hono adapter', () => {
  it('start, callback and logout work end to end', async () => {
    const { auth, store } = setup();
    const app = new Hono();
    app.use(authHandler(auth));
    const start = await app.request('/auth/google/start');
    expect(start.status).toBe(302);
    const oauth = cookieNamed(start.headers.getSetCookie(), 'ventrical_oauth')!;
    const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
    const cb = await app.request(`/auth/google/callback?code=fake-code&state=${encodeURIComponent(state)}`, { headers: { cookie: oauth } });
    expect(cb.status).toBe(302);
    expect(cb.headers.get('location')!.startsWith(FRONT)).toBe(true);
    const session = cookieNamed(cb.headers.getSetCookie(), 'ventrical_session')!;
    expect(store.sessions.size).toBe(1);

    expect((await app.request('/auth/logout', { method: 'POST', headers: { cookie: session } })).status).toBe(403);
    expect((await app.request('/auth/logout', { method: 'POST', headers: { cookie: session, origin: 'https://evil.example.test' } })).status).toBe(403);
    expect(store.sessions.size).toBe(1);
    const out = await app.request('/auth/logout', { method: 'POST', headers: { cookie: session, origin: FRONT } });
    expect(out.status).toBe(204);
    expect(store.sessions.size).toBe(0);
    expect(out.headers.getSetCookie().some((c) => /^ventrical_session=;/.test(c))).toBe(true);
  });

  it('unowned paths fall through to the app', async () => {
    const app = new Hono();
    app.use(authHandler(setup().auth));
    app.get('/hello', (c) => c.text('hi'));
    const res = await app.request('/hello');
    expect(await res.text()).toBe('hi');
    expect((await app.request('/nope')).status).toBe(404);
  });

  it('builds the URL from publicUrl, not the Host header', async () => {
    const { auth } = setup();
    const seen: string[] = [];
    const app = new Hono();
    app.use(authHandler({ ...auth, handle: async (q) => { seen.push(q.url); return auth.handle(q); } }));
    await app.request('https://evil.example.test/auth/providers?x=1');
    expect(seen).toEqual([`${PUBLIC}/auth/providers?x=1`]);
  });

  it('preserves multiple Set-Cookie headers', async () => {
    const { auth } = setup();
    const app = new Hono();
    app.use(authHandler({
      ...auth,
      handle: async (q) => {
        const res = (await auth.handle(q))!;
        const headers = new Headers(res.headers);
        headers.append('set-cookie', 'a=1; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT');
        headers.append('set-cookie', 'b=2; Path=/');
        return new Response(res.body, { status: res.status, headers });
      },
    }));
    const cookies = (await app.request('/auth/google/start')).headers.getSetCookie();
    expect(cookies.length).toBe(3);
    expect(cookies).toContain('a=1; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT');
  });

  it('requireSession sets user, answers 401 and 403 account_suspended as JSON, forwards refreshed cookie', async () => {
    const { auth, store } = setup();
    const app = new Hono<{ Variables: AuthVariables }>();
    app.get('/me', requireSession(auth), (c) => c.json({ id: c.get('user').id }));
    const anon = await app.request('/me');
    expect(anon.status).toBe(401);
    expect(await anon.json()).toEqual({ error: { code: 'unauthenticated', message: 'Sign in required' } });

    const { user, sid } = await seedSession(store, new Date(Date.now() + 10 * 864e5));
    const ok = await app.request('/me', { headers: { cookie: `ventrical_session=${sid.id}` } });
    expect(ok.status).toBe(200);
    expect(await ok.json()).toEqual({ id: user.id });
    expect(cookieNamed(ok.headers.getSetCookie(), 'ventrical_session')).toBe(`ventrical_session=${sid.id}`);

    const fresh = await seedSession(store, new Date(Date.now() + 30 * 864e5 - 1000), 'g6');
    const ok2 = await app.request('/me', { headers: { cookie: `ventrical_session=${fresh.sid.id}` } });
    expect(cookieNamed(ok2.headers.getSetCookie(), 'ventrical_session')).toBeUndefined();

    store.suspend(user.id);
    const sus = await app.request('/me', { headers: { cookie: `ventrical_session=${sid.id}` } });
    expect(sus.status).toBe(403);
    expect(await sus.json()).toEqual({ error: { code: 'account_suspended', message: SUSPENDED_MESSAGE } });
  });

  it('thrown errors reach the app error handler without details', async () => {
    const { auth } = setup();
    const app = new Hono();
    app.use(authHandler({ ...auth, handle: async () => { throw new Error('secret-detail'); } }));
    const res = await app.request('/auth/providers');
    expect(res.status).toBe(500);
    expect(await res.text()).not.toContain('secret-detail');
  });
});
