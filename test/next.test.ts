import { describe, expect, it } from 'vitest';
import { authRouteHandlers, getSessionFromRequest, requireSession } from '../src/next/index.js';
import { SUSPENDED_MESSAGE } from '../src/errors.js';
import { FRONT, PUBLIC, cookieNamed, seedSession, setup } from './helpers/adapter-setup.js';

const r = (path: string, init: RequestInit & { base?: string } = {}) =>
  new Request(new URL(path, init.base ?? 'http://localhost:3000'), { redirect: 'manual', ...init });

describe('next adapter', () => {
  it('start redirects, callback sets the session cookie, logout checks origin', async () => {
    const { auth, store } = setup();
    const { GET, POST } = authRouteHandlers(auth);
    const start = await GET(r('/auth/google/start'));
    expect(start.status).toBe(302);
    const oauth = cookieNamed(start.headers.getSetCookie(), '__Host-ventrical_oauth')!;
    const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
    const cb = await GET(r(`/auth/google/callback?code=fake-code&state=${encodeURIComponent(state)}`, { headers: { cookie: oauth } }));
    expect(cb.status).toBe(302);
    expect(cb.headers.get('location')!.startsWith(FRONT)).toBe(true);
    const session = cookieNamed(cb.headers.getSetCookie(), '__Host-ventrical_session')!;
    expect(session).toBeDefined();
    expect(store.sessions.size).toBe(1);

    const bad = await POST(r('/auth/logout', { method: 'POST', headers: { cookie: session } }));
    expect(bad.status).toBe(403);
    expect(store.sessions.size).toBe(1);
    const out = await POST(r('/auth/logout', { method: 'POST', headers: { cookie: session, origin: FRONT } }));
    expect(out.status).toBe(204);
    expect(store.sessions.size).toBe(0);
  });

  it('unowned paths get a 404 Response', async () => {
    const { GET } = authRouteHandlers(setup().auth);
    const res = await GET(r('/nope'));
    expect(res.status).toBe(404);
    expect((await res.json() as any).error.code).toBe('not_found');
  });

  it('builds the URL from publicUrl, not the request host', async () => {
    const { auth } = setup();
    const seen: string[] = [];
    const { GET } = authRouteHandlers({ ...auth, handle: async (q) => { seen.push(q.url); return auth.handle(q); } });
    await GET(r('/auth/providers?x=1', { base: 'https://evil.example.test' }));
    expect(seen).toEqual([`${PUBLIC}/auth/providers?x=1`]);
  });

  it('preserves multiple Set-Cookie headers', async () => {
    const { auth } = setup();
    const { GET } = authRouteHandlers({
      ...auth,
      handle: async (q) => {
        const res = (await auth.handle(q))!;
        const headers = new Headers(res.headers);
        headers.append('set-cookie', 'a=1; Path=/; Expires=Wed, 21 Oct 2026 07:28:00 GMT');
        headers.append('set-cookie', 'b=2; Path=/');
        return new Response(res.body, { status: res.status, headers });
      },
    });
    const cookies = (await GET(r('/auth/google/start'))).headers.getSetCookie();
    expect(cookies.length).toBe(3);
    expect(cookies).toContain('b=2; Path=/');
  });

  it('thrown errors become a fixed 500 without details', async () => {
    const { auth } = setup();
    const { GET } = authRouteHandlers({ ...auth, handle: async () => { throw new Error('secret-detail'); } });
    const res = await GET(r('/auth/providers'));
    expect(res.status).toBe(500);
    expect(await res.text()).not.toContain('secret-detail');
  });

  it('getSessionFromRequest resolves or returns undefined, and requireSession answers 401/403 JSON', async () => {
    const { auth, store } = setup();
    const get = getSessionFromRequest(auth);
    expect(await get(r('/me'))).toBeUndefined();
    const { user, sid } = await seedSession(store, new Date(Date.now() + 10 * 864e5));
    const s = await get(r('/me', { headers: { cookie: `__Host-ventrical_session=${sid.id}` } }));
    expect(s?.user.id).toBe(user.id);
    expect(s?.setCookie?.startsWith(`__Host-ventrical_session=${sid.id};`)).toBe(true);

    const need = requireSession(auth);
    const anon = await need(r('/me'));
    expect(anon).toBeInstanceOf(Response);
    expect((anon as Response).status).toBe(401);
    expect((await (anon as Response).json() as any).error.code).toBe('unauthenticated');
    store.suspend(user.id);
    const sus = await need(r('/me', { headers: { cookie: `__Host-ventrical_session=${sid.id}` } })) as Response;
    expect(sus.status).toBe(403);
    expect(await sus.json()).toEqual({ error: { code: 'account_suspended', message: SUSPENDED_MESSAGE } });
  });

  it('a malformed request URL gets 404 from the handlers and 401 from requireSession without calling the core', async () => {
    const { auth } = setup();
    let calls = 0;
    const counting = { ...auth, handle: async (q: Request) => { calls++; return auth.handle(q); } };
    const odd = () => {
      const q = new Request('https://x.example.test/auth/providers');
      Object.defineProperty(q, 'url', { value: 'not a url' });
      return q;
    };
    const { GET, POST } = authRouteHandlers(counting);
    expect((await GET(odd())).status).toBe(404);
    expect((await POST(odd())).status).toBe(404);
    expect(calls).toBe(0);
    const out = await requireSession(auth)(odd()) as Response;
    expect(out.status).toBe(401);
    expect(await out.json()).toEqual({ error: { code: 'unauthenticated', message: 'Sign in required' } });
    expect(await getSessionFromRequest(auth)(odd())).toBeUndefined();
  });
});
