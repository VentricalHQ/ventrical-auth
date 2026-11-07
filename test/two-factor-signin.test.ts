import { describe, expect, it } from 'vitest';
import { hashToken } from '../src/crypto.js';
import { createMemoryStore } from './helpers/memory-store.js';
import { FRONT, SESSION_COOKIE, req, tfSetup } from './helpers/two-factor.js';

const TEN_MIN = 10 * 60 * 1000;
const sessionRow = (t: ReturnType<typeof tfSetup>, cookieHeader: string) =>
  t.store.sessions.get(hashToken(decodeURIComponent(cookieHeader.split('=').slice(1).join('='))))!;

describe('sign-in matrix', () => {
  it('twoFactor unset: a normal session, a normal redirect, nothing pending', async () => {
    const t = tfSetup({ twoFactor: false });
    const { location, cookie, setCookie: sc } = await t.signIn('google', { redirect: '/memories' });
    expect(location).toBe(`${FRONT}/memories`);
    expect(sessionRow(t, cookie!).mfaPending).toBe(false);
    expect(Number(sc!.attrs['max-age'])).toBe(30 * 24 * 3600);
    expect(await t.auth.getSession(req('GET', '/x', { cookie: cookie! }))).toMatchObject({ user: { email: 'g1@example.test' } });
    expect(await t.auth.getPendingSession(req('GET', '/x', { cookie: cookie! }))).toBeUndefined();
  });

  it('configured, user not enrolled and not required: a normal session', async () => {
    const t = tfSetup();
    const { location, cookie } = await t.signIn('google', { redirect: '/memories' });
    expect(location).toBe(`${FRONT}/memories`);
    expect(sessionRow(t, cookie!).mfaPending).toBe(false);
    expect(await t.auth.getSession(req('GET', '/x', { cookie: cookie! }))).toBeDefined();
  });

  it('enrolled user: pending session, redirected to verifyPath, short life, state "verify"', async () => {
    const t = tfSetup();
    await t.enrol();
    const { location, cookie, setCookie: sc } = await t.signIn('google', { redirect: '/memories' });
    expect(location).toBe(`${FRONT}/2fa`);
    const row = sessionRow(t, cookie!);
    expect(row.mfaPending).toBe(true);
    expect(row.mfaRedirect).toBe('/memories');
    expect(row.expiresAt.getTime()).toBe(t.clock.now.getTime() + TEN_MIN);
    expect(Number(sc!.attrs['max-age'])).toBe(TEN_MIN / 1000);
    expect(await t.auth.getPendingSession(req('GET', '/x', { cookie: cookie! }))).toEqual({ state: 'verify' });
  });

  it('required but not enrolled: pending session in state "enroll"', async () => {
    const t = tfSetup({ twoFactor: { required: true } });
    const { location, cookie } = await t.signIn();
    expect(location).toBe(`${FRONT}/2fa`);
    expect(sessionRow(t, cookie!).mfaPending).toBe(true);
    expect(await t.auth.getPendingSession(req('GET', '/x', { cookie: cookie! }))).toEqual({ state: 'enroll' });
  });

  it('a required function is called with the user and isNew, and decides per user', async () => {
    const seen: Array<{ email: string | null; isNew: boolean }> = [];
    const t = tfSetup({
      profiles: { google: { subject: 'g1', emailVerified: true, email: 'g1@example.test' }, github: { subject: 'h1', emailVerified: true, email: 'h1@example.test' } },
      twoFactor: { required: ({ user, isNew }) => { seen.push({ email: user.email, isNew }); return user.email === 'g1@example.test'; } },
    });
    expect((await t.signIn('google')).location).toBe(`${FRONT}/2fa`);
    expect((await t.signIn('github')).location).toBe(`${FRONT}/`);
    expect((await t.signIn('google')).location).toBe(`${FRONT}/2fa`);
    expect(seen).toEqual([
      { email: 'g1@example.test', isNew: true }, { email: 'h1@example.test', isNew: true }, { email: 'g1@example.test', isNew: false },
    ]);
  });

  it('a required function that throws fails the sign-in closed and leaves no session', async () => {
    const t = tfSetup({ twoFactor: { required: () => { throw new Error('boom'); } } });
    const { location, cookie } = await t.signIn();
    expect(location).toBe(`${FRONT}/signin?error=sign_in_failed`);
    expect(cookie).toBeUndefined();
    expect(t.store.sessions.size).toBe(0);
  });

  it('a required function that rejects fails closed too', async () => {
    const t = tfSetup({ twoFactor: { required: async () => { throw new Error('boom'); } } });
    expect((await t.signIn()).location).toBe(`${FRONT}/signin?error=sign_in_failed`);
  });

  it('an enrolled user is not asked for the required hook', async () => {
    let called = 0;
    const t = tfSetup({ twoFactor: { required: () => { called++; return true; } } });
    await t.enrol();
    await t.signIn();
    expect(called).toBe(0);
  });

  it('verifyPath and resolveRedirect are honoured', async () => {
    const t = tfSetup({ twoFactor: { verifyPath: '/two-factor' }, config: { hooks: { resolveRedirect: (p) => ({ target: 'backend' as const, path: p }) } } });
    await t.enrol();
    expect((await t.signIn()).location).toBe('https://api.example.test/two-factor');
  });

  it('pendingTtlMs sets the pending life and the cookie life', async () => {
    const t = tfSetup({ twoFactor: { pendingTtlMs: 60_000 } });
    await t.enrol();
    const { cookie, setCookie: sc } = await t.signIn();
    expect(sessionRow(t, cookie!).expiresAt.getTime()).toBe(t.clock.now.getTime() + 60_000);
    expect(Number(sc!.attrs['max-age'])).toBe(60);
  });

  it('a pending session never outlives sessionMaxAgeMs', async () => {
    const t = tfSetup({ config: { sessionMaxAgeMs: 120_000 } });
    await t.enrol();
    const { cookie } = await t.signIn();
    expect(sessionRow(t, cookie!).expiresAt.getTime()).toBe(t.clock.now.getTime() + 120_000);
  });

  it('afterSignIn still runs in the same transaction, after the session row exists', async () => {
    const order: string[] = [];
    const t = tfSetup({ config: { hooks: { afterSignIn: async ({ tx }) => { order.push(`hook tx${tx.id} sessions=${t.store.sessions.size}`); } } } });
    await t.enrol();
    await t.signIn();
    expect(order).toHaveLength(1);
    expect(order[0]).toMatch(/sessions=1$/);
  });

  it('the old session is deleted on a new sign-in, pending or not', async () => {
    const t = tfSetup();
    const first = await t.signIn();
    expect(t.store.sessions.size).toBe(1);
    await t.enrol();
    const second = await t.signIn('google', { cookie: first.cookie });
    expect(t.store.sessions.size).toBe(1);
    expect(second.cookie).not.toBe(first.cookie);
    // A stale pending session is replaced by the next sign-in too.
    const third = await t.signIn('google', { cookie: second.cookie });
    expect(t.store.sessions.size).toBe(1);
    expect(third.cookie).not.toBe(second.cookie);
  });
});

describe('suspended users', () => {
  it('a suspended enrolled user is refused at the callback and gets no session', async () => {
    const t = tfSetup();
    const { user } = await t.enrol();
    t.store.suspend(user.id);
    const { location, cookie } = await t.signIn();
    expect(location).toBe(`${FRONT}/signin?error=suspended`);
    expect(cookie).toBeUndefined();
    expect(t.store.sessions.size).toBe(0);
  });
});

describe('a store that ignores the pending flag fails closed', () => {
  it('the callback refuses to hand out a cookie when the stored row is not reported pending', async () => {
    const store = createMemoryStore();
    const t = tfSetup({ store });
    await t.enrol();
    store.ignorePendingFlag = true;
    const { location, cookie } = await t.signIn();
    expect(location).toBe(`${FRONT}/signin?error=sign_in_failed`);
    expect(cookie).toBeUndefined();
    expect(store.sessions.size).toBe(0);
  });

  it('with twoFactor configured, a session row without a boolean mfaPending is signed out', async () => {
    const store = createMemoryStore();
    const t = tfSetup({ store });
    const { cookie } = await t.signIn();
    expect(await t.auth.getSession(req('GET', '/x', { cookie: cookie! }))).toBeDefined();
    store.ignorePendingFlag = true;
    expect(await t.auth.getSession(req('GET', '/x', { cookie: cookie! }))).toBeUndefined();
    await expect(t.auth.requireSession(req('GET', '/x', { cookie: cookie! }))).rejects.toMatchObject({ status: 401 });
  });
});

describe('a pending session is never a signed-in session', () => {
  async function pending() {
    const t = tfSetup();
    await t.enrol();
    const { cookie } = await t.signIn();
    return { t, cookie: cookie! };
  }

  it('getSession and requireSession treat it as signed out', async () => {
    const { t, cookie } = await pending();
    const r = req('GET', '/x', { cookie });
    expect(await t.auth.getSession(r)).toBeUndefined();
    await expect(t.auth.requireSession(r)).rejects.toMatchObject({ status: 401, code: 'unauthenticated' });
  });

  it('logout-everywhere answers 401 and deletes nothing', async () => {
    const { t, cookie } = await pending();
    const other = await t.enrol('other');
    void other;
    const before = t.store.sessions.size;
    const { status } = await t.post('/auth/logout-everywhere', {}, cookie);
    expect(status).toBe(401);
    expect(t.store.sessions.size).toBe(before);
  });

  it('a pending session cannot be used to link another identity to its user', async () => {
    const t = tfSetup({ profiles: { google: { subject: 'g1', emailVerified: true, email: 'g1@example.test' }, github: { subject: 'h1', emailVerified: true, email: 'h1@example.test' } } });
    const { user } = await t.enrol();
    const first = await t.signIn('google');
    const linked = await t.signIn('github', { cookie: first.cookie });
    const h1 = await t.store.findUserByIdentity('github', 'h1');
    expect(h1).toBeDefined();
    expect(h1!.id).not.toBe(user.id);
    expect(linked.location).toBe(`${FRONT}/`);
  });

  it('an expired pending session is gone', async () => {
    const { t, cookie } = await pending();
    t.advance(TEN_MIN + 1);
    expect(await t.auth.getPendingSession(req('GET', '/x', { cookie }))).toBeUndefined();
  });

  it('a pending session does not refresh or extend', async () => {
    const { t, cookie } = await pending();
    const before = sessionRow(t, cookie).expiresAt.getTime();
    t.advance(60_000);
    await t.auth.getPendingSession(req('GET', '/x', { cookie }));
    expect(sessionRow(t, cookie).expiresAt.getTime()).toBe(before);
  });

  it('an unknown cookie and no cookie give no pending session', async () => {
    const { t } = await pending();
    expect(await t.auth.getPendingSession(req('GET', '/x', { cookie: `${SESSION_COOKIE}=nope` }))).toBeUndefined();
    expect(await t.auth.getPendingSession(req('GET', '/x'))).toBeUndefined();
  });

  it('getPendingSession is undefined for a full session and for any request when twoFactor is unset', async () => {
    const t = tfSetup();
    const { cookie } = await t.signIn();
    expect(await t.auth.getPendingSession(req('GET', '/x', { cookie: cookie! }))).toBeUndefined();
    const off = tfSetup({ twoFactor: false });
    expect(await off.auth.getPendingSession(req('GET', '/x'))).toBeUndefined();
  });
});

describe('required: true holds sessions that never passed the second factor', () => {
  it('a session created before 2FA was on (mfa_verified_at null) is held pending on its next request', async () => {
    const store = createMemoryStore();
    const before = tfSetup({ store, twoFactor: false });
    const { cookie } = await before.signIn();
    const t = tfSetup({ store, twoFactor: { required: true } });
    t.clock.now = new Date(before.clock.now);
    const r = req('GET', '/x', { cookie: cookie! });
    expect(await t.auth.getSession(r)).toBeUndefined();
    await expect(t.auth.requireSession(r)).rejects.toMatchObject({ status: 401 });
    expect(await t.auth.getPendingSession(r)).toEqual({ state: 'enroll' });
    // Pending life starts now, and the row is now an ordinary pending one.
    const row = sessionRow(t, cookie!);
    expect(row.mfaPending).toBe(true);
    expect(row.expiresAt.getTime()).toBe(t.clock.now.getTime() + TEN_MIN);
  });

  it('an enrolled user in that position gets state "verify"', async () => {
    const store = createMemoryStore();
    const before = tfSetup({ store, twoFactor: false });
    await before.enrol();
    const { cookie } = await before.signIn();
    const t = tfSetup({ store, twoFactor: { required: true } });
    t.clock.now = new Date(before.clock.now);
    expect(await t.auth.getPendingSession(req('GET', '/x', { cookie: cookie! }))).toEqual({ state: 'verify' });
  });

  it('the pending life never extends a session that would expire sooner', async () => {
    const store = createMemoryStore();
    const before = tfSetup({ store, twoFactor: false, config: { sessionTtlMs: 120_000 } });
    const { cookie } = await before.signIn();
    const t = tfSetup({ store, twoFactor: { required: true }, config: { sessionTtlMs: 120_000 } });
    t.clock.now = new Date(before.clock.now);
    await t.auth.getPendingSession(req('GET', '/x', { cookie: cookie! }));
    expect(sessionRow(t, cookie!).expiresAt.getTime()).toBe(t.clock.now.getTime() + 120_000);
  });

  it('a required function does not hold existing sessions: they stay valid until they expire', async () => {
    const store = createMemoryStore();
    const before = tfSetup({ store, twoFactor: false });
    const { cookie } = await before.signIn();
    const t = tfSetup({ store, twoFactor: { required: () => true } });
    t.clock.now = new Date(before.clock.now);
    expect(await t.auth.getSession(req('GET', '/x', { cookie: cookie! }))).toBeDefined();
  });

  it('a session that has passed the second factor is not held', async () => {
    const t = tfSetup({ twoFactor: { required: true } });
    const { secret } = await t.enrol();
    const { cookie } = await t.signIn();
    t.nextStep();
    const v = await t.post('/auth/2fa/verify', { code: t.codeFor(secret) }, cookie);
    expect(v.status).toBe(200);
    const r = req('GET', '/x', { cookie: cookie! });
    const s = await t.auth.getSession(r);
    expect(s?.mfaVerifiedAt).toEqual(t.clock.now);
  });
});
