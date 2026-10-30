import { describe, expect, it } from 'vitest';
import { hashToken } from '../src/crypto.js';
import { AuthHttpError, SUSPENDED_MESSAGE } from '../src/errors.js';
import { makeSessions, newSessionId } from '../src/session.js';
import { createMemoryStore } from './helpers/memory-store.js';

const DAY = 24 * 60 * 60 * 1000;
const TTL = 30 * DAY;
const t0 = new Date('2026-01-01T00:00:00Z');

async function setup(publicUrl = 'https://auth.example.test', cookieDomain?: string) {
  const store = createMemoryStore();
  let now = t0;
  const sessions = makeSessions({
    store, cookieNames: { session: 'sid', oauth: 'oauth' }, publicUrl, sessionTtlMs: TTL, clock: () => now, ...(cookieDomain ? { cookieDomain } : {}),
  });
  const user = await store.createUserWithIdentity({ provider: 'github', subject: 's1', email: 'a@example.test', emailVerified: true, name: 'A' });
  const { id, idHash } = newSessionId();
  await store.transaction((tx) => store.createSessionUnlessSuspended(user.id, idHash, new Date(t0.getTime() + TTL), { provider: 'github', subject: 's1' }, tx));
  const req = (cookie?: string) => new Request('https://x.test/', cookie === undefined ? {} : { headers: { cookie } });
  return { store, sessions, user, id, idHash, req, setNow: (d: Date) => { now = d; } };
}

describe('newSessionId', () => {
  it('is 32-byte base64url and hashes with sha256', () => {
    const { id, idHash } = newSessionId();
    expect(id).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(idHash).toBe(hashToken(id));
  });
});

describe('sessions', () => {
  it('returns undefined with no cookie', async () => {
    const s = await setup();
    expect(await s.sessions.getSession(s.req())).toBeUndefined();
  });

  it('returns the user for a valid session', async () => {
    const s = await setup();
    const r = await s.sessions.getSession(s.req(`sid=${s.id}`));
    expect(r?.user.id).toBe(s.user.id);
    expect(r?.id).toBe(s.id);
  });

  it('does not refresh a fresh session', async () => {
    const s = await setup();
    s.setNow(new Date(t0.getTime() + 0.5 * DAY));
    const r = await s.sessions.getSession(s.req(`sid=${s.id}`));
    expect(r?.setCookie).toBeUndefined();
    expect(s.store.sessions.get(s.idHash)!.expiresAt.getTime()).toBe(t0.getTime() + TTL);
  });

  it('refreshes expiry and returns a Set-Cookie when under 29 days remain', async () => {
    const s = await setup();
    const now = new Date(t0.getTime() + 2 * DAY);
    s.setNow(now);
    const r = await s.sessions.getSession(s.req(`sid=${s.id}`));
    expect(r?.setCookie).toBe(s.sessions.sessionCookie(s.id));
    expect(s.store.sessions.get(s.idHash)!.expiresAt.getTime()).toBe(now.getTime() + TTL);
  });

  it('a suspended user\'s session is invalid', async () => {
    const s = await setup();
    s.store.suspend(s.user.id);
    expect(await s.sessions.getSession(s.req(`sid=${s.id}`))).toBeUndefined();
  });

  it('requireSession returns 403 account_suspended for a suspended tombstone', async () => {
    const s = await setup();
    s.store.suspend(s.user.id);
    const err = await s.sessions.requireSession(s.req(`sid=${s.id}`)).catch((e) => e);
    expect(err).toBeInstanceOf(AuthHttpError);
    expect(err).toMatchObject({ status: 403, code: 'account_suspended', message: SUSPENDED_MESSAGE });
  });

  it('requireSession returns 401 otherwise', async () => {
    const s = await setup();
    const err = await s.sessions.requireSession(s.req('sid=nope')).catch((e) => e);
    expect(err).toMatchObject({ status: 401, code: 'unauthenticated', message: 'Sign in required' });
    expect((await s.sessions.requireSession(s.req(`sid=${s.id}`))).user.id).toBe(s.user.id);
  });

  it('an empty, 10,000-character or non-UTF-8 cookie value is treated as signed out', async () => {
    const s = await setup();
    for (const c of ['sid=', `sid=${'a'.repeat(10_000)}`, 'sid=%FF%FE', 'sid=%E0%A4%A', 'sid=%', 'sid="', 'garbage', ';;;']) {
      expect(await s.sessions.getSession(s.req(c))).toBeUndefined();
    }
  });

  it('cookie attributes: secure only for https, optional domain, clearing', async () => {
    const a = await setup('https://auth.example.test', 'example.test');
    const c = a.sessions.sessionCookie('abc');
    expect(c).toContain('sid=abc');
    expect(c).toContain('HttpOnly');
    expect(c).toContain('SameSite=Lax');
    expect(c).toContain('Path=/');
    expect(c).toContain('Secure');
    expect(c).toContain('Domain=example.test');
    expect(c).toContain(`Max-Age=${TTL / 1000}`);
    expect(a.sessions.clearSessionCookie()).toContain('Max-Age=0');
    const b = await setup('http://localhost:3000');
    expect(b.sessions.sessionCookie('abc')).not.toContain('Secure');
    expect(b.sessions.sessionCookie('abc')).not.toContain('Domain');
  });
});

describe('memory store', () => {
  it('rolls back a transaction on throw', async () => {
    const s = await setup();
    await expect(s.store.transaction(async () => {
      await s.store.createUserWithIdentity({ provider: 'google', subject: 'g', emailVerified: false });
      throw new Error('boom');
    })).rejects.toThrow('boom');
    expect(await s.store.findUserByIdentity('google', 'g')).toBeUndefined();
  });
  it('throws DuplicateIdentityError on a duplicate identity', async () => {
    const s = await setup();
    await expect(s.store.createUserWithIdentity({ provider: 'github', subject: 's1', emailVerified: false })).rejects.toMatchObject({ name: 'DuplicateIdentityError' });
  });
  it('emailBelongsToSuspendedUser matches verified emails case-insensitively', async () => {
    const s = await setup();
    expect(await s.store.emailBelongsToSuspendedUser('A@EXAMPLE.test')).toBe(false);
    s.store.suspend(s.user.id);
    expect(await s.store.emailBelongsToSuspendedUser('A@EXAMPLE.test')).toBe(true);
    expect(await s.store.emailBelongsToSuspendedUser('other@example.test')).toBe(false);
  });
  it('createSessionUnlessSuspended returns false when suspended; deleteSessionsForUser counts', async () => {
    const s = await setup();
    expect(await s.store.deleteSessionsForUser(s.user.id)).toBe(1);
    s.store.suspend(s.user.id);
    expect(await s.store.transaction((tx) => s.store.createSessionUnlessSuspended(s.user.id, 'h', t0, { provider: 'github', subject: 's1' }, tx))).toBe(false);
  });
});
