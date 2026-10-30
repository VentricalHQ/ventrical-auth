import { describe, expect, it } from 'vitest';
import { createAuth, type AuthConfig, type ProviderName, type ProviderProfile } from '../src/index.js';
import { clearCookie, serializeCookie } from '../src/cookies.js';
import { fakeProvider } from './helpers/fake-provider.js';
import { createMemoryStore, type MemoryTx } from './helpers/memory-store.js';
import { req, setCookie, setCookies } from './helpers/request.js';

const FRONT = 'https://app.example.test';
const prof: ProviderProfile = { subject: 'g1', emailVerified: true, email: 'g1@example.test' };

function setup(over: Partial<AuthConfig<MemoryTx>> = {}) {
  return createAuth<MemoryTx>({
    providers: { google: { clientId: 'a', clientSecret: 'b' } },
    publicUrl: 'https://api.example.test', frontendUrl: FRONT, encryptionKey: Buffer.alloc(32, 7), store: createMemoryStore(),
    providerOverrides: { google: fakeProvider('google' as ProviderName, prof) }, ...over,
  });
}

/** Runs start + callback and reports the cookie names seen, plus the raw responses. */
async function signIn(auth: ReturnType<typeof setup>, names: { session: string; oauth: string }) {
  const start = (await auth.handle(req('GET', '/auth/google/start')))!;
  const oauth = setCookie(start, names.oauth)!;
  const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
  const cb = (await auth.handle(req('GET', `/auth/google/callback?code=c&state=${encodeURIComponent(state)}`, { cookie: `${names.oauth}=${encodeURIComponent(oauth.value)}` })))!;
  return { start, cb, session: setCookie(cb, names.session)! };
}

const HOST = { session: '__Host-ventrical_session', oauth: '__Host-ventrical_oauth' };
const PLAIN = { session: 'ventrical_session', oauth: 'ventrical_oauth' };

describe('cookie names', () => {
  it('https publicUrl without cookieDomain defaults to __Host- names', async () => {
    const { start, cb, session } = await signIn(setup(), HOST);
    expect(setCookies(start).map((c) => c.name)).toEqual([HOST.oauth]);
    expect(session).toBeDefined();
    expect(setCookies(cb).map((c) => c.name)).toEqual([HOST.session, HOST.oauth]);
  });

  it('https with cookieDomain keeps the plain names (and the Domain attribute)', async () => {
    const { start, session, cb } = await signIn(setup({ cookieDomain: 'example.test' }), PLAIN);
    expect(setCookies(start).map((c) => c.name)).toEqual([PLAIN.oauth]);
    expect(session.attrs.domain).toBe('example.test');
    expect(setCookie(cb, PLAIN.oauth)!.attrs.domain).toBe('example.test');
  });

  it('http publicUrl keeps the plain names and no Secure', async () => {
    const auth = setup({ publicUrl: 'http://localhost:3000', frontendUrl: 'http://localhost:5173' });
    const { start, session } = await signIn(auth, PLAIN);
    expect(setCookies(start).map((c) => c.name)).toEqual([PLAIN.oauth]);
    expect(session.attrs.secure).toBeUndefined();
  });

  it('explicit cookieNames win per name, over every default', async () => {
    const both = await signIn(setup({ cookieNames: { session: 'my_s', oauth: 'my_o' } }), { session: 'my_s', oauth: 'my_o' });
    expect(both.session).toBeDefined();
    const partial = await signIn(setup({ cookieNames: { session: 'my_s' } }), { session: 'my_s', oauth: HOST.oauth });
    expect(partial.session).toBeDefined();
    const partialOauth = await signIn(setup({ cookieNames: { oauth: 'my_o' } }), { session: HOST.session, oauth: 'my_o' });
    expect(partialOauth.session).toBeDefined();
    const withDomain = await signIn(setup({ cookieDomain: 'example.test', cookieNames: { session: 'my_s' } }), { session: 'my_s', oauth: PLAIN.oauth });
    expect(withDomain.session).toBeDefined();
    const undef = await signIn(setup({ cookieNames: { session: undefined, oauth: undefined } }), HOST);
    expect(undef.session).toBeDefined();
  });

  it('__Host- cookies: Path=/, Secure, HttpOnly, SameSite=Lax and no Domain, on set and on clear', async () => {
    const auth = setup();
    const { start, cb, session } = await signIn(auth, HOST);
    const clearedOauth = setCookies(cb).find((c) => c.name === HOST.oauth)!;
    const logout = (await auth.handle(req('POST', '/auth/logout', { origin: FRONT, cookie: `${HOST.session}=${session.value}` })))!;
    const clearedSession = setCookie(logout, HOST.session)!;
    for (const c of [setCookie(start, HOST.oauth)!, session, clearedOauth, clearedSession]) {
      expect(c.attrs.path).toBe('/');
      expect(c.attrs.secure).toBe(true);
      expect(c.attrs.httponly).toBe(true);
      expect(c.attrs.samesite).toBe('Lax');
      expect(c.attrs.domain).toBeUndefined();
      expect(c.raw.toLowerCase()).not.toContain('domain');
    }
    expect(clearedOauth.attrs['max-age']).toBe('0');
    expect(clearedSession.attrs['max-age']).toBe('0');
    expect(clearedSession.value).toBe('');
  });

  it('an explicit __Host- name never gets a Domain, and is Secure, even when cookieDomain is set or the URL is http', () => {
    for (const secure of [true, false]) {
      for (const c of [
        serializeCookie('__Host-x', 'v', { maxAgeSec: 5, secure, domain: 'example.test' }),
        clearCookie('__Host-x', { maxAgeSec: 0, secure, domain: 'example.test' }),
      ]) {
        expect(c).toContain('Path=/');
        expect(c).toContain('Secure');
        expect(c).not.toMatch(/domain/i);
      }
    }
    expect(serializeCookie('plain', 'v', { maxAgeSec: 5, secure: false, domain: 'example.test' })).toContain('Domain=example.test');
  });

  it('a session refresh re-sets the __Host- cookie with the same attributes', async () => {
    let now = Date.now();
    const auth = setup({ clock: () => new Date(now) });
    const { session } = await signIn(auth, HOST);
    now += 2 * 864e5; // older than the 1-day refresh threshold
    const res = await auth.getSession(req('GET', '/me', { cookie: `${HOST.session}=${session.value}` }));
    const c = res!.setCookie!;
    expect(c.startsWith(`${HOST.session}=`)).toBe(true);
    expect(c).toContain('Path=/');
    expect(c).toContain('Secure');
    expect(c).not.toMatch(/domain/i);
  });

  it('full round trip over https with the __Host- names: start, callback, session, logout', async () => {
    const auth = setup();
    const { session } = await signIn(auth, HOST);
    const cookie = `${HOST.session}=${session.value}`;
    expect((await auth.getSession(req('GET', '/me', { cookie })))?.user.email).toBe('g1@example.test');
    // The old plain name is not a session.
    expect(await auth.getSession(req('GET', '/me', { cookie: `${PLAIN.session}=${session.value}` }))).toBeUndefined();
    const out = (await auth.handle(req('POST', '/auth/logout', { origin: FRONT, cookie })))!;
    expect(out.status).toBe(204);
    expect(setCookie(out, HOST.session)).toBeDefined();
    expect(await auth.getSession(req('GET', '/me', { cookie }))).toBeUndefined();
  });

  it('logout-everywhere clears the __Host- session cookie', async () => {
    const auth = setup();
    const { session } = await signIn(auth, HOST);
    const out = (await auth.handle(req('POST', '/auth/logout-everywhere', { origin: FRONT, cookie: `${HOST.session}=${session.value}` })))!;
    expect(out.status).toBe(204);
    const c = setCookie(out, HOST.session)!;
    expect(c.attrs['max-age']).toBe('0');
    expect(c.attrs.secure).toBe(true);
    expect(c.attrs.domain).toBeUndefined();
  });
});
