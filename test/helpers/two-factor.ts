import { createAuth, type AuthConfig, type AuthErrorEvent, type ProviderName, type ProviderProfile, type TwoFactorConfig } from '../../src/index.js';
import { base32Encode } from '../../src/base32.js';
import { encrypt, hashToken } from '../../src/crypto.js';
import { hotp, totpStep, generateTotpSecret } from '../../src/totp.js';
import { totpAad } from '../../src/twofactor.js';
import { fakeProvider } from './fake-provider.js';
import { createMemoryStore, type MemoryStore, type MemoryTx } from './memory-store.js';
import { req, setCookie, setCookies } from './request.js';

export const KEY = Buffer.alloc(32, 7);
export const FRONT = 'https://app.example.test';
export const PUBLIC = 'https://api.example.test';
export const SESSION_COOKIE = '__Host-ventrical_session';
export const START = new Date('2026-03-01T12:00:00Z');

export const profile = (subject = 'g1', over: Partial<ProviderProfile> = {}): ProviderProfile =>
  ({ subject, emailVerified: true, email: `${subject}@example.test`, ...over });

export interface TfOptions {
  twoFactor?: Partial<TwoFactorConfig> | false;
  profiles?: Partial<Record<ProviderName, ProviderProfile | Error>>;
  config?: Partial<AuthConfig<MemoryTx>>;
  store?: MemoryStore;
}

/** A mutable clock shared by the handler and the store, plus everything tests need to drive the 2FA flow. */
export function tfSetup(o: TfOptions = {}) {
  const clock = { now: new Date(START) };
  const now = () => new Date(clock.now);
  const store = o.store ?? createMemoryStore(now);
  const events: AuthErrorEvent[] = [];
  const profiles = o.profiles ?? { google: profile('g1') };
  const overrides: Partial<Record<ProviderName, ReturnType<typeof fakeProvider>>> = {};
  for (const [n, p] of Object.entries(profiles)) overrides[n as ProviderName] = fakeProvider(n as ProviderName, p!);
  const auth = createAuth<MemoryTx>({
    providers: { google: { clientId: 'fake-id', clientSecret: 'fake-secret' }, github: { clientId: 'fake-id', clientSecret: 'fake-secret' } },
    publicUrl: PUBLIC, frontendUrl: FRONT, encryptionKey: KEY, store, providerOverrides: overrides, clock: now,
    ...(o.twoFactor === false ? {} : { twoFactor: { issuer: 'TrueMark', ...o.twoFactor } }),
    ...o.config,
    hooks: { ...o.config?.hooks, onError: (e) => { events.push(e); } },
  });

  /**
   * Sign-in via /start then the callback. `cookie` is an existing session cookie sent to the callback only (a different
   * sign-in from the same browser); `startCookie` is sent to /start (which binds an account link when it is a full session).
   */
  async function signIn(provider: ProviderName = 'google', opts: { cookie?: string; startCookie?: string; redirect?: string } = {}) {
    const start = (await auth.handle(req('GET', `/auth/${provider}/start${opts.redirect ? `?redirect=${encodeURIComponent(opts.redirect)}` : ''}`, opts.startCookie ? { cookie: opts.startCookie } : {})))!;
    const oauth = `__Host-ventrical_oauth=${encodeURIComponent(setCookie(start, '__Host-ventrical_oauth')!.value)}`;
    const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
    const res = (await auth.handle(req('GET', `/auth/${provider}/callback?code=c&state=${encodeURIComponent(state)}`, { cookie: [oauth, opts.cookie].filter(Boolean).join('; ') })))!;
    const sc = setCookie(res, SESSION_COOKIE);
    return { res, location: res.headers.get('location'), cookie: sc && sc.value !== '' ? `${SESSION_COOKIE}=${encodeURIComponent(sc.value)}` : undefined, setCookie: sc };
  }

  /** A same-origin POST (JSON body) to an auth route. */
  async function post(path: string, body: unknown, cookie?: string, extra: { origin?: string | null; raw?: string } = {}) {
    const headers: Record<string, string> = { 'content-type': 'application/json' };
    if (cookie) headers.cookie = cookie;
    if (extra.origin !== null) headers.origin = extra.origin ?? FRONT;
    const res = (await auth.handle(new Request(new URL(path, PUBLIC), {
      method: 'POST', headers, body: extra.raw ?? JSON.stringify(body), redirect: 'manual',
    })))!;
    return { res, status: res.status, json: (await res.clone().json().catch(() => undefined)) as Record<string, any> | undefined };
  }

  const get = async (path: string, cookie?: string) => {
    const res = (await auth.handle(req('GET', path, cookie ? { cookie } : {})))!;
    return { res, status: res.status, json: (await res.clone().json().catch(() => undefined)) as Record<string, any> | undefined };
  };

  /** Enrols a user directly in the store with a known secret; the confirming step is far in the past. */
  async function enrol(subject = 'g1', opts: { recoveryCodes?: string[]; email?: string } = {}) {
    const existing = await store.findUserByIdentity('google', subject);
    const user = existing ?? await store.createUserWithIdentity({ provider: 'google', subject, email: opts.email ?? `${subject}@example.test`, emailVerified: true });
    const secret = generateTotpSecret();
    const enc = encrypt(base32Encode(secret), KEY, totpAad(user.id));
    await store.setPendingTotpSecret(user.id, enc, now());
    await store.confirmTotp(user.id, { expectedPendingEnc: enc, step: 0, now: now(), recoveryCodeHashes: (opts.recoveryCodes ?? []).map(hashToken) });
    return { user, secret };
  }

  /** The code for the clock's current step, shifted by `offset` steps. */
  const codeFor = (secret: Uint8Array, offset = 0) => hotp(secret, totpStep(clock.now.getTime()) + offset);
  const advance = (ms: number) => { clock.now = new Date(clock.now.getTime() + ms); };
  /** Moves the clock to the next step so a fresh code (not the previous one) is valid. */
  const nextStep = () => advance(30_000);

  return { auth, store, clock, events, signIn, post, get, enrol, codeFor, advance, nextStep };
}

export type Tf = ReturnType<typeof tfSetup>;
export { req, setCookie, setCookies };
