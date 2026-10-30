import { randomNonce, randomPKCECodeVerifier, randomState } from 'openid-client';
import {
  OAUTH_STATE_MAX_AGE_SEC, clearCookie, isSameOrigin, openOAuthState, parseCookies, safeRedirect, sameString, sealOAuthState,
  serializeCookie, type CookieOptions,
} from './cookies.js';
import { hashToken } from './crypto.js';
import { normalizeEmail } from './email.js';
import { AuthHttpError, DuplicateIdentityError } from './errors.js';
import { PROVIDER_ORDER, createProviders, issOf, type AuthProvider } from './providers.js';
import { SESSION_TTL_MS, makeSessions, newSessionId, type SessionResult } from './session.js';
import type { AuthConfig, AuthErrorEvent, AuthUser, ProviderName, ProviderProfile } from './types.js';

const DEFAULT_ON_ERROR_TIMEOUT_MS = 2000;

export const DEFAULT_COOKIE_NAMES = { session: 'ventrical_session', oauth: 'ventrical_oauth' } as const;
export const HOST_COOKIE_NAMES = { session: '__Host-ventrical_session', oauth: '__Host-ventrical_oauth' } as const;

export interface Auth {
  /** The configured public base URL; adapters build request URLs from it, never from the Host header. */
  readonly publicUrl: string;
  handle(request: Request): Promise<Response | undefined>;
  getSession(request: Request): Promise<SessionResult | undefined>;
  requireSession(request: Request): Promise<SessionResult>;
}

function json(status: number, body: unknown, cookies: string[] = []): Response {
  const headers = new Headers({ 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  for (const c of cookies) headers.append('set-cookie', c);
  return new Response(JSON.stringify(body), { status, headers });
}

function errorResponse(err: unknown): Response {
  if (err instanceof AuthHttpError) {
    return json(err.status, { error: { code: err.code, message: err.message } });
  }
  // Anything else may carry secrets (provider bodies, SQL, tokens): no detail, nothing logged.
  return json(500, { error: { code: 'internal_error', message: 'Internal error' } });
}

/** A malformed percent-escape cannot name a provider; it falls through to not_found. */
function safeDecode(v: string): string {
  try {
    return decodeURIComponent(v);
  } catch {
    return '';
  }
}

const MAX_START_REDIRECT = 512;

/** Thrown inside the sign-in transaction to roll everything back and redirect to ?error=suspended. */
class SuspendedSignal extends Error {}

export function createHandler<Tx>(config: AuthConfig<Tx>): Auth {
  const clock = config.clock ?? (() => new Date());
  // __Host- names need https, Path=/ and no Domain, so they are the default only when cookieDomain is unset.
  const defaults = new URL(config.publicUrl).protocol === 'https:' && !config.cookieDomain ? HOST_COOKIE_NAMES : DEFAULT_COOKIE_NAMES;
  const cookieNames = {
    session: config.cookieNames?.session ?? defaults.session,
    oauth: config.cookieNames?.oauth ?? defaults.oauth,
  };
  const sessions = makeSessions({
    store: config.store,
    cookieNames,
    publicUrl: config.publicUrl,
    sessionTtlMs: config.sessionTtlMs ?? SESSION_TTL_MS,
    ...(config.sessionMaxAgeMs !== undefined ? { sessionMaxAgeMs: config.sessionMaxAgeMs } : {}),
    clock,
    ...(config.cookieDomain ? { cookieDomain: config.cookieDomain } : {}),
  });
  const providers: Partial<Record<ProviderName, AuthProvider>> = {
    ...createProviders({
      providers: config.providers, publicUrl: config.publicUrl, clock,
      ...(config.fetch ? { fetch: config.fetch } : {}),
      ...(config.userAgent ? { userAgent: config.userAgent } : {}),
    }),
    ...config.providerOverrides,
  };
  const cookieOpts = (maxAgeSec: number): CookieOptions => ({
    maxAgeSec,
    secure: new URL(config.publicUrl).protocol === 'https:',
    ...(config.cookieDomain ? { domain: config.cookieDomain } : {}),
  });

  /** Class name only, never the message. Anything that is not a named object yields no name. */
  const nameOf = (err: unknown): string | undefined => {
    const n = typeof err === 'object' && err !== null ? (err as { constructor?: { name?: unknown } }).constructor?.name : undefined;
    return typeof n === 'string' && n !== '' ? n : undefined;
  };
  const providerOf = (name: string): ProviderName | undefined =>
    (PROVIDER_ORDER as readonly string[]).includes(name) ? (name as ProviderName) : undefined;
  /** Whitelisted fields only. The hook is awaited but can neither throw into nor alter the response. */
  async function report(stage: string, code: string, provider?: ProviderName, err?: unknown): Promise<void> {
    const hook = config.hooks?.onError;
    if (!hook) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const errorName = err === undefined ? undefined : nameOf(err);
      const event: AuthErrorEvent = {
        stage, code,
        ...(provider !== undefined ? { provider } : {}),
        ...(errorName !== undefined ? { errorName } : {}),
      };
      // A sync throw lands in the catch below; a late rejection is absorbed so it can never go unhandled.
      const running = Promise.resolve(hook.call(config.hooks, event));
      running.catch(() => undefined);
      const timedOut = new Promise<void>((resolve) => { timer = setTimeout(resolve, config.onErrorTimeoutMs ?? DEFAULT_ON_ERROR_TIMEOUT_MS); });
      await Promise.race([running, timedOut]);
    } catch {
      // Swallowed: the package logs nothing.
    } finally {
      if (timer !== undefined) clearTimeout(timer);
    }
  }
  /** Reports a thrown error and turns it into the response. not_found and invalid_state are attacker-triggerable noise and are not reported. */
  async function fail(stage: string, err: unknown, provider?: ProviderName): Promise<Response> {
    const code = err instanceof AuthHttpError ? err.code : 'internal_error';
    if (code !== 'not_found' && code !== 'invalid_state') await report(stage, code, provider, err);
    return errorResponse(err);
  }

  const lookupProvider = (name: string): AuthProvider => {
    const p = Object.hasOwn(providers, name) ? providers[name as ProviderName] : undefined;
    if (p) return p;
    if ((PROVIDER_ORDER as readonly string[]).includes(name)) {
      throw new AuthHttpError(404, 'provider_disabled', 'This sign-in provider is not configured');
    }
    throw new AuthHttpError(404, 'not_found', 'Not found');
  };

  const requireSameOrigin = (request: Request): void => {
    if (!isSameOrigin(request, config.frontendUrl, config.publicUrl)) {
      throw new AuthHttpError(403, 'forbidden', 'Cross-origin request rejected');
    }
  };

  /** The /start redirect is capped so the state cookie stays small; hook paths are not capped here. */
  const startRedirect = (v: string | null): string => (v !== null && v.length > MAX_START_REDIRECT ? '/' : safeRedirect(v));

  async function start(request: Request, url: URL, name: string): Promise<Response> {
    const provider = lookupProvider(name);
    const session = await sessions.getSession(request);
    const state = randomState();
    const codeVerifier = randomPKCECodeVerifier();
    const nonce = randomNonce();
    const authUrl = await provider.authorizeUrl(state, codeVerifier, nonce);
    const sealed = sealOAuthState({
      provider: provider.name, state, codeVerifier, nonce,
      redirect: startRedirect(url.searchParams.get('redirect')),
      iat: clock().getTime(),
      ...(session ? { linkUserId: session.user.id } : {}),
    }, config.encryptionKey);
    const headers = new Headers({ location: authUrl.toString(), 'cache-control': 'no-store' });
    headers.append('set-cookie', serializeCookie(cookieNames.oauth, sealed, cookieOpts(OAUTH_STATE_MAX_AGE_SEC)));
    if (session?.setCookie) headers.append('set-cookie', session.setCookie);
    return new Response(null, { status: 302, headers });
  }

  const trimSlash = (u: string): string => u.replace(/\/+$/, '');
  const redirectTo = (location: string, cookies: string[] = []): Response => {
    // new URL percent-encodes non-ASCII paths; a Location must never throw (this runs after the commit).
    let href: string;
    try {
      href = new URL(location).href;
    } catch {
      href = `${trimSlash(config.frontendUrl)}/`;
    }
    const headers = new Headers({ location: href, 'cache-control': 'no-store' });
    for (const c of cookies) headers.append('set-cookie', c);
    return new Response(null, { status: 302, headers });
  };

  /** Never trusts the request's Host: only the configured frontendUrl and publicUrl build locations. */
  function resolveTarget(savedRedirect: string): string {
    const path = safeRedirect(savedRedirect);
    const r = config.hooks?.resolveRedirect?.(path) ?? { target: 'frontend' as const, path };
    const base = r.target === 'backend' ? config.publicUrl : config.frontendUrl;
    return trimSlash(base) + safeRedirect(r.path);
  }

  async function callback(request: Request, url: URL, name: string, ctx: { stage: string }): Promise<Response> {
    const provider = lookupProvider(name);
    const saved = openOAuthState(parseCookies(request.headers.get('cookie'))[cookieNames.oauth], config.encryptionKey);
    const state = url.searchParams.get('state') ?? '';
    // Strictly older than the cookie's life is stale (exactly at the limit still passes); a future iat is forged.
    const age = saved ? clock().getTime() - saved.iat : 0;
    if (!saved || age < 0 || age > OAUTH_STATE_MAX_AGE_SEC * 1000 || saved.provider !== provider.name || !sameString(saved.state, state)) {
      throw new AuthHttpError(400, 'invalid_state', 'Invalid or expired sign-in state');
    }
    const code = url.searchParams.get('code');
    if (url.searchParams.has('error') || !code) throw new AuthHttpError(400, 'oauth_error', 'Sign-in failed');
    let raw: ProviderProfile;
    try {
      raw = await provider.exchange(code, saved.codeVerifier, { state: saved.state, nonce: saved.nonce ?? '', ...issOf(url.searchParams) });
    } catch (err) {
      // Provider errors can embed codes, tokens or response bodies: drop them entirely (only the class name is reported).
      await report(ctx.stage, 'exchange_failed', provider.name, err);
      return errorResponse(new AuthHttpError(400, 'oauth_error', 'Sign-in failed'));
    }
    // Normalised once (trim, then lowercase) before any comparison or storage; empty after trimming means no email.
    const email = raw.email !== undefined ? normalizeEmail(raw.email) : undefined;
    const profile: ProviderProfile = {
      subject: raw.subject, emailVerified: raw.emailVerified === true,
      ...(email !== undefined ? { email } : {}),
      ...(raw.name !== undefined ? { name: raw.name } : {}),
    };
    const target = resolveTarget(saved.redirect);
    const front = trimSlash(config.frontendUrl);
    const signinError = async (reason: string, err?: unknown) => {
      await report(ctx.stage, reason, provider.name, err);
      return redirectTo(`${front}/signin?error=${encodeURIComponent(reason)}`);
    };
    const identity = {
      provider: provider.name, subject: profile.subject, emailVerified: profile.emailVerified,
      ...(profile.email !== undefined ? { email: profile.email } : {}),
    };

    // Linking needs the same session that began the flow (bound at /start) to still be current.
    const current = await sessions.getSession(request);
    if (current && saved.linkUserId === current.user.id) {
      ctx.stage = 'link';
      const linkError = async (reason: string) => {
        await report(ctx.stage, reason, provider.name);
        return redirectTo(`${front}/settings?error=${reason}`);
      };
      let linkDuplicate = false;
      let linkSuspended = false;
      const owner = await config.store.transaction(async (tx) => {
        const existing = await config.store.findUserByIdentity(provider.name, profile.subject, tx);
        if (!existing) {
          // A verified email that belongs to a suspended user cannot be attached to another account (authoritative, locked).
          if (profile.emailVerified && profile.email !== undefined && (await config.store.emailBelongsToSuspendedUser(profile.email, tx))) {
            throw new SuspendedSignal();
          }
          await config.store.linkIdentity(current.user.id, identity, tx);
        }
        return existing;
      }).catch(async (err: unknown) => {
        if (err instanceof SuspendedSignal) { linkSuspended = true; return undefined; }
        if (!(err instanceof DuplicateIdentityError)) throw err;
        linkDuplicate = true; // the transaction was abandoned; look again outside it
        return config.store.findUserByIdentity(provider.name, profile.subject);
      });
      if (linkSuspended) return await linkError('suspended');
      if (owner && owner.id !== current.user.id) {
        await report(ctx.stage, 'identity_in_use', provider.name);
        return redirectTo(`${front}/settings?error=identity_in_use`);
      }
      if (linkDuplicate && !owner) return await linkError('link_failed');
      return redirectTo(target, current.setCookie ? [current.setCookie] : []);
    }

    // Signed out, or the session changed since /start: sign in or create. Never link by email.
    let existing = await config.store.findUserByIdentity(provider.name, profile.subject);
    const suspendedEmail = !existing && profile.emailVerified && profile.email !== undefined ? profile.email : undefined;
    if (suspendedEmail !== undefined && (await config.store.emailBelongsToSuspendedUser(suspendedEmail))) {
      return await signinError('suspended');
    }
    if (!existing && config.hooks?.canCreateAccount) {
      const verdict = await config.hooks.canCreateAccount({ ...profile, provider: provider.name });
      if (!verdict.allow) return await signinError(verdict.reason);
    }

    const { id, idHash } = newSessionId();
    const signedInAt = clock();
    const expiresAt = sessions.newExpiry(signedInAt);
    const attempt = (found: Awaited<ReturnType<typeof config.store.findUserByIdentity>>) => config.store.transaction(async (tx) => {
      let user: AuthUser | undefined = found && { id: found.id, email: found.email, name: found.name };
      let isNew = false;
      // Every sign-in, new or returning: a verified email that belongs to a suspended user (another account's row; the
      // signing-in user's own row is ignored) refuses the sign-in. Authoritative: locked, same tx as the writes below.
      if (profile.emailVerified && profile.email !== undefined
        && (await config.store.emailBelongsToSuspendedUser(profile.email, tx, found ? { exceptUserId: found.id } : undefined))) {
        throw new SuspendedSignal();
      }
      if (found && user && config.store.updateIdentity && profile.email !== undefined && found.identity
        && (found.identity.email !== profile.email || found.identity.emailVerified !== profile.emailVerified)) {
        // Returning user whose provider email changed: keep the stored identity current (it feeds the suspended-email
        // check). Same tx, so it commits or rolls back with the sign-in; a retry re-reads the identity and is idempotent.
        // A profile without an email never clears the stored one.
        await config.store.updateIdentity(provider.name, profile.subject, { email: profile.email, emailVerified: profile.emailVerified }, tx);
      }
      if (!user) {
        user = await config.store.createUserWithIdentity({ ...identity, ...(profile.name !== undefined ? { name: profile.name } : {}) }, tx);
        isNew = true;
      }
      // The request's old session (a valid one that is not the new one) goes with this sign-in: same tx, so a suspended
      // refusal below rolls the delete back and the person keeps it. Not done on the link path.
      if (current) {
        const oldHash = hashToken(current.id);
        if (oldHash !== idHash) await config.store.deleteSession(oldHash, tx);
      }
      const ok = await config.store.createSessionUnlessSuspended(user.id, idHash, expiresAt, { provider: provider.name, subject: profile.subject }, tx);
      if (!ok) throw new SuspendedSignal();
      // After the session row exists, so a suspended person never reaches the hook's non-transaction side effects. If the
      // hook throws, the whole tx (user, session, old-session delete) rolls back.
      await config.hooks?.afterSignIn?.({ user, profile, provider: provider.name, isNew, tx });
    });
    try {
      try {
        await attempt(existing);
      } catch (err) {
        if (!(err instanceof DuplicateIdentityError)) throw err;
        // Lost a race to create the same identity. The transaction was abandoned: re-run it once as a whole,
        // now finding that identity and continuing as a returning user. A second failure is sign_in_failed.
        existing = await config.store.findUserByIdentity(provider.name, profile.subject);
        if (!existing) throw err;
        await attempt(existing);
      }
    } catch (err) {
      return err instanceof SuspendedSignal ? await signinError('suspended') : await signinError('sign_in_failed', err);
    }
    // Only after the transaction has committed.
    return redirectTo(target, [sessions.sessionCookie(id, expiresAt.getTime() - signedInAt.getTime())]);
  }

  async function callbackRoute(request: Request, url: URL, name: string): Promise<Response> {
    const ctx = { stage: 'callback' };
    let res: Response;
    try {
      res = await callback(request, url, name, ctx);
    } catch (err) {
      res = await fail(ctx.stage, err, providerOf(name));
    }
    // The state cookie is single-use: cleared on every path, errors included, so a replay fails with invalid_state.
    res.headers.append('set-cookie', clearCookie(cookieNames.oauth, cookieOpts(0)));
    return res;
  }

  async function logout(request: Request): Promise<Response> {
    requireSameOrigin(request);
    const id = parseCookies(request.headers.get('cookie'))[cookieNames.session];
    if (id) await config.store.deleteSession(hashToken(id));
    return new Response(null, { status: 204, headers: { 'set-cookie': sessions.clearSessionCookie() } });
  }

  async function logoutEverywhere(request: Request): Promise<Response> {
    requireSameOrigin(request);
    const { user } = await sessions.requireSession(request);
    await config.store.transaction(async (tx) => {
      await config.hooks?.onLogoutEverywhere?.(user.id, tx);
      await config.store.deleteSessionsForUser(user.id, tx);
    });
    return new Response(null, { status: 204, headers: { 'set-cookie': sessions.clearSessionCookie() } });
  }

  async function handle(request: Request): Promise<Response | undefined> {
    let stage = 'request';
    let provider: ProviderName | undefined;
    try {
      const url = new URL(request.url);
      const path = url.pathname;
      const method = request.method.toUpperCase();
      if (method === 'GET' && path === '/auth/providers') {
        return json(200, { providers: PROVIDER_ORDER.filter((n) => Object.hasOwn(providers, n)) });
      }
      if (method === 'POST' && (path === '/auth/logout' || path === '/auth/logout-everywhere')) stage = 'logout';
      if (method === 'POST' && path === '/auth/logout') return await logout(request);
      if (method === 'POST' && path === '/auth/logout-everywhere') return await logoutEverywhere(request);
      const m = method === 'GET' ? /^\/auth\/([^/]+)\/start$/.exec(path) : null;
      if (m) {
        stage = 'start';
        provider = providerOf(safeDecode(m[1]!));
        return await start(request, url, safeDecode(m[1]!));
      }
      const cb = method === 'GET' ? /^\/auth\/([^/]+)\/callback$/.exec(path) : null;
      if (cb) return await callbackRoute(request, url, safeDecode(cb[1]!));
      return undefined;
    } catch (err) {
      return await fail(stage, err, provider);
    }
  }

  return { publicUrl: config.publicUrl, handle, getSession: sessions.getSession, requireSession: sessions.requireSession };
}
