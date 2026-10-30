import { randomNonce, randomPKCECodeVerifier, randomState } from 'openid-client';
import {
  OAUTH_STATE_MAX_AGE_SEC, clearCookie, isSameOrigin, parseCookies, safeRedirect, sealOAuthState, serializeCookie,
  type CookieOptions,
} from './cookies.js';
import { hashToken } from './crypto.js';
import { AuthHttpError } from './errors.js';
import { PROVIDER_ORDER, createProviders, type AuthProvider } from './providers.js';
import { SESSION_TTL_MS, makeSessions, type SessionResult } from './session.js';
import type { AuthConfig, ProviderName } from './types.js';

export const DEFAULT_COOKIE_NAMES = { session: 'ventrical_session', oauth: 'ventrical_oauth' } as const;

export interface Auth {
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

export function createHandler<Tx>(config: AuthConfig<Tx>): Auth {
  const clock = config.clock ?? (() => new Date());
  const cookieNames = { ...DEFAULT_COOKIE_NAMES, ...config.cookieNames };
  const sessions = makeSessions({
    store: config.store,
    cookieNames,
    publicUrl: config.publicUrl,
    sessionTtlMs: config.sessionTtlMs ?? SESSION_TTL_MS,
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
    secure: config.publicUrl.startsWith('https'),
    ...(config.cookieDomain ? { domain: config.cookieDomain } : {}),
  });

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

  async function start(request: Request, url: URL, name: string): Promise<Response> {
    const provider = lookupProvider(name);
    const session = await sessions.getSession(request);
    const state = randomState();
    const codeVerifier = randomPKCECodeVerifier();
    const nonce = randomNonce();
    const authUrl = await provider.authorizeUrl(state, codeVerifier, nonce);
    const sealed = sealOAuthState({
      provider: provider.name, state, codeVerifier, nonce,
      redirect: safeRedirect(url.searchParams.get('redirect')),
      ...(session ? { linkUserId: session.user.id } : {}),
    }, config.encryptionKey);
    const headers = new Headers({ location: authUrl.toString(), 'cache-control': 'no-store' });
    headers.append('set-cookie', serializeCookie(cookieNames.oauth, sealed, cookieOpts(OAUTH_STATE_MAX_AGE_SEC)));
    if (session?.setCookie) headers.append('set-cookie', session.setCookie);
    return new Response(null, { status: 302, headers });
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
    try {
      const url = new URL(request.url);
      const path = url.pathname;
      const method = request.method.toUpperCase();
      if (method === 'GET' && path === '/auth/providers') {
        return json(200, { providers: PROVIDER_ORDER.filter((n) => Object.hasOwn(providers, n)) });
      }
      if (method === 'POST' && path === '/auth/logout') return await logout(request);
      if (method === 'POST' && path === '/auth/logout-everywhere') return await logoutEverywhere(request);
      const m = method === 'GET' ? /^\/auth\/([^/]+)\/start$/.exec(path) : null;
      if (m) return await start(request, url, decodeURIComponent(m[1]!));
      return undefined;
    } catch (err) {
      return errorResponse(err);
    }
  }

  return { handle, getSession: sessions.getSession, requireSession: sessions.requireSession };
}
