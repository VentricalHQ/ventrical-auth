import { clearCookie, parseCookies, serializeCookie, type CookieOptions } from './cookies.js';
import { hashToken, randomToken } from './crypto.js';
import { AuthHttpError, SUSPENDED_MESSAGE } from './errors.js';
import type { AuthStore, AuthUser } from './types.js';

/** Default session life: 30 days. */
export const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
/** A session with less than 29 days left is refreshed on use. */
export const REFRESH_BELOW_MS = 29 * 24 * 60 * 60 * 1000;

export interface SessionResult {
  user: AuthUser;
  id: string;
  /** Present when the session was refreshed; the caller must send it as Set-Cookie. */
  setCookie?: string;
}

export function newSessionId(): { id: string; idHash: string } {
  const id = randomToken();
  return { id, idHash: hashToken(id) };
}

export interface SessionsConfig {
  store: AuthStore<any>;
  cookieNames: { session: string; oauth: string };
  cookieDomain?: string;
  publicUrl: string;
  sessionTtlMs: number;
  clock: () => Date;
}

export function makeSessions(cfg: SessionsConfig) {
  const opts = (maxAgeSec: number): CookieOptions => ({
    maxAgeSec,
    secure: cfg.publicUrl.startsWith('https'),
    ...(cfg.cookieDomain ? { domain: cfg.cookieDomain } : {}),
  });

  function sessionCookie(id: string): string {
    return serializeCookie(cfg.cookieNames.session, id, opts(cfg.sessionTtlMs / 1000));
  }

  function clearSessionCookie(): string {
    return clearCookie(cfg.cookieNames.session, opts(0));
  }

  function readId(request: Request): string | undefined {
    return parseCookies(request.headers.get('cookie'))[cfg.cookieNames.session] || undefined;
  }

  async function lookup(request: Request, now: Date): Promise<SessionResult | undefined> {
    const id = readId(request);
    if (!id) return undefined;
    const idHash = hashToken(id);
    const found = await cfg.store.getSessionWithExpiry(idHash, now);
    if (!found) return undefined;
    const result: SessionResult = { user: found.user, id };
    if (found.expiresAt.getTime() - now.getTime() < REFRESH_BELOW_MS) {
      await cfg.store.touchSession(idHash, new Date(now.getTime() + cfg.sessionTtlMs));
      result.setCookie = sessionCookie(id);
    }
    return result;
  }

  async function getSession(request: Request): Promise<SessionResult | undefined> {
    return lookup(request, cfg.clock());
  }

  async function requireSession(request: Request): Promise<SessionResult> {
    const now = cfg.clock();
    const s = await lookup(request, now);
    if (s) return s;
    // Read-only: a tombstone of a currently suspended user only picks the error code.
    const id = readId(request);
    if (id && cfg.store.isSuspendedCredential && (await cfg.store.isSuspendedCredential(hashToken(id), now))) {
      throw new AuthHttpError(403, 'account_suspended', SUSPENDED_MESSAGE);
    }
    throw new AuthHttpError(401, 'unauthenticated', 'Sign in required');
  }

  return { getSession, requireSession, sessionCookie, clearSessionCookie };
}
