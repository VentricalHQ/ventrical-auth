import { clearCookie, parseCookies, serializeCookie, type CookieOptions } from './cookies.js';
import { hashToken, randomToken } from './crypto.js';
import { AuthHttpError, SUSPENDED_MESSAGE } from './errors.js';
import type { AuthStore, AuthUser } from './types.js';

/**
 * The session user. `email` is provider data that may be unverified: never use it for authorization, ownership or
 * matching. Only `verifiedEmail` (null unless the signing-in identity's email is verified) may be.
 */
export type SessionUser = AuthUser & { verifiedEmail: string | null };

/** Default session life: 30 days. */
export const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
/** A session with less than 29 days left is refreshed on use. */
/** Default absolute cap on a session's life, from its creation: 90 days. */
export const SESSION_MAX_AGE_MS = 90 * 24 * 60 * 60 * 1000;
export const REFRESH_BELOW_MS = 29 * 24 * 60 * 60 * 1000;

export interface SessionResult {
  user: SessionUser;
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
  sessionMaxAgeMs?: number;
  clock: () => Date;
}

export function makeSessions(cfg: SessionsConfig) {
  const maxAgeMs = cfg.sessionMaxAgeMs ?? SESSION_MAX_AGE_MS;
  /** Expiry for a session created at `createdAt`, if refreshed at `now`: never beyond createdAt + cap. */
  const expiryFor = (now: Date, createdAt: Date): Date =>
    new Date(Math.min(now.getTime() + cfg.sessionTtlMs, createdAt.getTime() + maxAgeMs));
  const opts = (maxAgeSec: number): CookieOptions => ({
    maxAgeSec,
    secure: new URL(cfg.publicUrl).protocol === 'https:',
    ...(cfg.cookieDomain ? { domain: cfg.cookieDomain } : {}),
  });

  /** Expiry of a session created now. */
  const newExpiry = (now: Date): Date => expiryFor(now, now);

  /** `lifeMs` is how long the cookie should live; default is a new session's life, min(ttl, cap). */
  function sessionCookie(id: string, lifeMs: number = Math.min(cfg.sessionTtlMs, maxAgeMs)): string {
    return serializeCookie(cfg.cookieNames.session, id, opts(Math.max(0, Math.floor(lifeMs / 1000))));
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
    if (found.createdAt && now.getTime() >= found.createdAt.getTime() + maxAgeMs) {
      // Past the absolute cap: signed out. Deleting is housekeeping, so a failure must not change the answer.
      await Promise.resolve(cfg.store.deleteSession(idHash)).catch(() => undefined);
      return undefined;
    }
    const result: SessionResult = { user: { ...found.user, verifiedEmail: found.verifiedEmail ?? null }, id };
    if (found.expiresAt.getTime() - now.getTime() < REFRESH_BELOW_MS) {
      // A store without createdAt cannot be capped on refresh: the plain ttl applies.
      const next = found.createdAt ? expiryFor(now, found.createdAt) : new Date(now.getTime() + cfg.sessionTtlMs);
      // Near the cap there is nothing left to extend; do not rewrite the row or the cookie on every request.
      if (next.getTime() > found.expiresAt.getTime()) {
        await cfg.store.touchSession(idHash, next);
        result.setCookie = sessionCookie(id, next.getTime() - now.getTime());
      }
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

  return { getSession, requireSession, sessionCookie, clearSessionCookie, newExpiry };
}
