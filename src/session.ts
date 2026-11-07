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
/** Default absolute cap on a session's life, from its creation: 90 days. */
export const SESSION_MAX_AGE_MS = 90 * 24 * 60 * 60 * 1000;
/** A session with less than 29 days left is refreshed on use. */
export const REFRESH_BELOW_MS = 29 * 24 * 60 * 60 * 1000;

export interface SessionResult {
  user: SessionUser;
  id: string;
  /** When this session passed the second factor; null when it has not (or two-factor is off). */
  mfaVerifiedAt: Date | null;
  /** Present when the session was refreshed; the caller must send it as Set-Cookie. */
  setCookie?: string;
}

/** What a pending user must do: enter a code from their authenticator, or set one up first. */
export interface PendingSession {
  state: 'verify' | 'enroll';
}

/** A session held before the second factor passed. Never returned by getSession or requireSession. */
export interface PendingResolved extends PendingSession {
  id: string;
  idHash: string;
  user: SessionUser;
  createdAt: Date | undefined;
  expiresAt: Date;
  attempts: number;
  redirect: string | null;
}

export type Resolved = { kind: 'full'; session: SessionResult; idHash: string; createdAt: Date | undefined } | ({ kind: 'pending' } & PendingResolved);

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
  /** Present when `twoFactor` is configured. `requiredForAll` is `required === true`. */
  mfa?: { requiredForAll: boolean; pendingTtlMs: number };
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

  /** Cookie id, the stored row, and the absolute-cap check shared by every kind of session. */
  async function load(request: Request, now: Date) {
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
    return { id, idHash, found };
  }

  async function pendingState(userId: string): Promise<'verify' | 'enroll'> {
    const totp = await cfg.store.getTotp?.(userId);
    return totp && totp.confirmedAt !== null ? 'verify' : 'enroll';
  }

  /**
   * Resolves the cookie to a full session, a pending one, or nothing. A pending row is never reported as full, whether
   * or not twoFactor is configured, and with twoFactor configured a row whose pending flag the store did not report
   * (a boolean) is treated as signed out: unknown means closed.
   */
  async function resolve(request: Request, now: Date): Promise<Resolved | undefined> {
    const loaded = await load(request, now);
    if (!loaded) return undefined;
    const { id, idHash, found } = loaded;
    const user: SessionUser = { ...found.user, verifiedEmail: found.verifiedEmail ?? null };
    let pending = found.mfaPending === true;
    let expiresAt = found.expiresAt;
    if (cfg.mfa && typeof found.mfaPending !== 'boolean') return undefined;
    if (cfg.mfa && !pending && cfg.mfa.requiredForAll && !found.mfaVerifiedAt) {
      // required: true and this session never passed the second factor: hold it, with a pending life from now (never
      // longer than it already had). Written once; from then on it is an ordinary pending row.
      expiresAt = new Date(Math.min(found.expiresAt.getTime(), now.getTime() + cfg.mfa.pendingTtlMs));
      await cfg.store.markSessionPending?.(idHash, expiresAt);
      pending = true;
    }
    if (pending) {
      return {
        kind: 'pending', id, idHash, user, createdAt: found.createdAt, expiresAt,
        state: await pendingState(found.user.id), attempts: found.mfaAttempts ?? 0, redirect: found.mfaRedirect ?? null,
      };
    }
    const result: SessionResult = { user, id, mfaVerifiedAt: found.mfaVerifiedAt ?? null };
    if (found.expiresAt.getTime() - now.getTime() < REFRESH_BELOW_MS) {
      // A store without createdAt cannot be capped on refresh: the plain ttl applies.
      const next = found.createdAt ? expiryFor(now, found.createdAt) : new Date(now.getTime() + cfg.sessionTtlMs);
      // Near the cap there is nothing left to extend; do not rewrite the row or the cookie on every request.
      if (next.getTime() > found.expiresAt.getTime()) {
        await cfg.store.touchSession(idHash, next);
        result.setCookie = sessionCookie(id, next.getTime() - now.getTime());
      }
    }
    return { kind: 'full', session: result, idHash, createdAt: found.createdAt };
  }

  async function lookup(request: Request, now: Date): Promise<SessionResult | undefined> {
    const r = await resolve(request, now);
    return r?.kind === 'full' ? r.session : undefined;
  }

  async function getPendingSession(request: Request): Promise<PendingSession | undefined> {
    if (!cfg.mfa) return undefined;
    const r = await resolve(request, cfg.clock());
    return r?.kind === 'pending' ? { state: r.state } : undefined;
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

  return { getSession, requireSession, getPendingSession, resolve, readId, sessionCookie, clearSessionCookie, newExpiry, expiryFor };
}
