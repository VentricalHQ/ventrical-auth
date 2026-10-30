import type { AuthProvider } from './providers.js';

export type ProviderName = 'google' | 'microsoft' | 'github';

export interface ProviderProfile {
  subject: string;
  email?: string;
  emailVerified: boolean;
  name?: string;
}

export interface AuthUser {
  id: string;
  email: string | null;
  name: string | null;
}

export interface NewIdentity {
  provider: ProviderName;
  subject: string;
  email?: string;
  emailVerified: boolean;
}

/** The stored email and verified flag of one identity. `email` is null or absent when none is stored. */
export interface StoredIdentityEmail {
  email?: string | null;
  emailVerified: boolean;
}

export interface AuthStore<Tx = unknown> {
  transaction<T>(fn: (tx: Tx) => Promise<T>): Promise<T>;
  /**
   * `identity` carries the identity's stored email and verified flag. Optional for compatibility: when a store omits
   * it, the handler cannot tell whether the email changed and does not refresh it.
   */
  findUserByIdentity(
    provider: ProviderName,
    subject: string,
    tx?: Tx,
  ): Promise<(AuthUser & { identity?: StoredIdentityEmail }) | undefined>;
  /**
   * Must throw DuplicateIdentityError when (provider, subject) already exists. The handler then abandons the
   * transaction (it rolls back entirely) and re-runs it once, so no savepoint is needed.
   */
  createUserWithIdentity(p: NewIdentity & { name?: string }, tx?: Tx): Promise<AuthUser>;
  linkIdentity(userId: string, identity: NewIdentity, tx?: Tx): Promise<void>;
  /**
   * Verified identity emails only, case-insensitive. When given a tx it must hold FOR SHARE (or an equivalent lock)
   * on the matching user rows, so a suspension cannot slip in before the transaction commits.
   */
  emailBelongsToSuspendedUser(email: string, tx?: Tx): Promise<boolean>;
  /** Holds the user row FOR SHARE; returns false when the user is suspended. */
  createSessionUnlessSuspended(
    userId: string,
    idHash: string,
    expiresAt: Date,
    identity: { provider: string; subject: string },
    tx: Tx,
  ): Promise<boolean>;
  /** Excludes suspended users. */
  getSessionWithExpiry(
    idHash: string,
    now: Date,
  ): Promise<
    | {
        user: AuthUser;
        expiresAt: Date;
        identity?: { provider: string; subject: string };
        /**
         * When the session row was created (sessions.created_at). Optional: a store that omits it skips the
         * `sessionMaxAgeMs` cap for its sessions.
         */
        createdAt?: Date;
        /**
         * The stored email of the identity the session was created with, when that identity is verified; null when the
         * session has no identity, the identity is unverified, or it has no email. Optional so existing custom stores
         * keep compiling: an omitted value is treated as null.
         */
        verifiedEmail?: string | null;
      }
    | undefined
  >;
  touchSession(idHash: string, expiresAt: Date): Promise<void>;
  /** With a tx the delete commits or rolls back with it. */
  deleteSession(idHash: string, tx?: Tx): Promise<void>;
  deleteSessionsForUser(userId: string, tx?: Tx): Promise<number>;
  /**
   * Optional. Updates the stored email and email_verified of an existing identity. `email` undefined leaves the
   * email unchanged, null clears it. A no-op when the identity does not exist. The handler calls it inside the
   * sign-in transaction of a returning user whose provider email or verified flag changed.
   */
  updateIdentity?(
    provider: ProviderName,
    subject: string,
    update: { email?: string | null; emailVerified: boolean },
    tx?: Tx,
  ): Promise<void>;
  /**
   * Deletes every session with expires_at <= now and returns how many were removed. With `opts.maxAgeMs` it also
   * deletes sessions with created_at + maxAgeMs <= now.
   */
  purgeExpiredSessions(now: Date, opts?: { maxAgeMs?: number }): Promise<number>;
  isSuspendedCredential?(idHash: string, now: Date): Promise<boolean>;
}

export type CanCreateResult = { allow: true } | { allow: false; reason: string };

/**
 * Passed to hooks.onError for every non-success outcome. Built from a fixed whitelist: it never holds a message,
 * stack, token, auth code, JWKS or response body, only the error class name.
 *
 * stage: 'start' (GET /auth/:provider/start), 'callback' (GET /auth/:provider/callback, sign-in), 'link' (the same
 *   callback when it completes an account link for a signed-in user; it can report identity_in_use, link_failed, suspended, internal_error), 'logout' (POST /auth/logout and /auth/logout-everywhere).
 * code: an AuthHttpError code (oauth_error, provider_disabled, forbidden, unauthenticated, account_suspended),
 *   'exchange_failed' (code exchange or ID-token verification threw), 'suspended', 'sign_in_failed', 'identity_in_use',
 *   'link_failed', 'internal_error' (unexpected throw), or the canCreateAccount deny reason.
 *   invalid_state (a missing, forged, replayed or expired state cookie) and not_found are never reported: anyone can trigger them.
 *   A canCreateAccount reason is also placed in the sign-in redirect URL (?error=), so it must be a short code and
 *   must not embed PII (no emails, names or ids).
 * 'request' is the fallback stage for a failure that happens before the route is recognised (for example a
 *   malformed request URL).
 */
export interface AuthErrorEvent {
  stage: string;
  code: string;
  provider?: ProviderName;
  /** The error class name only, when an error was involved. */
  errorName?: string;
}

export interface AuthHooks<Tx = unknown> {
  /**
   * Observes failures. A throwing or rejecting hook is swallowed and never changes the response.
   * It is awaited before the response is returned, but for at most `onErrorTimeoutMs` (default 2000): after that the
   * response goes out anyway and the hook's eventual result, including a rejection, is ignored. Keep it fast.
   */
  onError?(event: AuthErrorEvent): void | Promise<void>;
  canCreateAccount?(profile: ProviderProfile & { provider: ProviderName }): Promise<CanCreateResult>;
  /**
   * Runs inside the sign-in transaction. It may run twice if a duplicate-identity race
   * retries the transaction, so side effects must be done through `tx`.
   */
  afterSignIn?(ctx: {
    user: AuthUser;
    profile: ProviderProfile;
    provider: ProviderName;
    isNew: boolean;
    tx: Tx;
  }): Promise<void>;
  resolveRedirect?(path: string): { target: 'backend' | 'frontend'; path: string };
  onLogoutEverywhere?(userId: string, tx: Tx): Promise<void>;
}

export interface AuthConfig<Tx = unknown> {
  providers: {
    google?: { clientId: string; clientSecret: string };
    microsoft?: { clientId: string; clientSecret: string; tenant: string };
    github?: { clientId: string; clientSecret: string };
  };
  publicUrl: string;
  frontendUrl: string;
  encryptionKey: Buffer;
  store: AuthStore<Tx>;
  hooks?: AuthHooks<Tx>;
  /**
   * Per-name overrides. Defaults: `__Host-ventrical_session` / `__Host-ventrical_oauth` when publicUrl is https and
   * cookieDomain is unset (Secure, Path=/, no Domain); otherwise `ventrical_session` / `ventrical_oauth`.
   */
  cookieNames?: { session?: string; oauth?: string };
  /** Setting it switches the default cookie names back to the plain ones (a __Host- cookie cannot carry a Domain). */
  cookieDomain?: string;
  sessionTtlMs?: number;
  /**
   * Absolute cap on a session's life, counted from its creation; refresh never extends past it. Positive, finite;
   * default 90 days.
   */
  sessionMaxAgeMs?: number;
  /** Longest the handler waits for hooks.onError before responding anyway. Positive, finite; default 2000. */
  onErrorTimeoutMs?: number;
  clock?: () => Date;
  fetch?: typeof fetch;
  userAgent?: string;
  /**
   * TEST-ONLY seam: replaces (or adds) providers by name so tests can run without network.
   * Not part of the supported public API; never set it in production.
   */
  providerOverrides?: Partial<Record<ProviderName, AuthProvider>>;
}
