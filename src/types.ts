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
   * Verified identity emails only; the argument is trimmed and lowercased before comparing. When given a tx it must hold FOR SHARE (or an equivalent lock)
   * on the matching user rows, so a suspension cannot slip in before the transaction commits.
   * With `opts.exceptUserId`, that user's own rows are not locked or counted by this check; the other matching rows
   * are still locked. It does not let a suspended user in: their own sign-in is refused because createSessionUnlessSuspended returns false.
   */
  emailBelongsToSuspendedUser(email: string, tx?: Tx, opts?: { exceptUserId?: string }): Promise<boolean>;
  /** Holds the user row FOR SHARE; returns false when the user is suspended. */
  createSessionUnlessSuspended(
    userId: string,
    idHash: string,
    expiresAt: Date,
    identity: { provider: string; subject: string },
    tx: Tx,
    /**
     * Two-factor sign-in. With `pending`, the row is stored as a pending session (mfa_pending, mfa_redirect = redirect).
     * A store that ignores it would let a usable session exist before the second factor, so createAuth requires the
     * 2FA store methods when `twoFactor` is configured and the handler checks the stored row is pending.
     */
    opts?: { pending?: { expiresAt: Date; redirect?: string } },
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
        /** Required of a store used with `twoFactor`: whether the row is a pending session (second factor not yet passed). */
        mfaPending?: boolean;
        /** When the second factor passed for this session; null if it has not. */
        mfaVerifiedAt?: Date | null;
        /** Wrong codes counted against this pending session. */
        mfaAttempts?: number;
        /** The path saved at sign-in, kept on a pending session until verify or enrolment completes. */
        mfaRedirect?: string | null;
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

  // Two-factor methods. All optional so existing custom stores keep compiling; createAuth throws at startup when
  // `twoFactor` is configured and any is missing. Each one marked atomic must be a single conditional write.

  /** The user's TOTP record, or undefined when none exists. */
  getTotp?(userId: string, tx?: Tx): Promise<TotpRecord | undefined>;
  /** Creates or replaces the unconfirmed secret (encrypted). Never touches a confirmed secret. */
  setPendingTotpSecret?(userId: string, secretEnc: string, now: Date, tx?: Tx): Promise<void>;
  /**
   * Atomic. Promotes the pending secret to the active one only if it still equals `expectedPendingEnc`: sets
   * confirmed_at = now, last_step = step, clears failures and the lock, and replaces the recovery codes with
   * `recoveryCodeHashes`. Returns false (changing nothing) when the pending secret is missing or different.
   */
  confirmTotp?(
    userId: string,
    p: { expectedPendingEnc: string; step: number; now: Date; recoveryCodeHashes: string[] },
    tx?: Tx,
  ): Promise<boolean>;
  /** Removes the TOTP record and every recovery code. */
  deleteTotp?(userId: string, tx?: Tx): Promise<void>;
  /**
   * Atomic. Sets last_step = step only when the user is enrolled, `step` is greater than last_step, and the user is
   * not locked at `now`. Returns whether it did: of two requests with the same valid code exactly one gets true.
   */
  consumeTotpStep?(userId: string, step: number, now: Date, tx?: Tx): Promise<boolean>;
  /**
   * Atomic. Counts one wrong code. A lock that has expired starts a new count. On reaching `maxAttempts` the user is
   * locked until now + lockoutMs and the count restarts. Returns the lock state afterwards.
   */
  recordTotpFailure?(
    userId: string,
    p: { maxAttempts: number; lockoutMs: number; now: Date },
    tx?: Tx,
  ): Promise<{ locked: boolean; lockedUntil: Date | null }>;
  /** Clears the failure count and any lock. */
  resetTotpFailures?(userId: string, tx?: Tx): Promise<void>;
  /**
   * Atomic single use: true for exactly one caller per unused code, false for an unknown or used one, and false while
   * the user is locked at `now`.
   */
  consumeRecoveryCode?(userId: string, codeHash: string, now: Date, tx?: Tx): Promise<boolean>;
  /** Replaces all of the user's recovery codes: old ones, used or not, stop working. */
  replaceRecoveryCodes?(userId: string, codeHashes: string[], tx?: Tx): Promise<void>;
  /**
   * Clears the pending flag, sets mfa_verified_at = now, expires_at = expiresAt and clears the saved redirect. Holds
   * the user row FOR SHARE and returns false when the user is suspended or the session no longer exists or has expired.
   */
  markSessionVerified?(idHash: string, userId: string, p: { now: Date; expiresAt: Date }, tx: Tx): Promise<boolean>;
  /** Makes a session with mfa_verified_at null and not pending into a pending one expiring at `expiresAt`. */
  markSessionPending?(idHash: string, expiresAt: Date, tx?: Tx): Promise<void>;
  /** Atomic increment of a pending session's wrong-code count; returns the new count, or 0 when the session is missing or not pending. */
  incrementSessionMfaAttempts?(idHash: string, tx?: Tx): Promise<number>;
  /** Deletes every session of the user except `keepIdHash`; returns how many were removed. */
  deleteOtherSessions?(userId: string, keepIdHash: string, tx?: Tx): Promise<number>;
}

export interface TotpRecord {
  /** The active secret, encrypted with the user id as AAD; null until a first confirmation. */
  secretEnc: string | null;
  /** An enrolment in progress, not yet confirmed. */
  pendingSecretEnc: string | null;
  confirmedAt: Date | null;
  lastStep: number | null;
  failedCount: number;
  lockedUntil: Date | null;
}

export interface TwoFactorConfig {
  /** Shown in the authenticator app, e.g. "TrueMark". */
  issuer: string;
  /**
   * true: everyone. A function: decided per user at sign-in only (and again for status and disable), with `isNew` true
   * when the account was just created. With a plain `true`, sessions that never passed the second factor are also
   * held pending on their next request; with a function, existing sessions stay valid until they expire. Default false.
   */
  required?: boolean | ((ctx: { user: AuthUser; isNew: boolean }) => boolean | Promise<boolean>);
  /** Frontend path a pending user is sent to after the callback. Default '/2fa'. */
  verifyPath?: string;
  /** Life of a pending session. Default 10 minutes. */
  pendingTtlMs?: number;
  /** Wrong codes before a pending session is deleted and before a user is locked. Default 5. */
  maxAttempts?: number;
  /** How long a locked user is refused. Default 15 minutes. */
  lockoutMs?: number;
  /** Default 10. */
  recoveryCodeCount?: number;
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
 * '2fa' (the /auth/2fa/* routes; codes mfa_invalid_code, mfa_locked, mfa_not_pending, mfa_required, plus the generic
 *   unauthenticated, forbidden, account_suspended, invalid_request and internal_error). Never a secret, code or recovery code.
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
   * Runs inside the sign-in transaction, after the session row has been written (a suspended person is refused
   * before this is called). If it throws, the transaction rolls back, session included. It may run twice if a
   * duplicate-identity race retries the transaction, so side effects must be done through `tx`.
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
  /** Optional TOTP second factor. Unset: behaviour is exactly as without the feature. */
  twoFactor?: TwoFactorConfig;
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
