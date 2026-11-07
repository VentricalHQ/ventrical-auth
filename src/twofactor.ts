import { base32Decode, base32Encode } from './base32.js';
import { MAX_BODY_CHARS } from './body.js';
import { decrypt, encrypt, hashToken } from './crypto.js';
import { AuthHttpError, SUSPENDED_MESSAGE } from './errors.js';
import type { makeSessions, PendingResolved, Resolved, SessionResult } from './session.js';
import { generateRecoveryCode, generateTotpSecret, normalizeRecoveryCode, otpauthUri, verifyTotp } from './totp.js';
import type { AuthConfig, AuthStore, AuthUser, TotpRecord, TwoFactorConfig } from './types.js';

/** AAD for a user's TOTP secret: a blob only opens for the user it was made for, and not as any other kind of secret. */
export const totpAad = (userId: string): string => `ventrical-auth/totp/${userId}`;

const MAX_CODE_CHARS = 64;

export interface TwoFactorDeps {
  config: AuthConfig<any>;
  tf: TwoFactorConfig;
  clock: () => Date;
  sessions: ReturnType<typeof makeSessions>;
  json(status: number, body: unknown, cookies?: string[]): Response;
  requireSameOrigin(request: Request): void;
  resolveTarget(savedRedirect: string): string;
  pendingTtlMs: number;
}

type Full = Extract<Resolved, { kind: 'full' }>;
type Pending = PendingResolved & { kind: 'pending' };
type Body = Record<string, unknown>;

const invalid = (message = 'Invalid request') => new AuthHttpError(400, 'invalid_request', message);
const unauthenticated = () => new AuthHttpError(401, 'unauthenticated', 'Sign in required');
const notPending = (message: string) => new AuthHttpError(409, 'mfa_not_pending', message);

/** The /auth/2fa/* routes. Every failure is an AuthHttpError with a fixed message: no code, secret or detail ever goes in one. */
export function makeTwoFactor(deps: TwoFactorDeps) {
  const { config, tf, clock, sessions } = deps;
  const store = config.store as Required<Pick<AuthStore<any>,
    'getTotp' | 'setPendingTotpSecret' | 'confirmTotp' | 'deleteTotp' | 'consumeTotpStep' | 'recordTotpFailure' | 'resetTotpFailures'
    | 'consumeRecoveryCode' | 'replaceRecoveryCodes' | 'markSessionVerified' | 'incrementSessionMfaAttempts' | 'deleteOtherSessions'>>
    & AuthStore<any>;
  const maxAttempts = tf.maxAttempts ?? 5;
  const lockoutMs = tf.lockoutMs ?? 15 * 60 * 1000;
  const recoveryCodeCount = tf.recoveryCodeCount ?? 10;

  async function readBody(request: Request): Promise<Body> {
    let text: string;
    try {
      text = await request.text();
    } catch {
      throw invalid();
    }
    if (text.length > MAX_BODY_CHARS) throw invalid();
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw invalid();
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw invalid();
    return parsed as Body;
  }

  /** A string field, or undefined when absent. Anything else (number, array, over-long string) is a bad request. */
  function field(body: Body, name: string): string | undefined {
    const v = body[name];
    if (v === undefined) return undefined;
    if (typeof v !== 'string' || v.length > MAX_CODE_CHARS) throw invalid();
    return v;
  }

  /** Same refusal as requireSession: a suspended user's credential is 403, anything else 401. */
  async function resolveOrThrow(request: Request, now: Date): Promise<Resolved> {
    const r = await sessions.resolve(request, now);
    if (r) return r;
    const id = sessions.readId(request);
    if (id && store.isSuspendedCredential && (await store.isSuspendedCredential(hashToken(id), now))) {
      throw new AuthHttpError(403, 'account_suspended', SUSPENDED_MESSAGE);
    }
    throw unauthenticated();
  }

  /** A full session, or 401: a pending session is a signed-out one everywhere but the routes that name it. */
  async function requireFull(request: Request, now: Date): Promise<Full> {
    const r = await resolveOrThrow(request, now);
    if (r.kind !== 'full') throw unauthenticated();
    return r;
  }

  /** Setup and confirm: a full session, or a pending one that is enrolling. */
  async function requireFullOrEnrolling(request: Request, now: Date): Promise<Full | Pending> {
    const r = await resolveOrThrow(request, now);
    if (r.kind === 'pending' && r.state !== 'enroll') throw notPending('Verify with your authenticator first');
    return r;
  }

  const userOf = (r: Full | Pending): AuthUser => {
    const u = r.kind === 'full' ? r.session.user : r.user;
    return { id: u.id, email: u.email, name: u.name };
  };

  function refuseIfLocked(totp: TotpRecord | undefined, now: Date): void {
    if (totp?.lockedUntil && totp.lockedUntil.getTime() > now.getTime()) {
      throw new AuthHttpError(429, 'mfa_locked', 'Too many wrong codes. Try again later.');
    }
  }

  function enrolledSecret(userId: string, totp: TotpRecord | undefined): Buffer {
    if (!totp || totp.confirmedAt === null || totp.secretEnc === null) throw invalid('Two-factor authentication is not turned on');
    return base32Decode(decrypt(totp.secretEnc, config.encryptionKey, totpAad(userId)));
  }

  /** TOTP code check that also spends the step. False for a wrong, malformed, replayed or locked-out code. */
  async function spendTotp(userId: string, secret: Buffer, code: string, now: Date, tx: unknown): Promise<boolean> {
    const step = verifyTotp(secret, code, now.getTime());
    return step !== undefined && (await store.consumeTotpStep(userId, step, now, tx));
  }

  async function spendRecovery(userId: string, code: string, now: Date, tx: unknown): Promise<boolean> {
    const normalized = normalizeRecoveryCode(code);
    return normalized !== '' && (await store.consumeRecoveryCode(userId, hashToken(normalized), now, tx));
  }

  /**
   * Counts a wrong code against the user and, for a pending session, against that session (deleted at the limit). Always
   * throws: 429 when the user is now locked, otherwise `invalidStatus` with mfa_invalid_code.
   */
  async function wrongCode(userId: string, session: { idHash: string } | undefined, now: Date, invalidStatus = 401): Promise<never> {
    const lock = await store.recordTotpFailure(userId, { maxAttempts, lockoutMs, now });
    const cookies: string[] = [];
    if (session) {
      const attempts = await store.incrementSessionMfaAttempts(session.idHash);
      if (attempts >= maxAttempts) {
        await store.deleteSession(session.idHash);
        cookies.push(sessions.clearSessionCookie());
      }
    }
    if (lock.locked) throw new AuthHttpError(429, 'mfa_locked', 'Too many wrong codes. Try again later.', cookies);
    throw new AuthHttpError(invalidStatus, 'mfa_invalid_code', 'That code is not valid', cookies);
  }

  const pendingOnly = (r: Resolved): { idHash: string } | undefined => (r.kind === 'pending' ? r : undefined);

  const newRecoveryCodes = (): { codes: string[]; hashes: string[] } => {
    const codes = Array.from({ length: recoveryCodeCount }, generateRecoveryCode);
    return { codes, hashes: codes.map(hashToken) };
  };

  const ok = (body: unknown, cookies: string[] = []): Response => deps.json(200, body, cookies);

  async function isRequired(user: AuthUser): Promise<boolean> {
    const r = tf.required;
    return typeof r === 'function' ? (await r({ user, isNew: false })) === true : r === true;
  }

  /** A fresh normal-life expiry and cookie for a session that just passed the second factor. */
  function verifiedExpiry(r: Full | Pending, now: Date) {
    const expiresAt = sessions.expiryFor(now, r.createdAt ?? now);
    const id = r.kind === 'full' ? r.session.id : r.id;
    return { expiresAt, cookie: sessions.sessionCookie(id, expiresAt.getTime() - now.getTime()) };
  }

  async function verify(request: Request): Promise<Response> {
    deps.requireSameOrigin(request);
    const body = await readBody(request);
    const code = field(body, 'code');
    const recoveryCode = field(body, 'recoveryCode');
    if ((code === undefined) === (recoveryCode === undefined)) throw invalid('Send either code or recoveryCode');
    const now = clock();
    const r = await resolveOrThrow(request, now);
    if (r.kind !== 'pending' || r.state !== 'verify') throw notPending('No second factor is waiting for a code');
    const userId = r.user.id;
    const totp = await store.getTotp(userId);
    if (!totp || totp.confirmedAt === null) throw notPending('No second factor is waiting for a code');
    refuseIfLocked(totp, now);
    const secret = code !== undefined ? enrolledSecret(userId, totp) : undefined;
    const { expiresAt, cookie } = verifiedExpiry(r, now);
    const passed = await store.transaction(async (tx) => {
      const good = secret ? await spendTotp(userId, secret, code!, now, tx) : await spendRecovery(userId, recoveryCode!, now, tx);
      if (!good) return false;
      // Suspension is checked again here, under the user row lock; throwing rolls back the spent code.
      if (!(await store.markSessionVerified(r.idHash, userId, { now, expiresAt }, tx))) {
        throw new AuthHttpError(403, 'account_suspended', SUSPENDED_MESSAGE);
      }
      await store.resetTotpFailures(userId, tx);
      return true;
    });
    if (!passed) return wrongCode(userId, r, now);
    return ok({ ok: true, redirect: deps.resolveTarget(r.redirect ?? '/') }, [cookie]);
  }

  async function setup(request: Request): Promise<Response> {
    deps.requireSameOrigin(request);
    const body = await readBody(request);
    const code = field(body, 'code');
    const recoveryCode = field(body, 'recoveryCode');
    const now = clock();
    const r = await requireFullOrEnrolling(request, now);
    const user = userOf(r);
    const totp = await store.getTotp(user.id);
    if (totp?.confirmedAt) {
      // Replacing a live secret needs proof of the current one, so a stolen full session alone cannot do it.
      refuseIfLocked(totp, now);
      if ((code === undefined) === (recoveryCode === undefined)) {
        throw new AuthHttpError(409, 'mfa_invalid_code', 'A current code is required to replace your authenticator');
      }
      const current = code !== undefined ? enrolledSecret(user.id, totp) : undefined;
      const good = await store.transaction((tx) => (current ? spendTotp(user.id, current, code!, now, tx) : spendRecovery(user.id, recoveryCode!, now, tx)));
      if (!good) return wrongCode(user.id, pendingOnly(r), now, 409);
    }
    const secret = generateTotpSecret();
    const secretText = base32Encode(secret);
    await store.setPendingTotpSecret(user.id, encrypt(secretText, config.encryptionKey, totpAad(user.id)), now);
    const cookies = r.kind === 'full' && r.session.setCookie ? [r.session.setCookie] : [];
    return ok({ secret: secretText, otpauthUri: otpauthUri({ issuer: tf.issuer, account: user.email ?? user.id, secret: secretText }) }, cookies);
  }

  async function confirm(request: Request): Promise<Response> {
    deps.requireSameOrigin(request);
    const body = await readBody(request);
    const code = field(body, 'code');
    if (code === undefined) throw invalid('Send code');
    const now = clock();
    const r = await requireFullOrEnrolling(request, now);
    const user = userOf(r);
    const totp = await store.getTotp(user.id);
    refuseIfLocked(totp, now);
    if (!totp?.pendingSecretEnc) throw invalid('Start setup first');
    const pendingEnc = totp.pendingSecretEnc;
    const step = verifyTotp(base32Decode(decrypt(pendingEnc, config.encryptionKey, totpAad(user.id))), code, now.getTime());
    if (step === undefined) return wrongCode(user.id, pendingOnly(r), now);
    const { codes, hashes } = newRecoveryCodes();
    const { expiresAt, cookie } = verifiedExpiry(r, now);
    const idHash = r.idHash;
    await store.transaction(async (tx) => {
      if (!(await store.confirmTotp(user.id, { expectedPendingEnc: pendingEnc, step, now, recoveryCodeHashes: hashes }, tx))) {
        throw invalid('Setup changed; start again');
      }
      if (!(await store.markSessionVerified(idHash, user.id, { now, expiresAt }, tx))) {
        throw new AuthHttpError(403, 'account_suspended', SUSPENDED_MESSAGE);
      }
      // Enrolling ends every other session: a thief holding one must not keep it past the new factor.
      await store.deleteOtherSessions(user.id, idHash, tx);
    });
    return ok({ recoveryCodes: codes, ...(r.kind === 'pending' ? { redirect: deps.resolveTarget(r.redirect ?? '/') } : {}) }, [cookie]);
  }

  async function recoveryCodes(request: Request): Promise<Response> {
    deps.requireSameOrigin(request);
    const body = await readBody(request);
    const code = field(body, 'code');
    if (code === undefined) throw invalid('Send code');
    const now = clock();
    const r = await requireFull(request, now);
    const userId = r.session.user.id;
    const totp = await store.getTotp(userId);
    const secret = enrolledSecret(userId, totp);
    refuseIfLocked(totp, now);
    const { codes, hashes } = newRecoveryCodes();
    const passed = await store.transaction(async (tx) => {
      if (!(await spendTotp(userId, secret, code, now, tx))) return false;
      await store.replaceRecoveryCodes(userId, hashes, tx);
      await store.resetTotpFailures(userId, tx);
      return true;
    });
    if (!passed) return wrongCode(userId, undefined, now);
    return ok({ recoveryCodes: codes }, r.session.setCookie ? [r.session.setCookie] : []);
  }

  async function disable(request: Request): Promise<Response> {
    deps.requireSameOrigin(request);
    const body = await readBody(request);
    const code = field(body, 'code');
    if (code === undefined) throw invalid('Send code');
    const now = clock();
    const r = await requireFull(request, now);
    const user = r.session.user;
    if (await isRequired(user)) throw new AuthHttpError(403, 'mfa_required', 'Two-factor authentication is required for this account');
    const totp = await store.getTotp(user.id);
    const secret = enrolledSecret(user.id, totp);
    refuseIfLocked(totp, now);
    const passed = await store.transaction(async (tx) => {
      if (!(await spendTotp(user.id, secret, code, now, tx))) return false;
      await store.deleteTotp(user.id, tx);
      await store.deleteOtherSessions(user.id, r.idHash, tx);
      return true;
    });
    if (!passed) return wrongCode(user.id, undefined, now);
    return ok({ ok: true }, r.session.setCookie ? [r.session.setCookie] : []);
  }

  async function status(request: Request): Promise<Response> {
    const r = await requireFull(request, clock());
    const session: SessionResult = r.session;
    const totp = await store.getTotp(session.user.id);
    return ok(
      { enrolled: totp?.confirmedAt != null, required: await isRequired(session.user), verified: session.mfaVerifiedAt !== null },
      session.setCookie ? [session.setCookie] : [],
    );
  }

  const routes: Record<string, (request: Request) => Promise<Response>> = {
    'POST /auth/2fa/verify': verify,
    'POST /auth/2fa/setup': setup,
    'POST /auth/2fa/setup/confirm': confirm,
    'POST /auth/2fa/recovery-codes': recoveryCodes,
    'POST /auth/2fa/disable': disable,
    'GET /auth/2fa/status': status,
  };

  /** Undefined for a method/path that is not a 2FA route, so the handler falls through as for any unknown path. */
  async function handle(request: Request, method: string, path: string): Promise<Response | undefined> {
    const key = `${method} ${path}`;
    const route = Object.hasOwn(routes, key) ? routes[key] : undefined;
    return route ? route(request) : undefined;
  }

  return { handle };
}
