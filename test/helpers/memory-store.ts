import { DuplicateIdentityError } from '../../src/errors.js';
import type { AuthStore, AuthUser, NewIdentity, TotpRecord } from '../../src/types.js';

interface StoredIdentity extends NewIdentity { userId: string }
interface StoredSession {
  userId: string; expiresAt: Date; createdAt: Date; identity: { provider: string; subject: string };
  mfaPending: boolean; mfaAttempts: number; mfaVerifiedAt: Date | null; mfaRedirect: string | null;
}
interface StoredUser extends AuthUser { suspended: boolean }

/** A distinct handle per transaction, so tests can tell whether two calls shared one. */
export interface MemoryTx { readonly id: number }

type TwoFactorMethods = 'getTotp' | 'setPendingTotpSecret' | 'confirmTotp' | 'deleteTotp' | 'consumeTotpStep' | 'recordTotpFailure' | 'resetTotpFailures'
  | 'consumeRecoveryCode' | 'replaceRecoveryCodes' | 'markSessionVerified' | 'markSessionPending' | 'incrementSessionMfaAttempts' | 'deleteOtherSessions';

export type MemoryStore = AuthStore<MemoryTx> & Required<Pick<AuthStore<MemoryTx>, TwoFactorMethods>> & {
  suspend(userId: string): void;
  /** Test-only: reassigns an identity to another user (as an account merge would). */
  moveIdentity(provider: string, subject: string, toUserId: string): void;
  sessions: Map<string, StoredSession>;
  /** Test-only: the raw TOTP records and recovery codes, to assert nothing is kept in the clear. */
  totps: Map<string, TotpRecord>;
  recoveryCodes: Map<string, Map<string, Date | null>>;
  /** Test-only: when set, getSessionWithExpiry omits the 2FA fields, like a store that ignores the pending flag. */
  ignorePendingFlag: boolean;
};

/** `clock` stamps created_at on new sessions (the handler's injected clock in tests); defaults to real time. */
export function createMemoryStore(clock: () => Date = () => new Date()): MemoryStore {
  let users = new Map<string, StoredUser>();
  let identities: StoredIdentity[] = [];
  let sessions = new Map<string, StoredSession>();
  let totps = new Map<string, TotpRecord>();
  let recovery = new Map<string, Map<string, Date | null>>();
  let ignorePendingFlag = false;
  let seq = 0;
  let txSeq = 0;
  // Transactions run one at a time (like row-level conflicts would force), so a rollback snapshot never erases a concurrent commit.
  let queue: Promise<unknown> = Promise.resolve();

  // Mirrors the pg store: trim, then lowercase; empty after trimming is no email.
  const norm = (e: string | null | undefined): string | undefined => (e == null || e.trim() === '' ? undefined : e.trim().toLowerCase());
  const publicUser = (u: StoredUser): AuthUser => ({ id: u.id, email: u.email, name: u.name });
  const isSuspended = (userId: string) => users.get(userId)?.suspended === true;

  async function runTx<T>(fn: (tx: MemoryTx) => Promise<T>): Promise<T> {
    const snap = {
      users: new Map([...users].map(([k, u]) => [k, { ...u }] as const)),
      identities: identities.map((i) => ({ ...i })),
      sessions: new Map([...sessions].map(([k, s]) => [k, { ...s, identity: { ...s.identity } }] as const)),
      totps: new Map([...totps].map(([k, t]) => [k, { ...t }] as const)),
      recovery: new Map([...recovery].map(([k, m]) => [k, new Map(m)] as const)),
      seq,
    };
    try {
      return await fn({ id: ++txSeq });
    } catch (err) {
      users = snap.users;
      identities = snap.identities;
      sessions = snap.sessions;
      totps = snap.totps;
      recovery = snap.recovery;
      seq = snap.seq;
      throw err;
    }
  }

  const store: MemoryStore = {
    get sessions() { return sessions; },
    get totps() { return totps; },
    get recoveryCodes() { return recovery; },
    get ignorePendingFlag() { return ignorePendingFlag; },
    set ignorePendingFlag(v: boolean) { ignorePendingFlag = v; },
    suspend(userId) {
      const u = users.get(userId);
      if (u) u.suspended = true;
    },
    moveIdentity(provider, subject, toUserId) {
      const i = identities.find((x) => x.provider === provider && x.subject === subject);
      if (i) i.userId = toUserId;
    },
    transaction(fn) {
      const run = queue.then(() => runTx(fn), () => runTx(fn));
      queue = run.catch(() => undefined);
      return run;
    },
    async findUserByIdentity(provider, subject) {
      const i = identities.find((x) => x.provider === provider && x.subject === subject);
      const u = i && users.get(i.userId);
      return u && i ? { ...publicUser(u), identity: { email: i.email ?? null, emailVerified: i.emailVerified } } : undefined;
    },
    async createUserWithIdentity(p) {
      if (identities.some((x) => x.provider === p.provider && x.subject === p.subject)) throw new DuplicateIdentityError();
      const id = `u${++seq}`;
      const user: StoredUser = { id, email: norm(p.email) ?? null, name: p.name ?? null, suspended: false };
      users.set(id, user);
      identities.push({ provider: p.provider, subject: p.subject, ...(norm(p.email) !== undefined ? { email: norm(p.email)! } : {}), emailVerified: p.emailVerified, userId: id });
      return publicUser(user);
    },
    async linkIdentity(userId, identity) {
      if (!users.has(userId)) throw new Error('foreign key violation: unknown user'); // like Postgres, not a DuplicateIdentityError
      if (identities.some((x) => x.provider === identity.provider && x.subject === identity.subject)) throw new DuplicateIdentityError();
      const { email: raw, ...rest } = identity;
      const email = norm(raw);
      identities.push({ ...rest, ...(email !== undefined ? { email } : {}), userId });
    },
    async updateIdentity(provider, subject, update) {
      const i = identities.find((x) => x.provider === provider && x.subject === subject);
      if (!i) return;
      if (update.email !== undefined) {
        const e = norm(update.email);
        if (e === undefined) delete i.email; else i.email = e;
      }
      i.emailVerified = update.emailVerified;
    },
    async emailBelongsToSuspendedUser(email, _tx, opts) {
      const e = norm(email);
      return e !== undefined && identities.some((i) => i.userId !== opts?.exceptUserId && i.emailVerified && norm(i.email) === e && isSuspended(i.userId));
    },
    async createSessionUnlessSuspended(userId, idHash, expiresAt, identity, _tx, opts) {
      if (!users.has(userId) || isSuspended(userId)) return false; // unknown user: refused, as the pg store does
      const pending = opts?.pending;
      sessions.set(idHash, {
        userId, expiresAt, createdAt: clock(), identity,
        mfaPending: pending !== undefined, mfaAttempts: 0, mfaVerifiedAt: null, mfaRedirect: pending?.redirect ?? null,
      });
      return true;
    },
    async getSessionWithExpiry(idHash, now) {
      const s = sessions.get(idHash);
      if (!s || s.expiresAt.getTime() <= now.getTime()) return undefined;
      const u = users.get(s.userId);
      if (!u || u.suspended) return undefined;
      const i = identities.find((x) => x.provider === s.identity.provider && x.subject === s.identity.subject && x.userId === s.userId);
      const verifiedEmail = i && i.emailVerified && i.email ? i.email : null;
      const base = { user: publicUser(u), expiresAt: s.expiresAt, createdAt: s.createdAt, identity: s.identity, verifiedEmail };
      if (ignorePendingFlag) return base;
      return { ...base, mfaPending: s.mfaPending, mfaVerifiedAt: s.mfaVerifiedAt, mfaAttempts: s.mfaAttempts, mfaRedirect: s.mfaRedirect };
    },
    async touchSession(idHash, expiresAt) {
      const s = sessions.get(idHash);
      if (s) s.expiresAt = expiresAt;
    },
    async deleteSession(idHash, _tx) {
      sessions.delete(idHash);
    },
    async deleteSessionsForUser(userId) {
      let n = 0;
      for (const [h, s] of sessions) if (s.userId === userId) { sessions.delete(h); n++; }
      return n;
    },
    async purgeExpiredSessions(now, opts) {
      let n = 0;
      for (const [h, s] of sessions) {
        const capped = opts?.maxAgeMs !== undefined && s.createdAt.getTime() + opts.maxAgeMs <= now.getTime();
        if (s.expiresAt.getTime() <= now.getTime() || capped) { sessions.delete(h); n++; }
      }
      return n;
    },
    async isSuspendedCredential(idHash, now) {
      const s = sessions.get(idHash);
      return !!s && s.expiresAt.getTime() > now.getTime() && isSuspended(s.userId);
    },

    // Two-factor. Bodies have no awaits, so each is atomic like a single conditional UPDATE.
    async getTotp(userId) {
      const t = totps.get(userId);
      return t && { ...t };
    },
    async setPendingTotpSecret(userId, secretEnc) {
      if (!users.has(userId)) throw new Error('foreign key violation: unknown user');
      const t = totps.get(userId);
      if (t) t.pendingSecretEnc = secretEnc;
      else totps.set(userId, { secretEnc: null, pendingSecretEnc: secretEnc, confirmedAt: null, lastStep: null, failedCount: 0, lockedUntil: null });
    },
    async confirmTotp(userId, p) {
      const t = totps.get(userId);
      if (!t || t.pendingSecretEnc === null || t.pendingSecretEnc !== p.expectedPendingEnc) return false;
      Object.assign(t, { secretEnc: t.pendingSecretEnc, pendingSecretEnc: null, confirmedAt: p.now, lastStep: p.step, failedCount: 0, lockedUntil: null });
      recovery.set(userId, new Map(p.recoveryCodeHashes.map((h) => [h, null] as const)));
      return true;
    },
    async deleteTotp(userId) {
      totps.delete(userId);
      recovery.delete(userId);
    },
    async consumeTotpStep(userId, step, now) {
      const t = totps.get(userId);
      if (!t || t.confirmedAt === null) return false;
      if (t.lockedUntil !== null && t.lockedUntil.getTime() > now.getTime()) return false;
      if (t.lastStep !== null && t.lastStep >= step) return false;
      t.lastStep = step;
      return true;
    },
    async recordTotpFailure(userId, p) {
      const t = totps.get(userId);
      if (!t) return { locked: false, lockedUntil: null };
      const lockExpired = t.lockedUntil !== null && t.lockedUntil.getTime() <= p.now.getTime();
      if (lockExpired) { t.lockedUntil = null; t.failedCount = 0; }
      t.failedCount += 1;
      if (t.failedCount >= p.maxAttempts) {
        t.lockedUntil = new Date(p.now.getTime() + p.lockoutMs);
        t.failedCount = 0;
      }
      const locked = t.lockedUntil !== null && t.lockedUntil.getTime() > p.now.getTime();
      return { locked, lockedUntil: locked ? t.lockedUntil : null };
    },
    async resetTotpFailures(userId) {
      const t = totps.get(userId);
      if (t) { t.failedCount = 0; t.lockedUntil = null; }
    },
    async consumeRecoveryCode(userId, codeHash, now) {
      const codes = recovery.get(userId);
      if (!codes || !codes.has(codeHash) || codes.get(codeHash) !== null) return false;
      const t = totps.get(userId);
      if (t?.lockedUntil && t.lockedUntil.getTime() > now.getTime()) return false;
      codes.set(codeHash, now);
      return true;
    },
    async replaceRecoveryCodes(userId, hashes) {
      recovery.set(userId, new Map(hashes.map((h) => [h, null] as const)));
    },
    async markSessionVerified(idHash, userId, p) {
      const s = sessions.get(idHash);
      if (!s || s.userId !== userId || isSuspended(userId) || s.expiresAt.getTime() <= p.now.getTime()) return false;
      Object.assign(s, { mfaPending: false, mfaVerifiedAt: p.now, expiresAt: p.expiresAt, mfaRedirect: null });
      return true;
    },
    async markSessionPending(idHash, expiresAt) {
      const s = sessions.get(idHash);
      if (s && !s.mfaPending && s.mfaVerifiedAt === null) { s.mfaPending = true; s.expiresAt = expiresAt; }
    },
    async incrementSessionMfaAttempts(idHash) {
      const s = sessions.get(idHash);
      if (!s || !s.mfaPending) return 0;
      s.mfaAttempts += 1;
      return s.mfaAttempts;
    },
    async deleteOtherSessions(userId, keepIdHash) {
      let n = 0;
      for (const [h, s] of sessions) if (s.userId === userId && h !== keepIdHash) { sessions.delete(h); n++; }
      return n;
    },
  };
  return store;
}
