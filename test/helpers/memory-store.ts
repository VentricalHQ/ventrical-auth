import { DuplicateIdentityError } from '../../src/errors.js';
import type { AuthStore, AuthUser, NewIdentity } from '../../src/types.js';

interface StoredIdentity extends NewIdentity { userId: string }
interface StoredSession { userId: string; expiresAt: Date; createdAt: Date; identity: { provider: string; subject: string } }
interface StoredUser extends AuthUser { suspended: boolean }

/** A distinct handle per transaction, so tests can tell whether two calls shared one. */
export interface MemoryTx { readonly id: number }

export type MemoryStore = AuthStore<MemoryTx> & {
  suspend(userId: string): void;
  /** Test-only: reassigns an identity to another user (as an account merge would). */
  moveIdentity(provider: string, subject: string, toUserId: string): void;
  sessions: Map<string, StoredSession>;
};

/** `clock` stamps created_at on new sessions (the handler's injected clock in tests); defaults to real time. */
export function createMemoryStore(clock: () => Date = () => new Date()): MemoryStore {
  let users = new Map<string, StoredUser>();
  let identities: StoredIdentity[] = [];
  let sessions = new Map<string, StoredSession>();
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
      seq,
    };
    try {
      return await fn({ id: ++txSeq });
    } catch (err) {
      users = snap.users;
      identities = snap.identities;
      sessions = snap.sessions;
      seq = snap.seq;
      throw err;
    }
  }

  const store: MemoryStore = {
    get sessions() { return sessions; },
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
    async createSessionUnlessSuspended(userId, idHash, expiresAt, identity) {
      if (!users.has(userId) || isSuspended(userId)) return false; // unknown user: refused, as the pg store does
      sessions.set(idHash, { userId, expiresAt, createdAt: clock(), identity });
      return true;
    },
    async getSessionWithExpiry(idHash, now) {
      const s = sessions.get(idHash);
      if (!s || s.expiresAt.getTime() <= now.getTime()) return undefined;
      const u = users.get(s.userId);
      if (!u || u.suspended) return undefined;
      const i = identities.find((x) => x.provider === s.identity.provider && x.subject === s.identity.subject && x.userId === s.userId);
      const verifiedEmail = i && i.emailVerified && i.email ? i.email : null;
      return { user: publicUser(u), expiresAt: s.expiresAt, createdAt: s.createdAt, identity: s.identity, verifiedEmail };
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
  };
  return store;
}
