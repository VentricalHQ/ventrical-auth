import { DuplicateIdentityError } from '../../src/errors.js';
import type { AuthStore, AuthUser, NewIdentity } from '../../src/types.js';

interface StoredIdentity extends NewIdentity { userId: string }
interface StoredSession { userId: string; expiresAt: Date; identity: { provider: string; subject: string } }
interface StoredUser extends AuthUser { suspended: boolean }

/** A distinct handle per transaction, so tests can tell whether two calls shared one. */
export interface MemoryTx { readonly id: number }

export type MemoryStore = AuthStore<MemoryTx> & {
  suspend(userId: string): void;
  sessions: Map<string, StoredSession>;
};

export function createMemoryStore(): MemoryStore {
  let users = new Map<string, StoredUser>();
  let identities: StoredIdentity[] = [];
  let sessions = new Map<string, StoredSession>();
  let seq = 0;
  let txSeq = 0;
  // Transactions run one at a time (like row-level conflicts would force), so a rollback snapshot never erases a concurrent commit.
  let queue: Promise<unknown> = Promise.resolve();

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
    transaction(fn) {
      const run = queue.then(() => runTx(fn), () => runTx(fn));
      queue = run.catch(() => undefined);
      return run;
    },
    async findUserByIdentity(provider, subject) {
      const i = identities.find((x) => x.provider === provider && x.subject === subject);
      const u = i && users.get(i.userId);
      return u ? publicUser(u) : undefined;
    },
    async createUserWithIdentity(p) {
      if (identities.some((x) => x.provider === p.provider && x.subject === p.subject)) throw new DuplicateIdentityError();
      const id = `u${++seq}`;
      const user: StoredUser = { id, email: p.email ?? null, name: p.name ?? null, suspended: false };
      users.set(id, user);
      identities.push({ provider: p.provider, subject: p.subject, ...(p.email !== undefined ? { email: p.email } : {}), emailVerified: p.emailVerified, userId: id });
      return publicUser(user);
    },
    async linkIdentity(userId, identity) {
      if (identities.some((x) => x.provider === identity.provider && x.subject === identity.subject)) throw new DuplicateIdentityError();
      identities.push({ ...identity, userId });
    },
    async emailBelongsToSuspendedUser(email) {
      const e = email.toLowerCase();
      return identities.some((i) => i.emailVerified && i.email?.toLowerCase() === e && isSuspended(i.userId));
    },
    async createSessionUnlessSuspended(userId, idHash, expiresAt, identity) {
      if (isSuspended(userId)) return false;
      sessions.set(idHash, { userId, expiresAt, identity });
      return true;
    },
    async getSessionWithExpiry(idHash, now) {
      const s = sessions.get(idHash);
      if (!s || s.expiresAt.getTime() <= now.getTime()) return undefined;
      const u = users.get(s.userId);
      if (!u || u.suspended) return undefined;
      return { user: publicUser(u), expiresAt: s.expiresAt, identity: s.identity };
    },
    async touchSession(idHash, expiresAt) {
      const s = sessions.get(idHash);
      if (s) s.expiresAt = expiresAt;
    },
    async deleteSession(idHash) {
      sessions.delete(idHash);
    },
    async deleteSessionsForUser(userId) {
      let n = 0;
      for (const [h, s] of sessions) if (s.userId === userId) { sessions.delete(h); n++; }
      return n;
    },
    async isSuspendedCredential(idHash, now) {
      const s = sessions.get(idHash);
      return !!s && s.expiresAt.getTime() > now.getTime() && isSuspended(s.userId);
    },
  };
  return store;
}
