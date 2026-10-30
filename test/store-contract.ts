import { afterEach, describe, expect, it } from 'vitest';
import { DuplicateIdentityError } from '../src/errors.js';
import type { AuthStore } from '../src/types.js';

export interface StoreHarness {
  store: AuthStore<any>;
  suspend(userId: string): Promise<void>;
  /** Backdates a session's created_at (the store stamps it itself on insert). */
  setCreatedAt(idHash: string, createdAt: Date): Promise<void>;
  /** Test-only: reassigns an identity to another user, as an account merge would. */
  moveIdentity(provider: string, subject: string, toUserId: string): Promise<void>;
  /** Optional teardown (e.g. dropping a schema). */
  close?(): Promise<void>;
}

const IDENT = { provider: 'google', subject: 'g1' } as const;
const future = () => new Date(Date.now() + 864e5);

/** Behaviour every AuthStore must have. Each test gets a fresh store from `make`. */
export function storeContract(name: string, make: () => Promise<StoreHarness>): void {
  describe(`store contract: ${name}`, () => {
    const open: StoreHarness[] = [];
    afterEach(async () => {
      for (const h of open.splice(0)) await h.close?.();
    });
    const fresh = async () => {
      const h = await make();
      open.push(h);
      return h;
    };
    const session = (s: AuthStore<any>, userId: string, hash: string, expiresAt: Date) =>
      s.transaction((tx) => s.createSessionUnlessSuspended(userId, hash, expiresAt, IDENT, tx));

    it('creates a user with an identity and finds it by identity', async () => {
      const { store } = await fresh();
      const user = await store.createUserWithIdentity({ ...IDENT, email: 'a@example.test', emailVerified: true, name: 'Ann' });
      expect(user).toEqual({ id: user.id, email: 'a@example.test', name: 'Ann' });
      expect(await store.findUserByIdentity('google', 'g1')).toEqual({ ...user, identity: { email: 'a@example.test', emailVerified: true } });
      expect(await store.findUserByIdentity('google', 'other')).toBeUndefined();
      expect(await store.findUserByIdentity('github', 'g1')).toBeUndefined();
    });

    it('findUserByIdentity exposes the stored identity email and verified flag, and tracks updateIdentity', async () => {
      const { store } = await fresh();
      await store.createUserWithIdentity({ ...IDENT, email: 'Ann@Example.test', emailVerified: true });
      await store.createUserWithIdentity({ provider: 'github', subject: 'h1', emailVerified: false });
      expect((await store.findUserByIdentity('google', 'g1'))?.identity).toEqual({ email: 'ann@example.test', emailVerified: true });
      const bare = (await store.findUserByIdentity('github', 'h1'))?.identity;
      expect(bare?.emailVerified).toBe(false);
      expect(bare?.email ?? null).toBeNull();
      if (store.updateIdentity) {
        await store.updateIdentity('google', 'g1', { email: 'b@example.test', emailVerified: false });
        expect((await store.findUserByIdentity('google', 'g1'))?.identity).toEqual({ email: 'b@example.test', emailVerified: false });
        expect((await store.transaction((tx) => store.findUserByIdentity('google', 'g1', tx)))?.identity?.email).toBe('b@example.test');
      }
    });

    it('stores null for a missing email and name', async () => {
      const { store } = await fresh();
      const user = await store.createUserWithIdentity({ ...IDENT, emailVerified: false });
      expect(user.email).toBeNull();
      expect(user.name).toBeNull();
    });

    it('throws DuplicateIdentityError for a second create or link of the same identity', async () => {
      const { store } = await fresh();
      const first = await store.createUserWithIdentity({ ...IDENT, emailVerified: true });
      await expect(store.createUserWithIdentity({ ...IDENT, emailVerified: true })).rejects.toBeInstanceOf(DuplicateIdentityError);
      await expect(store.linkIdentity(first.id, { ...IDENT, emailVerified: true })).rejects.toBeInstanceOf(DuplicateIdentityError);
    });

    it('linkIdentity attaches a second identity to the same user', async () => {
      const { store } = await fresh();
      const user = await store.createUserWithIdentity({ ...IDENT, emailVerified: true });
      await store.linkIdentity(user.id, { provider: 'github', subject: 'h1', emailVerified: false });
      expect((await store.findUserByIdentity('github', 'h1'))?.id).toBe(user.id);
    });

    it('linkIdentity for an unknown user fails like a foreign-key violation, and is not a duplicate-identity error', async () => {
      const { store } = await fresh();
      const err = await store.linkIdentity('no-such-user', { ...IDENT, emailVerified: true }).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(Error);
      expect(err).not.toBeInstanceOf(DuplicateIdentityError);
      // Nothing was attached: the identity is still free.
      expect(await store.findUserByIdentity('google', 'g1')).toBeUndefined();
      const user = await store.createUserWithIdentity({ ...IDENT, emailVerified: true });
      expect((await store.findUserByIdentity('google', 'g1'))?.id).toBe(user.id);
    });

    it('createSessionUnlessSuspended refuses an unknown user (false, nothing inserted) instead of creating an orphan session', async () => {
      const { store } = await fresh();
      expect(await session(store, 'no-such-user', 'orphan', future())).toBe(false);
      expect(await store.getSessionWithExpiry('orphan', new Date())).toBeUndefined();
      expect(await store.deleteSessionsForUser('no-such-user')).toBe(0);
    });

    it('emailBelongsToSuspendedUser is true only for a verified identity email of a suspended user, case-insensitively', async () => {
      const { store, suspend } = await fresh();
      const user = await store.createUserWithIdentity({ ...IDENT, email: 'Person@Example.test', emailVerified: true });
      const other = await store.createUserWithIdentity({ provider: 'github', subject: 'h2', email: 'unverified@example.test', emailVerified: false });
      expect(await store.emailBelongsToSuspendedUser('person@example.test')).toBe(false);
      await suspend(user.id);
      await suspend(other.id);
      expect(await store.emailBelongsToSuspendedUser('person@example.test')).toBe(true);
      expect(await store.emailBelongsToSuspendedUser('PERSON@EXAMPLE.TEST')).toBe(true);
      expect(await store.emailBelongsToSuspendedUser('unverified@example.test')).toBe(false);
      expect(await store.emailBelongsToSuspendedUser('nobody@example.test')).toBe(false);
      expect(await store.transaction((tx) => store.emailBelongsToSuspendedUser('person@example.test', tx))).toBe(true);
      expect(await store.transaction((tx) => store.emailBelongsToSuspendedUser('unverified@example.test', tx))).toBe(false);
    });

    it('emailBelongsToSuspendedUser ignores the exceptUserId row only', async () => {
      const { store, suspend } = await fresh();
      const a = await store.createUserWithIdentity({ ...IDENT, email: 'twin@example.test', emailVerified: true });
      const b = await store.createUserWithIdentity({ provider: 'github', subject: 'h-twin', email: 'twin@example.test', emailVerified: true });
      await suspend(a.id);
      expect(await store.emailBelongsToSuspendedUser('twin@example.test')).toBe(true);
      expect(await store.emailBelongsToSuspendedUser('twin@example.test', undefined, { exceptUserId: a.id })).toBe(false);
      expect(await store.emailBelongsToSuspendedUser('twin@example.test', undefined, { exceptUserId: b.id })).toBe(true);
      expect(await store.transaction((tx) => store.emailBelongsToSuspendedUser('twin@example.test', tx, { exceptUserId: a.id }))).toBe(false);
      expect(await store.transaction((tx) => store.emailBelongsToSuspendedUser('twin@example.test', tx, { exceptUserId: b.id }))).toBe(true);
      expect(await store.transaction((tx) => store.emailBelongsToSuspendedUser('twin@example.test', tx, {}))).toBe(true);
    });

    it('createSessionUnlessSuspended creates a session for an active user', async () => {
      const { store } = await fresh();
      const user = await store.createUserWithIdentity({ ...IDENT, emailVerified: true });
      expect(await session(store, user.id, 'h1', future())).toBe(true);
      const found = await store.getSessionWithExpiry('h1', new Date());
      expect(found?.user.id).toBe(user.id);
      expect(found?.identity).toEqual(IDENT);
    });

    it('createSessionUnlessSuspended returns false for a suspended user and inserts nothing', async () => {
      const { store, suspend } = await fresh();
      const user = await store.createUserWithIdentity({ ...IDENT, emailVerified: true });
      await suspend(user.id);
      expect(await session(store, user.id, 'h1', future())).toBe(false);
      expect(await store.deleteSessionsForUser(user.id)).toBe(0);
      expect(await store.isSuspendedCredential?.('h1', new Date()) ?? false).toBe(false);
    });

    it('getSessionWithExpiry hides suspended users and expired sessions, and returns expiresAt', async () => {
      const { store, suspend } = await fresh();
      const user = await store.createUserWithIdentity({ ...IDENT, emailVerified: true });
      const expiresAt = new Date(Date.now() + 5 * 864e5);
      await session(store, user.id, 'live', expiresAt);
      await session(store, user.id, 'old', new Date(Date.now() - 1000));
      const live = await store.getSessionWithExpiry('live', new Date());
      expect(live?.expiresAt.getTime()).toBe(expiresAt.getTime());
      expect(await store.getSessionWithExpiry('old', new Date())).toBeUndefined();
      expect(await store.getSessionWithExpiry('missing', new Date())).toBeUndefined();
      await suspend(user.id);
      expect(await store.getSessionWithExpiry('live', new Date())).toBeUndefined();
    });

    it('isSuspendedCredential is true only for an unexpired session of a suspended user', async () => {
      const { store, suspend } = await fresh();
      const user = await store.createUserWithIdentity({ ...IDENT, emailVerified: true });
      await session(store, user.id, 'live', future());
      await session(store, user.id, 'old', new Date(Date.now() - 1000));
      expect(await store.isSuspendedCredential!('live', new Date())).toBe(false);
      await suspend(user.id);
      expect(await store.isSuspendedCredential!('live', new Date())).toBe(true);
      expect(await store.isSuspendedCredential!('old', new Date())).toBe(false);
      expect(await store.isSuspendedCredential!('missing', new Date())).toBe(false);
    });

    it('touchSession extends and deleteSession removes a session', async () => {
      const { store } = await fresh();
      const user = await store.createUserWithIdentity({ ...IDENT, emailVerified: true });
      await session(store, user.id, 'h1', new Date(Date.now() + 1000));
      const later = new Date(Date.now() + 10 * 864e5);
      await store.touchSession('h1', later);
      expect((await store.getSessionWithExpiry('h1', new Date()))?.expiresAt.getTime()).toBe(later.getTime());
      await store.deleteSession('h1');
      expect(await store.getSessionWithExpiry('h1', new Date())).toBeUndefined();
    });

    it('deleteSessionsForUser returns the count and leaves other users alone', async () => {
      const { store } = await fresh();
      const a = await store.createUserWithIdentity({ ...IDENT, emailVerified: true });
      const b = await store.createUserWithIdentity({ provider: 'github', subject: 'h9', emailVerified: true });
      await session(store, a.id, 'a1', future());
      await session(store, a.id, 'a2', future());
      await session(store, b.id, 'b1', future());
      expect(await store.deleteSessionsForUser(a.id)).toBe(2);
      expect(await store.deleteSessionsForUser(a.id)).toBe(0);
      expect(await store.getSessionWithExpiry('b1', new Date())).toBeDefined();
      expect(await store.transaction((tx) => store.deleteSessionsForUser(b.id, tx))).toBe(1);
    });

    it('purgeExpiredSessions deletes only expired sessions (boundary inclusive) and returns the count', async () => {
      const { store } = await fresh();
      const a = await store.createUserWithIdentity({ ...IDENT, emailVerified: true });
      const b = await store.createUserWithIdentity({ provider: 'github', subject: 'h9', emailVerified: true });
      const now = new Date('2030-01-01T00:00:00.000Z');
      expect(await store.purgeExpiredSessions(now)).toBe(0);
      await session(store, a.id, 'past', new Date(now.getTime() - 1000));
      await session(store, a.id, 'edge', new Date(now.getTime()));
      await session(store, a.id, 'later', new Date(now.getTime() + 1));
      await session(store, b.id, 'other', new Date(now.getTime() + 864e5));
      expect(await store.purgeExpiredSessions(now)).toBe(2);
      expect(await store.purgeExpiredSessions(now)).toBe(0);
      const before = new Date(now.getTime() - 5000);
      expect(await store.getSessionWithExpiry('later', before)).toBeDefined();
      expect(await store.getSessionWithExpiry('other', before)).toBeDefined();
      expect(await store.getSessionWithExpiry('past', before)).toBeUndefined();
      expect(await store.getSessionWithExpiry('edge', before)).toBeUndefined();
    });

    it('updateIdentity updates email and verified, leaves email when undefined, clears it on null', async () => {
      const { store, suspend } = await fresh();
      if (!store.updateIdentity) throw new Error('updateIdentity missing');
      const user = await store.createUserWithIdentity({ ...IDENT, email: 'old@example.test', emailVerified: false });
      await suspend(user.id);
      expect(await store.emailBelongsToSuspendedUser('old@example.test')).toBe(false);
      await store.updateIdentity('google', 'g1', { emailVerified: true });
      expect(await store.emailBelongsToSuspendedUser('old@example.test')).toBe(true);
      await store.updateIdentity('google', 'g1', { email: 'new@example.test', emailVerified: true });
      expect(await store.emailBelongsToSuspendedUser('new@example.test')).toBe(true);
      expect(await store.emailBelongsToSuspendedUser('old@example.test')).toBe(false);
      await store.updateIdentity('google', 'g1', { email: 'new@example.test', emailVerified: false });
      expect(await store.emailBelongsToSuspendedUser('new@example.test')).toBe(false);
      await store.updateIdentity('google', 'g1', { emailVerified: true });
      expect(await store.emailBelongsToSuspendedUser('new@example.test')).toBe(true);
      await store.updateIdentity('google', 'g1', { email: null, emailVerified: true });
      expect(await store.emailBelongsToSuspendedUser('new@example.test')).toBe(false);
    });

    it('createUserWithIdentity and linkIdentity store the email trimmed and lowercased (users.email too)', async () => {
      const { store } = await fresh();
      const user = await store.createUserWithIdentity({ ...IDENT, email: '  Ann@Example.test\t', emailVerified: true });
      expect(user.email).toBe('ann@example.test');
      expect((await store.findUserByIdentity('google', 'g1'))).toEqual({ ...user, identity: { email: 'ann@example.test', emailVerified: true } });
      await store.linkIdentity(user.id, { provider: 'github', subject: 'h1', email: ' BOB@Example.TEST ', emailVerified: true });
      expect((await store.findUserByIdentity('github', 'h1'))?.identity).toEqual({ email: 'bob@example.test', emailVerified: true });
    });

    it('an email that is empty after trimming is stored as no email', async () => {
      const { store } = await fresh();
      const user = await store.createUserWithIdentity({ ...IDENT, email: '   ', emailVerified: true });
      expect(user.email).toBeNull();
      expect((await store.findUserByIdentity('google', 'g1'))?.identity?.email ?? null).toBeNull();
    });

    it('emailBelongsToSuspendedUser trims and lowercases its argument', async () => {
      const { store, suspend } = await fresh();
      const user = await store.createUserWithIdentity({ ...IDENT, email: 'Person@Example.test', emailVerified: true });
      await suspend(user.id);
      expect(await store.emailBelongsToSuspendedUser('  PERSON@Example.test \n')).toBe(true);
      expect(await store.emailBelongsToSuspendedUser('   ')).toBe(false);
    });

    it('updateIdentity stores the email trimmed and lowercased and it stays matchable', async () => {
      const { store, suspend } = await fresh();
      if (!store.updateIdentity) throw new Error('updateIdentity missing');
      const user = await store.createUserWithIdentity({ ...IDENT, email: 'old@example.test', emailVerified: true });
      await suspend(user.id);
      await store.updateIdentity('google', 'g1', { email: ' New@Example.test ', emailVerified: true });
      expect((await store.findUserByIdentity('google', 'g1'))?.identity).toEqual({ email: 'new@example.test', emailVerified: true });
      expect(await store.emailBelongsToSuspendedUser('new@example.test')).toBe(true);
      expect(await store.emailBelongsToSuspendedUser('NEW@EXAMPLE.TEST')).toBe(true);
      expect(await store.emailBelongsToSuspendedUser('old@example.test')).toBe(false);
    });

    it('getSessionWithExpiry.verifiedEmail is null for an unverified identity email and the email when verified', async () => {
      const { store } = await fresh();
      const a = await store.createUserWithIdentity({ ...IDENT, email: 'a@example.test', emailVerified: false });
      await session(store, a.id, 'ha', future());
      const unverified = await store.getSessionWithExpiry('ha', new Date());
      expect(unverified?.user.email).toBe('a@example.test');
      expect(unverified?.verifiedEmail ?? null).toBeNull();
      const b = await store.createUserWithIdentity({ provider: 'github', subject: 'h2', email: 'b@example.test', emailVerified: true });
      await store.transaction((tx) => store.createSessionUnlessSuspended(b.id, 'hb', future(), { provider: 'github', subject: 'h2' }, tx));
      expect((await store.getSessionWithExpiry('hb', new Date()))?.verifiedEmail).toBe('b@example.test');
    });

    it('verifiedEmail is null for a verified identity with no stored email', async () => {
      const { store } = await fresh();
      const u = await store.createUserWithIdentity({ ...IDENT, emailVerified: true });
      await session(store, u.id, 'h1', future());
      expect((await store.getSessionWithExpiry('h1', new Date()))?.verifiedEmail ?? null).toBeNull();
    });

    it('verifiedEmail uses the identity the session was created with, not another linked identity', async () => {
      const { store } = await fresh();
      await store.createUserWithIdentity({ provider: 'google', subject: 'g2', email: 'other@example.test', emailVerified: true });
      const u = await store.createUserWithIdentity({ ...IDENT, email: 'g@example.test', emailVerified: false });
      await store.linkIdentity(u.id, { provider: 'github', subject: 'h2', email: 'h@example.test', emailVerified: true });
      await session(store, u.id, 'h1', future());
      expect((await store.getSessionWithExpiry('h1', new Date()))?.verifiedEmail ?? null).toBeNull();
      await store.transaction((tx) => store.createSessionUnlessSuspended(u.id, 'h2', future(), { provider: 'github', subject: 'h2' }, tx));
      expect((await store.getSessionWithExpiry('h2', new Date()))?.verifiedEmail).toBe('h@example.test');
    });

    it('verifiedEmail is null for the old user session once its identity has moved to another user', async () => {
      const { store, moveIdentity } = await fresh();
      const a = await store.createUserWithIdentity({ ...IDENT, email: 'a@example.test', emailVerified: true });
      const b = await store.createUserWithIdentity({ provider: 'github', subject: 'b1', emailVerified: false });
      await session(store, a.id, 'h1', future());
      expect((await store.getSessionWithExpiry('h1', new Date()))?.verifiedEmail).toBe('a@example.test');
      await moveIdentity(IDENT.provider, IDENT.subject, b.id);
      expect((await store.getSessionWithExpiry('h1', new Date()))?.verifiedEmail ?? null).toBeNull();
    });

    it('verifiedEmail follows updateIdentity (new email, unverified, cleared)', async () => {
      const { store } = await fresh();
      if (!store.updateIdentity) throw new Error('updateIdentity missing');
      const u = await store.createUserWithIdentity({ ...IDENT, email: 'old@example.test', emailVerified: true });
      await session(store, u.id, 'h1', future());
      const ve = async () => (await store.getSessionWithExpiry('h1', new Date()))?.verifiedEmail ?? null;
      expect(await ve()).toBe('old@example.test');
      await store.updateIdentity('google', 'g1', { email: 'new@example.test', emailVerified: true });
      expect(await ve()).toBe('new@example.test');
      await store.updateIdentity('google', 'g1', { emailVerified: false });
      expect(await ve()).toBeNull();
      await store.updateIdentity('google', 'g1', { emailVerified: true });
      expect(await ve()).toBe('new@example.test');
      await store.updateIdentity('google', 'g1', { email: null, emailVerified: true });
      expect(await ve()).toBeNull();
    });

    it('updateIdentity is a no-op for an unknown identity', async () => {
      const { store } = await fresh();
      if (!store.updateIdentity) throw new Error('updateIdentity missing');
      await expect(store.updateIdentity('google', 'nope', { email: 'x@example.test', emailVerified: true })).resolves.toBeUndefined();
      expect(await store.findUserByIdentity('google', 'nope')).toBeUndefined();
    });

    it('updateIdentity inside a transaction commits, and a rolled-back transaction keeps the old values', async () => {
      const { store, suspend } = await fresh();
      if (!store.updateIdentity) throw new Error('updateIdentity missing');
      const update = store.updateIdentity.bind(store);
      const user = await store.createUserWithIdentity({ ...IDENT, email: 'old@example.test', emailVerified: true });
      await suspend(user.id);
      await expect(store.transaction(async (tx) => {
        await update('google', 'g1', { email: 'new@example.test', emailVerified: true }, tx);
        expect(await store.emailBelongsToSuspendedUser('new@example.test', tx)).toBe(true);
        throw new Error('boom');
      })).rejects.toThrow('boom');
      expect(await store.emailBelongsToSuspendedUser('old@example.test')).toBe(true);
      expect(await store.emailBelongsToSuspendedUser('new@example.test')).toBe(false);
      await store.transaction((tx) => update('google', 'g1', { email: 'new@example.test', emailVerified: true }, tx));
      expect(await store.emailBelongsToSuspendedUser('new@example.test')).toBe(true);
      expect(await store.emailBelongsToSuspendedUser('old@example.test')).toBe(false);
    });

    it('transaction commits on success and returns the result', async () => {
      const { store } = await fresh();
      const user = await store.transaction((tx) => store.createUserWithIdentity({ ...IDENT, emailVerified: true }, tx));
      expect(await store.findUserByIdentity('google', 'g1')).toEqual({ ...user, identity: { email: null, emailVerified: true } });
    });

    it('transaction rolls back on throw and rethrows the original error', async () => {
      const { store } = await fresh();
      const boom = new Error('boom');
      await expect(store.transaction(async (tx) => {
        await store.createUserWithIdentity({ ...IDENT, emailVerified: true }, tx);
        throw boom;
      })).rejects.toBe(boom);
      expect(await store.findUserByIdentity('google', 'g1')).toBeUndefined();
    });

    it('getSessionWithExpiry returns createdAt', async () => {
      const { store, setCreatedAt } = await fresh();
      const user = await store.createUserWithIdentity({ ...IDENT, emailVerified: true });
      await session(store, user.id, 'h1', future());
      const t = new Date('2029-05-05T00:00:00.000Z');
      await setCreatedAt('h1', t);
      expect((await store.getSessionWithExpiry('h1', new Date(0)))?.createdAt?.getTime()).toBe(t.getTime());
    });

    it('purgeExpiredSessions with maxAgeMs also deletes sessions whose created_at + maxAgeMs <= now (boundary inclusive)', async () => {
      const { store, setCreatedAt } = await fresh();
      const user = await store.createUserWithIdentity({ ...IDENT, emailVerified: true });
      const now = new Date('2030-01-01T00:00:00.000Z');
      const MAX = 10 * 864e5;
      for (const h of ['old', 'edge', 'young']) await session(store, user.id, h, new Date(now.getTime() + 100 * 864e5));
      await session(store, user.id, 'expired', new Date(now.getTime() - 1));
      await setCreatedAt('old', new Date(now.getTime() - MAX - 1));
      await setCreatedAt('edge', new Date(now.getTime() - MAX));
      await setCreatedAt('young', new Date(now.getTime() - MAX + 1));
      await setCreatedAt('expired', new Date(now.getTime() - 1000));
      // Without the option only expiry counts.
      expect(await store.purgeExpiredSessions(now, {})).toBe(1);
      expect(await store.purgeExpiredSessions(now, { maxAgeMs: MAX })).toBe(2);
      const before = new Date(now.getTime() - 5000);
      expect(await store.getSessionWithExpiry('young', before)).toBeDefined();
      expect(await store.getSessionWithExpiry('old', before)).toBeUndefined();
      expect(await store.getSessionWithExpiry('edge', before)).toBeUndefined();
    });

    it('deleteSession takes an optional tx: it commits with the transaction and rolls back with it', async () => {
      const { store } = await fresh();
      const user = await store.createUserWithIdentity({ ...IDENT, emailVerified: true });
      await session(store, user.id, 'a', future());
      await session(store, user.id, 'b', future());
      await expect(store.transaction(async (tx) => {
        await store.deleteSession('a', tx);
        throw new Error('boom');
      })).rejects.toThrow('boom');
      expect(await store.getSessionWithExpiry('a', new Date())).toBeDefined();
      await store.transaction((tx) => store.deleteSession('a', tx));
      expect(await store.getSessionWithExpiry('a', new Date())).toBeUndefined();
      expect(await store.getSessionWithExpiry('b', new Date())).toBeDefined();
    });
  });
}
