import { afterEach, describe, expect, it } from 'vitest';
import { DuplicateIdentityError } from '../src/errors.js';
import type { AuthStore } from '../src/types.js';

export interface StoreHarness {
  store: AuthStore<any>;
  suspend(userId: string): Promise<void>;
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
      expect(user).toMatchObject({ email: 'a@example.test', name: 'Ann' });
      expect(await store.findUserByIdentity('google', 'g1')).toEqual(user);
      expect(await store.findUserByIdentity('google', 'other')).toBeUndefined();
      expect(await store.findUserByIdentity('github', 'g1')).toBeUndefined();
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

    it('transaction commits on success and returns the result', async () => {
      const { store } = await fresh();
      const user = await store.transaction((tx) => store.createUserWithIdentity({ ...IDENT, emailVerified: true }, tx));
      expect(await store.findUserByIdentity('google', 'g1')).toEqual(user);
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
  });
}
