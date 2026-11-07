import { afterEach, describe, expect, it } from 'vitest';
import type { AuthStore, TotpRecord } from '../src/types.js';
import type { StoreHarness } from './store-contract.js';

const IDENT = { provider: 'google', subject: 'g1' } as const;
const T0 = new Date('2026-01-01T00:00:00Z');
const at = (ms: number) => new Date(T0.getTime() + ms);
const future = () => new Date(Date.now() + 864e5);

type Full = AuthStore<any> & Required<Pick<AuthStore<any>,
  'getTotp' | 'setPendingTotpSecret' | 'confirmTotp' | 'deleteTotp' | 'consumeTotpStep' | 'recordTotpFailure' | 'resetTotpFailures'
  | 'consumeRecoveryCode' | 'replaceRecoveryCodes' | 'markSessionVerified' | 'markSessionPending' | 'incrementSessionMfaAttempts' | 'deleteOtherSessions'>>;

/** Behaviour every store used with `twoFactor` must have. Each test gets a fresh store from `make`. */
export function twoFactorStoreContract(name: string, make: () => Promise<StoreHarness>): void {
  describe(`two-factor store contract: ${name}`, () => {
    const open: StoreHarness[] = [];
    afterEach(async () => {
      for (const h of open.splice(0)) await h.close?.();
    });
    async function fresh() {
      const h = await make();
      open.push(h);
      const s = h.store as Full;
      const user = await s.createUserWithIdentity({ ...IDENT, email: 'a@example.test', emailVerified: true });
      return { h, s, user };
    }
    /** Enrols the user: pending secret then confirm with the given recovery hashes. */
    async function enrol(s: Full, userId: string, step = 100, hashes: string[] = ['h1', 'h2']) {
      await s.setPendingTotpSecret(userId, 'enc-1', T0);
      expect(await s.confirmTotp(userId, { expectedPendingEnc: 'enc-1', step, now: T0, recoveryCodeHashes: hashes })).toBe(true);
    }
    const session = (s: Full, userId: string, hash: string, expiresAt: Date, opts?: Parameters<Full['createSessionUnlessSuspended']>[5]) =>
      s.transaction((tx) => s.createSessionUnlessSuspended(userId, hash, expiresAt, IDENT, tx, opts));

    describe('totp record', () => {
      it('has no record until a secret is set', async () => {
        const { s, user } = await fresh();
        expect(await s.getTotp(user.id)).toBeUndefined();
      });

      it('stores a pending secret, and a second call replaces it', async () => {
        const { s, user } = await fresh();
        await s.setPendingTotpSecret(user.id, 'enc-a', T0);
        expect(await s.getTotp(user.id)).toEqual<TotpRecord>({
          secretEnc: null, pendingSecretEnc: 'enc-a', confirmedAt: null, lastStep: null, failedCount: 0, lockedUntil: null,
        });
        await s.setPendingTotpSecret(user.id, 'enc-b', T0);
        expect((await s.getTotp(user.id))?.pendingSecretEnc).toBe('enc-b');
      });

      it('confirmTotp promotes the pending secret, records the step and the recovery codes', async () => {
        const { s, user } = await fresh();
        await enrol(s, user.id, 123);
        const rec = (await s.getTotp(user.id))!;
        expect(rec.secretEnc).toBe('enc-1');
        expect(rec.pendingSecretEnc).toBeNull();
        expect(rec.confirmedAt?.getTime()).toBe(T0.getTime());
        expect(rec.lastStep).toBe(123);
        expect(await s.consumeRecoveryCode(user.id, 'h1', T0)).toBe(true);
      });

      it('confirmTotp refuses when the expected pending secret differs or is missing, and changes nothing', async () => {
        const { s, user } = await fresh();
        expect(await s.confirmTotp(user.id, { expectedPendingEnc: 'x', step: 1, now: T0, recoveryCodeHashes: ['z'] })).toBe(false);
        await s.setPendingTotpSecret(user.id, 'enc-a', T0);
        expect(await s.confirmTotp(user.id, { expectedPendingEnc: 'enc-other', step: 1, now: T0, recoveryCodeHashes: ['z'] })).toBe(false);
        const rec = (await s.getTotp(user.id))!;
        expect(rec.confirmedAt).toBeNull();
        expect(rec.pendingSecretEnc).toBe('enc-a');
        expect(await s.consumeRecoveryCode(user.id, 'z', T0)).toBe(false);
      });

      it('setting a new pending secret for an enrolled user leaves the active secret alone', async () => {
        const { s, user } = await fresh();
        await enrol(s, user.id);
        await s.setPendingTotpSecret(user.id, 'enc-2', at(1000));
        const rec = (await s.getTotp(user.id))!;
        expect(rec.secretEnc).toBe('enc-1');
        expect(rec.confirmedAt).not.toBeNull();
        expect(rec.pendingSecretEnc).toBe('enc-2');
      });

      it('confirming a replacement swaps the secret, resets the step and replaces the recovery codes', async () => {
        const { s, user } = await fresh();
        await enrol(s, user.id, 100, ['old']);
        await s.setPendingTotpSecret(user.id, 'enc-2', at(1000));
        expect(await s.confirmTotp(user.id, { expectedPendingEnc: 'enc-2', step: 5, now: at(1000), recoveryCodeHashes: ['new'] })).toBe(true);
        expect((await s.getTotp(user.id))?.secretEnc).toBe('enc-2');
        expect((await s.getTotp(user.id))?.lastStep).toBe(5);
        expect(await s.consumeRecoveryCode(user.id, 'old', T0)).toBe(false);
        expect(await s.consumeRecoveryCode(user.id, 'new', T0)).toBe(true);
      });

      it('deleteTotp removes the record and every recovery code', async () => {
        const { s, user } = await fresh();
        await enrol(s, user.id);
        await s.deleteTotp(user.id);
        expect(await s.getTotp(user.id)).toBeUndefined();
        expect(await s.consumeRecoveryCode(user.id, 'h1', T0)).toBe(false);
      });
    });

    describe('consumeTotpStep', () => {
      it('is false for a user with no confirmed secret', async () => {
        const { s, user } = await fresh();
        expect(await s.consumeTotpStep(user.id, 5, T0)).toBe(false);
        await s.setPendingTotpSecret(user.id, 'enc', T0);
        expect(await s.consumeTotpStep(user.id, 5, T0)).toBe(false);
      });

      it('accepts only a step greater than the last one', async () => {
        const { s, user } = await fresh();
        await enrol(s, user.id, 100);
        expect(await s.consumeTotpStep(user.id, 100, T0)).toBe(false);
        expect(await s.consumeTotpStep(user.id, 99, T0)).toBe(false);
        expect(await s.consumeTotpStep(user.id, 101, T0)).toBe(true);
        expect(await s.consumeTotpStep(user.id, 101, T0)).toBe(false);
        expect((await s.getTotp(user.id))?.lastStep).toBe(101);
      });

      it('concurrent requests with the same step: exactly one wins', async () => {
        const { s, user } = await fresh();
        await enrol(s, user.id, 100);
        const results = await Promise.all(Array.from({ length: 8 }, () => s.consumeTotpStep(user.id, 150, T0)));
        expect(results.filter(Boolean)).toHaveLength(1);
      });

      it('is refused while the user is locked, even for a higher step', async () => {
        const { s, user } = await fresh();
        await enrol(s, user.id, 100);
        await s.recordTotpFailure(user.id, { maxAttempts: 1, lockoutMs: 60_000, now: T0 });
        expect(await s.consumeTotpStep(user.id, 200, at(1000))).toBe(false);
        expect(await s.consumeTotpStep(user.id, 200, at(60_001))).toBe(true);
      });
    });

    describe('recordTotpFailure / resetTotpFailures', () => {
      it('counts wrong codes and locks at the limit', async () => {
        const { s, user } = await fresh();
        await enrol(s, user.id);
        const p = { maxAttempts: 3, lockoutMs: 60_000, now: T0 };
        expect(await s.recordTotpFailure(user.id, p)).toEqual({ locked: false, lockedUntil: null });
        expect(await s.recordTotpFailure(user.id, p)).toEqual({ locked: false, lockedUntil: null });
        const third = await s.recordTotpFailure(user.id, p);
        expect(third.locked).toBe(true);
        expect(third.lockedUntil?.getTime()).toBe(T0.getTime() + 60_000);
        expect((await s.getTotp(user.id))?.lockedUntil?.getTime()).toBe(T0.getTime() + 60_000);
      });

      it('an expired lock starts a fresh count', async () => {
        const { s, user } = await fresh();
        await enrol(s, user.id);
        await s.recordTotpFailure(user.id, { maxAttempts: 2, lockoutMs: 1000, now: T0 });
        await s.recordTotpFailure(user.id, { maxAttempts: 2, lockoutMs: 1000, now: T0 });
        const after = await s.recordTotpFailure(user.id, { maxAttempts: 2, lockoutMs: 1000, now: at(5000) });
        expect(after.locked).toBe(false);
        expect((await s.getTotp(user.id))?.failedCount).toBe(1);
      });

      it('concurrent failures are all counted', async () => {
        const { s, user } = await fresh();
        await enrol(s, user.id);
        await Promise.all(Array.from({ length: 4 }, () => s.recordTotpFailure(user.id, { maxAttempts: 100, lockoutMs: 1000, now: T0 })));
        expect((await s.getTotp(user.id))?.failedCount).toBe(4);
      });

      it('resetTotpFailures clears the count and the lock', async () => {
        const { s, user } = await fresh();
        await enrol(s, user.id);
        await s.recordTotpFailure(user.id, { maxAttempts: 1, lockoutMs: 60_000, now: T0 });
        await s.resetTotpFailures(user.id);
        const rec = (await s.getTotp(user.id))!;
        expect(rec.failedCount).toBe(0);
        expect(rec.lockedUntil).toBeNull();
      });

      it('is a no-op for a user without a record', async () => {
        const { s, user } = await fresh();
        expect(await s.recordTotpFailure(user.id, { maxAttempts: 1, lockoutMs: 1000, now: T0 })).toEqual({ locked: false, lockedUntil: null });
        await s.resetTotpFailures(user.id);
      });
    });

    describe('recovery codes', () => {
      it('a code works once', async () => {
        const { s, user } = await fresh();
        await enrol(s, user.id, 100, ['a', 'b']);
        expect(await s.consumeRecoveryCode(user.id, 'a', T0)).toBe(true);
        expect(await s.consumeRecoveryCode(user.id, 'a', T0)).toBe(false);
        expect(await s.consumeRecoveryCode(user.id, 'b', T0)).toBe(true);
        expect(await s.consumeRecoveryCode(user.id, 'nope', T0)).toBe(false);
      });

      it('concurrent use of one code: exactly one wins', async () => {
        const { s, user } = await fresh();
        await enrol(s, user.id, 100, ['only']);
        const results = await Promise.all(Array.from({ length: 8 }, () => s.consumeRecoveryCode(user.id, 'only', T0)));
        expect(results.filter(Boolean)).toHaveLength(1);
      });

      it('a recovery code is refused while the user is locked, and works after the lock', async () => {
        const { s, user } = await fresh();
        await enrol(s, user.id, 100, ['a']);
        await s.recordTotpFailure(user.id, { maxAttempts: 1, lockoutMs: 60_000, now: T0 });
        expect(await s.consumeRecoveryCode(user.id, 'a', at(1000))).toBe(false);
        expect(await s.consumeRecoveryCode(user.id, 'a', at(61_000))).toBe(true);
      });

      it('codes belong to one user', async () => {
        const { s, user } = await fresh();
        const other = await s.createUserWithIdentity({ provider: 'google', subject: 'g2', emailVerified: true });
        await enrol(s, user.id, 100, ['shared']);
        expect(await s.consumeRecoveryCode(other.id, 'shared', T0)).toBe(false);
      });

      it('replaceRecoveryCodes invalidates old codes, used or not', async () => {
        const { s, user } = await fresh();
        await enrol(s, user.id, 100, ['a', 'b']);
        await s.consumeRecoveryCode(user.id, 'a', T0);
        await s.replaceRecoveryCodes(user.id, ['c', 'a']);
        expect(await s.consumeRecoveryCode(user.id, 'b', T0)).toBe(false);
        expect(await s.consumeRecoveryCode(user.id, 'c', T0)).toBe(true);
        expect(await s.consumeRecoveryCode(user.id, 'a', T0)).toBe(true); // a fresh row, not the used one
      });
    });

    describe('pending sessions', () => {
      it('a pending session is returned as pending, with its redirect and expiry', async () => {
        const { s, user } = await fresh();
        const exp = at(600_000);
        expect(await session(s, user.id, 'p1', exp, { pending: { expiresAt: exp, redirect: '/memories' } })).toBe(true);
        const found = (await s.getSessionWithExpiry('p1', T0))!;
        expect(found.mfaPending).toBe(true);
        expect(found.mfaVerifiedAt ?? null).toBeNull();
        expect(found.mfaAttempts).toBe(0);
        expect(found.mfaRedirect).toBe('/memories');
        expect(found.expiresAt.getTime()).toBe(exp.getTime());
      });

      it('an ordinary session is not pending and has no verified time', async () => {
        const { s, user } = await fresh();
        await session(s, user.id, 'n1', future());
        const found = (await s.getSessionWithExpiry('n1', new Date()))!;
        expect(found.mfaPending).toBe(false);
        expect(found.mfaVerifiedAt ?? null).toBeNull();
      });

      it('a suspended user gets no pending session, and an existing one is hidden', async () => {
        const { h, s, user } = await fresh();
        await session(s, user.id, 'p1', future(), { pending: { expiresAt: future() } });
        await h.suspend(user.id);
        expect(await s.getSessionWithExpiry('p1', new Date())).toBeUndefined();
        expect(await session(s, user.id, 'p2', future(), { pending: { expiresAt: future() } })).toBe(false);
      });

      it('incrementSessionMfaAttempts counts atomically', async () => {
        const { s, user } = await fresh();
        await session(s, user.id, 'p1', future(), { pending: { expiresAt: future() } });
        const counts = await Promise.all(Array.from({ length: 5 }, () => s.incrementSessionMfaAttempts('p1')));
        expect([...counts].sort((a, b) => a - b)).toEqual([1, 2, 3, 4, 5]);
        expect((await s.getSessionWithExpiry('p1', new Date()))?.mfaAttempts).toBe(5);
      });

      it('incrementSessionMfaAttempts ignores a session that is not pending', async () => {
        const { s, user } = await fresh();
        await session(s, user.id, 'n1', future());
        expect(await s.incrementSessionMfaAttempts('n1')).toBe(0);
        expect(await s.incrementSessionMfaAttempts('missing')).toBe(0);
        await session(s, user.id, 'p1', future(), { pending: { expiresAt: future() } });
        await s.transaction((tx) => s.markSessionVerified('p1', user.id, { now: new Date(), expiresAt: future() }, tx));
        expect(await s.incrementSessionMfaAttempts('p1')).toBe(0);
      });

      it('markSessionVerified is false for a session that has already expired', async () => {
        const { s, user } = await fresh();
        await session(s, user.id, 'p1', at(1000), { pending: { expiresAt: at(1000) } });
        expect(await s.transaction((tx) => s.markSessionVerified('p1', user.id, { now: at(2000), expiresAt: at(9_999_999) }, tx))).toBe(false);
      });

      it('markSessionVerified clears pending, stamps the time, moves expiry and drops the redirect', async () => {
        const { s, user } = await fresh();
        await session(s, user.id, 'p1', future(), { pending: { expiresAt: future(), redirect: '/x' } });
        const newExp = new Date(Date.now() + 2 * 864e5);
        const now = new Date();
        expect(await s.transaction((tx) => s.markSessionVerified('p1', user.id, { now, expiresAt: newExp }, tx))).toBe(true);
        const found = (await s.getSessionWithExpiry('p1', new Date()))!;
        expect(found.mfaPending).toBe(false);
        expect(found.mfaVerifiedAt?.getTime()).toBe(now.getTime());
        expect(found.expiresAt.getTime()).toBe(newExp.getTime());
        expect(found.mfaRedirect ?? null).toBeNull();
      });

      it('markSessionVerified returns false for a suspended user, an unknown session or another users session', async () => {
        const { h, s, user } = await fresh();
        const other = await s.createUserWithIdentity({ provider: 'google', subject: 'g2', emailVerified: true });
        await session(s, user.id, 'p1', future(), { pending: { expiresAt: future() } });
        const args = { now: new Date(), expiresAt: future() };
        expect(await s.transaction((tx) => s.markSessionVerified('missing', user.id, args, tx))).toBe(false);
        expect(await s.transaction((tx) => s.markSessionVerified('p1', other.id, args, tx))).toBe(false);
        await h.suspend(user.id);
        expect(await s.transaction((tx) => s.markSessionVerified('p1', user.id, args, tx))).toBe(false);
      });

      it('markSessionPending turns an unverified session pending with the new expiry, and leaves verified ones alone', async () => {
        const { s, user } = await fresh();
        await session(s, user.id, 'old', future());
        const exp = new Date(Date.now() + 600_000);
        await s.markSessionPending('old', exp);
        const found = (await s.getSessionWithExpiry('old', new Date()))!;
        expect(found.mfaPending).toBe(true);
        expect(found.expiresAt.getTime()).toBe(exp.getTime());

        await session(s, user.id, 'done', future(), { pending: { expiresAt: future() } });
        await s.transaction((tx) => s.markSessionVerified('done', user.id, { now: new Date(), expiresAt: future() }, tx));
        const before = (await s.getSessionWithExpiry('done', new Date()))!.expiresAt.getTime();
        await s.markSessionPending('done', exp);
        const after = (await s.getSessionWithExpiry('done', new Date()))!;
        expect(after.mfaPending).toBe(false);
        expect(after.expiresAt.getTime()).toBe(before);
      });

      it('deleteOtherSessions keeps only the named session of that user', async () => {
        const { s, user } = await fresh();
        const other = await s.createUserWithIdentity({ provider: 'google', subject: 'g2', emailVerified: true });
        await session(s, user.id, 'a', future());
        await session(s, user.id, 'b', future());
        await session(s, other.id, 'c', future());
        expect(await s.deleteOtherSessions(user.id, 'a')).toBe(1);
        expect(await s.getSessionWithExpiry('a', new Date())).toBeDefined();
        expect(await s.getSessionWithExpiry('b', new Date())).toBeUndefined();
        expect(await s.getSessionWithExpiry('c', new Date())).toBeDefined();
      });
    });
  });
}
