import { describe, expect, it } from 'vitest';
import { base32Decode } from '../src/base32.js';
import { hotp, totpStep } from '../src/totp.js';
import { tfSetup } from './helpers/two-factor.js';
import type { MemoryStore } from './helpers/memory-store.js';

const MAX = 5;
const N = 40;

/** Wraps a store so every call is counted by method name. */
function counting<S extends object>(store: S) {
  const calls: Record<string, number> = {};
  const proxy = new Proxy(store, {
    get(target, p: string) {
      const v = Reflect.get(target, p) as unknown;
      return typeof v === 'function'
        ? (...a: unknown[]) => { calls[p] = (calls[p] ?? 0) + 1; return (v as (...x: unknown[]) => unknown).apply(target, a); }
        : v;
    },
  });
  return { proxy, calls };
}

/** Distinct, well-formed 6-digit codes that are not the real code for the current or neighbouring steps. */
function wrongCodes(secretBytes: Uint8Array, nowMs: number, n: number): string[] {
  const bad = new Set([-2, -1, 0, 1, 2].map((o) => hotp(secretBytes, totpStep(nowMs) + o)));
  const out: string[] = [];
  for (let i = 1; out.length < n; i++) {
    const c = String(i * 7919 % 1000000).padStart(6, '0');
    if (!bad.has(c) && !out.includes(c)) out.push(c);
  }
  return out;
}

const statuses = (rs: { status: number }[]) => rs.map((r) => r.status);
const count = (rs: { status: number }[], s: number) => rs.filter((r) => r.status === s).length;

/**
 * Parallel wrong guesses must not outrun the lockout. Guarantee under test: the failure counter is reserved under a row
 * lock in the same transaction as the evaluation, so at most `maxAttempts` guesses are evaluated per lock window.
 */
export function twoFactorConcurrencyContract(name: string, make: () => Promise<{ store: MemoryStore; close?: () => Promise<void>; raw?: unknown }>): void {
  describe(`two-factor parallel attempts: ${name}`, () => {
    async function rig(tf: Record<string, unknown> = {}) {
      const h = await make();
      const { proxy, calls } = counting(h.store);
      const t = tfSetup({ store: proxy as MemoryStore, twoFactor: { maxAttempts: MAX, lockoutMs: 600_000, ...tf } });
      return { h, t, calls, done: async () => { await h.close?.(); } };
    }
    const reset = (calls: Record<string, number>) => { for (const k of Object.keys(calls)) delete calls[k]; };

    it('parallel wrong TOTP codes from many sessions of one user: exactly maxAttempts evaluated', async () => {
      const { t, calls, done } = await rig();
      const { secret } = await t.enrol(); t.nextStep();
      const sessions = [];
      for (let i = 0; i < N; i++) sessions.push(await t.signIn());
      const codes = wrongCodes(secret, t.clock.now.getTime(), N);
      reset(calls);
      const rs = await Promise.all(sessions.map((s, i) => t.post('/auth/2fa/verify', { code: codes[i] }, s.cookie)));
      expect(calls.recordTotpFailure).toBe(MAX);
      expect(count(rs, 401) + count(rs, 429)).toBe(N);
      expect(count(rs, 401)).toBe(MAX - 1);
      expect(count(rs, 429)).toBe(N - MAX + 1);
      await done();
    });

    it('parallel wrong TOTP codes on one session: at most maxAttempts evaluated, session is then gone', async () => {
      const { t, calls, done } = await rig({ maxAttempts: MAX });
      const { secret } = await t.enrol(); t.nextStep();
      const s = await t.signIn();
      const codes = wrongCodes(secret, t.clock.now.getTime(), N);
      reset(calls);
      const rs = await Promise.all(codes.map((c) => t.post('/auth/2fa/verify', { code: c }, s.cookie)));
      expect(calls.recordTotpFailure).toBeLessThanOrEqual(MAX);
      expect(statuses(rs).every((x) => [401, 429].includes(x))).toBe(true);
      const after = await t.post('/auth/2fa/verify', { code: 'x' }, s.cookie);
      expect(after.status).toBe(401);
      await done();
    });

    it('parallel wrong recovery codes from many sessions: exactly maxAttempts evaluated', async () => {
      const { t, calls, done } = await rig();
      await t.enrol('g1', { recoveryCodes: ['AAAAA-AAAAA'] }); t.nextStep();
      const sessions = [];
      for (let i = 0; i < N; i++) sessions.push(await t.signIn());
      reset(calls);
      const rs = await Promise.all(sessions.map((s, i) => t.post('/auth/2fa/verify', { recoveryCode: `BBBBB-${String(10000 + i)}` }, s.cookie)));
      expect(calls.recordTotpFailure).toBe(MAX);
      expect(calls.consumeRecoveryCode ?? 0).toBeLessThanOrEqual(MAX);
      expect(count(rs, 429)).toBe(N - MAX + 1);
      await done();
    });

    it('once parallel wrong guesses have engaged the lock, correct codes (TOTP and recovery) sent in parallel are all refused', async () => {
      const { t, done } = await rig();
      const { user, secret } = await t.enrol('g1', { recoveryCodes: ['GOODCODE23'] }); t.nextStep();
      const sessions: Awaited<ReturnType<typeof t.signIn>>[] = [];
      for (let i = 0; i < 20; i++) sessions.push(await t.signIn());
      const codes = wrongCodes(secret, t.clock.now.getTime(), N);
      const first = await Promise.all(codes.map((c, i) => t.post('/auth/2fa/verify', { code: c }, sessions[i % 10]!.cookie)));
      expect(count(first, 200)).toBe(0);
      expect((await t.store.getTotp(user.id))?.lockedUntil).not.toBeNull();
      const good = t.codeFor(secret);
      const rs = await Promise.all(sessions.slice(10).map((s, i) => t.post('/auth/2fa/verify', i % 2 ? { code: good } : { recoveryCode: 'GOODCODE23' }, s.cookie)));
      expect(statuses(rs)).toEqual(rs.map(() => 429));
      await done();
    });

    it('the same correct code submitted twice in parallel on one session: one 200, the other a plain not-pending refusal', async () => {
      const { t, done } = await rig();
      const { secret } = await t.enrol(); t.nextStep();
      const s = await t.signIn();
      const code = t.codeFor(secret);
      const rs = await Promise.all([t.post('/auth/2fa/verify', { code }, s.cookie), t.post('/auth/2fa/verify', { code }, s.cookie)]);
      expect(statuses(rs).sort()).toEqual([200, 409]);
      await done();
    });

    it('parallel wrong codes on disable and regenerate from full sessions: at most maxAttempts evaluated', async () => {
      const { t, calls, done } = await rig();
      const { user, secret } = await t.enrol(); t.nextStep();
      // Full sessions that passed 2FA.
      const full: Awaited<ReturnType<typeof t.signIn>>[] = [];
      for (let i = 0; i < 12; i++) {
        const s = await t.signIn();
        const ok = await t.post('/auth/2fa/verify', { code: t.codeFor(secret) }, s.cookie);
        expect(ok.status).toBe(200);
        t.nextStep();
        full.push(s);
      }
      const codes = wrongCodes(secret, t.clock.now.getTime(), 40);
      reset(calls);
      const rs = await Promise.all(codes.map((c, i) => t.post(i % 2 ? '/auth/2fa/disable' : '/auth/2fa/recovery-codes', { code: c }, full[i % full.length]!.cookie)));
      expect(calls.recordTotpFailure).toBe(MAX);
      expect(count(rs, 200)).toBe(0);
      expect((await t.store.getTotp(user.id))?.confirmedAt).not.toBeNull();
      await done();
    });

    it('parallel wrong codes on setup (replace) and confirm: at most maxAttempts evaluated', async () => {
      const { t, calls, done } = await rig();
      const { user, secret } = await t.enrol(); t.nextStep();
      const s = await t.signIn();
      expect((await t.post('/auth/2fa/verify', { code: t.codeFor(secret) }, s.cookie)).status).toBe(200);
      t.nextStep();
      const codes = wrongCodes(secret, t.clock.now.getTime(), 30);
      reset(calls);
      const rs = await Promise.all(codes.map((c, i) => t.post(i % 2 ? '/auth/2fa/setup' : '/auth/2fa/setup/confirm', { code: c }, s.cookie)));
      // Setup (replace) wrongs hit the lock; confirm has no pending secret so it never evaluates.
      expect(calls.recordTotpFailure ?? 0).toBeLessThanOrEqual(MAX);
      expect(count(rs, 200)).toBe(0);
      expect((await t.store.getTotp(user.id))?.lockedUntil).not.toBeNull();
      await done();
    });

    it('parallel wrong confirm codes during enrolment: at most maxAttempts evaluated', async () => {
      const { t, calls, done } = await rig();
      const s0 = await t.signIn();
      const setup = await t.post('/auth/2fa/setup', {}, s0.cookie);
      const secret = base32Decode(setup.json!.secret as string);
      const codes = wrongCodes(secret, t.clock.now.getTime(), 30);
      reset(calls);
      const rs = await Promise.all(codes.map((c) => t.post('/auth/2fa/setup/confirm', { code: c }, s0.cookie)));
      expect(calls.recordTotpFailure).toBe(MAX);
      expect(count(rs, 200)).toBe(0);
      await done();
    });
  });
}
