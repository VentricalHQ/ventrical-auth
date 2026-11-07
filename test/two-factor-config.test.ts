import { describe, expect, it } from 'vitest';
import { createAuth, type AuthConfig, type AuthStore } from '../src/index.js';
import { createMemoryStore, type MemoryTx } from './helpers/memory-store.js';

function base(over: Partial<AuthConfig<MemoryTx>> = {}): AuthConfig<MemoryTx> {
  return {
    providers: { google: { clientId: 'fake-id', clientSecret: 'fake-secret' } },
    publicUrl: 'https://api.example.test',
    frontendUrl: 'https://app.example.test',
    encryptionKey: Buffer.alloc(32, 1),
    store: createMemoryStore(),
    ...over,
  };
}
const withTf = (tf: unknown, store = createMemoryStore()) => base({ store, twoFactor: tf as never });

describe('twoFactor config validation', () => {
  it('accepts a minimal config and a full one', () => {
    expect(() => createAuth(withTf({ issuer: 'TrueMark' }))).not.toThrow();
    expect(() => createAuth(withTf({
      issuer: 'TrueMark', required: () => true, verifyPath: '/two-factor', pendingTtlMs: 1000, maxAttempts: 3, lockoutMs: 5000, recoveryCodeCount: 8,
    }))).not.toThrow();
  });

  it('requires a non-empty issuer', () => {
    for (const issuer of ['', '   ', undefined, 5]) expect(() => createAuth(withTf({ issuer }))).toThrow(/twoFactor\.issuer/);
  });

  it('rejects a non-object twoFactor', () => {
    expect(() => createAuth(withTf('yes'))).toThrow(/twoFactor/);
    expect(() => createAuth(withTf(null))).toThrow(/twoFactor/);
  });

  it('required must be a boolean or a function', () => {
    expect(() => createAuth(withTf({ issuer: 'X', required: 'yes' }))).toThrow(/twoFactor\.required/);
    expect(() => createAuth(withTf({ issuer: 'X', required: 1 }))).toThrow(/twoFactor\.required/);
  });

  it('verifyPath must be an absolute path on the frontend', () => {
    for (const verifyPath of ['2fa', '//evil.test', 'https://evil.test/x', '', 3]) {
      expect(() => createAuth(withTf({ issuer: 'X', verifyPath }))).toThrow(/twoFactor\.verifyPath/);
    }
  });

  it('numeric options must be positive and finite; counts must be integers', () => {
    for (const key of ['pendingTtlMs', 'maxAttempts', 'lockoutMs', 'recoveryCodeCount']) {
      for (const v of [0, -1, Infinity, NaN, '5']) {
        expect(() => createAuth(withTf({ issuer: 'X', [key]: v }))).toThrow(new RegExp(`twoFactor\\.${key}`));
      }
    }
    expect(() => createAuth(withTf({ issuer: 'X', maxAttempts: 2.5 }))).toThrow(/twoFactor\.maxAttempts/);
    expect(() => createAuth(withTf({ issuer: 'X', recoveryCodeCount: 1.5 }))).toThrow(/twoFactor\.recoveryCodeCount/);
  });

  it('does not echo bad values in the message', () => {
    let msg = '';
    try { createAuth(withTf({ issuer: 'X', verifyPath: 'secret-looking-value' })); } catch (e) { msg = (e as Error).message; }
    expect(msg).not.toContain('secret-looking-value');
  });

  it('throws at startup when the store lacks a 2FA method, naming the method', () => {
    const full = createMemoryStore();
    const methods = [
      'getTotp', 'setPendingTotpSecret', 'confirmTotp', 'deleteTotp', 'consumeTotpStep', 'recordTotpFailure', 'resetTotpFailures',
      'consumeRecoveryCode', 'replaceRecoveryCodes', 'markSessionVerified', 'markSessionPending', 'incrementSessionMfaAttempts', 'deleteOtherSessions',
    ] as const;
    for (const m of methods) {
      const partial = { ...full } as Record<string, unknown>;
      partial[m] = undefined;
      expect(() => createAuth(base({ store: partial as unknown as AuthStore<MemoryTx>, twoFactor: { issuer: 'X' } }))).toThrow(new RegExp(`store\\.${m}`));
    }
  });

  it('does not require the 2FA store methods when twoFactor is unset', () => {
    const bare = { ...createMemoryStore() } as Record<string, unknown>;
    for (const k of ['getTotp', 'consumeTotpStep', 'markSessionVerified']) delete bare[k];
    expect(() => createAuth(base({ store: bare as unknown as AuthStore<MemoryTx> }))).not.toThrow();
  });
});
