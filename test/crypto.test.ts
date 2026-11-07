import { createCipheriv, randomBytes } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { decrypt, encrypt, hashToken, randomToken, SecretError } from '../src/crypto.js';

const key = Buffer.alloc(32, 7);

describe('crypto', () => {
  it('round-trips a string', () => {
    expect(decrypt(encrypt('hello world', key), key)).toBe('hello world');
  });

  it('round-trips with an aad and emits the v2 format', () => {
    const blob = encrypt('hello', key, 'purpose-a');
    expect(blob.startsWith('v2:')).toBe(true);
    expect(decrypt(blob, key, 'purpose-a')).toBe('hello');
  });

  it('fails to open with a different aad, or with none', () => {
    const blob = encrypt('hello', key, 'purpose-a');
    expect(() => decrypt(blob, key, 'purpose-b')).toThrow(SecretError);
    expect(() => decrypt(blob, key)).toThrow(SecretError);
    expect(() => decrypt(encrypt('hello', key), key, 'purpose-a')).toThrow(SecretError);
  });

  it('rejects an old v1 blob', () => {
    const iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', key, iv, { authTagLength: 16 });
    const data = Buffer.concat([c.update('hello', 'utf8'), c.final()]);
    const v1 = ['v1', iv.toString('base64'), c.getAuthTag().toString('base64'), data.toString('base64')].join(':');
    expect(() => decrypt(v1, key)).toThrow(SecretError);
    expect(() => decrypt(v1, key, 'purpose-a')).toThrow(/version/);
  });

  it('rejects a key that is not 32 bytes', () => {
    expect(() => encrypt('x', Buffer.alloc(16))).toThrow(SecretError);
    expect(() => decrypt('v1:a:b:c', Buffer.alloc(16))).toThrow(SecretError);
  });

  it('rejects a tampered blob with SecretError', () => {
    const [v, iv, tag, data] = encrypt('hello world', key).split(':') as [string, string, string, string];
    const flipped = (data[0] === 'A' ? 'B' : 'A') + data.slice(1);
    expect(() => decrypt([v, iv, tag, flipped].join(':'), key)).toThrow(SecretError);
  });

  it('decrypt error message never contains the plaintext', () => {
    const plain = 'super-secret-plaintext';
    const [v, iv, tag, data] = encrypt(plain, key).split(':') as [string, string, string, string];
    const flipped = (data[0] === 'A' ? 'B' : 'A') + data.slice(1);
    let caught: unknown;
    try {
      decrypt([v, iv, tag, flipped].join(':'), key);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(SecretError);
    expect((caught as Error).message).not.toContain(plain);
  });

  it('hashToken is 64 hex chars and stable', () => {
    expect(hashToken('abc')).toMatch(/^[0-9a-f]{64}$/);
    expect(hashToken('abc')).toBe(hashToken('abc'));
  });

  it('randomToken differs on each call', () => {
    expect(randomToken()).not.toBe(randomToken());
  });
});

describe('recovery code storage', () => {
  it('is a keyed hash: not the plain SHA-256, different per key, same for a code however it is typed', async () => {
    const { recoveryCodeHash } = await import('../src/twofactor.js');
    const { hashToken } = await import('../src/crypto.js');
    const k1 = Buffer.alloc(32, 1);
    const k2 = Buffer.alloc(32, 2);
    expect(recoveryCodeHash(k1, 'ABCDE23456')).not.toBe(hashToken('ABCDE23456'));
    expect(recoveryCodeHash(k1, 'ABCDE23456')).not.toBe(recoveryCodeHash(k2, 'ABCDE23456'));
    expect(recoveryCodeHash(k1, 'abcde-23456')).toBe(recoveryCodeHash(k1, 'ABCDE23456'));
  });

  it('deriveSubkey separates labels and does not return the master key', async () => {
    const { deriveSubkey } = await import('../src/crypto.js');
    const k = Buffer.alloc(32, 9);
    expect(deriveSubkey(k, 'a').equals(deriveSubkey(k, 'b'))).toBe(false);
    expect(deriveSubkey(k, 'a').equals(k)).toBe(false);
    expect(deriveSubkey(k, 'a')).toHaveLength(32);
  });
});
