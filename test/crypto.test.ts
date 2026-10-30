import { describe, expect, it } from 'vitest';
import { decrypt, encrypt, hashToken, randomToken, SecretError } from '../src/crypto.js';

const key = Buffer.alloc(32, 7);

describe('crypto', () => {
  it('round-trips a string', () => {
    expect(decrypt(encrypt('hello world', key), key)).toBe('hello world');
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
    try {
      decrypt([v, iv, tag, flipped].join(':'), key);
      expect.unreachable();
    } catch (e) {
      expect((e as Error).message).not.toContain(plain);
    }
  });

  it('hashToken is 64 hex chars and stable', () => {
    expect(hashToken('abc')).toMatch(/^[0-9a-f]{64}$/);
    expect(hashToken('abc')).toBe(hashToken('abc'));
  });

  it('randomToken differs on each call', () => {
    expect(randomToken()).not.toBe(randomToken());
  });
});
