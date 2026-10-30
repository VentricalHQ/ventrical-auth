import { describe, expect, it } from 'vitest';
import { createAuth, type AuthConfig, type AuthStore } from '../src/index.js';

const store = {} as AuthStore;

function base(): AuthConfig {
  return {
    providers: { google: { clientId: 'fake-id', clientSecret: 'fake-secret' } },
    publicUrl: 'https://api.example.test',
    frontendUrl: 'https://app.example.test',
    encryptionKey: Buffer.alloc(32, 1),
    store,
  };
}

describe('createAuth config validation', () => {
  it('createAuth throws when the key is not 32 bytes', () => {
    expect(() => createAuth({ ...base(), encryptionKey: Buffer.alloc(16) })).toThrow(/encryptionKey/);
  });

  it('createAuth throws when no provider is configured', () => {
    expect(() => createAuth({ ...base(), providers: {} })).toThrow(/providers/);
  });

  it('createAuth throws when publicUrl is not a URL', () => {
    const bad = 'not-a-url-secret-value';
    let msg = '';
    try {
      createAuth({ ...base(), publicUrl: bad });
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).toMatch(/publicUrl/);
    expect(msg).not.toContain(bad);
  });

  it('does not echo a wrong-length encryptionKey in the message', () => {
    const key = Buffer.from('super-secret-key-material');
    let msg = '';
    try {
      createAuth({ ...base(), encryptionKey: key });
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).toMatch(/encryptionKey/);
    expect(msg).not.toContain(key.toString());
    expect(msg).not.toContain(key.toString('hex'));
    expect(msg).not.toContain(key.toString('base64'));
  });

  it.each(['ftp://x.example.test', 'javascript:alert(1)', 'file:///etc/passwd'])('rejects non-http(s) URL %s', (bad) => {
    expect(() => createAuth({ ...base(), publicUrl: bad })).toThrow(/publicUrl/);
    expect(() => createAuth({ ...base(), frontendUrl: bad })).toThrow(/frontendUrl/);
  });

  it('accepts http URLs', () => {
    expect(() => createAuth({ ...base(), publicUrl: 'http://localhost:3000', frontendUrl: 'http://localhost:5173' })).not.toThrow();
  });

  it('requires non-empty provider credentials and microsoft tenant', () => {
    expect(() => createAuth({ ...base(), providers: { google: { clientId: '', clientSecret: 's' } } })).toThrow(/providers\.google\.clientId/);
    expect(() => createAuth({ ...base(), providers: { github: { clientId: 'i', clientSecret: '' } } })).toThrow(/providers\.github\.clientSecret/);
    expect(() => createAuth({ ...base(), providers: { microsoft: { clientId: 'i', clientSecret: 's', tenant: '' } } })).toThrow(/tenant/);
  });

  it.each([0, -1, NaN, Infinity, '5' as unknown as number])('rejects sessionTtlMs %s', (v) => {
    expect(() => createAuth({ ...base(), sessionTtlMs: v })).toThrow(/sessionTtlMs/);
  });

  it('accepts a positive sessionTtlMs', () => {
    expect(() => createAuth({ ...base(), sessionTtlMs: 1000 })).not.toThrow();
  });

  it('validates sessionMaxAgeMs like sessionTtlMs', () => {
    const msg = 'Invalid auth config: sessionMaxAgeMs must be a positive finite number';
    for (const bad of [0, -1, Number.NaN, Infinity, '90', null]) {
      expect(() => createAuth({ ...base(), sessionMaxAgeMs: bad as never })).toThrow(msg);
    }
    expect(() => createAuth({ ...base(), sessionMaxAgeMs: 1000 })).not.toThrow();
    expect(() => createAuth({ ...base() })).not.toThrow();
  });
});
