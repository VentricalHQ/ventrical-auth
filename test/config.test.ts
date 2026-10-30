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
});
