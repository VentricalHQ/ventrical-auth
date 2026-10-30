import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

const VERSION = 'v2';
const ALGORITHM = 'aes-256-gcm';
const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;

export class SecretError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SecretError';
  }
}

function assertKey(key: Buffer): void {
  if (key.length !== KEY_BYTES) {
    throw new SecretError('encryption key must be 32 bytes');
  }
}

/**
 * Encrypts with AES-256-GCM. Output: `v2:<iv b64>:<tag b64>:<data b64>`.
 * `aad` is authenticated but not stored: a blob only opens with the same value (domain separation).
 */
export function encrypt(plain: string, key: Buffer, aad = ''): string {
  assertKey(key);
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const data = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [VERSION, iv.toString('base64'), tag.toString('base64'), data.toString('base64')].join(':');
}

/** Decrypts a blob produced by `encrypt`. Throws SecretError on any failure. */
export function decrypt(blob: string, key: Buffer, aad = ''): string {
  assertKey(key);
  const parts = blob.split(':');
  if (parts.length !== 4) {
    throw new SecretError('secret blob is malformed');
  }
  const [version, ivB64, tagB64, dataB64] = parts as [string, string, string, string];
  if (version !== VERSION) {
    throw new SecretError('unknown secret version');
  }
  const iv = Buffer.from(ivB64, 'base64');
  const tag = Buffer.from(tagB64, 'base64');
  if (iv.length !== IV_BYTES) {
    throw new SecretError('secret iv has invalid length');
  }
  if (tag.length !== TAG_BYTES) {
    throw new SecretError('secret tag has invalid length');
  }
  const data = Buffer.from(dataB64, 'base64');
  try {
    const decipher = createDecipheriv(ALGORITHM, key, iv, { authTagLength: TAG_BYTES });
    decipher.setAAD(Buffer.from(aad, 'utf8'));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
  } catch {
    // Deliberately no `cause`: the underlying error may carry data.
    throw new SecretError('secret could not be decrypted');
  }
}

/** SHA-256 hex digest. Used for session ids and MCP access tokens at rest. */
export function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

/** Random URL-safe token. Default 32 bytes of entropy. */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}
