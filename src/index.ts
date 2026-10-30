import type { AuthConfig } from './types.js';

export * from './types.js';
export { AuthHttpError, DuplicateIdentityError, SUSPENDED_MESSAGE } from './errors.js';

function isUrl(v: unknown): boolean {
  if (typeof v !== 'string') return false;
  try {
    new URL(v);
    return true;
  } catch {
    return false;
  }
}

/** Validates config. Error messages name the bad field, never its value. */
function validateConfig(config: AuthConfig<any>): void {
  if (!Buffer.isBuffer(config.encryptionKey) || config.encryptionKey.length !== 32) {
    throw new Error('Invalid auth config: encryptionKey must be a 32-byte Buffer');
  }
  const p = config.providers;
  if (!p || !(p.google || p.microsoft || p.github)) {
    throw new Error('Invalid auth config: providers must configure at least one provider');
  }
  if (!isUrl(config.publicUrl)) throw new Error('Invalid auth config: publicUrl must be a valid URL');
  if (!isUrl(config.frontendUrl)) throw new Error('Invalid auth config: frontendUrl must be a valid URL');
  if (!config.store) throw new Error('Invalid auth config: store is required');
}

/** Stub: validates config; the full implementation lands in later tasks. */
export function createAuth<Tx = unknown>(config: AuthConfig<Tx>): { config: AuthConfig<Tx> } {
  validateConfig(config);
  return { config };
}
