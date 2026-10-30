import { createHandler, type Auth } from './handler.js';
import type { AuthConfig } from './types.js';

export * from './types.js';
export { AuthHttpError, DuplicateIdentityError, SUSPENDED_MESSAGE } from './errors.js';

function isHttpUrl(v: unknown): boolean {
  if (typeof v !== 'string') return false;
  try {
    const u = new URL(v);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

const nonEmpty = (v: unknown): boolean => typeof v === 'string' && v !== '';

/** Validates config. Error messages name the bad field, never its value. */
function validateConfig(config: AuthConfig<any>): void {
  if (!Buffer.isBuffer(config.encryptionKey) || config.encryptionKey.length !== 32) {
    throw new Error('Invalid auth config: encryptionKey must be a 32-byte Buffer');
  }
  const p = config.providers;
  if (!p || !(p.google || p.microsoft || p.github)) {
    throw new Error('Invalid auth config: providers must configure at least one provider');
  }
  for (const name of ['google', 'microsoft', 'github'] as const) {
    const c = p[name];
    if (c === undefined) continue;
    if (!c || typeof c !== 'object') throw new Error(`Invalid auth config: providers.${name} must be an object`);
    if (!nonEmpty(c.clientId)) throw new Error(`Invalid auth config: providers.${name}.clientId must be a non-empty string`);
    if (!nonEmpty(c.clientSecret)) throw new Error(`Invalid auth config: providers.${name}.clientSecret must be a non-empty string`);
  }
  if (p.microsoft && !nonEmpty(p.microsoft.tenant)) {
    throw new Error('Invalid auth config: providers.microsoft.tenant must be a non-empty string');
  }
  if (!isHttpUrl(config.publicUrl)) throw new Error('Invalid auth config: publicUrl must be an http or https URL');
  if (!isHttpUrl(config.frontendUrl)) throw new Error('Invalid auth config: frontendUrl must be an http or https URL');
  if (!config.store) throw new Error('Invalid auth config: store is required');
  const onError: unknown = config.hooks?.onError;
  if (onError !== undefined && typeof onError !== 'function') throw new Error('Invalid auth config: hooks.onError must be a function');
  const hookTimeout: unknown = config.onErrorTimeoutMs;
  if (hookTimeout !== undefined && !(typeof hookTimeout === 'number' && Number.isFinite(hookTimeout) && hookTimeout > 0)) {
    throw new Error('Invalid auth config: onErrorTimeoutMs must be a positive finite number');
  }
  const ttl = config.sessionTtlMs;
  if (ttl !== undefined && !(typeof ttl === 'number' && Number.isFinite(ttl) && ttl > 0)) {
    throw new Error('Invalid auth config: sessionTtlMs must be a positive finite number');
  }
}

export type { Auth } from './handler.js';

/** Validates config and returns the framework-neutral core: `handle`, `getSession`, `requireSession`. */
export function createAuth<Tx = unknown>(config: AuthConfig<Tx>): Auth {
  validateConfig(config);
  return createHandler(config);
}
