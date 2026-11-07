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

/** Store methods the second factor cannot work (or fail closed) without. */
const TWO_FACTOR_STORE_METHODS = [
  'getTotp', 'setPendingTotpSecret', 'confirmTotp', 'deleteTotp', 'consumeTotpStep', 'recordTotpFailure', 'resetTotpFailures',
  'consumeRecoveryCode', 'replaceRecoveryCodes', 'markSessionVerified', 'markSessionPending', 'incrementSessionMfaAttempts', 'deleteOtherSessions',
] as const;

function validateTwoFactor(config: AuthConfig<any>): void {
  const tf: unknown = config.twoFactor;
  if (tf === undefined) return;
  if (typeof tf !== 'object' || tf === null || Array.isArray(tf)) throw new Error('Invalid auth config: twoFactor must be an object');
  const c = tf as Record<string, unknown>;
  if (typeof c.issuer !== 'string' || c.issuer.trim() === '') throw new Error('Invalid auth config: twoFactor.issuer must be a non-empty string');
  if (c.required !== undefined && typeof c.required !== 'boolean' && typeof c.required !== 'function') {
    throw new Error('Invalid auth config: twoFactor.required must be a boolean or a function');
  }
  if (c.verifyPath !== undefined && !(typeof c.verifyPath === 'string' && /^\/(?![/\\])/.test(c.verifyPath))) {
    throw new Error('Invalid auth config: twoFactor.verifyPath must be a path starting with a single "/"');
  }
  for (const key of ['pendingTtlMs', 'maxAttempts', 'lockoutMs', 'recoveryCodeCount'] as const) {
    const v = c[key];
    if (v === undefined) continue;
    if (!(typeof v === 'number' && Number.isFinite(v) && v > 0)) throw new Error(`Invalid auth config: twoFactor.${key} must be a positive finite number`);
    if ((key === 'maxAttempts' || key === 'recoveryCodeCount') && !Number.isInteger(v)) {
      throw new Error(`Invalid auth config: twoFactor.${key} must be a whole number`);
    }
  }
  const store = config.store as unknown as Record<string, unknown>;
  for (const m of TWO_FACTOR_STORE_METHODS) {
    if (typeof store[m] !== 'function') throw new Error(`Invalid auth config: twoFactor needs store.${m}, which this store does not implement`);
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
  if (hookTimeout !== undefined && !(typeof hookTimeout === 'number' && Number.isFinite(hookTimeout) && hookTimeout > 0 && hookTimeout <= 2147483647)) {
    throw new Error('Invalid auth config: onErrorTimeoutMs must be a positive finite number no greater than 2147483647');
  }
  const ttl = config.sessionTtlMs;
  if (ttl !== undefined && !(typeof ttl === 'number' && Number.isFinite(ttl) && ttl > 0)) {
    throw new Error('Invalid auth config: sessionTtlMs must be a positive finite number');
  }
  const maxAge = config.sessionMaxAgeMs;
  if (maxAge !== undefined && !(typeof maxAge === 'number' && Number.isFinite(maxAge) && maxAge > 0)) {
    throw new Error('Invalid auth config: sessionMaxAgeMs must be a positive finite number');
  }
  validateTwoFactor(config);
}

export type { Auth } from './handler.js';
export type { PendingSession, SessionResult, SessionUser } from './session.js';

/** Validates config and returns the framework-neutral core: `handle`, `getSession`, `requireSession`. */
export function createAuth<Tx = unknown>(config: AuthConfig<Tx>): Auth {
  validateConfig(config);
  return createHandler(config);
}
