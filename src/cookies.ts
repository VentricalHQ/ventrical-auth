import { timingSafeEqual } from 'node:crypto';
import { decrypt, encrypt } from './crypto.js';

/** Life of the OAuth state cookie: 10 minutes. */
export const OAUTH_STATE_MAX_AGE_SEC = 10 * 60;

export interface CookieOptions {
  maxAgeSec: number;
  secure: boolean;
  domain?: string;
}

export function parseCookies(header: string | null): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const name = part.slice(0, i).trim();
    let value = part.slice(i + 1).trim();
    if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) value = value.slice(1, -1);
    try { value = decodeURIComponent(value); } catch { continue; }
    if (name && !(name in out)) out[name] = value;
  }
  return out;
}

function build(name: string, value: string, maxAgeSec: number, opts: CookieOptions, extra: string[] = []): string {
  const parts = [`${name}=${value}`, 'Path=/', `Max-Age=${Math.floor(maxAgeSec)}`, ...extra, 'HttpOnly', 'SameSite=Lax'];
  // A __Host- cookie is only accepted with Secure, Path=/ and no Domain, so those are forced for it (set and clear alike).
  const hostPrefixed = name.startsWith('__Host-');
  if (opts.domain && !hostPrefixed) parts.push(`Domain=${opts.domain}`);
  if (opts.secure || hostPrefixed) parts.push('Secure');
  return parts.join('; ');
}

export function serializeCookie(name: string, value: string, opts: CookieOptions): string {
  return build(name, encodeURIComponent(value), opts.maxAgeSec, opts);
}

export function clearCookie(name: string, opts: CookieOptions): string {
  return build(name, '', 0, opts, ['Expires=Thu, 01 Jan 1970 00:00:00 GMT']);
}

export interface OAuthState {
  provider: string;
  state: string;
  codeVerifier: string;
  /** OIDC nonce; unused by plain OAuth2 providers. */
  nonce?: string;
  redirect: string;
  linkUserId?: string;
}

export function sealOAuthState(s: OAuthState, key: Buffer): string {
  return encrypt(JSON.stringify(s), key);
}

/** Returns undefined when the value is missing, tampered with, or malformed. */
export function openOAuthState(raw: string | undefined, key: Buffer): OAuthState | undefined {
  if (!raw) return undefined;
  try {
    const v = JSON.parse(decrypt(raw, key)) as Partial<OAuthState> | null;
    if (!v || typeof v !== 'object') return undefined;
    if (typeof v.provider !== 'string' || typeof v.state !== 'string' || typeof v.codeVerifier !== 'string' || typeof v.redirect !== 'string') return undefined;
    if (v.nonce !== undefined && typeof v.nonce !== 'string') return undefined;
    if (v.linkUserId !== undefined && typeof v.linkUserId !== 'string') return undefined;
    const out: OAuthState = { provider: v.provider, state: v.state, codeVerifier: v.codeVerifier, redirect: v.redirect };
    if (v.nonce !== undefined) out.nonce = v.nonce;
    if (v.linkUserId !== undefined) out.linkUserId = v.linkUserId;
    return out;
  } catch {
    return undefined;
  }
}

/** Only a single-leading-slash relative path is allowed; anything else becomes `/`. */
export function safeRedirect(v: unknown): string {
  if (typeof v !== 'string' || !v.startsWith('/') || v.startsWith('//')) return '/';
  // eslint-disable-next-line no-control-regex
  if (v.includes('\\') || /[\u0000-\u001f\u007f]/.test(v)) return '/';
  return v;
}

/** Constant-time string comparison. */
export function sameString(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

function originOf(url: string): string | undefined {
  try {
    const o = new URL(url).origin;
    return o === 'null' ? undefined : o;
  } catch {
    return undefined;
  }
}

/** True when the request's Origin (else Referer) origin matches frontendUrl's or publicUrl's. */
export function isSameOrigin(request: Request, frontendUrl: string, publicUrl: string): boolean {
  const header = request.headers.get('origin') ?? request.headers.get('referer');
  if (!header) return false;
  const origin = originOf(header);
  if (!origin) return false;
  return origin === originOf(frontendUrl) || origin === originOf(publicUrl);
}
