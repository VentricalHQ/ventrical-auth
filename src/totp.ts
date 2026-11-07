import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/** RFC 6238 with HMAC-SHA1, 6 digits, 30 second step. Fixed: authenticator apps ignore other parameters. */
export const TOTP_DIGITS = 6;
export const TOTP_PERIOD_SEC = 30;
const SECRET_BYTES = 20;
const RECOVERY_CODE_LENGTH = 10;
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** RFC 4226 HOTP: dynamic truncation of HMAC-SHA1 over the 8-byte big-endian counter. */
export function hotp(secret: Uint8Array, counter: number): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac('sha1', secret).update(msg).digest();
  const offset = mac[mac.length - 1]! & 0x0f;
  const bin = ((mac[offset]! & 0x7f) << 24) | (mac[offset + 1]! << 16) | (mac[offset + 2]! << 8) | mac[offset + 3]!;
  return String(bin % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, '0');
}

export const totpStep = (nowMs: number): number => Math.floor(nowMs / 1000 / TOTP_PERIOD_SEC);

export const totpAt = (secret: Uint8Array, nowMs: number): string => hotp(secret, totpStep(nowMs));

/**
 * Checks `code` against the current step and one either side. Returns the matched step, or undefined. All three steps
 * are always computed and compared in constant time, so timing does not reveal which (if any) matched.
 */
export function verifyTotp(secret: Uint8Array, code: string, nowMs: number): number | undefined {
  const given = code.replace(/\s/g, '');
  if (!/^\d{6}$/.test(given)) return undefined;
  const givenBuf = Buffer.from(given, 'ascii');
  const current = totpStep(nowMs);
  let matched: number | undefined;
  for (const step of [current - 1, current, current + 1]) {
    if (step < 0) continue;
    const expected = Buffer.from(hotp(secret, step), 'ascii');
    if (timingSafeEqual(expected, givenBuf)) matched = step;
  }
  return matched;
}

export const generateTotpSecret = (bytes = SECRET_BYTES): Buffer => randomBytes(bytes);

export function otpauthUri(p: { issuer: string; account: string; secret: string }): string {
  const issuer = encodeURIComponent(p.issuer);
  return `otpauth://totp/${issuer}:${encodeURIComponent(p.account)}?secret=${p.secret}&issuer=${issuer}`
    + `&algorithm=SHA1&digits=${TOTP_DIGITS}&period=${TOTP_PERIOD_SEC}`;
}

/** 10 random base32 characters (50 bits). 32 symbols divide 256, so masking a byte is unbiased. */
export function generateRecoveryCode(): string {
  const bytes = randomBytes(RECOVERY_CODE_LENGTH);
  let out = '';
  for (const b of bytes) out += BASE32[b & 31];
  return out;
}

export const normalizeRecoveryCode = (code: string): string => code.replace(/[\s-]/g, '').toUpperCase();
