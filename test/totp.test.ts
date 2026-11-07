import { describe, expect, it } from 'vitest';
import { base32Decode, base32Encode } from '../src/base32.js';
import {
  generateRecoveryCode, generateTotpSecret, hotp, normalizeRecoveryCode, otpauthUri, totpAt, totpStep, verifyTotp,
} from '../src/totp.js';

// RFC 6238 appendix B, SHA-1, secret "12345678901234567890", 8-digit values; we use the last 6 digits.
const RFC_SECRET = Buffer.from('12345678901234567890', 'ascii');
const VECTORS: Array<[number, string]> = [
  [59, '287082'], [1111111109, '081804'], [1111111111, '050471'],
  [1234567890, '005924'], [2000000000, '279037'], [20000000000, '353130'],
];

describe('base32 (RFC 4648, no padding)', () => {
  it('matches the RFC 4648 vectors', () => {
    const cases: Array<[string, string]> = [['', ''], ['f', 'MY'], ['fo', 'MZXQ'], ['foo', 'MZXW6'], ['foob', 'MZXW6YQ'], ['fooba', 'MZXW6YTB'], ['foobar', 'MZXW6YTBOI']];
    for (const [plain, enc] of cases) {
      expect(base32Encode(Buffer.from(plain))).toBe(enc);
      expect(base32Decode(enc).toString()).toBe(plain);
    }
  });
  it('round-trips random bytes of every length', () => {
    for (let n = 0; n < 40; n++) {
      const b = generateTotpSecret(n || 1);
      expect(base32Decode(base32Encode(b)).equals(b)).toBe(true);
    }
  });
  it('decodes case-insensitively and ignores spaces, dashes and padding', () => {
    expect(base32Decode('mzxw 6ytb-oi==').toString()).toBe('foobar');
  });
  it('rejects characters outside the alphabet', () => {
    expect(() => base32Decode('MZXW1')).toThrow();
    expect(() => base32Decode('MZXW!')).toThrow();
  });
});

describe('hotp / totp (RFC 6238, SHA-1, 6 digits, 30 s)', () => {
  it('matches the RFC 6238 test vectors', () => {
    for (const [t, code] of VECTORS) expect(totpAt(RFC_SECRET, t * 1000)).toBe(code);
  });
  it('hotp matches RFC 4226 appendix D', () => {
    const expected = ['755224', '287082', '359152', '969429', '338314', '254676', '287922', '162583', '399871', '520489'];
    expected.forEach((code, counter) => expect(hotp(RFC_SECRET, counter)).toBe(code));
  });
  it('totpStep is floor(seconds / 30)', () => {
    expect(totpStep(59_000)).toBe(1);
    expect(totpStep(60_000)).toBe(2);
    expect(totpStep(0)).toBe(0);
  });
});

describe('verifyTotp window', () => {
  const now = 1_700_000_000_000;
  const step = totpStep(now);
  const at = (s: number) => hotp(RFC_SECRET, s);
  it('accepts steps -1, 0, +1 and returns the matched step', () => {
    expect(verifyTotp(RFC_SECRET, at(step), now)).toBe(step);
    expect(verifyTotp(RFC_SECRET, at(step - 1), now)).toBe(step - 1);
    expect(verifyTotp(RFC_SECRET, at(step + 1), now)).toBe(step + 1);
  });
  it('rejects steps -2 and +2', () => {
    expect(verifyTotp(RFC_SECRET, at(step - 2), now)).toBeUndefined();
    expect(verifyTotp(RFC_SECRET, at(step + 2), now)).toBeUndefined();
  });
  it('tolerates spaces and rejects malformed codes', () => {
    const c = at(step);
    expect(verifyTotp(RFC_SECRET, `${c.slice(0, 3)} ${c.slice(3)}`, now)).toBe(step);
    for (const bad of ['', '12345', '1234567', 'abcdef', '12345a', ' ']) expect(verifyTotp(RFC_SECRET, bad, now)).toBeUndefined();
  });
});

describe('otpauthUri', () => {
  it('has the fixed google-authenticator shape', () => {
    const uri = otpauthUri({ issuer: 'TrueMark', account: 'a@b.test', secret: 'JBSWY3DPEHPK3PXP' });
    expect(uri).toBe('otpauth://totp/TrueMark:a%40b.test?secret=JBSWY3DPEHPK3PXP&issuer=TrueMark&algorithm=SHA1&digits=6&period=30');
  });
  it('percent-encodes issuer and account, including a colon', () => {
    const uri = otpauthUri({ issuer: 'My App: Prod', account: 'x y', secret: 'AAAA' });
    expect(uri.startsWith('otpauth://totp/My%20App%3A%20Prod:x%20y?')).toBe(true);
    expect(new URL(uri).searchParams.get('issuer')).toBe('My App: Prod');
  });
});

describe('secrets and recovery codes', () => {
  it('a secret is 20 random bytes', () => {
    const a = generateTotpSecret();
    expect(a.length).toBe(20);
    expect(a.equals(generateTotpSecret())).toBe(false);
  });
  it('a recovery code is 10 base32 characters', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 200; i++) {
      const c = generateRecoveryCode();
      expect(c).toMatch(/^[A-Z2-7]{10}$/);
      seen.add(c);
    }
    expect(seen.size).toBe(200);
  });
  it('normalizeRecoveryCode strips spaces and dashes and uppercases', () => {
    expect(normalizeRecoveryCode(' abcde-fgh23 ')).toBe('ABCDEFGH23');
  });
});
