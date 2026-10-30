import { describe, expect, it } from 'vitest';
import {
  clearCookie, isSameOrigin, openOAuthState, parseCookies, safeRedirect, sameString,
  sealOAuthState, serializeCookie, OAUTH_STATE_MAX_AGE_SEC, type OAuthState,
} from '../src/cookies.js';

const key = Buffer.alloc(32, 9);
const state: OAuthState = { provider: 'google', state: 's1', codeVerifier: 'v1', nonce: 'n1', redirect: '/x', linkUserId: 'u1' };

describe('safeRedirect', () => {
  it('rejects open-redirect and control-character values', () => {
    for (const v of ['//evil.com', '/\\evil', '/a\nb', '/a\u0000b', '/a\u007fb', 'https://evil.com', 'x', '', 5, null, undefined, {}]) {
      expect(safeRedirect(v)).toBe('/');
    }
  });
  it('keeps a relative path with a query', () => {
    expect(safeRedirect('/settings?x=1')).toBe('/settings?x=1');
  });
});

describe('parseCookies', () => {
  it('skips undecodable values and keeps the first duplicate', () => {
    const c = parseCookies('a=1; bad=%E0%A4%A; a=2; q="x%20y"; novalue; =z');
    expect(c).toEqual({ a: '1', q: 'x y' });
  });
  it('returns empty for null', () => {
    expect(parseCookies(null)).toEqual({});
  });
});

describe('serializeCookie', () => {
  it('adds Secure only for https', () => {
    const on = serializeCookie('n', 'v w', { maxAgeSec: 60, secure: true, domain: 'example.test' });
    expect(on).toContain('n=v%20w');
    expect(on).toContain('HttpOnly');
    expect(on).toContain('SameSite=Lax');
    expect(on).toContain('Path=/');
    expect(on).toContain('Max-Age=60');
    expect(on).toContain('Domain=example.test');
    expect(on).toContain('Secure');
    const off = serializeCookie('n', 'v', { maxAgeSec: 60, secure: false });
    expect(off).not.toContain('Secure');
    expect(off).not.toContain('Domain');
  });
  it('clearCookie expires immediately', () => {
    const c = clearCookie('n', { maxAgeSec: 60, secure: true });
    expect(c).toContain('n=;');
    expect(c).toContain('Max-Age=0');
    expect(c).toContain('Secure');
  });
});

describe('oauth state', () => {
  it('round-trips and has a 10 minute life', () => {
    expect(openOAuthState(sealOAuthState(state, key), key)).toEqual(state);
    expect(OAUTH_STATE_MAX_AGE_SEC).toBe(600);
  });
  it('openOAuthState returns undefined for a tampered, empty or malformed value', () => {
    const sealed = sealOAuthState(state, key);
    expect(openOAuthState(undefined, key)).toBeUndefined();
    expect(openOAuthState('', key)).toBeUndefined();
    expect(openOAuthState('garbage', key)).toBeUndefined();
    const mid = Math.floor(sealed.length / 2);
    const tampered = sealed.slice(0, mid) + (sealed[mid] === 'A' ? 'B' : 'A') + sealed.slice(mid + 1);
    expect(tampered).not.toBe(sealed);
    expect(openOAuthState(tampered, key)).toBeUndefined();
    expect(openOAuthState(sealed, Buffer.alloc(32, 1))).toBeUndefined();
    const bad = sealOAuthState({ provider: 'g' } as unknown as OAuthState, key);
    expect(openOAuthState(bad, key)).toBeUndefined();
    const badNonce = sealOAuthState({ ...state, nonce: 5 } as unknown as OAuthState, key);
    expect(openOAuthState(badNonce, key)).toBeUndefined();
  });
  it('drops unknown fields', () => {
    const sealed = sealOAuthState({ ...state, kind: 'drive' } as unknown as OAuthState, key);
    expect(openOAuthState(sealed, key)).toEqual(state);
  });
});

describe('sameString', () => {
  it('compares', () => {
    expect(sameString('abc', 'abc')).toBe(true);
    expect(sameString('abc', 'abd')).toBe(false);
    expect(sameString('abc', 'abcd')).toBe(false);
  });
});

describe('isSameOrigin', () => {
  const f = 'https://app.example.test';
  const p = 'https://api.example.test:8443/base';
  const req = (h: Record<string, string>) => new Request('https://api.example.test/x', { headers: h });
  it('accepts frontendUrl and publicUrl origins', () => {
    expect(isSameOrigin(req({ origin: 'https://app.example.test' }), f, p)).toBe(true);
    expect(isSameOrigin(req({ origin: 'https://api.example.test:8443' }), f, p)).toBe(true);
    expect(isSameOrigin(req({ referer: 'https://app.example.test/page?q=1' }), f, p)).toBe(true);
  });
  it('rejects other origins, scheme/port mismatch and missing headers', () => {
    expect(isSameOrigin(req({ origin: 'https://evil.test' }), f, p)).toBe(false);
    expect(isSameOrigin(req({ origin: 'http://app.example.test' }), f, p)).toBe(false);
    expect(isSameOrigin(req({ origin: 'https://api.example.test' }), f, p)).toBe(false);
    expect(isSameOrigin(req({}), f, p)).toBe(false);
    expect(isSameOrigin(req({ origin: 'null' }), f, p)).toBe(false);
    expect(isSameOrigin(req({ origin: 'not a url' }), f, p)).toBe(false);
  });
  it('rejects suffix hosts, userinfo tricks and Origin: null with a valid Referer', () => {
    expect(isSameOrigin(req({ origin: 'https://app.example.test.evil.test' }), f, p)).toBe(false);
    expect(isSameOrigin(req({ origin: 'https://app.example.test@evil.test' }), f, p)).toBe(false);
    expect(isSameOrigin(req({ referer: 'https://app.example.test.evil.test/x' }), f, p)).toBe(false);
    expect(isSameOrigin(req({ referer: 'https://app.example.test@evil.test/x' }), f, p)).toBe(false);
    expect(isSameOrigin(req({ origin: 'null', referer: 'https://app.example.test/' }), f, p)).toBe(false);
  });
  it('prefers Origin over Referer', () => {
    expect(isSameOrigin(req({ origin: 'https://evil.test', referer: 'https://app.example.test/' }), f, p)).toBe(false);
  });
  it('returns false when configured urls are unparseable', () => {
    expect(isSameOrigin(req({ origin: 'https://app.example.test' }), 'nope', 'nope')).toBe(false);
  });
});
