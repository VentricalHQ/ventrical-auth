import { describe, expect, it } from 'vitest';
import { createProviders, fetchGithubProfile, googleProfile, issOf, microsoftProfile, PROVIDER_ORDER } from '../src/providers.js';
import { fakeIdp, type SignOptions } from './helpers/fake-fetch.js';

const providers = {
  google: { clientId: 'gid', clientSecret: 'gs' },
  microsoft: { clientId: 'mid', clientSecret: 'ms', tenant: 'common' },
  github: { clientId: 'ghid', clientSecret: 'ghs' },
};
const publicUrl = 'https://api.example.com';
const mk = (f?: typeof fetch, over: Partial<typeof providers> = {}, extra: { userAgent?: string; publicUrl?: string } = {}) =>
  createProviders({ providers: { ...providers, ...over }, publicUrl, ...(f ? { fetch: f } : {}), ...extra });

const VERIFIER = 'verifier-verifier-verifier-verifier-verifier';

describe('createProviders enabled set', () => {
  it('builds only the configured providers', () => {
    const p = mk(undefined, { microsoft: undefined, github: undefined });
    expect(Object.keys(p)).toEqual(['google']);
  });
  it('builds github sign-in without google or microsoft', () => {
    const p = mk(undefined, { google: undefined, microsoft: undefined });
    expect(Object.keys(p)).toEqual(['github']);
  });
});

describe('createProviders authorize URLs', () => {
  it('google: PKCE S256, nonce and exact scopes', async () => {
    const idp = await fakeIdp('https://accounts.google.com', 'https://accounts.google.com/.well-known/openid-configuration');
    const p = mk(idp.fetchFn) as Required<ReturnType<typeof createProviders>>;
    const u = await p.google.authorizeUrl('st', VERIFIER, 'nn');
    expect(u.origin + u.pathname).toBe('https://idp.test/authorize');
    expect(u.searchParams.get('scope')).toBe('openid email profile');
    expect(u.searchParams.get('code_challenge_method')).toBe('S256');
    expect(u.searchParams.get('code_challenge')).toBeTruthy();
    expect(u.searchParams.get('state')).toBe('st');
    expect(u.searchParams.get('nonce')).toBe('nn');
    expect(u.searchParams.get('response_type')).toBe('code');
    expect(u.searchParams.get('redirect_uri')).toBe('https://api.example.com/auth/google/callback');
    expect(u.searchParams.get('client_id')).toBe('gid');
  });
  it('microsoft: PKCE S256 and exact scopes', async () => {
    const idp = await fakeIdp(MS_ISSUER, MS_DISCOVERY);
    const p = mk(idp.fetchFn) as Required<ReturnType<typeof createProviders>>;
    const u = await p.microsoft.authorizeUrl('st', VERIFIER, 'nn');
    expect(u.searchParams.get('scope')).toBe('openid email profile offline_access');
    expect(u.searchParams.get('code_challenge_method')).toBe('S256');
    expect(u.searchParams.get('code_challenge')).toBeTruthy();
    expect(u.searchParams.get('nonce')).toBe('nn');
    expect(u.searchParams.get('redirect_uri')).toBe('https://api.example.com/auth/microsoft/callback');
  });
  it('github: exact scopes and no PKCE', async () => {
    const u = await mk().github!.authorizeUrl('st', 'ignored', 'ignored');
    expect(u.origin + u.pathname).toBe('https://github.com/login/oauth/authorize');
    expect(u.searchParams.get('scope')).toBe('read:user user:email');
    expect(u.searchParams.get('code_challenge')).toBeNull();
    expect(u.searchParams.get('redirect_uri')).toBe('https://api.example.com/auth/github/callback');
    expect(u.searchParams.get('client_id')).toBe('ghid');
    expect(u.searchParams.get('state')).toBe('st');
  });
});

const MS_ISSUER = 'https://login.microsoftonline.com/{tenantid}/v2.0';
const MS_DISCOVERY = 'https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration';
const G_ISSUER = 'https://accounts.google.com';
const ctx = { state: 'st', nonce: 'nn' };

describe('google ID token verification (offline)', () => {
  const setup = async () => {
    const idp = await fakeIdp(G_ISSUER, `${G_ISSUER}/.well-known/openid-configuration`);
    return { idp, p: mk(idp.fetchFn).google! };
  };
  const good = { iss: G_ISSUER, aud: 'gid', sub: 'g1', email: 'a@x.com', email_verified: true, name: 'A', nonce: 'nn' };
  it('accepts a valid token, sends the PKCE verifier and maps the profile', async () => {
    const { idp, p } = await setup();
    await idp.sign(good);
    expect(await p.exchange('code1', VERIFIER, ctx)).toEqual({ subject: 'g1', email: 'a@x.com', emailVerified: true, name: 'A' });
    expect(idp.tokenBodies[0]!.get('code_verifier')).toBe(VERIFIER);
    expect(idp.tokenBodies[0]!.get('redirect_uri')).toBe('https://api.example.com/auth/google/callback');
  });
  it('rejects a wrong aud', async () => {
    const { idp, p } = await setup();
    await idp.sign({ ...good, aud: 'someone-else' });
    await expect(p.exchange('c', VERIFIER, ctx)).rejects.toThrow();
  });
  it('rejects a wrong iss', async () => {
    const { idp, p } = await setup();
    await idp.sign({ ...good, iss: 'https://evil.example' });
    await expect(p.exchange('c', VERIFIER, ctx)).rejects.toThrow();
  });
  it('rejects a wrong nonce', async () => {
    const { idp, p } = await setup();
    await idp.sign({ ...good, nonce: 'other' });
    await expect(p.exchange('c', VERIFIER, ctx)).rejects.toThrow();
  });
});

describe('callback iss parameter (RFC 9207, Google advertises authorization_response_iss_parameter_supported)', () => {
  const good = { iss: G_ISSUER, aud: 'gid', sub: 'g1', email: 'a@x.com', email_verified: true, name: 'A', nonce: 'nn' };
  const setup = async () => {
    const idp = await fakeIdp(G_ISSUER, `${G_ISSUER}/.well-known/openid-configuration`, { authorization_response_iss_parameter_supported: true });
    await idp.sign(good);
    return { idp, p: mk(idp.fetchFn).google! };
  };
  it('sign-in succeeds when the callback iss equals the issuer', async () => {
    const { p } = await setup();
    expect(await p.exchange('c', VERIFIER, { ...ctx, iss: G_ISSUER })).toMatchObject({ subject: 'g1' });
  });
  it('sign-in fails when the route passes no iss', async () => {
    const { p } = await setup();
    await expect(p.exchange('c', VERIFIER, ctx)).rejects.toThrow();
  });
  it('sign-in fails on a wrong iss', async () => {
    const { p } = await setup();
    await expect(p.exchange('c', VERIFIER, { ...ctx, iss: 'https://evil.example' })).rejects.toThrow();
  });
});

describe('microsoft ID token verification (offline, common tenant)', () => {
  const setup = async () => {
    const idp = await fakeIdp(MS_ISSUER, MS_DISCOVERY);
    return { idp, p: mk(idp.fetchFn).microsoft! };
  };
  const good = { iss: 'https://login.microsoftonline.com/tid1/v2.0', tid: 'tid1', aud: 'mid', sub: 'm1', email: 'a@x.com', xms_edov: true, nonce: 'nn' };
  it('accepts an issuer matching the token tid', async () => {
    const { idp, p } = await setup();
    await idp.sign(good);
    expect(await p.exchange('c', VERIFIER, ctx)).toMatchObject({ subject: 'm1', email: 'a@x.com', emailVerified: true });
  });
  it('rejects an issuer that does not match the token tid', async () => {
    const { idp, p } = await setup();
    await idp.sign({ ...good, iss: 'https://login.microsoftonline.com/other/v2.0' });
    await expect(p.exchange('c', VERIFIER, ctx)).rejects.toThrow();
  });
  it('rejects a wrong iss host', async () => {
    const { idp, p } = await setup();
    await idp.sign({ ...good, iss: 'https://evil.example/tid1/v2.0' });
    await expect(p.exchange('c', VERIFIER, ctx)).rejects.toThrow();
  });
  it('rejects a wrong aud', async () => {
    const { idp, p } = await setup();
    await idp.sign({ ...good, aud: 'other' });
    await expect(p.exchange('c', VERIFIER, ctx)).rejects.toThrow();
  });
});

describe('github token exchange', () => {
  it('posts the code to the token endpoint and reads the profile, without PKCE', async () => {
    const calls: Array<{ url: string; body?: URLSearchParams }> = [];
    const f = (async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      calls.push({ url, ...(init?.body ? { body: new URLSearchParams(String(init.body)) } : {}) });
      if (url === 'https://github.com/login/oauth/access_token') return new Response(JSON.stringify({ access_token: 'gho_x' }));
      if (url.endsWith('/user')) return new Response(JSON.stringify({ id: 7, login: 'o' }));
      return new Response(JSON.stringify([{ email: 'm@x.com', primary: true, verified: true }]));
    }) as typeof fetch;
    const p = await mk(f).github!.exchange('code9', 'ignored', ctx);
    expect(p).toEqual({ subject: '7', email: 'm@x.com', emailVerified: true, name: 'o' });
    const b = calls[0]!.body!;
    expect(b.get('code')).toBe('code9');
    expect(b.get('client_id')).toBe('ghid');
    expect(b.get('client_secret')).toBe('ghs');
    expect(b.get('redirect_uri')).toBe('https://api.example.com/auth/github/callback');
  });
  it('fails without echoing provider data when no access_token is returned', async () => {
    const f = (async () => new Response(JSON.stringify({ error: 'bad_verification_code', error_description: 'LEAK' }))) as typeof fetch;
    const err = await mk(f).github!.exchange('c', 'x', ctx).catch((e: Error) => e);
    expect(err).toBeInstanceOf(Error);
    expect(String((err as Error).message)).not.toContain('LEAK');
  });
});

describe('profile mapping', () => {
  it('google uses email_verified', () => {
    expect(googleProfile({ sub: '1', email: 'a@x.com', email_verified: true, name: 'A' })).toEqual({ subject: '1', email: 'a@x.com', emailVerified: true, name: 'A' });
    expect(googleProfile({ sub: '1', email: 'a@x.com', email_verified: false }).emailVerified).toBe(false);
    expect(() => googleProfile({})).toThrow();
  });
  it('microsoft is verified only with xms_edov === true and falls back to preferred_username', () => {
    expect(microsoftProfile({ sub: 's', email: 'a@x.com', xms_edov: true }).emailVerified).toBe(true);
    expect(microsoftProfile({ sub: 's', email: 'a@x.com', xms_edov: '1' }).emailVerified).toBe(false);
    expect(microsoftProfile({ sub: 's', email: 'a@x.com' }).emailVerified).toBe(false);
    const pu = microsoftProfile({ sub: 's', preferred_username: 'u@x.com', xms_edov: true });
    expect(pu.email).toBe('u@x.com');
    expect(pu.emailVerified).toBe(false);
  });
  const fakeFetch = (emails: unknown, emailsOk = true): typeof fetch => (async (url: string | URL | Request) => {
    const u = String(url);
    if (u.endsWith('/user')) return new Response(JSON.stringify({ id: 42, login: 'octo', name: null, email: 'pub@x.com' }));
    return new Response(JSON.stringify(emails), { status: emailsOk ? 200 : 500 });
  }) as typeof fetch;
  it('github takes the primary verified email and the numeric id as subject', async () => {
    const p = await fetchGithubProfile('tok', fakeFetch([
      { email: 'other@x.com', primary: false, verified: true },
      { email: 'main@x.com', primary: true, verified: true },
    ]));
    expect(p).toEqual({ subject: '42', email: 'main@x.com', emailVerified: true, name: 'octo' });
  });
  it('github without a primary verified email is unverified', async () => {
    const p = await fetchGithubProfile('tok', fakeFetch([{ email: 'main@x.com', primary: true, verified: false }]));
    expect(p.emailVerified).toBe(false);
  });
  it('github throws when the emails request fails', async () => {
    await expect(fetchGithubProfile('tok', fakeFetch([], false))).rejects.toThrow();
  });
});

describe('ventrical-auth additions', () => {
  it('PROVIDER_ORDER is google, github, microsoft', () => {
    expect([...PROVIDER_ORDER]).toEqual(['google', 'github', 'microsoft']);
  });
  it('issOf returns iss only for a single string', () => {
    expect(issOf(new URLSearchParams('iss=https%3A%2F%2Fx.test&state=s'))).toEqual({ iss: 'https://x.test' });
    expect(issOf(new URLSearchParams('state=s'))).toEqual({});
    expect(issOf(new URLSearchParams('iss='))).toEqual({ iss: '' });
  });
  it('trims trailing slashes from publicUrl in redirect URIs', async () => {
    const u = await mk(undefined, {}, { publicUrl: 'https://api.example.com//' }).github!.authorizeUrl('s', 'v', 'n');
    expect(u.searchParams.get('redirect_uri')).toBe('https://api.example.com/auth/github/callback');
  });
  it('github user-agent defaults to ventrical-auth and honours userAgent', async () => {
    const seen: string[] = [];
    const f = (async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      seen.push(String((init?.headers as Record<string, string>)['user-agent']));
      if (url.endsWith('/access_token')) return new Response(JSON.stringify({ access_token: 't' }));
      if (url.endsWith('/user')) return new Response(JSON.stringify({ id: 1, login: 'o' }));
      return new Response('[]');
    }) as typeof fetch;
    await mk(f).github!.exchange('c', 'v', ctx);
    expect(new Set(seen)).toEqual(new Set(['ventrical-auth']));
    seen.length = 0;
    await mk(f, {}, { userAgent: 'my-app/1' }).github!.exchange('c', 'v', ctx);
    expect(new Set(seen)).toEqual(new Set(['my-app/1']));
  });
  it('github profile throws without a user id, and errors carry no response data', async () => {
    const f = (async (u: string | URL | Request) =>
      String(u).endsWith('/user') ? new Response(JSON.stringify({ login: 'LEAK' })) : new Response('[]')) as typeof fetch;
    const err = await fetchGithubProfile('SECRET', f).catch((e: Error) => e);
    expect((err as Error).message).not.toMatch(/LEAK|SECRET/);
  });
  it('an ID token without sub is rejected', async () => {
    const idp = await fakeIdp(G_ISSUER, `${G_ISSUER}/.well-known/openid-configuration`);
    await idp.sign({ iss: G_ISSUER, aud: 'gid', email: 'a@x.com', nonce: 'nn' });
    await expect(mk(idp.fetchFn).google!.exchange('c', VERIFIER, ctx)).rejects.toThrow();
  });
  it('a failed discovery is retried and the error message holds no response body', async () => {
    let n = 0;
    const idp = await fakeIdp(G_ISSUER, `${G_ISSUER}/.well-known/openid-configuration`);
    const f = (async (i: string | URL | Request, init?: RequestInit) => {
      if (n++ === 0) return new Response('LEAKBODY', { status: 500 });
      return idp.fetchFn(i, init);
    }) as typeof fetch;
    const p = mk(f).google!;
    const err = await Promise.resolve(p.authorizeUrl('s', VERIFIER, 'n')).then(() => undefined, (e: Error) => e);
    expect(err).toBeDefined();
    expect(String((err as Error).message)).not.toContain('LEAKBODY');
    await expect(p.authorizeUrl('s', VERIFIER, 'n')).resolves.toBeInstanceOf(URL);
  });
});

describe('RFC 9207 duplicate iss', () => {
  it('issOf rejects repeated iss', () => {
    expect(issOf(new URLSearchParams('?iss=a&iss=b'))).toEqual({});
    expect(issOf(new URLSearchParams('?iss=a&iss=a'))).toEqual({});
  });
  it('a duplicated iss fails the callback when the provider advertises iss', async () => {
    const idp = await fakeIdp(G_ISSUER, `${G_ISSUER}/.well-known/openid-configuration`, { authorization_response_iss_parameter_supported: true });
    await idp.sign({ iss: G_ISSUER, aud: 'gid', sub: 'g1', nonce: 'nn' });
    const p = mk(idp.fetchFn).google!;
    const q = new URLSearchParams(`iss=${encodeURIComponent(G_ISSUER)}&iss=${encodeURIComponent(G_ISSUER)}`);
    await expect(p.exchange('c', VERIFIER, { ...ctx, ...issOf(q) })).rejects.toThrow();
    await expect(p.exchange('c', VERIFIER, { ...ctx, ...issOf(new URLSearchParams(`iss=${encodeURIComponent(G_ISSUER)}`)) })).resolves.toMatchObject({ subject: 'g1' });
  });
});

describe('ID token signature and lifetime failures', () => {
  const MS_ISS = 'https://login.microsoftonline.com/tid1/v2.0';
  const cases: Array<[string, SignOptions]> = [
    ['signed with a different key', { wrongKey: true }],
    ['payload tampered after signing', { tamper: true }],
    ['alg none', { alg: 'none' }],
    ['expired', { expired: true }],
  ];
  for (const [label, opts] of cases) {
    it(`google rejects a token ${label}`, async () => {
      const idp = await fakeIdp(G_ISSUER, `${G_ISSUER}/.well-known/openid-configuration`);
      await idp.sign({ iss: G_ISSUER, aud: 'gid', sub: 'g1', nonce: 'nn' }, opts);
      await expect(mk(idp.fetchFn).google!.exchange('c', VERIFIER, ctx)).rejects.toThrow();
    });
    it(`microsoft rejects a token ${label}`, async () => {
      const idp = await fakeIdp(MS_ISSUER, MS_DISCOVERY);
      await idp.sign({ iss: MS_ISS, tid: 'tid1', aud: 'mid', sub: 'm1', nonce: 'nn' }, opts);
      await expect(mk(idp.fetchFn).microsoft!.exchange('c', VERIFIER, ctx)).rejects.toThrow();
    });
  }
});
