import { describe, expect, it } from 'vitest';
import { createProviders, fetchGithubProfile, googleProfile, issOf, microsoftProfile, PROVIDER_ORDER } from '../src/providers.js';
import { fakeIdp, makeKey, type SignOptions } from './helpers/fake-fetch.js';

const providers = {
  google: { clientId: 'gid', clientSecret: 'gs' },
  microsoft: { clientId: 'mid', clientSecret: 'ms', tenant: 'common' },
  github: { clientId: 'ghid', clientSecret: 'ghs' },
};
const publicUrl = 'https://api.example.com';
const mk = (f?: typeof fetch, over: Partial<typeof providers> = {}, extra: { userAgent?: string; publicUrl?: string; clock?: () => Date } = {}) =>
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

describe('ID token signature verification (JWKS)', () => {
  const MS_ISS = 'https://login.microsoftonline.com/tid1/v2.0';
  const SIGNATURE_MSG = /signature|key|token/i;
  const ALG_MSG = /invalid response|signature|key|token|alg/i; // openid-client may reject the header first
  const MARKER = 'PLANTED-MARKER-9f3a';
  type Idp = Awaited<ReturnType<typeof fakeIdp>>;
  type Target = { label: string; setup: () => Promise<{ idp: Idp; exchange: () => Promise<unknown>; claims: Record<string, unknown>; mkp: (clock?: () => Date) => { exchange: () => Promise<unknown> } }> };
  const targets: Target[] = [
    {
      label: 'google',
      setup: async () => {
        const idp = await fakeIdp(G_ISSUER, `${G_ISSUER}/.well-known/openid-configuration`);
        const claims = { iss: G_ISSUER, aud: 'gid', sub: 'g1', nonce: 'nn' };
        const mkp = (clock?: () => Date) => { const p = mk(idp.fetchFn, {}, clock ? { clock } : {}).google!; return { exchange: () => p.exchange('c', VERIFIER, ctx) }; };
        return { idp, claims, mkp, exchange: mkp().exchange };
      },
    },
    {
      label: 'microsoft (tenant issuer)',
      setup: async () => {
        const idp = await fakeIdp(MS_ISSUER, MS_DISCOVERY);
        const claims = { iss: MS_ISS, tid: 'tid1', aud: 'mid', sub: 'm1', nonce: 'nn' };
        const mkp = (clock?: () => Date) => { const p = mk(idp.fetchFn, {}, clock ? { clock } : {}).microsoft!; return { exchange: () => p.exchange('c', VERIFIER, ctx) }; };
        return { idp, claims, mkp, exchange: mkp().exchange };
      },
    },
  ];

  for (const t of targets) {
    describe(t.label, () => {
      const rejects = async (opts: SignOptions, msg = SIGNATURE_MSG, prep?: (idp: Idp) => void) => {
        const { idp, claims, exchange } = await t.setup();
        prep?.(idp);
        await idp.sign(claims, opts);
        const err = (await exchange().then(() => undefined, (e: unknown) => e)) as Error;
        expect(err).toBeInstanceOf(Error);
        expect(err.message).toMatch(msg);
        expect(err.message).not.toContain(idp.lastToken());
        expect(err.message).not.toContain(MARKER);
        expect(err.message).not.toMatch(/"n"|"kty"|BEGIN/);
      };

      it('accepts a validly signed token', async () => {
        const { idp, claims, exchange } = await t.setup();
        await idp.sign(claims);
        await expect(exchange()).resolves.toMatchObject({ emailVerified: false });
      });
      it('rejects a signature from a different key', () => rejects({ wrongKey: true }));
      it('rejects a payload tampered after signing', () => rejects({ tamper: true }));
      it('rejects an unknown kid after exactly one refetch', async () => {
        const { idp, claims, exchange } = await t.setup();
        await idp.sign(claims, { kid: 'nope' });
        await expect(exchange()).rejects.toThrow(SIGNATURE_MSG);
        expect(idp.jwksCalls()).toBe(1);
      });
      it('rejects when the JWKS fetch fails on the network', () => rejects({}, SIGNATURE_MSG, (i) => { i.jwks.networkError = true; }));
      it('rejects when the JWKS fetch is non-OK', () => rejects({}, SIGNATURE_MSG, (i) => { i.jwks.status = 500; i.jwks.body = MARKER; }));
      it('rejects a non-JSON JWKS without leaking the body or a SyntaxError', () => rejects({}, SIGNATURE_MSG, (i) => { i.jwks.body = `<html>${MARKER}</html>`; }));
      it('rejects a JWKS of the wrong shape', async () => {
        await rejects({}, SIGNATURE_MSG, (i) => { i.jwks.body = JSON.stringify({ keys: 'x', marker: MARKER }); });
        await rejects({}, SIGNATURE_MSG, (i) => { i.jwks.body = JSON.stringify({ keys: [1, 'a'], marker: MARKER }); });
        await rejects({}, SIGNATURE_MSG, (i) => { i.jwks.body = JSON.stringify([MARKER]); });
        await rejects({}, SIGNATURE_MSG, (i) => { i.jwks.body = 'null'; });
      });
      it('rejects alg none', () => rejects({ alg: 'none' }, ALG_MSG));
      it('rejects HS256 signed with the public key as the HMAC secret', () => rejects({ alg: 'HS256' }, ALG_MSG));
      it('rejects an RS384 header', () => rejects({ alg: 'RS384' }, ALG_MSG));
      it('rejects an expired token', () => rejects({ expired: true }, /./));
      it('rejects a JWK that declares alg RS384', async () => {
        const k = makeKey({ kid: 'k1', jwkAlg: 'RS384' });
        await rejects({ key: k }, SIGNATURE_MSG, (i) => { i.jwks.keys = [k.jwk]; });
      });
      it('rejects a JWK with the wrong use or kty', async () => {
        const k = makeKey({ kid: 'k1', use: 'enc' });
        await rejects({ key: k }, SIGNATURE_MSG, (i) => { i.jwks.keys = [k.jwk]; });
        const k2 = makeKey({ kid: 'k1' });
        await rejects({ key: k2 }, SIGNATURE_MSG, (i) => { i.jwks.keys = [{ ...k2.jwk, kty: 'EC' }]; });
      });
      it('rejects a key under 2048 bits', async () => {
        const k = makeKey({ kid: 'k1', bits: 1024 });
        await rejects({ key: k }, SIGNATURE_MSG, (i) => { i.jwks.keys = [k.jwk]; });
      });
      it('accepts a JWK without alg', async () => {
        const { idp, claims, exchange } = await t.setup();
        const k = makeKey({ kid: 'k1', jwkAlg: null });
        idp.jwks.keys = [k.jwk];
        await idp.sign(claims, { key: k });
        await expect(exchange()).resolves.toBeDefined();
      });
      it('caches the JWKS: two logins make one JWKS fetch', async () => {
        const { idp, claims, exchange } = await t.setup();
        await idp.sign(claims);
        await exchange();
        await exchange();
        expect(idp.jwksCalls()).toBe(1);
      });
      it('refetches once on an unknown kid and succeeds when the new JWKS has it', async () => {
        const { idp, claims, exchange } = await t.setup();
        await idp.sign(claims);
        await exchange();
        expect(idp.jwksCalls()).toBe(1);
        const rotated = makeKey({ kid: 'k2' });
        idp.jwks.keys = [idp.mainKey.jwk, rotated.jwk];
        await idp.sign(claims, { key: rotated });
        await expect(exchange()).resolves.toBeDefined();
        expect(idp.jwksCalls()).toBe(2);
      });
      it('refetches once on an unknown kid and fails when the new JWKS still lacks it', async () => {
        const { idp, claims, exchange } = await t.setup();
        await idp.sign(claims);
        await exchange();
        await idp.sign(claims, { kid: 'ghost' });
        await expect(exchange()).rejects.toThrow(SIGNATURE_MSG);
        expect(idp.jwksCalls()).toBe(2);
      });
      it('concurrent logins with an unknown kid share ONE JWKS fetch', async () => {
        const { idp, claims, exchange } = await t.setup();
        await idp.sign(claims, { kid: 'nope' });
        const results = await Promise.allSettled([exchange(), exchange(), exchange()]);
        expect(results.map((r) => r.status)).toEqual(['rejected', 'rejected', 'rejected']);
        for (const r of results) expect((r as PromiseRejectedResult).reason.message).toMatch(SIGNATURE_MSG);
        expect(idp.jwksCalls()).toBe(1);
      });
      it('concurrent cold-cache logins share ONE JWKS fetch and all succeed', async () => {
        const { idp, claims, exchange } = await t.setup();
        await idp.sign(claims);
        await Promise.all([exchange(), exchange()]);
        expect(idp.jwksCalls()).toBe(1);
      });
      it('a concurrent rotation refetch is shared, and a failed shared fetch does not poison later retries', async () => {
        const { idp, claims, exchange } = await t.setup();
        await idp.sign(claims);
        await exchange();
        const rotated = makeKey({ kid: 'k2' });
        await idp.sign(claims, { key: rotated });
        idp.jwks.networkError = true;
        const failed = await Promise.allSettled([exchange(), exchange()]);
        expect(failed.map((r) => r.status)).toEqual(['rejected', 'rejected']);
        for (const r of failed) expect((r as PromiseRejectedResult).reason.message).toMatch(SIGNATURE_MSG);
        expect(idp.jwksCalls()).toBe(2); // 1 initial + exactly 1 shared failed refetch
        idp.jwks.networkError = false;
        idp.jwks.keys = [idp.mainKey.jwk, rotated.jwk];
        await expect(exchange()).resolves.toBeDefined();
        expect(idp.jwksCalls()).toBe(3);
      });
      it('does not cache a failed fetch', async () => {
        const { idp, claims, exchange } = await t.setup();
        await idp.sign(claims);
        idp.jwks.networkError = true;
        await expect(exchange()).rejects.toThrow(SIGNATURE_MSG);
        idp.jwks.networkError = false;
        await expect(exchange()).resolves.toBeDefined();
        expect(idp.jwksCalls()).toBe(2);
      });
      it('expires the cache after the 5 minute TTL', async () => {
        const { idp, claims, mkp } = await t.setup();
        let t0 = Date.now();
        const p = mkp(() => new Date(t0));
        await idp.sign(claims);
        await p.exchange();
        t0 += 4 * 60_000;
        await p.exchange();
        expect(idp.jwksCalls()).toBe(1);
        t0 += 2 * 60_000;
        await p.exchange();
        expect(idp.jwksCalls()).toBe(2);
      });
    });
  }
});
