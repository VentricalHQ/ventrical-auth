import * as oidc from 'openid-client';
import type { AuthConfig, ProviderName, ProviderProfile } from './types.js';

/** Saved at /start, plus the callback's `iss` (RFC 9207) when present; Google and others require it when their discovery advertises it. */
export interface ExchangeCtx { state: string; nonce: string; iss?: string }

/** The callback's `iss` as an optional ctx field; omitted (not undefined) when absent or repeated (RFC 9207). */
export const issOf = (query: URLSearchParams): { iss?: string } => {
  const all = query.getAll('iss');
  return all.length === 1 ? { iss: all[0]! } : {};
};

export interface AuthProvider {
  name: ProviderName;
  authorizeUrl(state: string, codeVerifier: string, nonce: string): URL | Promise<URL>;
  /** `ctx` carries the state and nonce saved at /start; OIDC providers verify them (plus iss and aud) in the ID token. */
  exchange(code: string, codeVerifier: string, ctx: ExchangeCtx): Promise<ProviderProfile>;
}

type Claims = Record<string, unknown>;
const str = (v: unknown): string | undefined => (typeof v === 'string' && v !== '' ? v : undefined);

function profile(subject: string, email: string | undefined, emailVerified: boolean, name: string | undefined): ProviderProfile {
  const p: ProviderProfile = { subject, emailVerified };
  if (email !== undefined) p.email = email;
  if (name !== undefined) p.name = name;
  return p;
}

export function googleProfile(claims: Claims): ProviderProfile {
  const sub = str(claims.sub);
  if (!sub) throw new Error('id token has no subject');
  const email = str(claims.email);
  return profile(sub, email, email !== undefined && claims.email_verified === true, str(claims.name));
}

/**
 * Entra ID has no email_verified claim: only the `email` claim, and only with xms_edov === true, counts as verified.
 * preferred_username is a display fallback and is never treated as verified.
 */
export function microsoftProfile(claims: Claims): ProviderProfile {
  const sub = str(claims.sub);
  if (!sub) throw new Error('id token has no subject');
  const email = str(claims.email);
  if (email !== undefined) return profile(sub, email, claims.xms_edov === true, str(claims.name));
  return profile(sub, str(claims.preferred_username), false, str(claims.name));
}

export async function fetchGithubProfile(accessToken: string, fetchFn: typeof fetch = fetch, userAgent = 'ventrical-auth'): Promise<ProviderProfile> {
  const headers = {
    authorization: `Bearer ${accessToken}`,
    accept: 'application/vnd.github+json',
    'user-agent': userAgent,
    'x-github-api-version': '2022-11-28',
  };
  const userRes = await fetchFn('https://api.github.com/user', { headers });
  if (!userRes.ok) throw new Error('github user request failed');
  const user = (await userRes.json()) as Claims;
  if (typeof user.id !== 'number' && typeof user.id !== 'string') throw new Error('github user has no id');

  const emailsRes = await fetchFn('https://api.github.com/user/emails', { headers });
  if (!emailsRes.ok) throw new Error('github emails request failed');
  const emails = (await emailsRes.json()) as Array<{ email?: unknown; primary?: unknown; verified?: unknown }>;
  const best = Array.isArray(emails) ? emails.find((e) => e.primary === true && e.verified === true && str(e.email)) : undefined;
  const name = str(user.name) ?? str(user.login);
  return best
    ? profile(String(user.id), str(best.email), true, name)
    : profile(String(user.id), str(user.email), false, name);
}

const GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token';
const GITHUB_AUTHORIZE_URL = 'https://github.com/login/oauth/authorize';

/** Lazily discovers the issuer once; a failed discovery is retried on the next call. */
export function cachedDiscovery(issuer: string, clientId: string, clientSecret: string, fetchFn: typeof fetch | undefined): () => Promise<oidc.Configuration> {
  let cached: Promise<oidc.Configuration> | undefined;
  return () => {
    cached ??= oidc.discovery(
      new URL(issuer), clientId, clientSecret, undefined,
      fetchFn ? { [oidc.customFetch]: fetchFn as unknown as oidc.CustomFetch } : undefined,
    ).catch((err: unknown) => { cached = undefined; throw err; });
    return cached;
  };
}

function oidcProvider(o: {
  name: 'google' | 'microsoft'; issuer: string; clientId: string; clientSecret: string; scopes: string[];
  redirectUri: string; toProfile: (c: Claims) => ProviderProfile; fetchFn: typeof fetch | undefined;
}): AuthProvider {
  const config = cachedDiscovery(o.issuer, o.clientId, o.clientSecret, o.fetchFn);
  return {
    name: o.name,
    authorizeUrl: async (state, verifier, nonce) => oidc.buildAuthorizationUrl(await config(), {
      redirect_uri: o.redirectUri, response_type: 'code', scope: o.scopes.join(' '), state, nonce,
      code_challenge: await oidc.calculatePKCECodeChallenge(verifier), code_challenge_method: 'S256',
    }),
    exchange: async (code, verifier, ctx) => {
      const cb = new URL(o.redirectUri);
      cb.searchParams.set('code', code);
      cb.searchParams.set('state', ctx.state);
      if (ctx.iss) cb.searchParams.set('iss', ctx.iss);
      // openid-client verifies state, nonce, signature, iss (incl. the Entra {tenantid} template vs the token's tid) and aud.
      // It also requires the callback's own iss parameter (RFC 9207) when discovery advertises it, as Google does, and checks it equals the issuer.
      const tokens = await oidc.authorizationCodeGrant(await config(), cb, {
        pkceCodeVerifier: verifier, expectedState: ctx.state, expectedNonce: ctx.nonce, idTokenExpected: true,
      });
      const claims = tokens.claims();
      if (!claims) throw new Error('no id token');
      return o.toProfile(claims as unknown as Claims);
    },
  };
}

/** Sign-in provider names in the order `/auth/providers` lists them. */
export const PROVIDER_ORDER: readonly ProviderName[] = ['google', 'github', 'microsoft'];

/** Builds only the providers whose credentials are configured. */
export function createProviders(opts: {
  providers: AuthConfig['providers']; publicUrl: string; fetch?: typeof fetch; userAgent?: string;
}): Partial<Record<ProviderName, AuthProvider>> {
  const fetchFn = opts.fetch;
  const doFetch = fetchFn ?? fetch;
  const userAgent = opts.userAgent ?? 'ventrical-auth';
  const redirect = (n: string) => `${opts.publicUrl.replace(/\/+$/, '')}/auth/${n}/callback`;
  const { google, microsoft, github } = opts.providers;
  const out: Partial<Record<ProviderName, AuthProvider>> = {};
  if (google) {
    out.google = oidcProvider({
      name: 'google', issuer: 'https://accounts.google.com', clientId: google.clientId,
      clientSecret: google.clientSecret, scopes: ['openid', 'email', 'profile'],
      redirectUri: redirect('google'), toProfile: googleProfile, fetchFn,
    });
  }
  if (microsoft) {
    out.microsoft = oidcProvider({
      name: 'microsoft', issuer: `https://login.microsoftonline.com/${microsoft.tenant}/v2.0`,
      clientId: microsoft.clientId, clientSecret: microsoft.clientSecret,
      scopes: ['openid', 'email', 'profile', 'offline_access'],
      redirectUri: redirect('microsoft'), toProfile: microsoftProfile, fetchFn,
    });
  }
  if (github) {
    const { clientId, clientSecret } = github;
    out.github = {
      name: 'github',
      // GitHub has no PKCE and no ID token: the verifier and nonce are ignored; state is checked by the route.
      authorizeUrl: (state) => {
        const u = new URL(GITHUB_AUTHORIZE_URL);
        u.searchParams.set('client_id', clientId);
        u.searchParams.set('redirect_uri', redirect('github'));
        u.searchParams.set('scope', 'read:user user:email');
        u.searchParams.set('state', state);
        return u;
      },
      exchange: async (code) => {
        const res = await doFetch(GITHUB_TOKEN_URL, {
          method: 'POST',
          headers: { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded', 'user-agent': userAgent },
          body: new URLSearchParams({ client_id: clientId, client_secret: clientSecret, code, redirect_uri: redirect('github') }),
        });
        if (!res.ok) throw new Error('github token request failed');
        const body = (await res.json()) as { access_token?: unknown };
        if (typeof body.access_token !== 'string' || body.access_token === '') throw new Error('github token request failed');
        return fetchGithubProfile(body.access_token, doFetch, userAgent);
      },
    };
  }
  return out;
}
