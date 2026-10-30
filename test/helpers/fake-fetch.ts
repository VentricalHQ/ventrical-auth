import { createHmac, createSign, generateKeyPairSync, type KeyObject } from 'node:crypto';

const b64u = (b: Buffer | string): string => Buffer.from(b).toString('base64url');

export interface FakeKey { kid: string; jwk: Record<string, unknown>; privateKey: KeyObject; publicPem: string }

/** A throwaway RSA key and its public JWK. `jwkAlg` null omits the JWK `alg` member. */
export function makeKey(o: { kid?: string; bits?: number; jwkAlg?: string | null; use?: string } = {}): FakeKey {
  const kid = o.kid ?? 'k1';
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: o.bits ?? 2048 });
  const jwk: Record<string, unknown> = { ...publicKey.export({ format: 'jwk' }), kid, use: o.use ?? 'sig' };
  if (o.jwkAlg !== null) jwk.alg = o.jwkAlg ?? 'RS256';
  return { kid, jwk, privateKey, publicPem: publicKey.export({ type: 'spki', format: 'pem' }).toString() };
}

export interface SignOptions {
  /** Sign with a key the JWKS does not publish (same kid). */
  wrongKey?: boolean;
  /** Change the payload after signing. */
  tamper?: boolean;
  /** Header alg. none is unsigned; HS256 uses the public key PEM as the HMAC secret; RS384 is validly signed. */
  alg?: 'none' | 'HS256' | 'RS384';
  /** Issue a token whose exp is in the past. */
  expired?: boolean;
  /** Sign with this key and use its kid. */
  key?: FakeKey;
  /** Header kid override. */
  kid?: string;
}

/** What the JWKS endpoint serves. `keys` is served as `{ keys }` unless `body` is set. */
export interface JwksMode { keys: Record<string, unknown>[]; body?: string; status?: number; networkError?: boolean }

/** Minimal offline IdP: discovery, JWKS and token endpoint served through an injected fetch; ID tokens signed with throwaway RSA keys. */
export async function fakeIdp(issuerTemplate: string, discoveryUrl: string, extraDiscovery: Record<string, unknown> = {}) {
  const main = makeKey();
  const other = makeKey();
  const jwks: JwksMode = { keys: [main.jwk] };
  let idToken = '';
  let jwksCalls = 0;
  const tokenBodies: URLSearchParams[] = [];
  const fetchFn = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input instanceof Request ? input.url : input);
    const json = (o: unknown) => new Response(JSON.stringify(o), { headers: { 'content-type': 'application/json' } });
    if (url === discoveryUrl) {
      return json({
        issuer: issuerTemplate, authorization_endpoint: 'https://idp.test/authorize', token_endpoint: 'https://idp.test/token',
        jwks_uri: 'https://idp.test/jwks', id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: ['client_secret_post'], code_challenge_methods_supported: ['S256'],
        ...extraDiscovery,
      });
    }
    if (url === 'https://idp.test/jwks') {
      jwksCalls++;
      if (jwks.networkError) throw new Error('network down');
      if (jwks.body !== undefined) return new Response(jwks.body, { status: jwks.status ?? 200 });
      return new Response(JSON.stringify({ keys: jwks.keys }), { status: jwks.status ?? 200, headers: { 'content-type': 'application/json' } });
    }
    if (url === 'https://idp.test/token') {
      tokenBodies.push(new URLSearchParams(String(init?.body)));
      return json({ access_token: 'at', token_type: 'bearer', id_token: idToken, expires_in: 3600 });
    }
    throw new Error(`unexpected fetch ${url}`);
  }) as typeof fetch;
  const sign = async (claims: Record<string, unknown>, opts: SignOptions = {}): Promise<void> => {
    const now = Math.floor(Date.now() / 1000);
    const key = opts.key ?? main;
    const alg = opts.alg ?? 'RS256';
    const head = b64u(JSON.stringify({ alg, kid: opts.kid ?? key.kid, typ: 'JWT' }));
    const exp = opts.expired ? now - 3600 : now + 300;
    const payload = { iat: now - (opts.expired ? 7200 : 0), exp, ...claims };
    const body = b64u(JSON.stringify(payload));
    let sig: Buffer;
    if (alg === 'none') sig = Buffer.alloc(0);
    else if (alg === 'HS256') sig = createHmac('sha256', key.publicPem).update(`${head}.${body}`).digest();
    else sig = createSign(alg === 'RS384' ? 'RSA-SHA384' : 'RSA-SHA256').update(`${head}.${body}`).sign(opts.wrongKey ? other.privateKey : key.privateKey);
    const finalBody = opts.tamper ? b64u(JSON.stringify({ ...payload, sub: 'attacker' })) : body;
    idToken = `${head}.${finalBody}.${b64u(sig)}`;
  };
  return { fetchFn, sign, tokenBodies, jwks, jwksCalls: () => jwksCalls, lastToken: () => idToken, mainKey: main };
}
