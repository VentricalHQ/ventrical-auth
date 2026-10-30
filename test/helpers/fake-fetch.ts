import { createSign, generateKeyPairSync } from 'node:crypto';

const b64u = (b: Buffer | string): string => Buffer.from(b).toString('base64url');

export interface SignOptions {
  /** Sign with a key the JWKS does not publish. */
  wrongKey?: boolean;
  /** Change the payload after signing. */
  tamper?: boolean;
  /** Unsigned token with alg none. */
  alg?: 'none';
  /** Issue a token whose exp is in the past. */
  expired?: boolean;
}

/** Minimal offline IdP: discovery, JWKS and token endpoint served through an injected fetch; ID tokens signed with a throwaway RSA key. */
export async function fakeIdp(issuerTemplate: string, discoveryUrl: string, extraDiscovery: Record<string, unknown> = {}) {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256', use: 'sig' };
  let idToken = '';
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
    if (url === 'https://idp.test/jwks') return json({ keys: [jwk] });
    if (url === 'https://idp.test/token') {
      tokenBodies.push(new URLSearchParams(String(init?.body)));
      return json({ access_token: 'at', token_type: 'bearer', id_token: idToken, expires_in: 3600 });
    }
    throw new Error(`unexpected fetch ${url}`);
  }) as typeof fetch;
  const other = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
  const sign = async (claims: Record<string, unknown>, opts: SignOptions = {}): Promise<void> => {
    const now = Math.floor(Date.now() / 1000);
    const head = b64u(JSON.stringify({ alg: opts.alg === 'none' ? 'none' : 'RS256', kid: 'k1', typ: 'JWT' }));
    const exp = opts.expired ? now - 3600 : now + 300;
    const body = b64u(JSON.stringify({ iat: now - (opts.expired ? 7200 : 0), exp, ...claims }));
    if (opts.alg === 'none') { idToken = `${head}.${body}.`; return; }
    const sig = createSign('RSA-SHA256').update(`${head}.${body}`).sign(opts.wrongKey ? other : privateKey);
    const finalBody = opts.tamper ? b64u(JSON.stringify({ iat: now, exp, ...claims, sub: 'attacker' })) : body;
    idToken = `${head}.${finalBody}.${b64u(sig)}`;
  };
  return { fetchFn, sign, tokenBodies };
}
