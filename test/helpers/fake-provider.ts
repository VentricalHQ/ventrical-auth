import type { AuthProvider, ExchangeCtx } from '../../src/providers.js';
import type { ProviderName, ProviderProfile } from '../../src/types.js';

export type FakeProvider = AuthProvider & {
  lastVerifier?: string;
  lastCtx?: ExchangeCtx;
};

/** A network-free provider: exchange resolves `result`, or rejects when it is an Error. */
export function fakeProvider(name: ProviderName, result: ProviderProfile | Error): FakeProvider {
  const p: FakeProvider = {
    name,
    authorizeUrl(state, codeVerifier) {
      p.lastVerifier = codeVerifier;
      return new URL(`https://idp.example.test/${name}/authorize?state=${encodeURIComponent(state)}`);
    },
    async exchange(_code, codeVerifier, ctx) {
      p.lastCtx = ctx;
      if (codeVerifier !== p.lastVerifier) throw new Error('verifier mismatch');
      if (result instanceof Error) throw result;
      return result;
    },
  };
  return p;
}
