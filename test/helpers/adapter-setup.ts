import { createAuth, type ProviderName, type ProviderProfile } from '../../src/index.js';
import { newSessionId } from '../../src/session.js';
import { fakeProvider } from './fake-provider.js';
import { createMemoryStore, type MemoryTx } from './memory-store.js';

export const FRONT = 'https://app.example.test';
export const PUBLIC = 'https://api.example.test';

export function setup(profile: ProviderProfile = { subject: 'g1', emailVerified: true, email: 'g1@example.test' }) {
  const store = createMemoryStore();
  const overrides: Partial<Record<ProviderName, ReturnType<typeof fakeProvider>>> = { google: fakeProvider('google', profile) };
  const auth = createAuth<MemoryTx>({
    providers: { google: { clientId: 'fake-id', clientSecret: 'fake-secret' } },
    publicUrl: PUBLIC, frontendUrl: FRONT, encryptionKey: Buffer.alloc(32, 7), store, providerOverrides: overrides,
  });
  return { auth, store };
}

export async function seedSession(store: ReturnType<typeof setup>['store'], expiresAt: Date, subject = 'g5') {
  const user = await store.createUserWithIdentity({ provider: 'google', subject, emailVerified: true });
  const sid = newSessionId();
  await store.transaction((tx) => store.createSessionUnlessSuspended(user.id, sid.idHash, expiresAt, { provider: 'google', subject }, tx));
  return { user, sid };
}

export const cookieNamed = (cookies: string[], name: string) => {
  const raw = cookies.find((c) => c.startsWith(`${name}=`));
  return raw ? raw.split(';')[0]! : undefined;
};
