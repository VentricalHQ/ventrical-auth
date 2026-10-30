import { describe, expect, it } from 'vitest';
import { createAuth, type AuthConfig, type ProviderName, type ProviderProfile } from '../src/index.js';
import { fakeProvider } from './helpers/fake-provider.js';
import { createMemoryStore, type MemoryStore, type MemoryTx } from './helpers/memory-store.js';
import { req, setCookie } from './helpers/request.js';

const FRONT = 'https://app.example.test';
const prof = (subject: string, over: Partial<ProviderProfile> = {}): ProviderProfile => ({ subject, emailVerified: true, email: `${subject}@example.test`, ...over });

type Update = { provider: string; subject: string; update: { email?: string | null; emailVerified: boolean }; tx: MemoryTx | undefined };

/** A store whose updateIdentity calls are recorded; `without` removes the method entirely. */
function spyStore(opts: { without?: boolean } = {}) {
  const base = createMemoryStore();
  const updates: Update[] = [];
  const txs: { find: (MemoryTx | undefined)[]; session: MemoryTx[] } = { find: [], session: [] };
  const store = Object.assign(Object.create(base) as MemoryStore, {
    findUserByIdentity: async (p: ProviderName, s: string, tx?: MemoryTx) => { txs.find.push(tx); return base.findUserByIdentity(p, s, tx); },
    createSessionUnlessSuspended: async (...a: Parameters<MemoryStore['createSessionUnlessSuspended']>) => { txs.session.push(a[4]); return base.createSessionUnlessSuspended(...a); },
    updateIdentity: async (provider: ProviderName, subject: string, update: { email?: string | null; emailVerified: boolean }, tx?: MemoryTx) => {
      updates.push({ provider, subject, update, tx });
      return base.updateIdentity!(provider, subject, update, tx);
    },
  });
  if (opts.without) (store as { updateIdentity?: unknown }).updateIdentity = undefined;
  return { store, base, updates, txs };
}

function setup(profiles: Partial<Record<ProviderName, ProviderProfile>>, store: MemoryStore, over: Partial<AuthConfig<MemoryTx>> = {}) {
  const overrides: Partial<Record<ProviderName, ReturnType<typeof fakeProvider>>> = {};
  for (const [n, p] of Object.entries(profiles)) overrides[n as ProviderName] = fakeProvider(n as ProviderName, p!);
  return createAuth<MemoryTx>({
    providers: { google: { clientId: 'a', clientSecret: 'b' }, github: { clientId: 'a', clientSecret: 'b' } },
    publicUrl: 'https://api.example.test', frontendUrl: FRONT, encryptionKey: Buffer.alloc(32, 7), store, providerOverrides: overrides, ...over,
  });
}
type Auth = ReturnType<typeof setup>;

async function flow(auth: Auth, provider: string, session?: string) {
  const start = (await auth.handle(req('GET', `/auth/${provider}/start`, session ? { cookie: session } : {})))!;
  const oauth = `__Host-ventrical_oauth=${encodeURIComponent(setCookie(start, '__Host-ventrical_oauth')!.value)}`;
  const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
  return (await auth.handle(req('GET', `/auth/${provider}/callback?code=c&state=${encodeURIComponent(state)}`, { cookie: [oauth, session].filter(Boolean).join('; ') })))!;
}
const identityOf = async (s: MemoryStore, p: ProviderName, sub: string) => (await s.findUserByIdentity(p, sub))!.identity;

describe('refreshing the stored identity email on sign-in', () => {
  it('a changed email is written to the identity', async () => {
    const { store, updates } = spyStore();
    const p = prof('g1', { email: 'old@example.test' });
    const auth = setup({ google: p }, store);
    await flow(auth, 'google');
    expect(updates).toEqual([]);
    p.email = 'new@example.test';
    const res = await flow(auth, 'google');
    expect(res.headers.get('location')).toBe(`${FRONT}/`);
    expect(updates).toHaveLength(1);
    expect(updates[0]).toMatchObject({ provider: 'google', subject: 'g1', update: { email: 'new@example.test', emailVerified: true } });
    expect(await identityOf(store, 'google', 'g1')).toEqual({ email: 'new@example.test', emailVerified: true });
  });

  it('a changed emailVerified is written to the identity', async () => {
    const { store, updates } = spyStore();
    const p = prof('g1', { emailVerified: false });
    const auth = setup({ google: p }, store);
    await flow(auth, 'google');
    p.emailVerified = true;
    await flow(auth, 'google');
    expect(updates).toHaveLength(1);
    expect(updates[0]!.update).toEqual({ email: 'g1@example.test', emailVerified: true });
    expect(await identityOf(store, 'google', 'g1')).toEqual({ email: 'g1@example.test', emailVerified: true });
  });

  it('is not called when nothing changed, for a new user, or in a link flow', async () => {
    const { store, updates } = spyStore();
    const auth = setup({ google: prof('g1'), github: prof('h1', { email: 'h1@example.test' }) }, store);
    await flow(auth, 'google'); // new user
    expect(updates).toEqual([]);
    const second = await flow(auth, 'google'); // unchanged
    expect(updates).toEqual([]);
    const session = `__Host-ventrical_session=${setCookie(second, '__Host-ventrical_session')!.value}`;
    await flow(auth, 'github', session); // link flow: new identity attached, never refreshed
    expect(updates).toEqual([]);
    // Linking an identity whose provider email differs from nothing stored still does not refresh.
    const linked = setup({ github: prof('h1', { email: 'changed@example.test' }) }, store);
    await flow(linked, 'github', session); // link flow again, identity already owned by the same user
    expect(updates).toEqual([]);
    expect((await identityOf(store, 'github', 'h1'))!.email).toBe('h1@example.test');
  });

  it('is not called when the provider returns no email', async () => {
    const { store, updates } = spyStore();
    const p = prof('g1');
    const auth = setup({ google: p }, store);
    await flow(auth, 'google');
    delete p.email;
    p.emailVerified = false;
    await flow(auth, 'google');
    expect(updates).toEqual([]);
    expect(await identityOf(store, 'google', 'g1')).toEqual({ email: 'g1@example.test', emailVerified: true });
  });

  it('a store without updateIdentity still signs in', async () => {
    const { store } = spyStore({ without: true });
    const p = prof('g1', { email: 'old@example.test' });
    const auth = setup({ google: p }, store);
    await flow(auth, 'google');
    p.email = 'new@example.test';
    const res = await flow(auth, 'google');
    expect(res.headers.get('location')).toBe(`${FRONT}/`);
    expect(setCookie(res, '__Host-ventrical_session')).toBeDefined();
  });

  it('a store that does not expose the stored identity does not refresh', async () => {
    const { store, updates } = spyStore();
    const noIdentity = Object.assign(Object.create(store) as MemoryStore, {
      findUserByIdentity: async (p: ProviderName, s: string, tx?: MemoryTx) => { const u = await store.findUserByIdentity(p, s, tx); if (u) delete u.identity; return u; },
    });
    const p = prof('g1', { email: 'old@example.test' });
    const auth = setup({ google: p }, noIdentity);
    await flow(auth, 'google');
    p.email = 'new@example.test';
    await flow(auth, 'google');
    expect(updates).toEqual([]);
  });

  it('runs in the sign-in transaction before afterSignIn and the session insert, and the user passed on has no identity field', async () => {
    const { store, updates, txs } = spyStore();
    const seen: { tx: MemoryTx; user: unknown; storedAtHook: unknown }[] = [];
    const p = prof('g1', { email: 'old@example.test' });
    const auth = setup({ google: p }, store, {
      hooks: { afterSignIn: async (c) => { seen.push({ tx: c.tx, user: c.user, storedAtHook: (await store.findUserByIdentity('google', 'g1', c.tx))!.identity }); } },
    });
    await flow(auth, 'google');
    p.email = 'new@example.test';
    await flow(auth, 'google');
    const second = seen[1]!;
    expect(updates[0]!.tx).toBe(second.tx);
    expect(txs.session[1]).toBe(second.tx);
    expect(second.storedAtHook).toEqual({ email: 'new@example.test', emailVerified: true });
    expect(Object.keys(second.user as object).sort()).toEqual(['email', 'id', 'name']);
  });

  it('rolls back with the transaction when afterSignIn throws', async () => {
    const { store, updates } = spyStore();
    let boom = false;
    const p = prof('g1', { email: 'old@example.test' });
    const auth = setup({ google: p }, store, { hooks: { afterSignIn: async () => { if (boom) throw new Error('x'); } } });
    await flow(auth, 'google');
    p.email = 'new@example.test';
    boom = true;
    const res = await flow(auth, 'google');
    expect(res.headers.get('location')).toBe(`${FRONT}/signin?error=sign_in_failed`);
    expect(updates).toHaveLength(1);
    expect((await identityOf(store, 'google', 'g1'))!.email).toBe('old@example.test');
    boom = false;
    await flow(auth, 'google');
    expect((await identityOf(store, 'google', 'g1'))!.email).toBe('new@example.test');
  });

  it('a suspended returning user is still refused, and the refresh is rolled back', async () => {
    const { store } = spyStore();
    const p = prof('g1', { email: 'old@example.test' });
    const auth = setup({ google: p }, store);
    await flow(auth, 'google');
    store.suspend((await store.findUserByIdentity('google', 'g1'))!.id);
    p.email = 'new@example.test';
    const res = await flow(auth, 'google');
    expect(res.headers.get('location')).toBe(`${FRONT}/signin?error=suspended`);
    expect(setCookie(res, '__Host-ventrical_session')).toBeUndefined();
    expect((await identityOf(store, 'google', 'g1'))!.email).toBe('old@example.test');
  });

  it('after a refresh and a later suspension, the new email blocks other providers and the old one does not', async () => {
    const { store } = spyStore();
    const g = prof('g1', { email: 'old@example.test' });
    const auth = setup({
      google: g,
      github: prof('h-new', { email: 'new@example.test' }),
    }, store);
    await flow(auth, 'google');
    g.email = 'new@example.test';
    await flow(auth, 'google'); // refresh
    store.suspend((await store.findUserByIdentity('google', 'g1'))!.id);

    const blocked = await flow(auth, 'github');
    expect(blocked.headers.get('location')).toBe(`${FRONT}/signin?error=suspended`);

    const other = setup({ github: prof('h-old', { email: 'old@example.test' }) }, store);
    const allowed = await flow(other, 'github');
    expect(allowed.headers.get('location')).toBe(`${FRONT}/`);
    expect(setCookie(allowed, '__Host-ventrical_session')).toBeDefined();
  });

  it('is idempotent when the duplicate-identity retry re-runs the transaction', async () => {
    const { store, base, updates } = spyStore();
    const p = prof('g1', { email: 'old@example.test' });
    const auth0 = setup({ google: p }, store);
    await flow(auth0, 'google');
    p.email = 'new@example.test';
    // The first attempt sees a stale "not found" and tries to create, losing the race; the retry finds the identity.
    let finds = 0;
    const racing = Object.assign(Object.create(store) as MemoryStore, {
      findUserByIdentity: async (pr: ProviderName, s: string, tx?: MemoryTx) => (finds++ === 0 ? undefined : base.findUserByIdentity(pr, s, tx)),
    });
    const auth = setup({ google: p }, racing);
    const res = await flow(auth, 'google');
    expect(res.headers.get('location')).toBe(`${FRONT}/`);
    expect(updates).toHaveLength(1);
    expect((await identityOf(base, 'google', 'g1'))!.email).toBe('new@example.test');
    // A further sign-in with the same data changes nothing.
    await flow(setup({ google: p }, store), 'google');
    expect(updates).toHaveLength(1);
  });
});
