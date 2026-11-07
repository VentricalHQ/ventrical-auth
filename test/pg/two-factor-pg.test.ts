import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import pg from 'pg';
import { afterAll, describe, expect, it } from 'vitest';
import { base32Decode } from '../../src/base32.js';
import { hotp, totpStep } from '../../src/totp.js';
import { migrationsDir, pgAuthStore } from '../../src/pg/index.js';
import { tfSetup } from '../helpers/two-factor.js';
import type { MemoryStore } from '../helpers/memory-store.js';
import { twoFactorConcurrencyContract } from '../two-factor-concurrency.js';

const URL_ENV = process.env.VENTRICAL_TEST_DATABASE_URL;

describe.skipIf(!URL_ENV)('two-factor on live postgres', () => {
  const admin = new pg.Pool({ connectionString: URL_ENV, max: 2 });
  afterAll(async () => { await admin.end(); });

  async function makeSchema(poolSize = 40) {
    const schema = `auth_tf_${Math.random().toString(36).slice(2, 10)}`;
    await admin.query(`create schema ${schema}`);
    const pool = new pg.Pool({ connectionString: URL_ENV, max: poolSize, options: `-c search_path=${schema}` });
    for (const f of readdirSync(migrationsDir).filter((n) => n.endsWith('.sql')).sort()) await pool.query(readFileSync(join(migrationsDir, f), 'utf8'));
    return {
      pool, store: pgAuthStore(pool) as unknown as MemoryStore,
      close: async () => { await pool.end(); await admin.query(`drop schema ${schema} cascade`); },
    };
  }

  twoFactorConcurrencyContract('postgres', makeSchema);

  it('sign-in that read getTotp before confirm committed does not leave a full session for the enrolled user', async () => {
    const h = await makeSchema();
    let gate: Promise<void> | undefined;
    let release!: () => void;
    let hit!: () => void;
    const hitP = new Promise<void>((r) => { hit = r; });
    const store = new Proxy(h.store, {
      get(target, p: string) {
        const v = Reflect.get(target, p) as (...a: unknown[]) => Promise<unknown>;
        if (p !== 'getTotp') return v;
        return async (uid: string, tx?: unknown) => {
          const r = await v.call(target, uid, tx);
          if (tx && gate) { hit(); await gate; }
          return r;
        };
      },
    });
    const t = tfSetup({ store: store as MemoryStore, twoFactor: {} });
    const s0 = await t.signIn();
    const setup = await t.post('/auth/2fa/setup', {}, s0.cookie);
    t.nextStep();
    const code = hotp(base32Decode(setup.json!.secret as string), totpStep(t.clock.now.getTime()));
    gate = new Promise<void>((r) => { release = r; });
    const attackerSignIn = t.signIn();
    // Whichever of the two commits first, the sign-in must see the enrolment or the confirm must wait for the sign-in.
    const raced = await Promise.race([hitP.then(() => 'hit'), new Promise((r) => setTimeout(() => r('timeout'), 1500))]);
    gate = undefined;
    const confirming = t.post('/auth/2fa/setup/confirm', { code }, s0.cookie);
    await new Promise((r) => setTimeout(r, 300));
    release();
    const [conf, atk] = await Promise.all([confirming, attackerSignIn]);
    expect(raced).toBe('hit');
    expect(conf.status).toBe(200);
    const st = await t.get('/auth/2fa/status', atk.cookie);
    // Either the sign-in landed first and confirm deleted that session (401), or it saw the enrolment (pending, 401). Never a full session (200).
    expect(st.status).toBe(401);
    await h.close();
  });

  it('sign-in that deletes another session of the user does not deadlock with a disable holding the user row', async () => {
    const h = await makeSchema();
    let hold: Promise<void> | undefined;
    let release!: () => void;
    let held!: () => void;
    const heldP = new Promise<void>((r) => { held = r; });
    const store = new Proxy(h.store, {
      get(target, p: string) {
        const v = Reflect.get(target, p) as (...a: unknown[]) => Promise<unknown>;
        if (p !== 'lockUser') return v;
        return async (...a: unknown[]) => {
          const r = await v.apply(target, a);
          if (a[1] === 'update' && hold) { held(); await hold; }
          return r;
        };
      },
    });
    const t = tfSetup({ store: store as MemoryStore, twoFactor: {} });
    const { secret } = await t.enrol(); t.nextStep();
    const x = await t.signIn();
    const y = await t.signIn();
    await t.post('/auth/2fa/verify', { code: t.codeFor(secret) }, x.cookie); t.nextStep();
    await t.post('/auth/2fa/verify', { code: t.codeFor(secret) }, y.cookie); t.nextStep();
    hold = new Promise<void>((r) => { release = r; });
    const disabling = t.post('/auth/2fa/disable', { code: t.codeFor(secret) }, y.cookie);
    await heldP;
    hold = undefined;
    const signing = t.signIn('google', { cookie: x.cookie });
    await new Promise((r) => setTimeout(r, 300));
    release();
    const [d, si] = await Promise.all([disabling, signing]);
    expect(d.status).toBe(200);
    expect(si.location).not.toContain('error=');
    await h.close();
  }, 30_000);

  it('a session row that vanishes before it is marked verified answers 401 unauthenticated, and the spent code rolls back', async () => {
    const h = await makeSchema();
    const store = new Proxy(h.store, {
      get(target, p: string) {
        const v = Reflect.get(target, p) as (...a: unknown[]) => Promise<unknown>;
        if (p !== 'markSessionVerified') return v;
        return async (...a: unknown[]) => { await (a[3] as pg.PoolClient).query('delete from sessions'); return v.apply(target, a); };
      },
    });
    const t = tfSetup({ store: store as MemoryStore });
    const { secret } = await t.enrol(); t.nextStep();
    const s = await t.signIn();
    const r = await t.post('/auth/2fa/verify', { code: t.codeFor(secret) }, s.cookie);
    expect(r.status).toBe(401);
    expect(r.json?.error?.code).toBe('unauthenticated');
    expect(JSON.stringify(r.json)).not.toMatch(/suspend/i);
    expect((await h.pool.query('select last_step from user_totp')).rows[0].last_step).toBe('0');
    await h.close();
  });

  it('lock order users -> user_totp -> sessions/recovery_codes: a mixed parallel storm of every route finishes without a deadlock', async () => {
    const h = await makeSchema(60);
    const t = tfSetup({ store: h.store, twoFactor: { maxAttempts: 1000 } });
    const { secret } = await t.enrol('g1', { recoveryCodes: [] }); t.nextStep();
    const pend = [];
    for (let i = 0; i < 20; i++) pend.push(await t.signIn());
    const full = [];
    for (let i = 0; i < 4; i++) { const s = await t.signIn(); await t.post('/auth/2fa/verify', { code: t.codeFor(secret) }, s.cookie); t.nextStep(); full.push(s); }
    const bad = '000003';
    const jobs: Promise<{ status: number }>[] = [];
    for (let i = 0; i < 40; i++) {
      const f = full[i % 4]!.cookie;
      jobs.push(t.post('/auth/2fa/verify', { code: bad }, pend[i % 20]!.cookie));
      jobs.push(t.post('/auth/2fa/recovery-codes', { code: bad }, f));
      jobs.push(t.post('/auth/2fa/disable', { code: bad }, f));
      jobs.push(t.post('/auth/2fa/setup', { code: bad }, f));
      jobs.push(t.signIn().then((x) => ({ status: x.res.status })));
    }
    const rs = await Promise.race([Promise.all(jobs), new Promise<never>((_, rej) => setTimeout(() => rej(new Error('deadlock or hang')), 40_000))]);
    expect(rs.length).toBe(jobs.length);
    await h.close();
  }, 60_000);
});
