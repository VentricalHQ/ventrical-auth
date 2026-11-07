import { readFileSync, readdirSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import pg from 'pg';
import { afterEach, beforeAll, afterAll, describe, expect, it } from 'vitest';
import { DuplicateIdentityError } from '../../src/errors.js';
import { migrationsDir, pgAuthStore } from '../../src/pg/index.js';
import { storeContract, type StoreHarness } from '../store-contract.js';
import { twoFactorStoreContract } from '../two-factor-store-contract.js';

const URL_ENV = process.env.VENTRICAL_TEST_DATABASE_URL;

describe('migrationsDir', () => {
  it('is an absolute path holding the shipped SQL', () => {
    expect(isAbsolute(migrationsDir)).toBe(true);
    expect(readdirSync(migrationsDir)).toContain('001_auth.sql');
    expect(readdirSync(migrationsDir)).toContain('002_totp.sql');
  });
});

describe.skipIf(!URL_ENV)('pgAuthStore (live postgres)', () => {
  const admin = new pg.Pool({ connectionString: URL_ENV, max: 2 });
  afterAll(async () => { await admin.end(); });

  /** A fresh randomly named schema with the shipped migrations applied; dropped by close(). */
  async function makeSchema(): Promise<StoreHarness & { pool: pg.Pool; store: ReturnType<typeof pgAuthStore> }> {
    const schema = `auth_test_${Math.random().toString(36).slice(2, 10)}`;
    await admin.query(`create schema ${schema}`);
    const pool = new pg.Pool({ connectionString: URL_ENV, max: 4, options: `-c search_path=${schema}` });
    for (const f of readdirSync(migrationsDir).filter((n) => n.endsWith('.sql')).sort()) {
      await pool.query(readFileSync(join(migrationsDir, f), 'utf8'));
    }
    return {
      pool,
      store: pgAuthStore(pool),
      suspend: async (userId) => { await pool.query('update users set suspended_at = now() where id = $1', [userId]); },
      moveIdentity: async (p, s, to) => { await pool.query('update identities set user_id = $3 where provider = $1 and subject = $2', [p, s, to]); },
      setCreatedAt: async (h, d) => { await pool.query('update sessions set created_at = $2 where id_hash = $1', [h, d]); },
      close: async () => {
        await pool.end();
        await admin.query(`drop schema ${schema} cascade`);
      },
    };
  }

  storeContract('pg', makeSchema);
  twoFactorStoreContract('pg', makeSchema);

  describe('pg specifics', () => {
    let h: Awaited<ReturnType<typeof makeSchema>>;
    beforeAll(async () => { h = await makeSchema(); });
    afterAll(async () => { await h.close!(); });
    const IDENT = { provider: 'google', subject: 'dup' } as const;

    it('a duplicate identity aborts the transaction, and re-running the whole transaction succeeds', async () => {
      const first = await h.store.createUserWithIdentity({ ...IDENT, emailVerified: true });
      let aborted: unknown;
      await expect(h.store.transaction(async (tx) => {
        try {
          await h.store.createUserWithIdentity({ ...IDENT, emailVerified: true }, tx);
        } catch (err) {
          expect(err).toBeInstanceOf(DuplicateIdentityError);
          // No savepoint: Postgres has aborted the transaction.
          await tx.query('select 1').catch((e: unknown) => { aborted = e; });
          throw err;
        }
      })).rejects.toBeInstanceOf(DuplicateIdentityError);
      expect((aborted as { code?: string }).code).toBe('25P02');
      // The handler's retry: run everything again in a new transaction.
      const user = await h.store.transaction(async (tx) => (await h.store.findUserByIdentity('google', 'dup', tx)) ?? h.store.createUserWithIdentity({ ...IDENT, emailVerified: true }, tx));
      expect(user.id).toBe(first.id);
    });

    it('a non-identity unique violation is not reported as DuplicateIdentityError', async () => {
      const u = await h.store.createUserWithIdentity({ provider: 'github', subject: 'x1', emailVerified: true });
      await h.store.transaction((tx) => h.store.createSessionUnlessSuspended(u.id, 'same-hash', new Date(Date.now() + 1e6), { provider: 'github', subject: 'x1' }, tx));
      const err = await h.store.transaction((tx) => h.store.createSessionUnlessSuspended(u.id, 'same-hash', new Date(Date.now() + 1e6), { provider: 'github', subject: 'x1' }, tx)).catch((e: unknown) => e);
      expect(err).toBeInstanceOf(Error);
      expect(err).not.toBeInstanceOf(DuplicateIdentityError);
    });

    const migrationFiles = () => readdirSync(migrationsDir).filter((n) => n.endsWith('.sql')).sort();
    /** A schema with only the named migrations applied. */
    async function schemaWith(files: string[]) {
      const schema = `auth_test_${Math.random().toString(36).slice(2, 10)}`;
      await admin.query(`create schema ${schema}`);
      const pool = new pg.Pool({ connectionString: URL_ENV, max: 2, options: `-c search_path=${schema}` });
      for (const f of files) await pool.query(readFileSync(join(migrationsDir, f), 'utf8'));
      return { pool, close: async () => { await pool.end(); await admin.query(`drop schema ${schema} cascade`); } };
    }

    it('migration 002 applies on top of 001 with existing users and sessions, which stay valid and not pending', async () => {
      const [first, ...rest] = migrationFiles();
      const m = await schemaWith([first!]);
      try {
        const store = pgAuthStore(m.pool);
        const user = await store.createUserWithIdentity({ provider: 'google', subject: 'old', emailVerified: true });
        await store.transaction((tx) => store.createSessionUnlessSuspended(user.id, 'old-session', new Date(Date.now() + 1e6), { provider: 'google', subject: 'old' }, tx));
        for (const f of rest) await m.pool.query(readFileSync(join(migrationsDir, f), 'utf8'));
        const found = await store.getSessionWithExpiry('old-session', new Date());
        expect(found?.user.id).toBe(user.id);
        expect(found?.mfaPending).toBe(false);
        expect(found?.mfaVerifiedAt).toBeNull();
        expect(found?.mfaAttempts).toBe(0);
      } finally {
        await m.close();
      }
    });

    it('without migration 002 the store still signs people in and reports no mfa fields (twoFactor off)', async () => {
      const m = await schemaWith([migrationFiles()[0]!]);
      try {
        const store = pgAuthStore(m.pool);
        const user = await store.createUserWithIdentity({ provider: 'google', subject: 'old', emailVerified: true });
        await store.transaction((tx) => store.createSessionUnlessSuspended(user.id, 's1', new Date(Date.now() + 1e6), { provider: 'google', subject: 'old' }, tx));
        const found = await store.getSessionWithExpiry('s1', new Date());
        expect(found?.user.id).toBe(user.id);
        expect(found?.mfaPending).toBeUndefined();
      } finally {
        await m.close();
      }
    });

    it('deleting a user cascades to the totp record, recovery codes and sessions', async () => {
      const u = await h.store.createUserWithIdentity({ provider: 'google', subject: 'cascade', emailVerified: true });
      await h.store.setPendingTotpSecret!(u.id, 'enc', new Date());
      await h.store.confirmTotp!(u.id, { expectedPendingEnc: 'enc', step: 1, now: new Date(), recoveryCodeHashes: ['x'] });
      await h.store.transaction((tx) => h.store.createSessionUnlessSuspended(u.id, 'cascade-s', new Date(Date.now() + 1e6), { provider: 'google', subject: 'cascade' }, tx));
      await h.pool.query('delete from users where id = $1', [u.id]);
      expect((await h.pool.query('select 1 from user_totp where user_id = $1', [u.id])).rowCount).toBe(0);
      expect((await h.pool.query('select 1 from recovery_codes where user_id = $1', [u.id])).rowCount).toBe(0);
      expect((await h.pool.query('select 1 from sessions where user_id = $1', [u.id])).rowCount).toBe(0);
    });

    it('the secret column holds only what the caller passed (no plaintext added by the store)', async () => {
      const u = await h.store.createUserWithIdentity({ provider: 'google', subject: 'blob', emailVerified: true });
      await h.store.setPendingTotpSecret!(u.id, 'v2:opaque:blob:here', new Date());
      const r = await h.pool.query('select pending_secret_enc from user_totp where user_id = $1', [u.id]);
      expect(r.rows[0].pending_secret_enc).toBe('v2:opaque:blob:here');
    });

    it('transaction releases the client on throw and on success', async () => {
      const idleBefore = h.pool.idleCount;
      await expect(h.store.transaction(async () => { throw new Error('x'); })).rejects.toThrow('x');
      await h.store.transaction(async () => 1);
      expect(h.pool.totalCount - h.pool.idleCount).toBe(0);
      expect(h.pool.idleCount).toBeGreaterThanOrEqual(idleBefore);
    });

    it('a failing ROLLBACK rethrows the original error and destroys the client', async () => {
      const released: unknown[] = [];
      const wrapped = {
        connect: async () => {
          const client = await h.pool.connect();
          const query = client.query.bind(client) as (...a: unknown[]) => Promise<unknown>;
          (client as unknown as { query: unknown }).query = (...a: unknown[]) =>
            (a[0] === 'ROLLBACK' ? Promise.reject(new Error('rollback boom')) : query(...a));
          const release = client.release.bind(client);
          client.release = ((err?: Error | boolean) => { released.push(err); release(err); }) as typeof client.release;
          return client;
        },
      } as unknown as pg.Pool;
      const total = h.pool.totalCount;
      await expect(pgAuthStore(wrapped).transaction(async () => { throw new Error('original'); })).rejects.toThrow('original');
      expect(released).toHaveLength(1);
      expect(released[0]).toBeInstanceOf(Error);
      expect((released[0] as Error).message).toBe('rollback boom');
      // A destroyed client leaves the pool instead of going idle.
      expect(h.pool.totalCount).toBeLessThanOrEqual(total);
      expect(h.pool.totalCount - h.pool.idleCount).toBe(0);
    });

    const RACE_TIMEOUT_MS = 10_000;
    const TEST_TIMEOUT_MS = 30_000;
    const LOCK_WAIT_MS = 5_000;

    /** Rejects with a readable message instead of hanging when `p` does not settle in time. */
    function within<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
      return new Promise<T>((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`timed out after ${ms}ms waiting for ${what}`)), ms);
        p.then(
          (v) => { clearTimeout(timer); resolve(v); },
          (e: unknown) => { clearTimeout(timer); reject(e); },
        );
      });
    }

    async function waitForLockWait(): Promise<void> {
      const deadline = Date.now() + LOCK_WAIT_MS;
      while (Date.now() < deadline) {
        const r = await within(
          admin.query(`select 1 from pg_stat_activity where wait_event_type = 'Lock' and datname = current_database() and query ilike '%suspended_at%'`),
          RACE_TIMEOUT_MS, 'the pg_stat_activity lookup',
        );
        if (r.rowCount) return;
        await new Promise((res) => setTimeout(res, 25));
      }
      throw new Error('suspend never blocked on the FOR SHARE lock');
    }

    /**
     * Runs `inTx` in a transaction that stays open until released, then issues a suspension of `userId` from another
     * connection and checks that it blocks until the transaction commits. Every wait is bounded and the held
     * transaction is always released, so a regression fails the test instead of hanging it.
     */
    async function suspendWaitsForTx(userId: string, inTx: (tx: unknown) => Promise<void>): Promise<void> {
      let release!: () => void;
      const gate = new Promise<void>((r) => { release = r; });
      let reached!: () => void;
      const reachedP = new Promise<void>((r) => { reached = r; });
      const txP = h.store.transaction(async (tx) => {
        await inTx(tx);
        reached();
        await gate;
      });
      txP.catch(() => {}); // observed below; avoids an unhandled rejection if we bail out early
      let suspended = false;
      let suspendP: Promise<void> = Promise.resolve();
      try {
        await within(Promise.race([reachedP, txP]), RACE_TIMEOUT_MS, 'the transaction to take its lock');
        suspendP = h.pool.query('update users set suspended_at = now() where id = $1', [userId]).then(() => { suspended = true; });
        suspendP.catch(() => {});
        await waitForLockWait();
        expect(suspended).toBe(false);
      } finally {
        release();
      }
      await within(txP, RACE_TIMEOUT_MS, 'the held transaction to commit');
      await within(suspendP, RACE_TIMEOUT_MS, 'the suspension to proceed after the commit');
    }

    it('createSessionUnlessSuspended holds FOR SHARE: a concurrent suspend waits for the commit, so no live session survives it', async () => {
      const u = await h.store.createUserWithIdentity({ provider: 'github', subject: 'race1', emailVerified: true });
      await suspendWaitsForTx(u.id, async (tx) => {
        expect(await h.store.createSessionUnlessSuspended(u.id, 'race-hash', new Date(Date.now() + 1e6), { provider: 'github', subject: 'race1' }, tx)).toBe(true);
      });
      // The session was committed before the suspension, so it is now hidden and flagged.
      expect(await h.store.getSessionWithExpiry('race-hash', new Date())).toBeUndefined();
      expect(await h.store.isSuspendedCredential!('race-hash', new Date())).toBe(true);
      // And a later attempt is refused.
      expect(await h.store.transaction((tx) => h.store.createSessionUnlessSuspended(u.id, 'race-hash-2', new Date(Date.now() + 1e6), { provider: 'github', subject: 'race1' }, tx))).toBe(false);
    }, TEST_TIMEOUT_MS);

    it('emailBelongsToSuspendedUser with a tx holds FOR SHARE on the matching user, so a suspension waits for the commit', async () => {
      const u = await h.store.createUserWithIdentity({ provider: 'github', subject: 'race2', email: 'race2@example.test', emailVerified: true });
      await suspendWaitsForTx(u.id, async (tx) => {
        expect(await h.store.emailBelongsToSuspendedUser('race2@example.test', tx)).toBe(false);
      });
      expect(await h.store.emailBelongsToSuspendedUser('race2@example.test')).toBe(true);
    }, TEST_TIMEOUT_MS);
  });
});
