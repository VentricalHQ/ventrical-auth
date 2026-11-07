import { fileURLToPath } from 'node:url';
import type pg from 'pg';
import { ulid } from 'ulid';
import { DuplicateIdentityError } from '../errors.js';
import { normalizeEmail } from '../email.js';
import type { AuthStore, AuthUser, NewIdentity } from '../types.js';

/** Absolute path of the shipped SQL migrations (`001_auth.sql`, ...). Apply them in file-name order. */
export const migrationsDir: string = fileURLToPath(new URL('./migrations', import.meta.url));

type Queryable = pg.Pool | pg.PoolClient;

const normOrNull = (email: string | null | undefined): string | null => (email == null ? null : normalizeEmail(email) ?? null);

const toUser = (r: { id: string; email: string | null; name: string | null }): AuthUser => ({ id: r.id, email: r.email, name: r.name });

/** True for a primary-key violation of identities (provider, subject). */
function isDuplicateIdentity(err: unknown): boolean {
  const e = err as { code?: unknown; constraint?: unknown } | null;
  return e?.code === '23505' && e.constraint === 'identities_pkey';
}

async function insertIdentity(db: Queryable, userId: string, p: NewIdentity): Promise<void> {
  try {
    await db.query(
      'insert into identities (provider, subject, user_id, email, email_verified) values ($1, $2, $3, $4, $5)',
      [p.provider, p.subject, userId, normOrNull(p.email), p.emailVerified],
    );
  } catch (err) {
    if (isDuplicateIdentity(err)) throw new DuplicateIdentityError();
    throw err;
  }
}

/** Deletes and re-inserts a user's recovery codes. Duplicates in `hashes` collapse to one row. */
async function replaceCodes(q: Queryable, userId: string, hashes: string[]): Promise<void> {
  await q.query('delete from recovery_codes where user_id = $1', [userId]);
  if (hashes.length === 0) return;
  await q.query(
    'insert into recovery_codes (user_id, code_hash) select $1, h from unnest($2::text[]) as h on conflict do nothing',
    [userId, hashes],
  );
}

async function readTotp(q: Queryable, userId: string, lock: boolean) {
  const r = await q.query(
    `select secret_enc, pending_secret_enc, confirmed_at, last_step, failed_count, locked_until
     from user_totp where user_id = $1${lock ? ' for update' : ''}`,
    [userId],
  );
  const row = r.rows[0];
  if (!row) return undefined;
  return {
    secretEnc: row.secret_enc as string | null,
    pendingSecretEnc: row.pending_secret_enc as string | null,
    confirmedAt: row.confirmed_at as Date | null,
    // bigint arrives as a string; steps are far below 2^53.
    lastStep: row.last_step === null ? null : Number(row.last_step),
    failedCount: row.failed_count as number,
    lockedUntil: row.locked_until as Date | null,
  };
}

/**
 * Postgres-backed store. `transaction` is plain BEGIN/COMMIT/ROLLBACK (no savepoints): after a duplicate-identity
 * error the Postgres transaction is aborted, and the handler re-runs the whole transaction.
 */
export function pgAuthStore(pool: pg.Pool): AuthStore<pg.PoolClient> {
  const db = (tx?: pg.PoolClient): Queryable => tx ?? pool;

  const store: AuthStore<pg.PoolClient> = {
    async transaction(fn) {
      const client = await pool.connect();
      let broken: Error | undefined;
      try {
        await client.query('BEGIN');
        try {
          const result = await fn(client);
          await client.query('COMMIT');
          return result;
        } catch (err) {
          try {
            await client.query('ROLLBACK');
          } catch (rollbackErr) {
            // Keep the original error; a client that cannot roll back must not return to the pool.
            broken = rollbackErr instanceof Error ? rollbackErr : new Error('ROLLBACK failed');
          }
          throw err;
        }
      } finally {
        client.release(broken);
      }
    },

    async findUserByIdentity(provider, subject, tx) {
      const r = await db(tx).query(
        `select u.id, u.email, u.name, i.email as identity_email, i.email_verified as identity_verified
         from users u join identities i on i.user_id = u.id
         where i.provider = $1 and i.subject = $2`,
        [provider, subject],
      );
      const row = r.rows[0];
      return row
        ? { ...toUser(row), identity: { email: row.identity_email as string | null, emailVerified: row.identity_verified as boolean } }
        : undefined;
    },

    async createUserWithIdentity(p, tx) {
      const id = ulid();
      const q = db(tx);
      // Identity first would break the FK; the user insert cannot collide, so a 23505 here is the identity's.
      const email = normOrNull(p.email);
      await q.query('insert into users (id, email, name) values ($1, $2, $3)', [id, email, p.name ?? null]);
      await insertIdentity(q, id, p);
      return { id, email, name: p.name ?? null };
    },

    async linkIdentity(userId, identity, tx) {
      await insertIdentity(db(tx), userId, identity);
    },

    async updateIdentity(provider, subject, update, tx) {
      // Two statements on purpose: `email` undefined must leave the column alone, while null must clear it. A single
      // parameterised update cannot tell the two apart (both arrive as null), so the unchanged case omits the column.
      if (update.email === undefined) {
        await db(tx).query(
          'update identities set email_verified = $3 where provider = $1 and subject = $2',
          [provider, subject, update.emailVerified],
        );
      } else {
        await db(tx).query(
          'update identities set email = $3, email_verified = $4 where provider = $1 and subject = $2',
          [provider, subject, normOrNull(update.email), update.emailVerified],
        );
      }
    },

    async emailBelongsToSuspendedUser(email, tx, opts) {
      // users.email is not consulted: it is an unverified copy and must not let a stranger block the real owner.
      // With a tx, lock every matching user row (suspended or not) so a suspension cannot commit before we do.
      const r = await db(tx).query(
        `select u.suspended_at from users u join identities i on i.user_id = u.id
         where i.email_verified and lower(i.email) = $1
           and ($2::text is null or u.id <> $2)${tx ? ' for share of u' : ''}`,
        [normalizeEmail(email) ?? null, opts?.exceptUserId ?? null],
      );
      return r.rows.some((row) => row.suspended_at !== null);
    },

    async createSessionUnlessSuspended(userId, idHash, expiresAt, identity, tx, opts) {
      const u = await tx.query('select suspended_at from users where id = $1 for share', [userId]);
      if (u.rows.length === 0 || u.rows[0].suspended_at !== null) return false;
      const pending = opts?.pending;
      if (pending) {
        // Only a pending sign-in touches the 002 columns, so a database without migration 002 still works with twoFactor off.
        await tx.query(
          `insert into sessions (id_hash, user_id, expires_at, identity_provider, identity_subject, mfa_pending, mfa_redirect)
           values ($1, $2, $3, $4, $5, true, $6)`,
          [idHash, userId, expiresAt, identity.provider, identity.subject, pending.redirect ?? null],
        );
        return true;
      }
      await tx.query(
        'insert into sessions (id_hash, user_id, expires_at, identity_provider, identity_subject) values ($1, $2, $3, $4, $5)',
        [idHash, userId, expiresAt, identity.provider, identity.subject],
      );
      return true;
    },

    async getSessionWithExpiry(idHash, now) {
      const r = await pool.query(
        // s.* so the mfa_* columns (migration 002) are read when they exist and simply absent when they do not.
        `select s.*, u.id, u.email, u.name,
                case when i.email_verified then i.email end as verified_email
         from sessions s join users u on u.id = s.user_id
         left join identities i on i.provider = s.identity_provider and i.subject = s.identity_subject and i.user_id = s.user_id
         where s.id_hash = $1 and s.expires_at > $2 and u.suspended_at is null`,
        [idHash, now],
      );
      const row = r.rows[0];
      if (!row) return undefined;
      const identity = row.identity_provider && row.identity_subject
        ? { provider: row.identity_provider as string, subject: row.identity_subject as string }
        : undefined;
      return {
        user: toUser(row),
        expiresAt: row.expires_at as Date,
        createdAt: row.created_at as Date,
        ...(identity ? { identity } : {}),
        verifiedEmail: (row.verified_email as string | null) ?? null,
        // Undefined (not false) when migration 002 is missing: a store used with twoFactor must then fail closed.
        ...(typeof row.mfa_pending === 'boolean'
          ? {
              mfaPending: row.mfa_pending as boolean,
              mfaVerifiedAt: (row.mfa_verified_at as Date | null) ?? null,
              mfaAttempts: row.mfa_attempts as number,
              mfaRedirect: (row.mfa_redirect as string | null) ?? null,
            }
          : {}),
      };
    },

    async touchSession(idHash, expiresAt) {
      await pool.query('update sessions set expires_at = $2 where id_hash = $1', [idHash, expiresAt]);
    },

    async deleteSession(idHash, tx) {
      await db(tx).query('delete from sessions where id_hash = $1', [idHash]);
    },

    async deleteSessionsForUser(userId, tx) {
      const r = await db(tx).query('delete from sessions where user_id = $1', [userId]);
      return r.rowCount ?? 0;
    },

    async purgeExpiredSessions(now, opts) {
      const r = opts?.maxAgeMs === undefined
        ? await pool.query('delete from sessions where expires_at <= $1', [now])
        // created_at + maxAge <= now, written as created_at <= now - maxAge.
        : await pool.query('delete from sessions where expires_at <= $1 or created_at <= $2', [now, new Date(now.getTime() - opts.maxAgeMs)]);
      return r.rowCount ?? 0;
    },

    async lockUser(userId, mode, tx) {
      const r = await tx.query(`select suspended_at from users where id = $1 for ${mode === 'update' ? 'update' : 'share'}`, [userId]);
      return r.rows.length > 0 && r.rows[0].suspended_at === null;
    },

    async lockTotp(userId, tx) {
      return readTotp(tx, userId, true);
    },

    async getTotp(userId, tx) {
      return readTotp(db(tx), userId, false);
    },

    async setPendingTotpSecret(userId, secretEnc, now, tx) {
      await db(tx).query(
        `insert into user_totp (user_id, pending_secret_enc, created_at) values ($1, $2, $3)
         on conflict (user_id) do update set pending_secret_enc = excluded.pending_secret_enc`,
        [userId, secretEnc, now],
      );
    },

    async confirmTotp(userId, p, tx) {
      const run = async (q: Queryable): Promise<boolean> => {
        const r = await q.query(
          `update user_totp set secret_enc = pending_secret_enc, pending_secret_enc = null, confirmed_at = $3,
             last_step = $4, failed_count = 0, locked_until = null
           where user_id = $1 and pending_secret_enc = $2`,
          [userId, p.expectedPendingEnc, p.now, p.step],
        );
        if ((r.rowCount ?? 0) === 0) return false;
        await replaceCodes(q, userId, p.recoveryCodeHashes);
        return true;
      };
      if (tx) return run(tx);
      // Without a caller's tx the swap and the new codes must still land together.
      return store.transaction(run);
    },

    async deleteTotp(userId, tx) {
      await db(tx).query('delete from recovery_codes where user_id = $1', [userId]);
      await db(tx).query('delete from user_totp where user_id = $1', [userId]);
    },

    async consumeTotpStep(userId, step, now, tx) {
      // One conditional UPDATE: of two concurrent requests with the same step the second waits on the row lock, re-reads
      // last_step and matches nothing. The lock check lives here too, so a locked user is refused even with a good code.
      const r = await db(tx).query(
        `update user_totp set last_step = $2
         where user_id = $1 and confirmed_at is not null
           and (last_step is null or last_step < $2)
           and (locked_until is null or locked_until <= $3)`,
        [userId, step, now],
      );
      return (r.rowCount ?? 0) > 0;
    },

    async recordTotpFailure(userId, p, tx) {
      const lockUntil = new Date(p.now.getTime() + p.lockoutMs);
      // $2 maxAttempts, $3 now, $4 lock end. An expired lock starts a new count; reaching the limit locks and restarts it.
      const r = await db(tx).query(
        `with base as (
           select user_id,
                  case when locked_until is not null and locked_until <= $3 then 0 else failed_count end as cnt,
                  case when locked_until is not null and locked_until <= $3 then null else locked_until end as lock
           from user_totp where user_id = $1 for update
         )
         update user_totp t set
           failed_count = case when base.cnt + 1 >= $2 then 0 else base.cnt + 1 end,
           locked_until = case when base.cnt + 1 >= $2 then $4::timestamptz else base.lock end
         from base where t.user_id = base.user_id
         returning t.locked_until`,
        [userId, p.maxAttempts, p.now, lockUntil],
      );
      const until = (r.rows[0]?.locked_until as Date | null | undefined) ?? null;
      const locked = until !== null && until.getTime() > p.now.getTime();
      return { locked, lockedUntil: locked ? until : null };
    },

    async resetTotpFailures(userId, tx) {
      await db(tx).query('update user_totp set failed_count = 0, locked_until = null where user_id = $1', [userId]);
    },

    async consumeRecoveryCode(userId, codeHash, now, tx) {
      const r = await db(tx).query(
        // The lock is checked here too, so a lock that lands after the caller's own check still blocks a correct code.
        `update recovery_codes set used_at = $3
         where user_id = $1 and code_hash = $2 and used_at is null
           and not exists (select 1 from user_totp t where t.user_id = $1 and t.locked_until is not null and t.locked_until > $3)`,
        [userId, codeHash, now],
      );
      return (r.rowCount ?? 0) > 0;
    },

    async replaceRecoveryCodes(userId, codeHashes, tx) {
      if (tx) return replaceCodes(tx, userId, codeHashes);
      await store.transaction((t) => replaceCodes(t, userId, codeHashes));
    },

    async markSessionVerified(idHash, userId, p, tx) {
      const u = await tx.query('select suspended_at from users where id = $1 for share', [userId]);
      if (u.rows.length === 0 || u.rows[0].suspended_at !== null) return false;
      const r = await tx.query(
        `update sessions set mfa_pending = false, mfa_verified_at = $3, expires_at = $4, mfa_redirect = null
         where id_hash = $1 and user_id = $2 and expires_at > $3`,
        [idHash, userId, p.now, p.expiresAt],
      );
      return (r.rowCount ?? 0) > 0;
    },

    async markSessionPending(idHash, expiresAt, tx) {
      await db(tx).query(
        'update sessions set mfa_pending = true, expires_at = $2 where id_hash = $1 and not mfa_pending and mfa_verified_at is null',
        [idHash, expiresAt],
      );
    },

    async incrementSessionMfaAttempts(idHash, tx) {
      // Pending sessions only: a session that has just been verified (a double submit) must not be counted or deleted.
      const r = await db(tx).query('update sessions set mfa_attempts = mfa_attempts + 1 where id_hash = $1 and mfa_pending returning mfa_attempts', [idHash]);
      return (r.rows[0]?.mfa_attempts as number | undefined) ?? 0;
    },

    async deleteOtherSessions(userId, keepIdHash, tx) {
      const r = await db(tx).query('delete from sessions where user_id = $1 and id_hash <> $2', [userId, keepIdHash]);
      return r.rowCount ?? 0;
    },

    async isSuspendedCredential(idHash, now) {
      const r = await pool.query(
        `select 1 from sessions s join users u on u.id = s.user_id
         where s.id_hash = $1 and s.expires_at > $2 and u.suspended_at is not null`,
        [idHash, now],
      );
      return (r.rowCount ?? 0) > 0;
    },
  };
  return store;
}
