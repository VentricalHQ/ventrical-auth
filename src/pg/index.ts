import { fileURLToPath } from 'node:url';
import type pg from 'pg';
import { ulid } from 'ulid';
import { DuplicateIdentityError } from '../errors.js';
import type { AuthStore, AuthUser, NewIdentity } from '../types.js';

/** Absolute path of the shipped SQL migrations (`001_auth.sql`, ...). Apply them in file-name order. */
export const migrationsDir: string = fileURLToPath(new URL('./migrations', import.meta.url));

type Queryable = pg.Pool | pg.PoolClient;

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
      [p.provider, p.subject, userId, p.email ?? null, p.emailVerified],
    );
  } catch (err) {
    if (isDuplicateIdentity(err)) throw new DuplicateIdentityError();
    throw err;
  }
}

/**
 * Postgres-backed store. `transaction` is plain BEGIN/COMMIT/ROLLBACK (no savepoints): after a duplicate-identity
 * error the Postgres transaction is aborted, and the handler re-runs the whole transaction.
 */
export function pgAuthStore(pool: pg.Pool): AuthStore<pg.PoolClient> {
  const db = (tx?: pg.PoolClient): Queryable => tx ?? pool;

  return {
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
      await q.query('insert into users (id, email, name) values ($1, $2, $3)', [id, p.email ?? null, p.name ?? null]);
      await insertIdentity(q, id, p);
      return { id, email: p.email ?? null, name: p.name ?? null };
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
          [provider, subject, update.email, update.emailVerified],
        );
      }
    },

    async emailBelongsToSuspendedUser(email, tx) {
      // users.email is not consulted: it is an unverified copy and must not let a stranger block the real owner.
      // With a tx, lock every matching user row (suspended or not) so a suspension cannot commit before we do.
      const r = await db(tx).query(
        `select u.suspended_at from users u join identities i on i.user_id = u.id
         where i.email_verified and lower(i.email) = lower($1)${tx ? ' for share of u' : ''}`,
        [email],
      );
      return r.rows.some((row) => row.suspended_at !== null);
    },

    async createSessionUnlessSuspended(userId, idHash, expiresAt, identity, tx) {
      const u = await tx.query('select suspended_at from users where id = $1 for share', [userId]);
      if (u.rows.length === 0 || u.rows[0].suspended_at !== null) return false;
      await tx.query(
        'insert into sessions (id_hash, user_id, expires_at, identity_provider, identity_subject) values ($1, $2, $3, $4, $5)',
        [idHash, userId, expiresAt, identity.provider, identity.subject],
      );
      return true;
    },

    async getSessionWithExpiry(idHash, now) {
      const r = await pool.query(
        `select u.id, u.email, u.name, s.expires_at, s.identity_provider, s.identity_subject
         from sessions s join users u on u.id = s.user_id
         where s.id_hash = $1 and s.expires_at > $2 and u.suspended_at is null`,
        [idHash, now],
      );
      const row = r.rows[0];
      if (!row) return undefined;
      const identity = row.identity_provider && row.identity_subject
        ? { provider: row.identity_provider as string, subject: row.identity_subject as string }
        : undefined;
      return { user: toUser(row), expiresAt: row.expires_at as Date, ...(identity ? { identity } : {}) };
    },

    async touchSession(idHash, expiresAt) {
      await pool.query('update sessions set expires_at = $2 where id_hash = $1', [idHash, expiresAt]);
    },

    async deleteSession(idHash) {
      await pool.query('delete from sessions where id_hash = $1', [idHash]);
    },

    async deleteSessionsForUser(userId, tx) {
      const r = await db(tx).query('delete from sessions where user_id = $1', [userId]);
      return r.rowCount ?? 0;
    },

    async purgeExpiredSessions(now) {
      const r = await pool.query('delete from sessions where expires_at <= $1', [now]);
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
}
