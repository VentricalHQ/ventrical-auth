# @ventrical/auth

OIDC sign-in for Ventrical services: Google, Microsoft and GitHub, with the security properties of the Kagaya backend's sign-in code it was extracted from. It has a framework-neutral core that speaks the Fetch API (`Request` and `Response`), thin adapters for Express, Next.js, Hono, Fastify and Postgres, and a storage interface so each app keeps its own database tables.

> **Experimental (0.0.x): not yet recommended for production.** The API and the store contract may change between releases. Read [Security notes](#security-notes) before using it, and report vulnerabilities as described in [SECURITY.md](SECURITY.md).

Status: experimental. Releases are cut automatically from `main` (see [Release](#release)); until the first release exists, nothing is published.

Requirements: Node 22 or newer, ESM only. `openid-client` is pinned to exactly 6.8.8.

## What it does

- Authorization-code flow with PKCE (S256), `state` and `nonce` for Google and Microsoft. GitHub has no PKCE or ID token; its `state` is checked.
- Verifies the ID token's `iss` (including Entra's `{tenantid}` template), `aud`, `exp` and `nonce`, requires the callback's own `iss` parameter (RFC 9207) when the provider advertises it, and verifies the token's signature (see [ID-token signature check](#id-token-signature-check)).
- Email counts as verified only when the provider proves it: Google's `email_verified`; Microsoft only when `xms_edov` is true on the `email` claim (`preferred_username` is never verified); GitHub only for the primary verified email.
- Emails are stored trimmed and lowercased (identity and user rows); an email that is empty after trimming counts as no email. The `canCreateAccount` and `afterSignIn` hooks receive the same normalised profile (lowercased, trimmed, and omitted when empty), not only the store. A custom store must apply the same rule in `createUserWithIdentity`, `linkIdentity`, `updateIdentity` and `emailBelongsToSuspendedUser`. Rows written before this version are not rewritten: matching is case-insensitive for them, but legacy rows with surrounding whitespace are not matched.
- The OAuth state cookie is encrypted (AES-256-GCM, bound to its purpose), lives 10 minutes, and is cleared on every callback outcome.
- Accounts are never linked by email. Linking happens only inside the session that started the flow (bound at `/start`).
- Every sign-in (new or returning) with a verified email is refused with `suspended` when that email belongs to another, suspended user, and so is linking such an email. Two people who share one verified mailbox are therefore treated as one person: suspending one blocks the other from signing in. Suspend each account you want locked out, and call `deleteSessionsForUser` for each suspended user.
- The suspended check and the session insert share one transaction, with the user row held `FOR SHARE`.
- Sessions: random id, only its hash stored, 30-day life refreshed on use (when less than 29 days remain) but never beyond a 90-day absolute cap from creation (`sessionMaxAgeMs`), `httpOnly`, `sameSite=lax`, `secure` when `publicUrl` is https. Log out, and log out everywhere.
- Post-sign-in redirects accept only a single-leading-slash relative path, otherwise `/`.
- Provider errors never leak codes, tokens, key material or response bodies into responses or logs; the package logs nothing.

## Install

```json
"@ventrical/auth": "^0.0.1"
```

From npm the package ships prebuilt (`dist`). Until the first release exists you can install from git instead (`"@ventrical/auth": "github:VentricalHQ/ventrical-auth#staging"`, needs repository access); a git install builds itself because `prepare` runs `npm run build`. TypeScript consumers of the Express adapter also need `@types/express` (the adapter exports Express types), and consumers of `@ventrical/auth/pg` need `@types/pg` (the store's signature uses `pg` types). Express 5, Next (>=14), Hono 4 and Fastify 5 are optional peer dependencies, needed only for the matching entry point; install just the one you use. The Next adapter uses plain `Request` and `Response` and never imports `next` (not even as a type); the Hono and Fastify adapters import their framework as types only. `pg` is a regular dependency.

Entry points:

| Import | Contents |
| --- | --- |
| `@ventrical/auth` | `createAuth`, the types, `AuthHttpError`, `DuplicateIdentityError`, `SUSPENDED_MESSAGE` |
| `@ventrical/auth/express` | `authRouter`, `requireSession`, `currentSession`, `req.user` typing |
| `@ventrical/auth/next` | `authRouteHandlers`, `getSessionFromRequest`, `requireSession` |
| `@ventrical/auth/hono` | `authHandler`, `requireSession`, `AuthVariables` type |
| `@ventrical/auth/fastify` | `authPlugin`, `requireSession`, `request.user` typing |
| `@ventrical/auth/pg` | `pgAuthStore`, `migrationsDir` |

## Quick start (Express and Postgres)

All values below are placeholders.

```ts
import express from 'express';
import pg from 'pg';
import { createAuth } from '@ventrical/auth';
import { authRouter, requireSession } from '@ventrical/auth/express';
import { pgAuthStore } from '@ventrical/auth/pg';

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });

const auth = createAuth({
  providers: {
    google: { clientId: 'example-google-client-id', clientSecret: process.env.GOOGLE_CLIENT_SECRET! },
    microsoft: { clientId: 'example-ms-client-id', clientSecret: process.env.MS_CLIENT_SECRET!, tenant: 'common' },
  },
  publicUrl: 'https://api.example.com',      // where this server is reached; callbacks are built from it
  frontendUrl: 'https://app.example.com',    // where people land after sign-in
  encryptionKey: Buffer.from(process.env.AUTH_ENCRYPTION_KEY!, 'base64'), // exactly 32 bytes
  store: pgAuthStore(pool),
});

const app = express();
app.use(authRouter(auth));                    // serves every /auth/* route, passes everything else on
app.get('/api/me', requireSession(auth), (req, res) => res.json({ id: req.user!.id }));
```

`authRouter(auth)` returns a plain Express request handler, so mount it with `app.use(authRouter(auth))`. It builds the request URL from `publicUrl`, never from the `Host` header, and keeps the mount path of nested routers (mounted under `/api`, the routes would be `/api/auth/...`, which the core does not serve; mount it at the root).

## Configuration

`createAuth(config)` validates the config (error messages name the bad field, never its value) and returns the core.

| Field | Meaning |
| --- | --- |
| `providers` | Which of `google`, `microsoft`, `github` are on, each with `clientId` and `clientSecret` (`microsoft` also takes `tenant`). At least one is required. A provider that is not listed has no routes and answers `404 provider_disabled`. |
| `publicUrl` | Public URL of the server running the auth routes (http or https). Redirect URIs are `<publicUrl>/auth/<provider>/callback`. Cookies are `secure` when it is https. |
| `frontendUrl` | Where people are sent after sign-in; also a trusted origin for POST routes. |
| `encryptionKey` | A 32-byte `Buffer`, used to encrypt the OAuth state cookie. |
| `store` | An `AuthStore` (see below). |
| `hooks` | Optional hooks, including `onError` (see [Hooks](#hooks)). |
| `cookieNames` | `{ session?, oauth? }`, each overriding its default. Defaults: `__Host-ventrical_session` and `__Host-ventrical_oauth` when `publicUrl` is https and `cookieDomain` is unset (Secure, Path=/, no Domain); otherwise `ventrical_session` and `ventrical_oauth`. |
| `cookieDomain` | Optional `Domain` attribute for both cookies. Setting it switches the default cookie names back to the plain ones. An explicit `cookieNames` value that starts with `__Host-` is always Secure with `Path=/` and no `Domain`, ignoring `cookieDomain`. |
| `sessionTtlMs` | Session life, default 30 days. |
| `sessionMaxAgeMs` | Absolute cap on a session's life, counted from its creation, default 90 days. Refresh never extends a session beyond it, and a session past it is signed out and deleted. Positive, finite. A custom store must return `createdAt` from `getSessionWithExpiry` for the cap to apply to its sessions. |
| `onErrorTimeoutMs` | Longest wait for `hooks.onError` before responding anyway, default 2000. Positive, finite, at most 2147483647 (the `setTimeout` maximum). |
| `clock` | Optional `() => Date`, for tests. |
| `fetch` | Optional `fetch` used for discovery, the token endpoint, the JWKS and GitHub's API. |
| `userAgent` | `User-Agent` for GitHub's API, default `ventrical-auth`. |
| `providerOverrides` | **Test-only.** Replaces providers by name so tests can run without a network. Not part of the supported API; never set it in production. |

Routes served by `handle` (and so by `authRouter`):

- `GET /auth/providers`: `{ "providers": ["google", "github", "microsoft"] }`, only the enabled ones, in that order.
- `GET /auth/:provider/start?redirect=/path`
- `GET /auth/:provider/callback`
- `POST /auth/logout`
- `POST /auth/logout-everywhere`

`/api/me` is not in the package: it returns app-specific fields.

### The core

`createAuth` returns `{ publicUrl, handle, getSession, requireSession }`:

- `handle(request: Request): Promise<Response | undefined>` serves the auth routes. It returns `undefined` for any path it does not own, **and also for the wrong method on an owned path** (for example `POST /auth/providers`), so the host application decides what a 404 or 405 looks like.
- `getSession(request)` returns `{ user, id, setCookie? }` (`user` is the `AuthUser` plus `verifiedEmail`) or `undefined`. When `setCookie` is present the session was refreshed and the caller must send it as `Set-Cookie`.
- `requireSession(request)` is like `getSession` but throws `AuthHttpError` (`401 unauthenticated`, or `403 account_suspended` when the cookie belongs to a currently suspended user).

> **Warning**
>
> **`user.email` is unverified provider data.** It is the first email the provider returned and it may not be verified. **Never use `user.email` for authorization, ownership, account matching or any security decision.** Only `user.verifiedEmail` may be used for that. `verifiedEmail` is `string | null`: the stored email of the identity this session signed in with, when that identity's email is verified, otherwise `null` (including a session with no identity). It follows later identity updates: it turns `null` only when the provider still returns an email on sign-in and that email is unverified. A provider that returns no email leaves the stored value unchanged (a stored email is never cleared by a sign-in that omits it), so `verifiedEmail` does not turn `null` in that case. The identity must also still belong to the session's user, otherwise it is `null`. The same `user` shape (`id`, `email`, `name`, `verifiedEmail`) is what `req.user`, `request.user`, `c.get('user')` and the Next helpers expose. A custom store supplies it as the optional `verifiedEmail` on `getSessionWithExpiry`; when omitted it reads as `null`.

The core never touches Express's `req` or `res`. Cookies are read from the `Cookie` header and written as `Set-Cookie` headers on the `Response`; redirects are `Response` objects with a `Location` header.

### Express adapter

`@ventrical/auth/express` has three exports (plus the `req.user` type augmentation):

- `authRouter(auth)`: an Express request handler for every auth route. Unknown paths and wrong methods fall through to `next()`. Request targets that are not origin-form paths (absolute-form, `*`) are never treated as auth routes. Unexpected errors go to `next()` with a fixed message, never the original detail.
- `requireSession(auth)`: middleware that sets `req.user`, appends a refreshed session cookie when needed, and passes an `AuthHttpError` to `next()` on failure (`401`, or `403` for a suspended account; the same non-path targets get `401`). Map it to a response in your error handler.
- `currentSession(auth)`: returns `async (req, res?) => SessionResult | undefined` for routes that serve signed-in and anonymous callers alike. It sets `req.user` when there is a session, appends a refreshed cookie to `res` when one is passed, and resolves `undefined` (never rejects) for an anonymous caller. Only unexpected store failures reject.

### Next.js, Hono and Fastify adapters

Each is a thin layer over `handle` and `requireSession`. All of them build the request URL from `publicUrl`, never from the `Host` header, never forward a body (no auth route reads one), and answer unexpected errors with a fixed message. Auth failures use the same JSON shape as the core, `{ "error": { "code", "message" } }`: `401 unauthenticated`, or `403 account_suspended` when the cookie belongs to a suspended user. Mount the auth routes at the root, as with Express.

**Next.js** (`@ventrical/auth/next`, App Router). `next` is an optional peer and is not a runtime dependency. Exports `authRouteHandlers(auth)` (`{ GET, POST }` for a catch-all route; paths the core does not serve answer `404`), `getSessionFromRequest(auth)` (resolves the session or `undefined`) and `requireSession(auth)` (resolves the session, or a ready `401`/`403` `Response` to return). When `setCookie` is present on a session, append it to your response as `Set-Cookie`.

```ts
// app/auth/[...auth]/route.ts
import { authRouteHandlers } from '@ventrical/auth/next';
import { auth } from '@/lib/auth'; // your createAuth(...) result

export const { GET, POST } = authRouteHandlers(auth);
```

```ts
// app/api/me/route.ts
import { requireSession } from '@ventrical/auth/next';
import { auth } from '@/lib/auth';

const need = requireSession(auth);

export async function GET(req: Request) {
  const session = await need(req);
  if (session instanceof Response) return session;
  const res = Response.json({ id: session.user.id });
  if (session.setCookie) res.headers.append('set-cookie', session.setCookie);
  return res;
}
```

**Hono** (`@ventrical/auth/hono`, Hono 4). `authHandler(auth)` is a middleware serving every auth route and passing other paths on; `requireSession(auth)` sets `c.get('user')` (typed by `AuthVariables`), forwards a refreshed session cookie, and answers `401`/`403` JSON.

```ts
import { Hono } from 'hono';
import { authHandler, requireSession, type AuthVariables } from '@ventrical/auth/hono';

const app = new Hono<{ Variables: AuthVariables }>();
app.use(authHandler(auth));
app.get('/api/me', requireSession(auth), (c) => c.json({ id: c.get('user').id }));
```

**Fastify** (`@ventrical/auth/fastify`, Fastify 5). `authPlugin(auth)` serves the auth routes from an `onRequest` hook and is not encapsulated, so it covers the whole app; register it once, at the root. `requireSession(auth)` is a `preHandler` that sets `request.user` (typed) and sets a refreshed cookie on the reply.

```ts
import Fastify from 'fastify';
import { authPlugin, requireSession } from '@ventrical/auth/fastify';

const app = Fastify();
await app.register(authPlugin(auth));
app.get('/api/me', { preHandler: requireSession(auth) }, async (req) => ({ id: req.user!.id }));
```

## POST routes and the Origin check

Log out and log out everywhere are state-changing POSTs, protected by `isSameOrigin`: the request must carry an `Origin` header, or else a `Referer`, whose origin equals the origin of `frontendUrl` **or** of `publicUrl`. Both are trusted because backend-served pages (such as an app's own authorize page) post from the public URL. A request with neither header, or with any other origin, is rejected with `403 forbidden` and nothing is changed.

## Same-site deployment only

The frontend and the API must share a registrable domain: sessions use `sameSite=lax` cookies, and cross-origin cookie setups are not supported. If the cookie must be visible to sibling subdomains, set `cookieDomain` (for example `.example.com`). Leave it unset for a host-only cookie.

## ID-token signature check

`openid-client` 6.8.8 checks an ID token's claims on the code-exchange path but does not verify its signature (OIDC Core 3.1.3.7 allows that for tokens received directly from the token endpoint, relying on TLS). This package verifies the signature anyway (the ID-token signature verification, implemented by `jwksVerifier` in `src/providers.ts`), against the issuer's discovered `jwks_uri`:

- RS256 only: `alg: none`, HMAC and other algorithms are rejected. The token header must carry a `kid`.
- The matching JWK must be an RSA signing key (`use` is `sig` or absent, `alg` is `RS256` or absent) of at least 2048 bits.
- The JWKS is cached for 5 minutes per URI. An unknown `kid` triggers exactly one refetch, then fails. Concurrent lookups for the same URI share a single in-flight fetch (single-flight), so a burst of tokens with an unknown `kid` causes one request to the provider, and a failed fetch is not cached.
- Fails closed: a JWKS fetch error, a non-OK or non-JSON response, a malformed key set or a bad signature all end the sign-in with a generic error. The error never includes the token, key material or response bodies.

The upstream implementation relied on TLS to the token endpoint; this package additionally verifies the signature. Anyone migrating from the upstream code should be aware of the difference.

## Hooks

All hooks are optional. `Tx` is the transaction handle type of your store.

- `onError(event)` observes failures so they leave a trace in your own logs or metrics. It receives `{ stage, code, provider?, errorName? }`:
  - `stage`: `start`, `callback`, `link` (the callback when it completes an account link), `logout` (both logout routes), or `request` (a failure before the route is recognised, such as a malformed request URL).
  - `code`: see the table below. `provider` is set when the provider name is known. `errorName` is the error's class name, when an error was involved.
  - The event is built from a fixed whitelist. It **never carries** a message, stack, token, authorization code, JWKS, key material, response body, email or any other profile data, only the class name.
  - A throwing or rejecting `onError` is swallowed and never changes the response. The hook is awaited before the response is returned, for at most `onErrorTimeoutMs` (default 2000 ms), so keep it fast: hand slow work (network calls, queues) off instead of blocking on it.
  - Success paths report nothing, and so do unknown routes and providers (`not_found`) and a missing, forged, replayed or expired state cookie (`invalid_state`): anyone can trigger these, so they are kept out of your logs. Calling `getSession` or `requireSession` directly is not reported; the caller handles those errors.

  | Stage | Codes |
  | --- | --- |
  | `start` | `provider_disabled`, `internal_error` |
  | `callback` | `oauth_error`, `provider_disabled`, `exchange_failed` (code exchange or ID-token and signature verification threw; the response is still `400 oauth_error`), `suspended`, `sign_in_failed`, the `canCreateAccount` deny reason, `internal_error` |
  | `link` | `identity_in_use`, `link_failed`, `suspended`, `internal_error` |
  | `logout` | `forbidden`, `unauthenticated`, `account_suspended`, `internal_error` |

  A `canCreateAccount` reason is also placed in the redirect URL (`?error=`), so it must be a short code and must not contain PII.

  ```ts
  hooks: {
    onError: ({ stage, code, provider, errorName }) => {
      logger.warn({ stage, code, provider, errorName }, 'auth failure'); // your logger; keep it fast
    },
  },
  ```

- `canCreateAccount(profile)` returns `{ allow: true }` or `{ allow: false, reason }`. It runs only when no identity matches and the flow is not a link flow, before any write, and never for returning users or linking. It sees the full profile including `emailVerified` and `provider`. A denied sign-in redirects to `<frontendUrl>/signin?error=<reason>`. Use it for invite-only apps.
- `afterSignIn({ user, profile, provider, isNew, tx })` runs inside the sign-in transaction, after the session row is written (a suspended person is refused first and never reaches it) and before any cookie is set, for new and returning users (`isNew: false`). If it throws, everything rolls back (no user, no session) and the person is redirected to `<frontendUrl>/signin?error=sign_in_failed`. **It may run twice** when two sign-ins race to create the same identity: the loser's transaction is abandoned and the whole transaction re-runs once as a returning user. Keep it transaction-only: do all its writes through `tx` and trigger no external side effects.
- `resolveRedirect(path)` returns `{ target: 'backend' | 'frontend', path }` to decide whether a post-sign-in path belongs to the backend (`publicUrl`) or the frontend (`frontendUrl`). The default is the frontend.
- `onLogoutEverywhere(userId, tx)` runs in the same transaction that deletes the user's sessions, so an app can revoke its own credentials atomically.

Sign-in failures redirect to `<frontendUrl>/signin?error=<code>` with codes such as `suspended` and `sign_in_failed`; link flows redirect to `<frontendUrl>/settings?error=identity_in_use`, `link_failed` or `suspended`. Failures before a profile is known (`invalid_state`, `oauth_error`, `provider_disabled`, `not_found`) are JSON errors: `{ "error": { "code", "message" } }`.

## The `AuthStore` contract

Each app implements `AuthStore<Tx>` over its own database (or uses the Postgres reference store below). The store owns the transaction.

| Method | Contract |
| --- | --- |
| `transaction(fn)` | Runs `fn` in a unit of work; commits when it resolves, rolls back everything when it throws, and rethrows the original error. |
| `findUserByIdentity(provider, subject, tx?)` | The user owning that identity, or `undefined`. |
| `createUserWithIdentity(profile, tx?)` | Creates both. Must throw **`DuplicateIdentityError`** when `(provider, subject)` already exists. |
| `linkIdentity(userId, identity, tx?)` | Adds an identity to a user; also throws `DuplicateIdentityError` on a duplicate. |
| `emailBelongsToSuspendedUser(email, tx?, opts?)` | Verified identity emails only; the argument is trimmed and lowercased before comparing. `opts.exceptUserId` excludes that user's own rows, so the check does not lock them (the sign-in passes the returning user's id). It does not exempt a suspended user from being refused: their own sign-in is still refused because `createSessionUnlessSuspended` returns false. **With a `tx` it must hold `FOR SHARE` (or an equivalent lock) on the matching user rows**, so a suspension cannot commit between the check and the end of the transaction. |
| `createSessionUnlessSuspended(userId, idHash, expiresAt, identity, tx)` | Holds the user row `FOR SHARE`; inserts the session and returns `true`, or returns `false` when the user is suspended. |
| `getSessionWithExpiry(idHash, now)` | The session's user and expiry, excluding suspended users. Also `verifiedEmail`: the email of the identity the session was created with when that identity is verified and still belongs to the session's user, else `null`. |
| `touchSession(idHash, expiresAt)`, `deleteSession(idHash, tx?)`, `deleteSessionsForUser(userId, tx?)` | As named; `deleteSessionsForUser` returns the number deleted. With a `tx`, `deleteSession` commits or rolls back with it (the sign-in transaction uses this to drop the previous session). A custom store's `deleteSession` must accept the optional `tx` and run in it: otherwise the old-session delete runs outside the sign-in transaction, and a suspended rollback would still delete the old session. |
| `purgeExpiredSessions(now, opts?)` | **Required.** Deletes every session with `expires_at <= now` and returns how many were removed. With `opts.maxAgeMs` it also deletes sessions with `created_at + maxAgeMs <= now`. Custom `AuthStore` implementers must add it. |
| `updateIdentity?(provider, subject, update, tx?)` | Optional. Updates the stored `email` and `emailVerified` of an existing identity (`email` undefined leaves it unchanged, null clears it; a no-op when the identity does not exist). The handler calls it inside the sign-in transaction on a returning sign-in, so the stored identity email stays current. Without it the stored email is not refreshed. |
| `isSuspendedCredential?(idHash, now)` | Optional, read-only. Lets `requireSession` answer `account_suspended` instead of `unauthenticated`. |

**`DuplicateIdentityError` contract.** The handler treats it as "the transaction is dead": it abandons the whole transaction and re-runs it once (so no savepoint is needed), finding the now-existing identity and continuing as a returning user. A store must therefore throw it only for a duplicate `(provider, subject)`, and a second failure ends in `sign_in_failed`. Because the transaction re-runs, `afterSignIn` may run twice (see Hooks).

### Running the contract suite against your own store

The repository has a behaviour suite every store must pass, `test/store-contract.ts` (it is not shipped in `dist`; copy it, or run it from a checkout). It takes a name and a factory returning a store plus a `suspend(userId)` helper, and runs the same tests against any store:

```ts
import { storeContract } from './store-contract.js';

storeContract('my store', async () => {
  const store = createMyStore();
  return {
    store,
    suspend: async (userId) => { /* mark the user suspended */ },
    setCreatedAt: async (idHash, createdAt) => { /* backdate the session's created_at */ },
    moveIdentity: async (provider, subject, toUserId) => { /* reassign the identity to another user */ },
    close: async () => { /* optional teardown */ },
  };
});
```

`setCreatedAt` and `moveIdentity` are test-only helpers the contract suite uses (the store stamps `created_at` itself on insert, and no store method reassigns an identity); they are not part of `AuthStore`. `close` is optional.

`test/memory-store.test.ts` (in-memory store) and `test/pg/pg-store.test.ts` (Postgres) are the two examples.

## Postgres reference store and migrations

`@ventrical/auth/pg` exports `pgAuthStore(pool)` (a `pg.Pool`) and `migrationsDir`, the absolute path of the shipped SQL migrations. Transactions are plain `BEGIN` / `COMMIT` / `ROLLBACK`; if `ROLLBACK` itself fails the original error is still thrown and the client is destroyed rather than returned to the pool.

The migrations are plain SQL files (currently `001_auth.sql`: `users`, `identities`, `sessions`, with `users.suspended_at`). Apply them in file-name order, **each file once**: `001_auth.sql` has no `if not exists`, so running it again fails with "relation already exists". Track what has been applied with your own migration runner, or with a small table as below:

```ts
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { migrationsDir } from '@ventrical/auth/pg';

await pool.query('create table if not exists _migrations (name text primary key, applied_at timestamptz not null default now())');
for (const file of readdirSync(migrationsDir).filter((f) => f.endsWith('.sql')).sort()) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Skip files already recorded; a concurrent starter inserting the same name makes this fail and roll back.
    const done = await client.query('insert into _migrations (name) values ($1) on conflict do nothing', [file]);
    if (done.rowCount === 1) await client.query(readFileSync(join(migrationsDir, file), 'utf8'));
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}
```

## Operational notes

- **Suspending a user:** set `users.suspended_at`. Their sessions are only hidden while suspended, not deleted, so they **reappear when you un-suspend** the user. Your app MUST therefore call `store.deleteSessionsForUser(userId)` when it suspends someone, unless it deliberately wants old sessions to come back on un-suspend. Trade-off: once the sessions are deleted, a suspended person's old cookie matches nothing and the `403 account_suspended` answer degrades to `401 unauthenticated`.
- **Non-browser clients:** the logout POSTs require an `Origin` or `Referer` header from a trusted origin (see above). Scripts and mobile clients must send one.
- **Expired sessions are not purged automatically.** Expired rows are ignored but stay in the table; see [Security notes](#security-notes) for `store.purgeExpiredSessions`.
- **Upgrading:** sessions that refresh has kept alive for longer than `sessionMaxAgeMs` (default 90 days) are signed out when this version is deployed.

Keep your own data in your own tables keyed by user id, not as extra columns on `users`.

## Security notes

- **Rate limiting:** the package does no rate limiting at all. `/auth/*` must be rate limited by your application (a reverse proxy or middleware in front of the auth routes).
- **`cookieDomain` weakens cookie isolation.** Setting it gives up the `__Host-` protection against cookie tossing (a sibling subdomain can set or overwrite the cookies) and exposes the session cookie to every subdomain of that domain. Leave it unset unless you need to share the cookie across subdomains you fully trust.
- **Purge expired sessions on a schedule.** `store.purgeExpiredSessions(now: Date, opts?: { maxAgeMs?: number }): Promise<number>` deletes every session with `expires_at <= now` and returns how many rows were removed. Pass `{ maxAgeMs }` (the same value as `sessionMaxAgeMs`, default 90 days) to also delete sessions older than the cap by `created_at`. `pgAuthStore` supports it, and it is a required method of `AuthStore`, so custom stores must implement it. Example:

  ```ts
  setInterval(() => {
    store.purgeExpiredSessions(new Date(), { maxAgeMs: 90 * 24 * 60 * 60 * 1000 }).then(
      (n) => console.log(`purged ${n} expired sessions`),
      () => { /* log and try again next time */ },
    );
  }, 60 * 60 * 1000);
  ```

  A cron job or a scheduled task that calls the same method works equally well.
- **A suspended session past its absolute cap can return 403, not 401.** `requireSession` answers `403 account_suspended` for a suspended user's session only while the row's `expires_at` is still in the future, for example after `sessionMaxAgeMs` was lowered below the age of an existing session. Under unchanged config such a session is already expired and gets `401`. The store simply excludes suspended users, so the cap check is never reached for them and the row is not deleted on that path; it is only removed by `purgeExpiredSessions`.
- **A refresh never shortens a session.** A session with 29 days or more left is not refreshed at all (`REFRESH_BELOW_MS`). When a refresh does run, it only ever extends the session: the row is touched only when the new expiry is later than the stored one, so a session issued with a longer life keeps its stored expiry, and `sessionMaxAgeMs` still bounds it.
- **Keep `hooks.onError` fast.** It is awaited before the response is returned, bounded by `onErrorTimeoutMs` (default 2000 ms, at most 2147483647). Hand slow work off instead of blocking on it.
- **Same-site deployment only.** The frontend and the API must share a registrable domain (use `cookieDomain` to share the cookie with sibling subdomains). The `Origin`/`Referer` check on POST routes trusts `frontendUrl` and `publicUrl`. See [Same-site deployment only](#same-site-deployment-only) and [POST routes and the Origin check](#post-routes-and-the-origin-check).
- **ID-token signature check:** RS256 only, JWKS cached for 5 minutes, one refetch on an unknown `kid` (concurrent lookups share a single in-flight fetch), and it fails closed. Details in [ID-token signature check](#id-token-signature-check).
- **`__Host-` cookies:** when `publicUrl` is https and `cookieDomain` is unset, the cookies are named `__Host-ventrical_session` and `__Host-ventrical_oauth` (Secure, `Path=/`, no `Domain`). To use other names, set `cookieNames`. An explicit `cookieNames` value starting with `__Host-` is always Secure with `Path=/` and no `Domain`, ignoring `cookieDomain`. **One-time sign-out:** an https deployment that upgrades to this default stops recognising its old plain-named session cookies, so everyone is signed out once. To avoid that, pin `cookieNames` to the old names (`ventrical_session`, `ventrical_oauth`).
- **Stored identity email:** on a returning sign-in the handler refreshes the identity's stored email and verified flag through the optional `store.updateIdentity` (see [The `AuthStore` contract](#the-authstore-contract)); custom stores should implement it.
- **Reporting vulnerabilities:** see [SECURITY.md](SECURITY.md).

## Development

```sh
npm install
npm test               # vitest; no network needed
npm run build          # compiles src to dist and copies the SQL migrations
npm run check:dist     # after a build: dist entry points load and migrationsDir has 001_auth.sql
npx tsc --noEmit
```

Tests run with no network. `test/helpers/no-network.ts` is a vitest setup file that replaces `fetch` and patches socket, TLS and DNS connects so any non-loopback outbound attempt throws (loopback and the host of `VENTRICAL_TEST_DATABASE_URL` are allowed). Tests pass their own `fetch` through config. `test/no-leaks.test.ts` plants a marker string as a client secret, authorization code, token, JWKS content and key material, and fails if it shows up in any response, header, cookie, or console, stdout or stderr output.

The Postgres tests are skipped unless `VENTRICAL_TEST_DATABASE_URL` is set to a database you may create and drop schemas in (each test uses a random schema). For example, with a throwaway local container and your own throwaway credentials:

```sh
export VENTRICAL_TEST_DATABASE_URL='<connection string of a throwaway local database>'
npm test
```

## Source and baseline

The code was extracted, by copying, from the Kagaya backend's sign-in code (routes, providers, session, session and user storage, and the encryption helper), and its auth tests were ported as this package's behaviour spec. The pinned Kagaya baseline is commit `b8d4c0eff0a99f72a1d5656b113942e9f54a3b15`. That fixes the baseline for Kagaya's later migration, which happens separately on its own branch.

## Release

Releases are automatic. Merging into `main` runs CI, then [semantic-release](https://github.com/semantic-release/semantic-release) reads the commits since the last tag, picks the next version, tags it, creates a GitHub release with notes generated from the commits, and publishes `@ventrical/auth` to npm with provenance. There is no manual tagging.

Work lands on `staging` (CI runs on every push and PR), and a PR from `staging` into `main` makes a release. **Merge it with a merge commit, not a squash**, so the individual commit messages reach the release.

### Commit messages decide the version

Use conventional commits: `feat:`, `fix:`, `perf:`, `revert:` produce a release, and `docs:`, `test:`, `chore:`, `refactor:` do not. While the package is `0.x`, the release rules are capped so that it stays there:

| Commit | Release while `0.x` |
|---|---|
| `fix:`, `feat:`, `perf:`, `revert:` | patch (0.0.1, 0.0.2, ...) |
| a breaking change (`feat!:` or a `BREAKING CHANGE:` footer) | minor (0.1.0, 0.2.0, ...) |

To reach `1.0.0`, remove the `releaseRules` from `.releaserc.json` and make the commit that declares the interface stable a breaking change.

### One-time setup (maintainers)

1. **Baseline tag.** semantic-release makes `1.0.0` when there is no earlier tag. Create `v0.0.0` on the repository's first commit, and push it: `git tag v0.0.0 $(git rev-list --max-parents=0 main) && git push origin v0.0.0`. The first release then becomes `0.0.1`.
2. **npm, with no token.** The `@ventrical` organization must exist and `ventricalhq` must have 2FA on. Trusted publishing is configured on an existing package, so publish the first version by hand once: `npm login` as `ventricalhq`, then `npm publish` in this repository (it publishes `0.0.0`, matching the baseline tag; that one version has no provenance). Then, in the package's settings on npmjs.com, add a trusted publisher: GitHub Actions, owner `VentricalHQ`, repository `ventrical-auth`, workflow filename `release.yml`. npm does not validate this when you save it, and the configuration must complete a successful publish within 2 days, so do it right before the first merge to `main`. From then on every release is published by the workflow, with provenance, and no npm token exists anywhere.
3. **Repository settings.** Protect `main` (require the CI check and a PR from `staging`), allow GitHub Actions to create releases and tags (Settings, Actions, Workflow permissions: read and write), and turn on private vulnerability reporting (Settings, Code security).
4. **Dependabot** is configured in `.github/dependabot.yml` and opens PRs against `staging`.

Consumers install from npm: `npm install @ventrical/auth`.

## Not in v0.1

The package does no logging of its own; use the `onError` hook to observe failures.

Firms, roles and invites (they live in the apps), Drive and OneDrive consent, admin roles, connector linking, OAuth token revocation, passwords, email magic links, MFA and SAML.
