# @ventrical/auth

OIDC sign-in for Ventrical services: Google, Microsoft and GitHub, with the security properties of the Kagaya backend's sign-in code it was extracted from. It has a framework-neutral core that speaks the Fetch API (`Request` and `Response`), thin adapters for Express and Postgres, and a storage interface so each app keeps its own database tables.

Status: version 0.1.0 is being prepared. **No git tag exists yet and nothing is published.** See [Release](#release).

Requirements: Node 22 or newer, ESM only. `openid-client` is pinned to exactly 6.8.8.

## What it does

- Authorization-code flow with PKCE (S256), `state` and `nonce` for Google and Microsoft. GitHub has no PKCE or ID token; its `state` is checked.
- Verifies the ID token's `iss` (including Entra's `{tenantid}` template), `aud`, `exp` and `nonce`, requires the callback's own `iss` parameter (RFC 9207) when the provider advertises it, and verifies the token's signature (see [ID-token signature check](#id-token-signature-check)).
- Email counts as verified only when the provider proves it: Google's `email_verified`; Microsoft only when `xms_edov` is true on the `email` claim (`preferred_username` is never verified); GitHub only for the primary verified email.
- The OAuth state cookie is encrypted (AES-256-GCM), lives 10 minutes, and is cleared on every callback outcome.
- Accounts are never linked by email. Linking happens only inside the session that started the flow (bound at `/start`).
- A suspended person cannot return through another provider with the same verified email.
- The suspended check and the session insert share one transaction, with the user row held `FOR SHARE`.
- Sessions: random id, only its hash stored, 30-day life refreshed on use (when less than 29 days remain), `httpOnly`, `sameSite=lax`, `secure` when `publicUrl` is https. Log out, and log out everywhere.
- Post-sign-in redirects accept only a single-leading-slash relative path, otherwise `/`.
- Provider errors never leak codes, tokens, key material or response bodies into responses or logs; the package logs nothing.

## Install

```json
"@ventrical/auth": "github:VentricalHQ/ventrical-auth#v0.1.0"
```

The package builds itself on install (`prepare` runs `npm run build`). Consumers need access to the private repository. TypeScript consumers of the Express adapter also need `@types/express` (the adapter exports Express types), and Express 5 itself is an optional peer dependency needed only for `@ventrical/auth/express`. `pg` is a regular dependency.

Entry points:

| Import | Contents |
| --- | --- |
| `@ventrical/auth` | `createAuth`, the types, `AuthHttpError`, `DuplicateIdentityError`, `SUSPENDED_MESSAGE` |
| `@ventrical/auth/express` | `authRouter`, `requireSession`, `req.user` typing |
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
| `hooks` | Optional hooks (see below). |
| `cookieNames` | `{ session?, oauth? }`, defaults `ventrical_session` and `ventrical_oauth`. |
| `cookieDomain` | Optional `Domain` attribute for both cookies. |
| `sessionTtlMs` | Session life, default 30 days. |
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
- `getSession(request)` returns `{ user, id, setCookie? }` or `undefined`. This is the `currentSession` of the design spec, exposed as `auth.getSession`. When `setCookie` is present the session was refreshed and the caller must send it as `Set-Cookie`.
- `requireSession(request)` is like `getSession` but throws `AuthHttpError` (`401 unauthenticated`, or `403 account_suspended` when the cookie belongs to a currently suspended user).

The core never touches Express's `req` or `res`. Cookies are read from the `Cookie` header and written as `Set-Cookie` headers on the `Response`; redirects are `Response` objects with a `Location` header.

### Express adapter

`@ventrical/auth/express` has exactly two exports (plus the `req.user` type augmentation); there is no `currentSession` in the adapter, use `auth.getSession` on the core:

- `authRouter(auth)`: an Express request handler for every auth route. Unknown paths and wrong methods fall through to `next()`. Request targets that are not origin-form paths (absolute-form, `*`) are never treated as auth routes. Unexpected errors go to `next()` with a fixed message, never the original detail.
- `requireSession(auth)`: middleware that sets `req.user`, appends a refreshed session cookie when needed, and passes an `AuthHttpError` to `next()` on failure (`401`, or `403` for a suspended account; the same non-path targets get `401`). Map it to a response in your error handler.

## POST routes and the Origin check

Log out and log out everywhere are state-changing POSTs, protected by `isSameOrigin`: the request must carry an `Origin` header, or else a `Referer`, whose origin equals the origin of `frontendUrl` **or** of `publicUrl`. Both are trusted because backend-served pages (such as an app's own authorize page) post from the public URL. A request with neither header, or with any other origin, is rejected with `403 forbidden` and nothing is changed.

## Same-site deployment only

The frontend and the API must share a registrable domain: sessions use `sameSite=lax` cookies, and cross-origin cookie setups are not supported. If the cookie must be visible to sibling subdomains, set `cookieDomain` (for example `.example.com`). Leave it unset for a host-only cookie.

## ID-token signature check

`openid-client` 6.8.8 checks an ID token's claims on the code-exchange path but does not verify its signature (OIDC Core 3.1.3.7 allows that for tokens received directly from the token endpoint, relying on TLS). This package verifies the signature anyway (the ID-token signature verification, implemented by `jwksVerifier` in `src/providers.ts`), against the issuer's discovered `jwks_uri`:

- RS256 only: `alg: none`, HMAC and other algorithms are rejected. The token header must carry a `kid`.
- The matching JWK must be an RSA signing key (`use` is `sig` or absent, `alg` is `RS256` or absent) of at least 2048 bits.
- The JWKS is cached for 5 minutes per URI. An unknown `kid` triggers exactly one refetch, then fails.
- Fails closed: a JWKS fetch error, a non-OK or non-JSON response, a malformed key set or a bad signature all end the sign-in with a generic error. The error never includes the token, key material or response bodies.

This is stricter than Kagaya, whose comment claims it verifies the signature but whose `openid-client` call does not. Kagaya's later migration should know about the gap.

## Hooks

All hooks are optional. `Tx` is the transaction handle type of your store.

- `canCreateAccount(profile)` returns `{ allow: true }` or `{ allow: false, reason }`. It runs only when no identity matches and the flow is not a link flow, before any write, and never for returning users or linking. It sees the full profile including `emailVerified` and `provider`. A denied sign-in redirects to `<frontendUrl>/signin?error=<reason>`. Use it for invite-only apps.
- `afterSignIn({ user, profile, provider, isNew, tx })` runs inside the sign-in transaction, before the session row is written and before any cookie is set, for new and returning users (`isNew: false`). If it throws, everything rolls back (no user, no session) and the person is redirected to `<frontendUrl>/signin?error=sign_in_failed`. **It may run twice** when two sign-ins race to create the same identity: the loser's transaction is abandoned and the whole transaction re-runs once as a returning user. Keep it transaction-only: do all its writes through `tx` and trigger no external side effects.
- `resolveRedirect(path)` returns `{ target: 'backend' | 'frontend', path }` to decide whether a post-sign-in path belongs to the backend (`publicUrl`) or the frontend (`frontendUrl`). The default is the frontend.
- `onLogoutEverywhere(userId, tx)` runs in the same transaction that deletes the user's sessions, so an app can revoke its own credentials atomically.

Sign-in failures redirect to `<frontendUrl>/signin?error=<code>` with codes such as `suspended` and `sign_in_failed`; link flows redirect to `<frontendUrl>/settings?error=identity_in_use` or `link_failed`. Failures before a profile is known (`invalid_state`, `oauth_error`, `provider_disabled`, `not_found`) are JSON errors: `{ "error": { "code", "message" } }`.

## The `AuthStore` contract

Each app implements `AuthStore<Tx>` over its own database (or uses the Postgres reference store below). The store owns the transaction.

| Method | Contract |
| --- | --- |
| `transaction(fn)` | Runs `fn` in a unit of work; commits when it resolves, rolls back everything when it throws, and rethrows the original error. |
| `findUserByIdentity(provider, subject, tx?)` | The user owning that identity, or `undefined`. |
| `createUserWithIdentity(profile, tx?)` | Creates both. Must throw **`DuplicateIdentityError`** when `(provider, subject)` already exists. |
| `linkIdentity(userId, identity, tx?)` | Adds an identity to a user; also throws `DuplicateIdentityError` on a duplicate. |
| `emailBelongsToSuspendedUser(email, tx?)` | Verified identity emails only, case-insensitive. **With a `tx` it must hold `FOR SHARE` (or an equivalent lock) on the matching user rows**, so a suspension cannot commit between the check and the end of the transaction. |
| `createSessionUnlessSuspended(userId, idHash, expiresAt, identity, tx)` | Holds the user row `FOR SHARE`; inserts the session and returns `true`, or returns `false` when the user is suspended. |
| `getSessionWithExpiry(idHash, now)` | The session's user and expiry, excluding suspended users. |
| `touchSession(idHash, expiresAt)`, `deleteSession(idHash)`, `deleteSessionsForUser(userId, tx?)` | As named; `deleteSessionsForUser` returns the number deleted. |
| `isSuspendedCredential?(idHash, now)` | Optional, read-only. Lets `requireSession` answer `account_suspended` instead of `unauthenticated`. |

**`DuplicateIdentityError` contract.** The handler treats it as "the transaction is dead": it abandons the whole transaction and re-runs it once (so no savepoint is needed), finding the now-existing identity and continuing as a returning user. A store must therefore throw it only for a duplicate `(provider, subject)`, and a second failure ends in `sign_in_failed`. Because the transaction re-runs, `afterSignIn` may run twice (see Hooks).

### Running the contract suite against your own store

The repository has a behaviour suite every store must pass, `test/store-contract.ts` (it is not shipped in `dist`; copy it, or run it from a checkout). It takes a name and a factory returning a store plus a `suspend(userId)` helper, and runs the same tests against any store:

```ts
import { storeContract } from './store-contract.js';

storeContract('my store', async () => {
  const store = createMyStore();
  return { store, suspend: async (userId) => { /* mark the user suspended */ }, close: async () => { /* optional teardown */ } };
});
```

`test/memory-store.test.ts` (in-memory store) and `test/pg/pg-store.test.ts` (Postgres) are the two examples.

## Postgres reference store and migrations

`@ventrical/auth/pg` exports `pgAuthStore(pool)` (a `pg.Pool`) and `migrationsDir`, the absolute path of the shipped SQL migrations. Transactions are plain `BEGIN` / `COMMIT` / `ROLLBACK`; if `ROLLBACK` itself fails the original error is still thrown and the client is destroyed rather than returned to the pool.

The migrations are plain SQL files (currently `001_auth.sql`: `users`, `identities`, `sessions`, with `users.suspended_at`). Apply them in file-name order with your own runner:

```ts
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { migrationsDir } from '@ventrical/auth/pg';

for (const file of readdirSync(migrationsDir).filter((f) => f.endsWith('.sql')).sort()) {
  await pool.query(readFileSync(join(migrationsDir, file), 'utf8'));
}
```

Keep your own data in your own tables keyed by user id, not as extra columns on `users`.

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

There is no release automation, no CI workflow, and **no tag has been created**. When Ashwin decides to cut the first version, the step is:

```sh
git tag v0.1.0
```

(then pushing the tag), after which consumers install it with the line shown under [Install](#install): `"@ventrical/auth": "github:VentricalHQ/ventrical-auth#v0.1.0"`. Until that tag exists the install line does not resolve. The package is not published to npm; that waits until it goes open source (the license is Apache-2.0).

## Not in v0.1

Firms, roles and invites (they live in the apps), Drive and OneDrive consent, admin roles, connector linking, OAuth token revocation, passwords, email magic links, MFA and SAML. Next.js, Hono and Fastify adapters are not built; each should be a few dozen lines over `handle`.
