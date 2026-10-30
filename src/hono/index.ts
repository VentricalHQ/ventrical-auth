// Types only: hono stays an optional peer and must never be imported at runtime.
import type { MiddlewareHandler } from 'hono';
import type { Auth } from '../index.js';
import { AuthHttpError } from '../errors.js';
import type { AuthUser } from '../types.js';

/** Context variables set by `requireSession`: `c.get('user')`. */
export type AuthVariables = { user: AuthUser };

function toRequest(raw: Request, publicUrl: string): Request | undefined {
  let source: URL;
  try {
    source = new URL(raw.url);
  } catch {
    return undefined;
  }
  // Origin comes from config, never the Host header.
  const url = new URL(new URL(publicUrl).origin + source.pathname + source.search);
  return new Request(url, { method: raw.method, headers: raw.headers, redirect: 'manual' });
}

/** Middleware serving every auth route; other paths continue to the next handler. Use `app.use(authHandler(auth))`. */
export function authHandler(auth: Auth): MiddlewareHandler {
  return async (c, next) => {
    const built = toRequest(c.req.raw, auth.publicUrl);
    if (!built) return next();
    let response: Response | undefined;
    try {
      response = await auth.handle(built);
    } catch (err) {
      // Details of unexpected errors may carry secrets; hand the app a fixed error.
      throw err instanceof AuthHttpError ? err : new Error('Auth handler failed');
    }
    if (response === undefined) return next();
    return response;
  };
}

/** Middleware that requires a valid session and sets `c.get('user')`; answers 401/403 JSON like the express error shape. */
export function requireSession(auth: Auth): MiddlewareHandler<{ Variables: AuthVariables }> {
  return async (c, next) => {
    const built = toRequest(c.req.raw, auth.publicUrl);
    if (!built) return c.json({ error: { code: 'unauthenticated', message: 'Sign in required' } }, 401);
    let session;
    try {
      session = await auth.requireSession(built);
    } catch (err) {
      if (err instanceof AuthHttpError) {
        return c.json({ error: { code: err.code, message: err.message } }, err.status as 401 | 403);
      }
      throw new Error('Auth session check failed');
    }
    if (session.setCookie) c.header('set-cookie', session.setCookie, { append: true });
    c.set('user', session.user);
    return next();
  };
}
