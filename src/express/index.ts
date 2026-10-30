// Types only: express stays an optional peer and must never be imported at runtime.
import type { NextFunction, Request as ExpressRequest, RequestHandler, Response as ExpressResponse } from 'express';
import type { Auth } from '../index.js';
import { AuthHttpError } from '../errors.js';
import type { AuthUser } from '../types.js';

declare module 'express-serve-static-core' {
  interface Request {
    user?: AuthUser;
  }
}

function toRequest(req: ExpressRequest, publicUrl: string): Request {
  // Origin comes from config, never the Host header. originalUrl keeps the mount path of nested routers.
  const url = new URL(new URL(publicUrl).origin + req.originalUrl);
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    headers.set(name, Array.isArray(value) ? value.join(', ') : value);
  }
  // No auth route reads a body, so none is forwarded.
  return new Request(url, { method: req.method, headers, redirect: 'manual' });
}

/**
 * Express handler serving every auth route; other paths fall through via `next()`.
 * Mount with `app.use(authRouter(auth))`.
 */
export function authRouter(auth: Auth): RequestHandler {
  return (req: ExpressRequest, res: ExpressResponse, next: NextFunction): void => {
    void (async () => {
      const response = await auth.handle(toRequest(req, auth.publicUrl));
      if (response === undefined) {
        next();
        return;
      }
      res.statusCode = response.status;
      const cookies = response.headers.getSetCookie();
      for (const [name, value] of response.headers) {
        if (name.toLowerCase() === 'set-cookie') continue;
        res.setHeader(name, value);
      }
      if (cookies.length > 0) res.setHeader('set-cookie', cookies);
      res.end(Buffer.from(await response.arrayBuffer()));
    })().catch((err: unknown) => {
      // Details of unexpected errors may carry secrets; hand next() a fixed error.
      next(err instanceof AuthHttpError ? err : new Error('Auth handler failed'));
    });
  };
}

/** Middleware that requires a valid session, sets `req.user`, and passes `AuthHttpError` to `next`. */
export function requireSession(auth: Auth): RequestHandler {
  return (req: ExpressRequest, res: ExpressResponse, next: NextFunction): void => {
    void (async () => {
      const session = await auth.requireSession(toRequest(req, auth.publicUrl));
      if (session.setCookie) res.append('set-cookie', session.setCookie);
      req.user = session.user;
      next();
    })().catch((err: unknown) => next(err instanceof AuthHttpError ? err : new Error('Auth session check failed')));
  };
}
