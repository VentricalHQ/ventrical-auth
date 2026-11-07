// Types only: express stays an optional peer and must never be imported at runtime.
import type { NextFunction, Request as ExpressRequest, RequestHandler, Response as ExpressResponse } from 'express';
import type { Auth, PendingSession } from '../index.js';
import { MAX_BODY_CHARS, needsBody, readCapped } from '../body.js';
import { AuthHttpError } from '../errors.js';
import type { SessionResult, SessionUser } from '../session.js';

declare module 'express-serve-static-core' {
  interface Request {
    user?: SessionUser;
  }
}

/** Request targets that are not origin-form paths (absolute-form, `*`) are never auth routes. */
const isPathTarget = (req: ExpressRequest): boolean => req.originalUrl.startsWith('/');

/**
 * Body text for a 2FA route: what express.json()/text()/raw() already parsed, or else the raw stream (capped). Only
 * called for the 2FA POST routes.
 */
async function bodyText(req: ExpressRequest): Promise<string> {
  const parsed: unknown = (req as { body?: unknown }).body;
  if (typeof parsed === 'string') return parsed.slice(0, MAX_BODY_CHARS + 1);
  if (Buffer.isBuffer(parsed)) return parsed.toString('utf8', 0, MAX_BODY_CHARS + 1);
  if (parsed !== undefined && parsed !== null) {
    try {
      return JSON.stringify(parsed).slice(0, MAX_BODY_CHARS + 1);
    } catch {
      return '';
    }
  }
  return readCapped(req as AsyncIterable<Buffer>);
}

function toRequest(req: ExpressRequest, publicUrl: string, body?: string): Request {
  // Origin comes from config, never the Host header. originalUrl keeps the mount path of nested routers.
  const url = new URL(new URL(publicUrl).origin + req.originalUrl);
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    headers.set(name, Array.isArray(value) ? value.join(', ') : value);
  }
  // Only the 2FA POST routes read a body, so it is forwarded for them alone.
  if (body !== undefined) headers.delete('content-length');
  return new Request(url, { method: req.method, headers, redirect: 'manual', ...(body !== undefined ? { body } : {}) });
}

/**
 * Express handler serving every auth route; other paths fall through via `next()`.
 * Mount with `app.use(authRouter(auth))`.
 */
export function authRouter(auth: Auth): RequestHandler {
  return (req: ExpressRequest, res: ExpressResponse, next: NextFunction): void => {
    if (!isPathTarget(req)) {
      next();
      return;
    }
    void (async () => {
      const requestBody = auth.twoFactorEnabled && needsBody(req.method, new URL(req.originalUrl, 'http://x').pathname) ? await bodyText(req) : undefined;
      const response = await auth.handle(toRequest(req, auth.publicUrl, requestBody));
      if (response === undefined) {
        next();
        return;
      }
      // Buffer first, so a failure while reading the body cannot leave a half-written response.
      const body = Buffer.from(await response.arrayBuffer());
      res.statusCode = response.status;
      const cookies = response.headers.getSetCookie();
      for (const [name, value] of response.headers) {
        if (name.toLowerCase() === 'set-cookie') continue;
        res.setHeader(name, value);
      }
      if (cookies.length > 0) res.setHeader('set-cookie', cookies);
      res.end(body);
    })().catch((err: unknown) => {
      if (res.headersSent) {
        res.destroy();
        return;
      }
      // Details of unexpected errors may carry secrets; hand next() a fixed error.
      next(err instanceof AuthHttpError ? err : new Error('Auth handler failed'));
    });
  };
}

/** Middleware that requires a valid session, sets `req.user`, and passes `AuthHttpError` to `next`. */
export function requireSession(auth: Auth): RequestHandler {
  return (req: ExpressRequest, res: ExpressResponse, next: NextFunction): void => {
    if (!isPathTarget(req)) {
      next(new AuthHttpError(401, 'unauthenticated', 'Sign in required'));
      return;
    }
    void (async () => {
      const session = await auth.requireSession(toRequest(req, auth.publicUrl));
      if (session.setCookie) res.append('set-cookie', session.setCookie);
      req.user = session.user;
      next();
    })().catch((err: unknown) => next(err instanceof AuthHttpError ? err : new Error('Auth session check failed')));
  };
}

/**
 * Optional-session helper for routes that serve both signed-in and anonymous callers. Resolves the session (setting
 * `req.user` and, when `res` is given, appending a refreshed session cookie) or `undefined` when there is none.
 * An anonymous caller is not an error; only unexpected store failures reject.
 */
export function currentSession(auth: Auth): (req: ExpressRequest, res?: ExpressResponse) => Promise<SessionResult | undefined> {
  return async (req, res) => {
    if (!isPathTarget(req)) return undefined;
    const session = await auth.getSession(toRequest(req, auth.publicUrl));
    if (!session) return undefined;
    if (session.setCookie && res) res.append('set-cookie', session.setCookie);
    req.user = session.user;
    return session;
  };
}

/**
 * Resolves the session held before the second factor, for the app's 2FA page: `{ state: 'verify' | 'enroll' }`, or
 * `undefined` for no session, a full session, or when `twoFactor` is not configured.
 */
export function getPendingSession(auth: Auth): (req: ExpressRequest) => Promise<PendingSession | undefined> {
  return async (req) => (isPathTarget(req) ? auth.getPendingSession(toRequest(req, auth.publicUrl)) : undefined);
}
