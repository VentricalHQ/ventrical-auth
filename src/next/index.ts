// Plain Request/Response only: next is an optional peer and is never imported, even as a type.
import type { Auth } from '../index.js';
import { AuthHttpError } from '../errors.js';
import type { SessionResult } from '../session.js';

/** Rebuilds the request on the configured public origin; the request's own host is never trusted. */
function toRequest(req: Request, publicUrl: string): Request | undefined {
  let source: URL;
  try {
    source = new URL(req.url);
  } catch {
    return undefined;
  }
  const url = new URL(new URL(publicUrl).origin + source.pathname + source.search);
  // No auth route reads a body, so none is forwarded.
  return new Request(url, { method: req.method, headers: req.headers, redirect: 'manual' });
}

const json = (status: number, code: string, message: string): Response =>
  Response.json({ error: { code, message } }, { status });

const errorResponse = (err: unknown): Response =>
  err instanceof AuthHttpError ? json(err.status, err.code, err.message) : json(500, 'internal_error', 'Internal error');

/**
 * App Router handlers for a catch-all route that owns the auth prefix, e.g. `app/auth/[...auth]/route.ts`:
 * `export const { GET, POST } = authRouteHandlers(auth);`. Paths the auth core does not serve answer 404.
 */
export function authRouteHandlers(auth: Auth): { GET: (req: Request) => Promise<Response>; POST: (req: Request) => Promise<Response> } {
  const handler = async (req: Request): Promise<Response> => {
    try {
      const built = toRequest(req, auth.publicUrl);
      const response = built ? await auth.handle(built) : undefined;
      return response ?? json(404, 'not_found', 'Not found');
    } catch {
      // Details of unexpected errors may carry secrets; answer with a fixed body.
      return json(500, 'internal_error', 'Internal error');
    }
  };
  return { GET: handler, POST: handler };
}

/**
 * Optional-session helper: resolves the session or `undefined` for anonymous callers. When `setCookie` is
 * present, append it to the response as `Set-Cookie` to refresh the session.
 */
export function getSessionFromRequest(auth: Auth): (req: Request) => Promise<SessionResult | undefined> {
  return async (req) => {
    const built = toRequest(req, auth.publicUrl);
    return built ? auth.getSession(built) : undefined;
  };
}

/**
 * Requires a valid session: resolves the `SessionResult`, or a ready 401/403 JSON `Response` (same body shape as the
 * other adapters) for the caller to return.
 */
export function requireSession(auth: Auth): (req: Request) => Promise<SessionResult | Response> {
  return async (req) => {
    const built = toRequest(req, auth.publicUrl);
    if (!built) return json(401, 'unauthenticated', 'Sign in required');
    try {
      return await auth.requireSession(built);
    } catch (err) {
      return errorResponse(err);
    }
  };
}
