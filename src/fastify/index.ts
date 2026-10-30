// Types only: fastify stays an optional peer and must never be imported at runtime.
import type { FastifyInstance, FastifyReply, FastifyRequest, preHandlerAsyncHookHandler } from 'fastify';
import type { Auth } from '../index.js';
import { AuthHttpError } from '../errors.js';
import type { SessionUser } from '../session.js';

declare module 'fastify' {
  interface FastifyRequest {
    user?: SessionUser;
  }
}

/** Request targets that are not origin-form paths (absolute-form, `*`) are never auth routes. */
const isPathTarget = (req: FastifyRequest): boolean => req.raw.url?.startsWith('/') === true;

function toRequest(req: FastifyRequest, publicUrl: string): Request {
  // Origin comes from config, never the Host header. raw.url keeps the full original path and query.
  const url = new URL(new URL(publicUrl).origin + req.raw.url!);
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    headers.set(name, Array.isArray(value) ? value.join(', ') : value);
  }
  // No auth route reads a body, so none is forwarded.
  return new Request(url, { method: req.method, headers, redirect: 'manual' });
}

/**
 * Plugin serving every auth route via an `onRequest` hook; other paths continue to the app's own routes.
 * Register with `await app.register(authPlugin(auth))`. It is not encapsulated, so the hook covers the whole app.
 */
export function authPlugin(auth: Auth): (app: FastifyInstance) => Promise<void> {
  const plugin = async (app: FastifyInstance): Promise<void> => {
    app.addHook('onRequest', async (req: FastifyRequest, reply: FastifyReply) => {
      if (!isPathTarget(req)) return;
      let response: Response | undefined;
      let body: Buffer | undefined;
      try {
        response = await auth.handle(toRequest(req, auth.publicUrl));
        // Buffer first, so a failure while reading the body cannot leave a half-written response.
        if (response) body = Buffer.from(await response.arrayBuffer());
      } catch (err) {
        // Details of unexpected errors may carry secrets; answer with a fixed body.
        if (err instanceof AuthHttpError) return reply.code(err.status).send({ error: { code: err.code, message: err.message } });
        return reply.code(500).send({ error: { code: 'internal_error', message: 'Internal error' } });
      }
      if (response === undefined || body === undefined) return;
      reply.code(response.status);
      const cookies = response.headers.getSetCookie();
      for (const [name, value] of response.headers) {
        if (name.toLowerCase() === 'set-cookie') continue;
        reply.header(name, value);
      }
      if (cookies.length > 0) reply.header('set-cookie', cookies);
      return reply.send(body.length > 0 ? body : undefined);
    });
  };
  // Equivalent of fastify-plugin: skip encapsulation so the hook applies app-wide.
  (plugin as unknown as Record<symbol, boolean>)[Symbol.for('skip-override')] = true;
  return plugin;
}

/** `preHandler` that requires a valid session and sets `request.user`; answers 401/403 JSON like the express error shape. */
export function requireSession(auth: Auth): preHandlerAsyncHookHandler {
  return async (req, reply) => {
    if (!isPathTarget(req)) return reply.code(401).send({ error: { code: 'unauthenticated', message: 'Sign in required' } });
    try {
      const session = await auth.requireSession(toRequest(req, auth.publicUrl));
      if (session.setCookie) reply.header('set-cookie', session.setCookie);
      req.user = session.user;
    } catch (err) {
      if (err instanceof AuthHttpError) return reply.code(err.status).send({ error: { code: err.code, message: err.message } });
      return reply.code(500).send({ error: { code: 'internal_error', message: 'Internal error' } });
    }
  };
}
