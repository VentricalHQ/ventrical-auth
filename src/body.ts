/** The five POST routes that read a JSON body. Adapters forward a body for these paths (and only these). */
export const TWO_FACTOR_BODY_PATHS: readonly string[] = [
  '/auth/2fa/verify', '/auth/2fa/setup', '/auth/2fa/setup/confirm', '/auth/2fa/recovery-codes', '/auth/2fa/disable',
];

/** Largest request body the routes read; a valid body is a few dozen characters. */
export const MAX_BODY_CHARS = 4096;

export const needsBody = (method: string, pathname: string): boolean =>
  method.toUpperCase() === 'POST' && TWO_FACTOR_BODY_PATHS.includes(pathname);

/**
 * Reads up to MAX_BODY_CHARS + 1 characters of a body stream, so an oversized body is seen as oversized (the route
 * answers 400) without ever buffering all of it.
 */
export async function readCapped(chunks: AsyncIterable<Uint8Array | string>): Promise<string> {
  const decoder = new TextDecoder();
  // Manual iteration: leaving a `for await` early would call return(), which destroys a node request stream (and its socket).
  const it = chunks[Symbol.asyncIterator]();
  let text = '';
  try {
    for (;;) {
      const { done, value } = await it.next();
      if (done) return text + decoder.decode();
      text += typeof value === 'string' ? value : decoder.decode(value, { stream: true });
      if (text.length > MAX_BODY_CHARS) return text.slice(0, MAX_BODY_CHARS + 1);
    }
  } catch {
    return '';
  }
}

/**
 * Body text of a web Request, capped like readCapped. Reads a clone, so the original stays readable if the auth core
 * does not handle the path. Stops by cancelling without waiting: cancelling one branch of a cloned stream only settles
 * once the other branch is done too, so awaiting it would hang.
 */
export async function readRequestText(req: Request): Promise<string> {
  const body = req.clone().body;
  if (!body) return '';
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let text = '';
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return text + decoder.decode();
      text += decoder.decode(value, { stream: true });
      if (text.length > MAX_BODY_CHARS) {
        void reader.cancel().catch(() => undefined);
        return text.slice(0, MAX_BODY_CHARS + 1);
      }
    }
  } catch {
    return '';
  }
}
