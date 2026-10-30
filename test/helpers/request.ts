export interface ReqOpts {
  cookie?: string;
  origin?: string;
  referer?: string;
  headers?: Record<string, string>;
}

export const BASE = 'https://api.example.test';

/** Builds a Request for `path` (relative to BASE). */
export function req(method: string, path: string, opts: ReqOpts = {}): Request {
  const headers: Record<string, string> = { ...opts.headers };
  if (opts.cookie !== undefined) headers.cookie = opts.cookie;
  if (opts.origin !== undefined) headers.origin = opts.origin;
  if (opts.referer !== undefined) headers.referer = opts.referer;
  return new Request(new URL(path, BASE), { method, headers, redirect: 'manual' });
}

export interface ParsedSetCookie {
  name: string;
  value: string;
  /** Raw header, for attribute assertions. */
  raw: string;
  attrs: Record<string, string | true>;
}

/** Parses every Set-Cookie header of a response (via getSetCookie). Values are URI-decoded. */
export function setCookies(res: Response): ParsedSetCookie[] {
  return res.headers.getSetCookie().map((raw) => {
    const [pair, ...rest] = raw.split(';').map((s) => s.trim());
    const i = pair!.indexOf('=');
    const attrs: Record<string, string | true> = {};
    for (const a of rest) {
      const j = a.indexOf('=');
      if (j < 0) attrs[a.toLowerCase()] = true;
      else attrs[a.slice(0, j).toLowerCase()] = a.slice(j + 1);
    }
    return { name: pair!.slice(0, i), value: decodeURIComponent(pair!.slice(i + 1)), raw, attrs };
  });
}

export const setCookie = (res: Response, name: string): ParsedSetCookie | undefined =>
  setCookies(res).find((c) => c.name === name);

/** Cookie request-header value from a response's Set-Cookie headers (non-empty ones only). */
export function cookieHeaderFrom(res: Response): string {
  return setCookies(res).filter((c) => c.value !== '').map((c) => `${c.name}=${encodeURIComponent(c.value)}`).join('; ');
}
