// Vitest setup file (see vitest.config.ts): any outbound network attempt that is not loopback fails the test.
// Tests that need an HTTP client pass their own `fetch` through config; those never reach this guard.
import dns from 'node:dns';
import net from 'node:net';
import tls from 'node:tls';

const LOOPBACK_NAMES = new Set(['localhost', '::1', '0:0:0:0:0:0:0:1']);

/** Host of VENTRICAL_TEST_DATABASE_URL, read on every call so tests can set it. */
function databaseHost(): string | undefined {
  const raw = process.env.VENTRICAL_TEST_DATABASE_URL;
  if (!raw) return undefined;
  try {
    return normalize(new URL(raw).hostname);
  } catch {
    return undefined;
  }
}

const normalize = (host: string): string => host.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');

/** True for loopback (127.0.0.0/8, ::1, localhost) and for the host of VENTRICAL_TEST_DATABASE_URL. */
export function isAllowedHost(host: string | undefined | null): boolean {
  if (host === undefined || host === null || host === '') return true; // no host means a local default (localhost)
  const h = normalize(host);
  if (LOOPBACK_NAMES.has(h) || h.endsWith('.localhost')) return true;
  if (/^127(\.\d{1,3}){3}$/.test(h)) return true;
  if (/^::ffff:127(\.\d{1,3}){3}$/.test(h)) return true;
  return h === databaseHost();
}

/** The message never includes the URL, only the host: URLs can carry credentials. */
const blocked = (host: string): Error => new Error(`network access blocked in tests (host: ${host}); pass a fake fetch through config`);

function hostOfFetchInput(input: unknown): string {
  try {
    const raw = typeof input === 'string' ? input : input instanceof URL ? input.href : (input as { url?: string }).url ?? '';
    return new URL(raw, 'http://localhost').hostname;
  } catch {
    return '<unparseable>';
  }
}

const realFetch = globalThis.fetch;
globalThis.fetch = (async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
  const host = hostOfFetchInput(input);
  if (!isAllowedHost(host)) throw blocked(host);
  return realFetch(input, init);
}) as typeof fetch;

// Socket-level connects (net.connect, http, https, pg): unix-socket paths are local; anything else needs an allowed host.
const realConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function patchedConnect(this: net.Socket, ...args: unknown[]) {
  // Node passes either (options | port, host | path) or the already-normalized array [options, cb].
  const first = Array.isArray(args[0]) ? args[0][0] : args[0];
  let host: string | undefined;
  if (typeof first === 'object' && first !== null) {
    const o = first as { host?: string; path?: string };
    if (o.path !== undefined) return (realConnect as (...a: unknown[]) => net.Socket).apply(this, args);
    host = o.host;
  } else if (typeof first === 'string') {
    return (realConnect as (...a: unknown[]) => net.Socket).apply(this, args); // a unix-socket path
  } else {
    host = typeof args[1] === 'string' ? args[1] : undefined;
  }
  if (!isAllowedHost(host)) throw blocked(host ?? '<none>');
  return (realConnect as (...a: unknown[]) => net.Socket).apply(this, args);
} as typeof net.Socket.prototype.connect;

const realTlsConnect = tls.connect;
tls.connect = function patchedTlsConnect(...args: unknown[]) {
  const first = args[0];
  const host = typeof first === 'object' && first !== null ? (first as { host?: string; servername?: string }).host
    : typeof args[1] === 'string' ? args[1] : undefined;
  if (!isAllowedHost(host)) throw blocked(host ?? '<none>');
  return (realTlsConnect as (...a: unknown[]) => tls.TLSSocket)(...args);
} as typeof tls.connect;

// Name resolution: a non-allowed name never resolves, in both the callback and the promise APIs.
const realLookup = dns.lookup;
dns.lookup = function patchedLookup(hostname: string, ...rest: unknown[]) {
  if (!isAllowedHost(hostname)) {
    const cb = rest.find((a) => typeof a === 'function') as ((err: Error) => void) | undefined;
    const err = blocked(hostname);
    if (cb) {
      process.nextTick(cb, err);
      return undefined as unknown as ReturnType<typeof dns.lookup>;
    }
    throw err;
  }
  return (realLookup as (...a: unknown[]) => unknown)(hostname, ...rest);
} as typeof dns.lookup;
(dns.lookup as unknown as { __promisify__: unknown }).__promisify__ = (realLookup as unknown as { __promisify__: unknown }).__promisify__;

const realLookupP = dns.promises.lookup;
dns.promises.lookup = (async (hostname: string, ...rest: unknown[]) => {
  if (!isAllowedHost(hostname)) throw blocked(hostname);
  return (realLookupP as (...a: unknown[]) => Promise<unknown>)(hostname, ...rest);
}) as typeof dns.promises.lookup;

for (const fn of ['resolve', 'resolve4', 'resolve6'] as const) {
  const real = dns[fn] as (...a: unknown[]) => unknown;
  (dns as unknown as Record<string, unknown>)[fn] = (hostname: string, ...rest: unknown[]) => {
    if (!isAllowedHost(hostname)) {
      const cb = rest.find((a) => typeof a === 'function') as ((err: Error) => void) | undefined;
      const err = blocked(hostname);
      if (cb) { process.nextTick(cb, err); return undefined; }
      throw err;
    }
    return real(hostname, ...rest);
  };
}
