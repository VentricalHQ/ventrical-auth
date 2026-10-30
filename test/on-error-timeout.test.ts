import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createAuth, type AuthConfig, type AuthErrorEvent } from '../src/index.js';
import { createMemoryStore, type MemoryTx } from './helpers/memory-store.js';
import { req } from './helpers/request.js';

const FRONT = 'https://app.example.test';

function mk(onError: (e: AuthErrorEvent) => void | Promise<void>, over: Partial<AuthConfig<MemoryTx>> = {}) {
  return createAuth<MemoryTx>({
    providers: { google: { clientId: 'a', clientSecret: 'b' } }, publicUrl: 'https://api.example.test', frontendUrl: FRONT,
    encryptionKey: Buffer.alloc(32, 1), store: createMemoryStore(), hooks: { onError }, ...over,
  });
}
// A cross-origin logout is a cheap, network-free failure that reports once.
const fire = (auth: ReturnType<typeof mk>) => auth.handle(req('POST', '/auth/logout'));

describe('onError timeout', () => {
  beforeEach(() => { vi.useFakeTimers(); });
  afterEach(() => { vi.useRealTimers(); });

  it('a hung hook delays the response by the default 2000ms, and the response is unchanged', async () => {
    const auth = mk(() => new Promise<void>(() => {}));
    let res: Response | undefined;
    const p = fire(auth).then((r) => { res = r; });
    await vi.advanceTimersByTimeAsync(1999);
    expect(res).toBeUndefined();
    await vi.advanceTimersByTimeAsync(1);
    await p;
    expect(res!.status).toBe(403);
    expect(await res!.json()).toEqual({ error: { code: 'forbidden', message: 'Cross-origin request rejected' } });
  });

  it('a hook that resolves before the timeout returns promptly and clears the timer', async () => {
    const auth = mk(async () => {});
    const res = await fire(auth);
    expect(res!.status).toBe(403);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('a throwing or rejecting hook clears the timer too', async () => {
    const a = mk(() => { throw new Error('x'); });
    expect((await fire(a))!.status).toBe(403);
    expect(vi.getTimerCount()).toBe(0);
    const b = mk(() => Promise.reject(new Error('x')));
    expect((await fire(b))!.status).toBe(403);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('a hook that rejects after the timeout causes no unhandled rejection', async () => {
    const unhandled: unknown[] = [];
    const on = (e: unknown) => unhandled.push(e);
    process.on('unhandledRejection', on);
    try {
      const auth = mk(() => new Promise<void>((_, rej) => { setTimeout(() => rej(new Error('late')), 5000); }));
      const p = fire(auth);
      await vi.advanceTimersByTimeAsync(2000);
      expect((await p)!.status).toBe(403);
      await vi.advanceTimersByTimeAsync(4000);
      vi.useRealTimers();
      await new Promise((r) => setTimeout(r, 10));
    } finally {
      process.off('unhandledRejection', on);
    }
    expect(unhandled).toEqual([]);
  });

  it('honours a custom onErrorTimeoutMs', async () => {
    const auth = mk(() => new Promise<void>(() => {}), { onErrorTimeoutMs: 50 });
    let done = false;
    const p = fire(auth).then(() => { done = true; });
    await vi.advanceTimersByTimeAsync(49);
    expect(done).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    await p;
    expect(done).toBe(true);
  });

  it('does not start a timer when no hook is configured', async () => {
    const auth = mk(() => {}, { hooks: {} });
    expect((await fire(auth))!.status).toBe(403);
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe('onErrorTimeoutMs validation', () => {
  const build = (v: unknown) => () => mk(() => {}, { onErrorTimeoutMs: v as number });
  it.each([0, -1, NaN, Infinity, '5', null])('rejects %s without echoing it', (v) => {
    expect(build(v)).toThrow('onErrorTimeoutMs must be a positive finite number');
  });
  it('does not echo the value', () => {
    expect(build('SECRET-VALUE')).not.toThrow(/SECRET-VALUE/);
  });
  it('accepts undefined and a positive number', () => {
    expect(build(undefined)).not.toThrow();
    expect(build(10)).not.toThrow();
  });
});
