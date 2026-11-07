import { describe, expect, it } from 'vitest';
import { FRONT, PUBLIC, tfSetup } from './helpers/two-factor.js';

describe('auth.handle request body cap', () => {
  it('does not pull an endless streamed body into memory on an unauthenticated 2FA route', async () => {
    const t = tfSetup();
    let pulled = 0;
    const chunk = new Uint8Array(64 * 1024).fill(0x61);
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulled += chunk.length;
        controller.enqueue(chunk);
        if (pulled > 256 * 1024 * 1024) controller.close(); // a safety stop for the test itself
      },
    }, { highWaterMark: 0 });
    const res = await t.auth.handle(new Request(new URL('/auth/2fa/verify', PUBLIC), {
      method: 'POST', headers: { 'content-type': 'application/json', origin: FRONT }, body, duplex: 'half',
    } as RequestInit & { duplex: 'half' }));
    expect(res!.status).toBe(400);
    expect(pulled).toBeLessThan(1024 * 1024);
  });

  it('still answers 400 for an oversized body that is not streamed', async () => {
    const t = tfSetup();
    const r = await t.post('/auth/2fa/verify', {}, undefined, { raw: JSON.stringify({ code: 'x'.repeat(10_000) }) });
    expect(r.status).toBe(400);
  });
});
