import dns from 'node:dns';
import http from 'node:http';
import net from 'node:net';
import type { AddressInfo } from 'node:net';
import tls from 'node:tls';
import { afterEach, describe, expect, it } from 'vitest';
import { isAllowedHost } from './helpers/no-network.js';

const BLOCKED = /network access blocked in tests/;

describe('no-network guard', () => {
  const saved = process.env.VENTRICAL_TEST_DATABASE_URL;
  afterEach(() => {
    if (saved === undefined) delete process.env.VENTRICAL_TEST_DATABASE_URL;
    else process.env.VENTRICAL_TEST_DATABASE_URL = saved;
  });

  it('fetch to a non-loopback URL throws', async () => {
    await expect(fetch('https://example.com/')).rejects.toThrow(BLOCKED);
    await expect(fetch(new URL('http://203.0.113.9/x'))).rejects.toThrow(BLOCKED);
    await expect(fetch(new Request('https://example.org/'))).rejects.toThrow(BLOCKED);
  });

  it('the error names only the host, never the URL', async () => {
    const err = (await fetch('https://user:pw@example.com/path?token=abc').catch((e: unknown) => e)) as Error;
    expect(err.message).toContain('example.com');
    expect(err.message).not.toMatch(/pw|token=abc|\/path/);
  });

  it('raw sockets, TLS and DNS to non-loopback hosts throw', async () => {
    expect(() => net.connect(80, '203.0.113.9')).toThrow(BLOCKED);
    expect(() => tls.connect(443, 'example.com')).toThrow(BLOCKED);
    await expect(dns.promises.lookup('example.com')).rejects.toThrow(BLOCKED);
    await new Promise<void>((resolve) => dns.lookup('example.com', (err) => { expect(err?.message).toMatch(BLOCKED); resolve(); }));
  });

  it('loopback still works: fetch and a raw socket reach a local server', async () => {
    const server = http.createServer((_req, res) => { res.end('local-ok'); });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const port = (server.address() as AddressInfo).port;
    try {
      const res = await fetch(`http://127.0.0.1:${port}/`);
      expect(await res.text()).toBe('local-ok');
      const viaName = await fetch(`http://localhost:${port}/`).then((r) => r.text()).catch(() => 'ipv6-only');
      expect(['local-ok', 'ipv6-only']).toContain(viaName);
      await new Promise<void>((resolve, reject) => {
        const s = net.connect(port, '127.0.0.1', () => { s.destroy(); resolve(); });
        s.on('error', reject);
      });
    } finally {
      await new Promise<void>((r) => { server.close(() => r()); server.closeAllConnections(); });
    }
  });

  it('allows loopback names and ranges, blocks look-alikes', () => {
    for (const h of ['127.0.0.1', '127.1.2.3', '::1', '[::1]', 'localhost', 'LOCALHOST', 'app.localhost', '::ffff:127.0.0.1']) {
      expect(isAllowedHost(h), h).toBe(true);
    }
    for (const h of ['localhost.example.com', '127.0.0.1.example.com', '10.0.0.1', '0.0.0.0', 'example.com', '128.0.0.1']) {
      expect(isAllowedHost(h), h).toBe(false);
    }
  });

  it('allows the host of VENTRICAL_TEST_DATABASE_URL only while it is set', () => {
    delete process.env.VENTRICAL_TEST_DATABASE_URL;
    expect(isAllowedHost('db.example.test')).toBe(false);
    process.env.VENTRICAL_TEST_DATABASE_URL = `${'postgres'}://user:fake@db.example.test:5432/fakedb`;
    expect(isAllowedHost('db.example.test')).toBe(true);
    expect(isAllowedHost('DB.example.test')).toBe(true);
    expect(isAllowedHost('other.example.test')).toBe(false);
  });
});
