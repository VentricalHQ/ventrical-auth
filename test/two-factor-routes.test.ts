import { describe, expect, it } from 'vitest';
import { base32Decode } from '../src/base32.js';
import { decrypt, hashToken } from '../src/crypto.js';
import { hotp, totpStep } from '../src/totp.js';
import { recoveryCodeHash, totpAad } from '../src/twofactor.js';
import { FRONT, KEY, SESSION_COOKIE, req, setCookie, tfSetup, type Tf } from './helpers/two-factor.js';

const DAY = 24 * 3600 * 1000;
const sessionRow = (t: Tf, cookie: string) => t.store.sessions.get(hashToken(decodeURIComponent(cookie.split('=').slice(1).join('='))))!;
const codesOf = (t: Tf, secret: Uint8Array, offset = 0) => t.codeFor(secret, offset);

/** An enrolled user with a pending (verify-state) session. */
async function pendingVerify(t = tfSetup(), recoveryCodes: string[] = []) {
  const { user, secret } = await t.enrol('g1', { recoveryCodes });
  const { cookie } = await t.signIn('google', { redirect: '/memories' });
  return { t, user, secret, cookie: cookie! };
}

/** A user with a full, verified session (enrolled, then verified through the route). */
async function fullSession(t = tfSetup(), recoveryCodes: string[] = []) {
  const p = await pendingVerify(t, recoveryCodes);
  p.t.nextStep();
  const v = await p.t.post('/auth/2fa/verify', { code: codesOf(p.t, p.secret) }, p.cookie);
  expect(v.status).toBe(200);
  const sc = setCookie(v.res, SESSION_COOKIE)!;
  return { ...p, cookie: `${SESSION_COOKIE}=${encodeURIComponent(sc.value)}` };
}

describe('POST /auth/2fa/verify', () => {
  it('a correct code makes the session full, extends it, reissues the cookie and returns the saved redirect', async () => {
    const { t, secret, cookie } = await pendingVerify();
    t.nextStep();
    const { res, status, json } = await t.post('/auth/2fa/verify', { code: codesOf(t, secret) }, cookie);
    expect(status).toBe(200);
    expect(json).toEqual({ ok: true, redirect: `${FRONT}/memories` });
    expect(res.headers.get('cache-control')).toBe('no-store');
    const sc = setCookie(res, SESSION_COOKIE)!;
    expect(sc.value).toBe(decodeURIComponent(cookie.split('=')[1]!));
    expect(Number(sc.attrs['max-age'])).toBe(30 * 24 * 3600);
    const row = sessionRow(t, cookie);
    expect(row.mfaPending).toBe(false);
    expect(row.mfaVerifiedAt).toEqual(t.clock.now);
    expect(row.expiresAt.getTime()).toBe(t.clock.now.getTime() + 30 * DAY);
    const s = await t.auth.getSession(req('GET', '/x', { cookie }));
    expect(s?.mfaVerifiedAt).toEqual(t.clock.now);
    expect(await t.auth.getPendingSession(req('GET', '/x', { cookie }))).toBeUndefined();
  });

  it('the redirect is "/" on the frontend when none was saved, and goes through resolveRedirect', async () => {
    const t = tfSetup({ config: { hooks: { resolveRedirect: (p) => ({ target: 'backend' as const, path: p }) } } });
    const { secret } = await t.enrol();
    const { cookie } = await t.signIn('google', { redirect: '/memories' });
    t.nextStep();
    const { json } = await t.post('/auth/2fa/verify', { code: codesOf(t, secret) }, cookie);
    expect(json?.redirect).toBe('https://api.example.test/memories');
  });

  it('the absolute cap still counts from created_at', async () => {
    const t = tfSetup({ config: { sessionMaxAgeMs: 5 * 60 * 1000 } });
    const { secret } = await t.enrol();
    const { cookie } = await t.signIn();
    t.advance(2 * 60 * 1000);
    const { res } = await t.post('/auth/2fa/verify', { code: codesOf(t, secret) }, cookie!);
    expect(res.status).toBe(200);
    expect(sessionRow(t, cookie!).expiresAt.getTime()).toBe(START_PLUS(t, 5 * 60 * 1000));
  });

  it('accepts the step before and after, rejects two away', async () => {
    for (const [offset, ok] of [[-1, true], [1, true], [-2, false], [2, false]] as const) {
      const { t, secret, cookie } = await pendingVerify();
      t.nextStep();
      const { status } = await t.post('/auth/2fa/verify', { code: codesOf(t, secret, offset) }, cookie);
      expect(status, `offset ${offset}`).toBe(ok ? 200 : 401);
    }
  });

  it('a code cannot be replayed: the same step fails on the next sign-in', async () => {
    const { t, secret, cookie } = await pendingVerify();
    t.nextStep();
    const code = codesOf(t, secret);
    expect((await t.post('/auth/2fa/verify', { code }, cookie)).status).toBe(200);
    const again = await t.signIn();
    const replay = await t.post('/auth/2fa/verify', { code }, again.cookie);
    expect(replay.status).toBe(401);
    expect(replay.json?.error.code).toBe('mfa_invalid_code');
    // An earlier step than the one used is replay too, even though it is inside the window.
    expect((await t.post('/auth/2fa/verify', { code: codesOf(t, secret, -1) }, again.cookie)).status).toBe(401);
  });

  it('a wrong code answers 401 mfa_invalid_code and the session stays pending', async () => {
    const { t, cookie } = await pendingVerify();
    const { status, json } = await t.post('/auth/2fa/verify', { code: '000000' }, cookie);
    expect(status).toBe(401);
    expect(json?.error.code).toBe('mfa_invalid_code');
    expect(sessionRow(t, cookie).mfaPending).toBe(true);
    expect(sessionRow(t, cookie).mfaAttempts).toBe(1);
  });

  it('a recovery code works once, in any case and with dashes', async () => {
    const t = tfSetup();
    const code = 'ABCDEFGH23';
    const { cookie } = await pendingVerify(t, [code]);
    const ok = await t.post('/auth/2fa/verify', { recoveryCode: 'abcde-fgh23' }, cookie);
    expect(ok.status).toBe(200);
    const again = await t.signIn();
    const reuse = await t.post('/auth/2fa/verify', { recoveryCode: code }, again.cookie);
    expect(reuse.status).toBe(401);
  });

  it('a pending session in enroll state, a full session and no session are refused', async () => {
    const enrolling = tfSetup({ twoFactor: { required: true } });
    const { cookie: pendingEnroll } = await enrolling.signIn();
    expect((await enrolling.post('/auth/2fa/verify', { code: '123456' }, pendingEnroll)).json?.error.code).toBe('mfa_not_pending');

    const full = await fullSession();
    const r = await full.t.post('/auth/2fa/verify', { code: '123456' }, full.cookie);
    expect(r.status).toBe(409);
    expect(r.json?.error.code).toBe('mfa_not_pending');

    expect((await full.t.post('/auth/2fa/verify', { code: '123456' })).status).toBe(401);
    expect((await full.t.post('/auth/2fa/verify', { code: '123456' }, `${SESSION_COOKIE}=unknown`)).status).toBe(401);
  });

  it('is same-origin only', async () => {
    const { t, secret, cookie } = await pendingVerify();
    t.nextStep();
    const code = codesOf(t, secret);
    expect((await t.post('/auth/2fa/verify', { code }, cookie, { origin: 'https://evil.test' })).status).toBe(403);
    expect((await t.post('/auth/2fa/verify', { code }, cookie, { origin: null })).status).toBe(403);
    expect(sessionRow(t, cookie).mfaPending).toBe(true);
  });

  it('a GET is not a route', async () => {
    const { t, cookie } = await pendingVerify();
    expect(await t.auth.handle(req('GET', '/auth/2fa/verify', { cookie }))).toBeUndefined();
  });

  it('malformed bodies are 400 and do not count as wrong codes', async () => {
    const { t, cookie } = await pendingVerify();
    const bad: Array<[unknown, string?]> = [
      [{}], [{ code: 123456 }], [{ code: '123456', recoveryCode: 'ABCDEFGH23' }], [{ code: ['1'] }], [[]], [null], ['x'],
      [undefined, 'not json'], [undefined, ''], [{ code: 'x'.repeat(5000) }],
    ];
    for (const [body, raw] of bad) {
      const r = await t.post('/auth/2fa/verify', body, cookie, raw !== undefined ? { raw } : {});
      expect(r.status, JSON.stringify(body) ?? raw).toBe(400);
      expect(r.json?.error.code).toBe('invalid_request');
    }
    expect(sessionRow(t, cookie).mfaAttempts).toBe(0);
    expect((await t.store.getTotp('' + [...t.store.totps.keys()][0]))?.failedCount).toBe(0);
  });

  it('a suspended user is refused at verify with account_suspended, and the code is not spent', async () => {
    const { t, user, secret, cookie } = await pendingVerify();
    t.store.suspend(user.id);
    t.nextStep();
    const { status, json } = await t.post('/auth/2fa/verify', { code: codesOf(t, secret) }, cookie);
    expect(status).toBe(403);
    expect(json?.error.code).toBe('account_suspended');
    expect((await t.store.getTotp(user.id))!.lastStep).toBe(0);
  });
});

describe('abuse limits', () => {
  const wrong = (t: Tf, cookie: string, n: number) => Promise.all(Array.from({ length: n }, () => t.post('/auth/2fa/verify', { code: '000000' }, cookie)));

  it('the pending session is deleted at maxAttempts and the cookie cleared', async () => {
    const { t, cookie } = await pendingVerify(tfSetup({ twoFactor: { maxAttempts: 3 } }));
    expect((await t.post('/auth/2fa/verify', { code: '000000' }, cookie)).status).toBe(401);
    expect((await t.post('/auth/2fa/verify', { code: '000000' }, cookie)).status).toBe(401);
    const last = await t.post('/auth/2fa/verify', { code: '000000' }, cookie);
    expect(last.status).toBe(429);
    expect(setCookie(last.res, SESSION_COOKIE)?.value).toBe('');
    expect(t.store.sessions.size).toBe(0);
    expect((await t.post('/auth/2fa/verify', { code: '000000' }, cookie)).status).toBe(401);
  });

  it('the user is locked at maxAttempts, and the lock survives a fresh sign-in', async () => {
    const { t, user, secret, cookie } = await pendingVerify(tfSetup({ twoFactor: { maxAttempts: 3, lockoutMs: 60_000 } }));
    await wrong(t, cookie, 3);
    expect((await t.store.getTotp(user.id))!.lockedUntil).not.toBeNull();
    const fresh = await t.signIn();
    expect(fresh.location).toBe(`${FRONT}/2fa`);
    t.nextStep();
    const r = await t.post('/auth/2fa/verify', { code: codesOf(t, secret) }, fresh.cookie);
    expect(r.status).toBe(429);
    expect(r.json?.error.code).toBe('mfa_locked');
    expect(sessionRow(t, fresh.cookie!).mfaPending).toBe(true);
  });

  it('a correct code is refused while locked, and accepted once the lock has passed', async () => {
    const { t, secret, cookie } = await pendingVerify(tfSetup({ twoFactor: { maxAttempts: 2, lockoutMs: 60_000 } }));
    await wrong(t, cookie, 2);
    const fresh = await t.signIn();
    t.advance(30_000);
    expect((await t.post('/auth/2fa/verify', { code: codesOf(t, secret) }, fresh.cookie)).status).toBe(429);
    expect((await t.post('/auth/2fa/verify', { recoveryCode: 'ABCDEFGH23' }, fresh.cookie)).status).toBe(429);
    t.advance(31_000);
    expect((await t.post('/auth/2fa/verify', { code: codesOf(t, secret) }, fresh.cookie)).status).toBe(200);
  });

  it('a locked attempt does not extend the lock or count', async () => {
    const { t, user, cookie } = await pendingVerify(tfSetup({ twoFactor: { maxAttempts: 2, lockoutMs: 60_000 } }));
    await wrong(t, cookie, 2);
    const until = (await t.store.getTotp(user.id))!.lockedUntil!.getTime();
    const fresh = await t.signIn();
    await t.post('/auth/2fa/verify', { code: '000000' }, fresh.cookie);
    expect((await t.store.getTotp(user.id))!.lockedUntil!.getTime()).toBe(until);
    expect(sessionRow(t, fresh.cookie!).mfaAttempts).toBe(0);
  });

  it('wrong recovery codes count the same', async () => {
    const { t, user, cookie } = await pendingVerify(tfSetup({ twoFactor: { maxAttempts: 2 } }));
    await t.post('/auth/2fa/verify', { recoveryCode: 'AAAAAAAAAA' }, cookie);
    const r = await t.post('/auth/2fa/verify', { recoveryCode: 'BBBBBBBBBB' }, cookie);
    expect(r.status).toBe(429);
    expect((await t.store.getTotp(user.id))!.lockedUntil).not.toBeNull();
  });

  it('a success resets the failure count', async () => {
    const { t, user, secret, cookie } = await pendingVerify(tfSetup({ twoFactor: { maxAttempts: 4 } }));
    await t.post('/auth/2fa/verify', { code: '000000' }, cookie);
    await t.post('/auth/2fa/verify', { code: '000000' }, cookie);
    expect((await t.store.getTotp(user.id))!.failedCount).toBe(2);
    t.nextStep();
    expect((await t.post('/auth/2fa/verify', { code: codesOf(t, secret) }, cookie)).status).toBe(200);
    expect((await t.store.getTotp(user.id))!.failedCount).toBe(0);
  });
});

describe('double submit', () => {
  it('a duplicate of a winning code does not sign out the session it just verified', async () => {
    const { t, secret, cookie } = await pendingVerify(tfSetup({ twoFactor: { maxAttempts: 2 } }));
    await t.post('/auth/2fa/verify', { code: '000000' }, cookie); // one wrong attempt already on the session
    t.nextStep();
    const code = codesOf(t, secret);
    expect((await t.post('/auth/2fa/verify', { code }, cookie)).status).toBe(200);
    // The duplicate arrives after the winner: the session is full, so it is refused without touching it.
    const dup = await t.post('/auth/2fa/verify', { code }, cookie);
    expect(dup.status).toBe(409);
    expect(await t.auth.getSession(req('GET', '/x', { cookie }))).toBeDefined();
  });

  it('a loser that was already past the pending check counts for nothing and leaves the session alone', async () => {
    const { t, secret, cookie } = await pendingVerify(tfSetup({ twoFactor: { maxAttempts: 2 } }));
    await t.post('/auth/2fa/verify', { code: '000000' }, cookie);
    t.nextStep();
    const code = codesOf(t, secret);
    const results = await Promise.all([t.post('/auth/2fa/verify', { code }, cookie), t.post('/auth/2fa/verify', { code }, cookie)]);
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
    expect(await t.auth.getSession(req('GET', '/x', { cookie }))).toBeDefined();
  });
});

describe('recovery codes while locked', () => {
  it('a correct recovery code is refused during a lock', async () => {
    const t = tfSetup({ twoFactor: { maxAttempts: 2, lockoutMs: 60_000 } });
    const { cookie } = await pendingVerify(t, ['GOODCODE23']);
    await t.post('/auth/2fa/verify', { code: '000000' }, cookie);
    await t.post('/auth/2fa/verify', { code: '000000' }, cookie);
    const fresh = await t.signIn();
    const r = await t.post('/auth/2fa/verify', { recoveryCode: 'GOODCODE23' }, fresh.cookie);
    expect(r.status).toBe(429);
  });
});

describe('concurrency', () => {
  it('two requests with the same valid code on two pending sessions: exactly one wins', async () => {
    const t = tfSetup();
    const { secret } = await t.enrol();
    const a = (await t.signIn()).cookie!;
    const b = (await t.signIn()).cookie!;
    t.nextStep();
    const code = codesOf(t, secret);
    const results = await Promise.all([t.post('/auth/2fa/verify', { code }, a), t.post('/auth/2fa/verify', { code }, b)]);
    expect(results.map((r) => r.status).sort()).toEqual([200, 401]);
  });

  it('two requests with the same valid code on one session: exactly one wins', async () => {
    const { t, secret, cookie } = await pendingVerify();
    t.nextStep();
    const code = codesOf(t, secret);
    const results = await Promise.all(Array.from({ length: 4 }, () => t.post('/auth/2fa/verify', { code }, cookie)));
    expect(results.filter((r) => r.status === 200)).toHaveLength(1);
  });

  it('one recovery code used on two sessions at once: exactly one wins', async () => {
    const t = tfSetup();
    await t.enrol('g1', { recoveryCodes: ['ONLYONE234'] });
    const a = (await t.signIn()).cookie!;
    const b = (await t.signIn()).cookie!;
    const results = await Promise.all([t.post('/auth/2fa/verify', { recoveryCode: 'ONLYONE234' }, a), t.post('/auth/2fa/verify', { recoveryCode: 'ONLYONE234' }, b)]);
    expect(results.map((r) => r.status).sort()).toEqual([200, 401]);
  });
});

describe('POST /auth/2fa/setup and /setup/confirm', () => {
  async function fullNotEnrolled(t = tfSetup()) {
    const { cookie } = await t.signIn();
    return { t, cookie: cookie! };
  }

  it('a full session gets a secret and an otpauth URI; the stored secret is encrypted with the user id as AAD', async () => {
    const { t, cookie } = await fullNotEnrolled();
    const { status, json, res } = await t.post('/auth/2fa/setup', {}, cookie);
    expect(status).toBe(200);
    expect(json!.secret).toMatch(/^[A-Z2-7]{32}$/);
    expect(json!.otpauthUri).toBe(`otpauth://totp/TrueMark:g1%40example.test?secret=${json!.secret}&issuer=TrueMark&algorithm=SHA1&digits=6&period=30`);
    expect(res.headers.get('cache-control')).toBe('no-store');
    const user = (await t.store.findUserByIdentity('google', 'g1'))!;
    const rec = (await t.store.getTotp(user.id))!;
    expect(rec.confirmedAt).toBeNull();
    expect(rec.pendingSecretEnc).not.toContain(json!.secret);
    expect(base32Decode(decrypt(rec.pendingSecretEnc!, KEY, totpAad(user.id))).length).toBe(20);
    expect(() => decrypt(rec.pendingSecretEnc!, KEY, totpAad('someone-else'))).toThrow();
  });

  it('calling setup again replaces the unconfirmed secret', async () => {
    const { t, cookie } = await fullNotEnrolled();
    const a = (await t.post('/auth/2fa/setup', {}, cookie)).json!.secret;
    const b = (await t.post('/auth/2fa/setup', {}, cookie)).json!.secret;
    expect(a).not.toBe(b);
  });

  it('confirm with the first code enrols, returns recovery codes once, verifies the session and revokes other sessions', async () => {
    const t = tfSetup();
    const other = await t.signIn();
    const cookie = (await t.signIn('google')).cookie!;
    // The second sign-in replaced nothing here (no cookie sent), so there are two sessions.
    expect(t.store.sessions.size).toBe(2);
    const { json } = await t.post('/auth/2fa/setup', {}, cookie);
    const secret = base32Decode(json!.secret);
    const confirm = await t.post('/auth/2fa/setup/confirm', { code: hotp(secret, totpStep(t.clock.now.getTime())) }, cookie);
    expect(confirm.status).toBe(200);
    const codes: string[] = confirm.json!.recoveryCodes;
    expect(codes).toHaveLength(10);
    for (const c of codes) expect(c).toMatch(/^[A-Z2-7]{10}$/);
    expect(new Set(codes).size).toBe(10);
    expect(confirm.json!.redirect).toBeUndefined();
    const user = (await t.store.findUserByIdentity('google', 'g1'))!;
    expect((await t.store.getTotp(user.id))!.confirmedAt).toEqual(t.clock.now);
    // Stored hashed, never in the clear.
    expect([...t.store.recoveryCodes.get(user.id)!.keys()].sort()).toEqual(codes.map((c) => recoveryCodeHash(KEY, c)).sort());
    expect(sessionRow(t, cookie).mfaVerifiedAt).toEqual(t.clock.now);
    expect(t.store.sessions.size).toBe(1);
    expect(t.store.sessions.has(hashToken(decodeURIComponent(other.cookie!.split('=')[1]!)))).toBe(false);
    // The recovery codes work.
    const again = await t.signIn();
    expect((await t.post('/auth/2fa/verify', { recoveryCode: codes[0] }, again.cookie)).status).toBe(200);
  });

  it('recoveryCodeCount is honoured', async () => {
    const { t, cookie } = await fullNotEnrolled(tfSetup({ twoFactor: { recoveryCodeCount: 3 } }));
    const { json } = await t.post('/auth/2fa/setup', {}, cookie);
    const confirm = await t.post('/auth/2fa/setup/confirm', { code: hotp(base32Decode(json!.secret), totpStep(t.clock.now.getTime())) }, cookie);
    expect(confirm.json!.recoveryCodes).toHaveLength(3);
  });

  it('a required, not-yet-enrolled user enrols from the pending session and gets a full one with a redirect', async () => {
    const t = tfSetup({ twoFactor: { required: true } });
    const { cookie } = await t.signIn('google', { redirect: '/memories' });
    expect(await t.auth.getPendingSession(req('GET', '/x', { cookie: cookie! }))).toEqual({ state: 'enroll' });
    const { json } = await t.post('/auth/2fa/setup', {}, cookie);
    const confirm = await t.post('/auth/2fa/setup/confirm', { code: hotp(base32Decode(json!.secret), totpStep(t.clock.now.getTime())) }, cookie);
    expect(confirm.status).toBe(200);
    expect(confirm.json!.redirect).toBe(`${FRONT}/memories`);
    const sc = setCookie(confirm.res, SESSION_COOKIE)!;
    expect(Number(sc.attrs['max-age'])).toBe(30 * 24 * 3600);
    expect(await t.auth.getSession(req('GET', '/x', { cookie: cookie! }))).toBeDefined();
  });

  it('a wrong confirm code is 401, counts against the session and keeps the pending secret', async () => {
    const t = tfSetup({ twoFactor: { required: true } });
    const { cookie } = await t.signIn();
    await t.post('/auth/2fa/setup', {}, cookie);
    const r = await t.post('/auth/2fa/setup/confirm', { code: '000000' }, cookie);
    expect(r.status).toBe(401);
    expect(r.json?.error.code).toBe('mfa_invalid_code');
    expect(sessionRow(t, cookie!).mfaAttempts).toBe(1);
  });

  it('a pending session in verify state cannot run setup; no session is 401; confirm needs a started setup', async () => {
    const { t, cookie } = await pendingVerify();
    expect((await t.post('/auth/2fa/setup', {}, cookie)).json?.error.code).toBe('mfa_not_pending');
    expect((await t.post('/auth/2fa/setup/confirm', { code: '123456' }, cookie)).json?.error.code).toBe('mfa_not_pending');
    expect((await t.post('/auth/2fa/setup', {})).status).toBe(401);
    const fresh = tfSetup();
    const { cookie: c } = await fresh.signIn();
    const r = await fresh.post('/auth/2fa/setup/confirm', { code: '123456' }, c);
    expect(r.status).toBe(400);
    expect(r.json?.error.code).toBe('invalid_request');
  });

  it('setup for an enrolled user needs a current code: none or wrong is 409, right replaces; a stolen full session alone cannot', async () => {
    const full = await fullSession();
    const { t, cookie, secret, user } = full;
    const before = (await t.store.getTotp(user.id))!.secretEnc;
    const none = await t.post('/auth/2fa/setup', {}, cookie);
    expect(none.status).toBe(409);
    const wrong = await t.post('/auth/2fa/setup', { code: '000000' }, cookie);
    expect(wrong.status).toBe(409);
    expect((await t.store.getTotp(user.id))!.pendingSecretEnc).toBeNull();
    t.nextStep();
    const ok = await t.post('/auth/2fa/setup', { code: codesOf(t, secret) }, cookie);
    expect(ok.status).toBe(200);
    const rec = (await t.store.getTotp(user.id))!;
    expect(rec.secretEnc).toBe(before); // the live secret is untouched until the new one is confirmed
    expect(rec.pendingSecretEnc).not.toBeNull();
    // Confirm the new one: the old secret stops working, the new one works.
    t.nextStep();
    const confirm = await t.post('/auth/2fa/setup/confirm', { code: hotp(base32Decode(ok.json!.secret), totpStep(t.clock.now.getTime())) }, cookie);
    expect(confirm.status).toBe(200);
    const again = await t.signIn();
    t.nextStep();
    expect((await t.post('/auth/2fa/verify', { code: codesOf(t, secret) }, again.cookie)).status).toBe(401);
    expect((await t.post('/auth/2fa/verify', { code: hotp(base32Decode(ok.json!.secret), totpStep(t.clock.now.getTime())) }, again.cookie)).status).toBe(200);
  });

  it('a locked user cannot run setup, confirm, regenerate or disable', async () => {
    const full = await fullSession(tfSetup({ twoFactor: { maxAttempts: 2, lockoutMs: 60_000 } }));
    const { t, cookie, secret } = full;
    await t.post('/auth/2fa/recovery-codes', { code: '000000' }, cookie);
    await t.post('/auth/2fa/recovery-codes', { code: '000000' }, cookie);
    t.nextStep();
    const good = codesOf(t, secret);
    for (const path of ['/auth/2fa/setup', '/auth/2fa/setup/confirm', '/auth/2fa/recovery-codes', '/auth/2fa/disable']) {
      const r = await t.post(path, { code: good }, cookie);
      expect(r.status, path).toBe(429);
      expect(r.json?.error.code).toBe('mfa_locked');
    }
  });

  it('is same-origin only', async () => {
    const { t, cookie } = await fullNotEnrolled();
    expect((await t.post('/auth/2fa/setup', {}, cookie, { origin: 'https://evil.test' })).status).toBe(403);
    expect((await t.post('/auth/2fa/setup/confirm', { code: '1' }, cookie, { origin: 'https://evil.test' })).status).toBe(403);
  });
});

describe('POST /auth/2fa/recovery-codes', () => {
  it('a valid TOTP code regenerates the codes and the old ones stop working', async () => {
    const full = await fullSession(tfSetup(), ['OLDCODE234']);
    const { t, cookie, secret, user } = full;
    t.nextStep();
    const r = await t.post('/auth/2fa/recovery-codes', { code: codesOf(t, secret) }, cookie);
    expect(r.status).toBe(200);
    const codes: string[] = r.json!.recoveryCodes;
    expect(codes).toHaveLength(10);
    expect([...t.store.recoveryCodes.get(user.id)!.keys()].sort()).toEqual(codes.map((c) => recoveryCodeHash(KEY, c)).sort());
    const again = await t.signIn();
    expect((await t.post('/auth/2fa/verify', { recoveryCode: 'OLDCODE234' }, again.cookie)).status).toBe(401);
    expect((await t.post('/auth/2fa/verify', { recoveryCode: codes[3] }, again.cookie)).status).toBe(200);
  });

  it('a wrong or replayed code is 401 and counted; a recovery code is not accepted here; not enrolled is 400', async () => {
    const full = await fullSession(tfSetup(), ['SOMECODE23']);
    const { t, cookie, user } = full;
    expect((await t.post('/auth/2fa/recovery-codes', { code: '000000' }, cookie)).status).toBe(401);
    expect((await t.store.getTotp(user.id))!.failedCount).toBe(1);
    expect((await t.post('/auth/2fa/recovery-codes', { recoveryCode: 'SOMECODE23' }, cookie)).status).toBe(400);
    const plain = tfSetup();
    const { cookie: c } = await plain.signIn();
    expect((await plain.post('/auth/2fa/recovery-codes', { code: '123456' }, c)).status).toBe(400);
  });

  it('needs a full session', async () => {
    const { t, secret, cookie } = await pendingVerify();
    t.nextStep();
    const r = await t.post('/auth/2fa/recovery-codes', { code: codesOf(t, secret) }, cookie);
    expect(r.status).toBe(401);
    expect((await t.post('/auth/2fa/recovery-codes', { code: '1' })).status).toBe(401);
  });
});

describe('POST /auth/2fa/disable', () => {
  it('a valid code removes TOTP and the codes, revokes other sessions and keeps this one', async () => {
    const full = await fullSession(tfSetup(), ['ONECODE234']);
    const { t, cookie, secret, user } = full;
    const other = await t.signIn();
    void other;
    t.nextStep();
    const r = await t.post('/auth/2fa/disable', { code: codesOf(t, secret) }, cookie);
    expect(r.status).toBe(200);
    expect(await t.store.getTotp(user.id)).toBeUndefined();
    expect(t.store.recoveryCodes.has(user.id)).toBe(false);
    expect(t.store.sessions.size).toBe(1);
    expect(await t.auth.getSession(req('GET', '/x', { cookie }))).toBeDefined();
    // Next sign-in is plain.
    expect((await t.signIn()).location).toBe(`${FRONT}/`);
  });

  it('is refused with 403 mfa_required when required is true, and changes nothing', async () => {
    const t = tfSetup({ twoFactor: { required: true } });
    const full = await fullSession(t);
    const { cookie, secret, user } = full;
    t.nextStep();
    const r = await t.post('/auth/2fa/disable', { code: codesOf(t, secret) }, cookie);
    expect(r.status).toBe(403);
    expect(r.json?.error.code).toBe('mfa_required');
    expect((await t.store.getTotp(user.id))!.confirmedAt).not.toBeNull();
  });

  it('asks the required hook for that user: true refuses, false allows', async () => {
    for (const [answer, status] of [[true, 403], [false, 200]] as const) {
      const t = tfSetup({ twoFactor: { required: ({ isNew }) => { expect(isNew).toBe(false); return answer; } } });
      const { cookie, secret } = await fullSession(t);
      t.nextStep();
      expect((await t.post('/auth/2fa/disable', { code: codesOf(t, secret) }, cookie)).status).toBe(status);
    }
  });

  it('a wrong code is 401 and counted; not enrolled is 400; a pending session is 401', async () => {
    const full = await fullSession();
    const { t, cookie, user } = full;
    expect((await t.post('/auth/2fa/disable', { code: '000000' }, cookie)).status).toBe(401);
    expect((await t.store.getTotp(user.id))!.failedCount).toBe(1);
    const plain = tfSetup();
    const { cookie: c } = await plain.signIn();
    expect((await plain.post('/auth/2fa/disable', { code: '123456' }, c)).status).toBe(400);
    const p = await pendingVerify();
    p.t.nextStep();
    expect((await p.t.post('/auth/2fa/disable', { code: codesOf(p.t, p.secret) }, p.cookie)).status).toBe(401);
  });
});

describe('GET /auth/2fa/status', () => {
  it('reports enrolled, required and verified for a full session', async () => {
    const plain = tfSetup();
    const { cookie } = await plain.signIn();
    expect((await plain.get('/auth/2fa/status', cookie)).json).toEqual({ enrolled: false, required: false, verified: false });

    const full = await fullSession(tfSetup({ twoFactor: { required: () => true } }));
    expect((await full.t.get('/auth/2fa/status', full.cookie)).json).toEqual({ enrolled: true, required: true, verified: true });
    expect((await full.t.get('/auth/2fa/status', full.cookie)).res.headers.get('cache-control')).toBe('no-store');
  });

  it('is 401 for a pending session and for no session', async () => {
    const { t, cookie } = await pendingVerify();
    expect((await t.get('/auth/2fa/status', cookie)).status).toBe(401);
    expect((await t.get('/auth/2fa/status')).status).toBe(401);
  });
});

describe('a pending session is refused by every non-2FA route', () => {
  it('logout-everywhere is 401; logout only ends it', async () => {
    const { t, cookie } = await pendingVerify();
    expect((await t.post('/auth/logout-everywhere', {}, cookie)).status).toBe(401);
    expect(t.store.sessions.size).toBe(1);
    expect((await t.post('/auth/logout', {}, cookie)).status).toBe(204);
    expect(t.store.sessions.size).toBe(0);
  });
});

function START_PLUS(t: Tf, ms: number): number {
  return t.store.sessions.get([...t.store.sessions.keys()][0]!)!.createdAt.getTime() + ms;
}
