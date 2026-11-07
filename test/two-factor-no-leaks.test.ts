import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { base32Decode } from '../src/base32.js';
import { hotp, totpStep } from '../src/totp.js';
import { SESSION_COOKIE, setCookie, tfSetup, type Tf } from './helpers/two-factor.js';

let output: string[] = [];
const spies: Array<{ mockRestore(): void }> = [];
beforeEach(() => {
  output = [];
  const record = (...a: unknown[]) => { output.push(a.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))).join(' ')); };
  for (const m of ['log', 'info', 'warn', 'error', 'debug', 'trace', 'dir'] as const) spies.push(vi.spyOn(console, m).mockImplementation(record as never));
  const write = ((chunk: unknown) => { output.push(String(chunk)); return true; }) as never;
  spies.push(vi.spyOn(process.stdout, 'write').mockImplementation(write));
  spies.push(vi.spyOn(process.stderr, 'write').mockImplementation(write));
});
afterEach(() => { for (const s of spies.splice(0)) s.mockRestore(); });

async function dump(res: Response): Promise<string> {
  const headers = [...res.headers].map(([k, v]) => `${k}: ${v}`).concat(res.headers.getSetCookie().map((c) => `set-cookie: ${c}`));
  return [`${res.status}`, ...headers, await res.clone().text()].join('\n');
}
const has = (text: string, needles: string[]) => needles.filter((n) => n !== '' && text.includes(n));

/** Walks the whole 2FA lifecycle through the routes and records every response. */
async function lifecycle(t: Tf) {
  const responses: Array<{ label: string; res: Response }> = [];
  const note = <T extends { res: Response }>(label: string, r: T): T => { responses.push({ label, res: r.res }); return r; };

  const first = await t.signIn();
  const setup = note('setup', await t.post('/auth/2fa/setup', {}, first.cookie));
  const secretText: string = setup.json!.secret;
  const secret = base32Decode(secretText);
  const code1 = hotp(secret, totpStep(t.clock.now.getTime()));
  const confirm = note('confirm', await t.post('/auth/2fa/setup/confirm', { code: code1 }, first.cookie));
  const recovery: string[] = confirm.json!.recoveryCodes;

  const second = await t.signIn();
  const wrong = '135790';
  note('verify wrong', await t.post('/auth/2fa/verify', { code: wrong }, second.cookie));
  note('verify wrong recovery', await t.post('/auth/2fa/verify', { recoveryCode: 'ZZZZZZZZZZ' }, second.cookie));
  t.nextStep();
  const code2 = hotp(secret, totpStep(t.clock.now.getTime()));
  const v = note('verify', await t.post('/auth/2fa/verify', { code: code2 }, second.cookie));
  const cookie = `${SESSION_COOKIE}=${encodeURIComponent(setCookie(v.res, SESSION_COOKIE)!.value)}`;
  note('status', await t.get('/auth/2fa/status', cookie));
  t.nextStep();
  const code3 = hotp(secret, totpStep(t.clock.now.getTime()));
  const regen = await t.post('/auth/2fa/recovery-codes', { code: code3 }, cookie); // returns new recovery codes by design
  const newRecovery: string[] = regen.json!.recoveryCodes;
  note('replayed code', await t.post('/auth/2fa/recovery-codes', { code: code3 }, cookie));
  note('not pending', await t.post('/auth/2fa/verify', { code: code3 }, cookie));
  t.nextStep();
  const code4 = hotp(secret, totpStep(t.clock.now.getTime()));
  note('disable', await t.post('/auth/2fa/disable', { code: code4 }, cookie));
  const third = await t.signIn();
  note('plain sign in leaves nothing', { res: third.res });

  const everything = [secretText, code1, code2, code3, code4, wrong, ...recovery, ...newRecovery, 'ZZZZZZZZZZ'];
  return { responses, setup, confirm, regen, secretText, recovery, newRecovery, everything, wrong, code1, code2, code3, code4 };
}

describe('secrets, codes and recovery codes stay out of everything but setup/confirm responses', () => {
  it('no log output, no onError event, and no other response carries them', async () => {
    const t = tfSetup();
    const l = await lifecycle(t);

    expect(output.join('\n')).not.toMatch(/\S/);
    expect(has(JSON.stringify(t.events), l.everything)).toEqual([]);
    for (const { label, res } of l.responses) {
      // The secret is returned by setup only; recovery codes by confirm only (and by regeneration, which has no label here).
      const allowed = label === 'setup' ? [l.secretText] : label === 'confirm' ? l.recovery : [];
      const found = has(await dump(res), l.everything.filter((n) => !allowed.includes(n)));
      expect(found, label).toEqual([]);
    }
    expect(has(await dump(l.regen.res), [l.secretText, l.code1, l.code2, l.code3, ...l.recovery])).toEqual([]);
    // Setup itself: the secret appears; the recovery codes do not.
    expect(has(await dump(l.setup.res), l.recovery)).toEqual([]);
    // Confirm returns recovery codes but not the secret.
    expect(has(await dump(l.confirm.res), [l.secretText])).toEqual([]);
  });

  it('onError events carry only whitelisted fields and known codes', async () => {
    const t = tfSetup();
    await lifecycle(t);
    expect(t.events.length).toBeGreaterThan(0);
    const known = new Set(['mfa_invalid_code', 'mfa_locked', 'mfa_not_pending', 'mfa_required', 'unauthenticated', 'invalid_request', 'forbidden', 'account_suspended']);
    for (const e of t.events) {
      expect(Object.keys(e).every((k) => ['stage', 'code', 'errorName', 'provider'].includes(k))).toBe(true);
      expect(e.stage).toBe('2fa');
      expect(known.has(e.code)).toBe(true);
    }
    expect(t.events.map((e) => e.code)).toContain('mfa_invalid_code');
  });

  it('a store error that embeds the code surfaces as a class name only, with a generic 500', async () => {
    const t = tfSetup();
    const { secret } = await t.enrol();
    const { cookie } = await t.signIn();
    t.nextStep();
    const code = hotp(secret, totpStep(t.clock.now.getTime()));
    t.store.consumeTotpStep = async () => { throw new Error(`database exploded near ${code}`); };
    const { res, status } = await t.post('/auth/2fa/verify', { code }, cookie);
    expect(status).toBe(500);
    expect(has(await dump(res), [code, 'exploded'])).toEqual([]);
    expect(has(JSON.stringify(t.events), [code, 'exploded'])).toEqual([]);
    expect(t.events.at(-1)).toMatchObject({ stage: '2fa', code: 'internal_error', errorName: 'Error' });
    expect(output.join('\n')).not.toContain(code);
  });

  it('a corrupt stored secret fails with a generic error, not its contents', async () => {
    const t = tfSetup();
    const { user } = await t.enrol();
    const { cookie } = await t.signIn();
    t.store.totps.get(user.id)!.secretEnc = 'v2:garbage:garbage:garbage';
    const { res, status } = await t.post('/auth/2fa/verify', { code: '123456' }, cookie);
    expect(status).toBe(500);
    expect(await res.clone().text()).not.toContain('garbage');
    expect(JSON.stringify(t.events)).not.toContain('garbage');
  });
});
