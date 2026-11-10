/**
 * Authenticator (TOTP) account storage — unit tests
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';

const mockInvoke = vi.fn();

vi.mock('@tauri-apps/api/core', () => ({
  invoke: (...args: unknown[]) => mockInvoke(...args),
}));

import {
  AuthenticatorStorageManager,
  AUTHENTICATOR_CHANGED_EVENT,
  fetchAuthenticatorCodes,
  isValidTotpSecret,
  parseTotpInput,
} from '../lib/authenticator-storage';

beforeEach(() => {
  localStorage.clear();
  mockInvoke.mockReset();
  mockInvoke.mockImplementation(async (command: unknown, args: unknown) => {
    if (command === 'credential_seal') return `v1:test:${btoa((args as { secret: string }).secret)}`;
    return undefined;
  });
});

describe('parseTotpInput', () => {
  it('accepts a bare secret, ignoring case, spaces, dashes and padding', () => {
    expect(parseTotpInput(' jbsw y3dp-ehpk 3pxp== ')).toEqual({ secret: 'JBSWY3DPEHPK3PXP' });
  });

  it('rejects text that is not base32', () => {
    expect(parseTotpInput('not a secret!')).toBeNull();
    expect(parseTotpInput('ABC1')).toBeNull();
    expect(parseTotpInput('   ')).toBeNull();
    expect(isValidTotpSecret('JBSWY3DP')).toBe(true);
  });

  it('reads every parameter of an otpauth:// URI', () => {
    expect(parseTotpInput(
      'otpauth://totp/ACME%20Co:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60',
    )).toEqual({
      secret: 'JBSWY3DPEHPK3PXP',
      name: 'alice@example.com',
      issuer: 'ACME Co',
      algorithm: 'SHA256',
      digits: 8,
      period: 60,
    });
  });

  it('takes the issuer from the label when the query has none, and ignores bad parameters', () => {
    expect(parseTotpInput('otpauth://totp/GitHub:bob?secret=jbswy3dp&digits=12&period=0&algorithm=MD5')).toEqual({
      secret: 'JBSWY3DP',
      name: 'bob',
      issuer: 'GitHub',
    });
  });

  it('rejects HOTP and URIs without a valid secret', () => {
    expect(parseTotpInput('otpauth://hotp/x?secret=JBSWY3DP&counter=1')).toBeNull();
    expect(parseTotpInput('otpauth://totp/x?secret=nope!')).toBeNull();
    expect(parseTotpInput('otpauth://totp/x')).toBeNull();
  });
});

describe('AuthenticatorStorageManager', () => {
  it('seals the secret before storing it and announces the change', async () => {
    const listener = vi.fn();
    window.addEventListener(AUTHENTICATOR_CHANGED_EVENT, listener);
    const account = await AuthenticatorStorageManager.saveAccount({
      name: ' alice ', issuer: 'GitHub', secret: 'jbsw y3dp', algorithm: 'SHA1', digits: 6, period: 30,
    });
    window.removeEventListener(AUTHENTICATOR_CHANGED_EVENT, listener);

    expect(account.name).toBe('alice');
    expect(account.secret).toBe(`v1:test:${btoa('JBSWY3DP')}`);
    expect(localStorage.getItem('r-shell-authenticator-accounts')).not.toContain('JBSWY3DP');
    expect(listener).toHaveBeenCalled();
    expect(AuthenticatorStorageManager.getAccounts()).toEqual([account]);
  });

  it('keeps the saved secret when an edit leaves it blank', async () => {
    const created = await AuthenticatorStorageManager.saveAccount({
      name: 'alice', secret: 'JBSWY3DP', algorithm: 'SHA1', digits: 6, period: 30,
    });
    const edited = await AuthenticatorStorageManager.saveAccount({
      id: created.id, name: 'alice@work', secret: '', algorithm: 'SHA1', digits: 8, period: 30,
    });
    expect(edited.secret).toBe(created.secret);
    expect(edited.createdAt).toBe(created.createdAt);
    expect(AuthenticatorStorageManager.getAccounts()).toHaveLength(1);
    expect(AuthenticatorStorageManager.getAccounts()[0].digits).toBe(8);
  });

  it('refuses a new account without a valid secret', async () => {
    const base = { name: 'x', algorithm: 'SHA1' as const, digits: 6, period: 30 };
    await expect(AuthenticatorStorageManager.saveAccount(base)).rejects.toThrow();
    await expect(AuthenticatorStorageManager.saveAccount({ ...base, secret: 'bad!' })).rejects.toThrow();
    await expect(AuthenticatorStorageManager.saveAccount({ ...base, name: ' ', secret: 'JBSWY3DP' })).rejects.toThrow();
    expect(AuthenticatorStorageManager.getAccounts()).toEqual([]);
  });

  it('degrades corrupt storage to an empty list and fills missing parameters', () => {
    localStorage.setItem('r-shell-authenticator-accounts', 'not json');
    expect(AuthenticatorStorageManager.getAccounts()).toEqual([]);
    localStorage.setItem('r-shell-authenticator-accounts', JSON.stringify([{ id: 'a', name: 'n', digits: 4 }, 'junk']));
    expect(AuthenticatorStorageManager.getAccounts()).toMatchObject([
      { id: 'a', name: 'n', algorithm: 'SHA1', digits: 6, period: 30 },
    ]);
  });

  it('strips secrets from the public list', async () => {
    await AuthenticatorStorageManager.saveAccount({
      name: 'alice', secret: 'JBSWY3DP', algorithm: 'SHA1', digits: 6, period: 30,
    });
    const [account] = AuthenticatorStorageManager.getPublicAccounts();
    expect(account).not.toHaveProperty('secret');
    expect(account.name).toBe('alice');
  });

  it('imports secrets only from the sealed map, never from the list itself', () => {
    const count = AuthenticatorStorageManager.importAccounts(
      [
        { id: 'a', name: 'alice', secret: 'v1:attacker:supplied' },
        { id: 'b', name: 'bob' },
        { id: 'c', name: '  ' },
      ],
      false,
      new Map([['b', 'v1:local:bob']]),
    );
    expect(count).toBe(2);
    const accounts = AuthenticatorStorageManager.getAccounts();
    expect(accounts.map((a) => [a.id, a.secret])).toEqual([['a', undefined], ['b', 'v1:local:bob']]);
  });

  it('merge mode upserts by id and keeps a saved secret the import lacks', async () => {
    localStorage.setItem('r-shell-authenticator-accounts', JSON.stringify([
      { id: 'a', name: 'alice', secret: 'v1:local:alice' },
      { id: 'z', name: 'zed', secret: 'v1:local:zed' },
    ]));
    AuthenticatorStorageManager.importAccounts([{ id: 'a', name: 'alice@new' }, { id: 'n', name: 'new' }], true);
    expect(AuthenticatorStorageManager.getAccounts().map((a) => [a.id, a.name, a.secret])).toEqual([
      ['a', 'alice@new', 'v1:local:alice'],
      ['z', 'zed', 'v1:local:zed'],
      ['n', 'new', undefined],
    ]);

    AuthenticatorStorageManager.importAccounts([{ id: 'n', name: 'new' }], false);
    expect(AuthenticatorStorageManager.getAccounts().map((a) => a.id)).toEqual(['n']);
  });
});

describe('fetchAuthenticatorCodes', () => {
  it('asks the backend only for accounts that have a secret, keeping the order', async () => {
    mockInvoke.mockImplementation(async (command: unknown, args: unknown) => {
      expect(command).toBe('authenticator_codes');
      const { accounts } = args as { accounts: { sealed: string }[] };
      expect(accounts.map((a) => a.sealed)).toEqual(['v1:a', 'v1:c']);
      return [
        { code: '111111', expiresAt: 60, error: null },
        { code: null, expiresAt: null, error: 'bad' },
      ];
    });
    const base = { algorithm: 'SHA1' as const, digits: 6, period: 30, createdAt: '', updatedAt: '' };
    const codes = await fetchAuthenticatorCodes([
      { ...base, id: 'a', name: 'a', secret: 'v1:a' },
      { ...base, id: 'b', name: 'b' },
      { ...base, id: 'c', name: 'c', secret: 'v1:c' },
    ]);
    expect(codes).toEqual([
      { code: '111111', expiresAt: 60, error: null },
      { code: null, expiresAt: null, error: null },
      { code: null, expiresAt: null, error: 'bad' },
    ]);
  });

  it('skips the backend when no account has a secret', async () => {
    expect(await fetchAuthenticatorCodes([])).toEqual([]);
    expect(mockInvoke).not.toHaveBeenCalled();
  });
});
