/**
 * Config Export / Import with connection secrets.
 *
 * The master key is faked with a reversible `v1:` wrapper; the passphrase
 * encryption is the real WebCrypto code.
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ConnectionStorageManager, type ConnectionData } from '../lib/connection-storage';
import {
  decryptBundleSecrets,
  encryptBundleSecrets,
  WrongPassphraseError,
} from '../lib/config-secrets';
import {
  exportAllConfig,
  hasExportableSecrets,
  importAllConfig,
  UnreadableSecretError,
} from '../lib/config-export-import';

const mockSave = vi.fn();
const mockOpen = vi.fn();
const mockWriteTextFile = vi.fn();
const mockReadTextFile = vi.fn();

const seal = (secret: string) => `v1:${btoa('nonce')}:${btoa(secret)}`;
const unseal = (sealed: string) => atob(sealed.split(':')[2]);

const mockInvoke = vi.fn(async (command: string, args?: Record<string, string>) => {
  if (command === 'credential_seal') return seal(args!.secret);
  if (command === 'credential_open') {
    if (args!.sealed === seal('unreadable')) throw new Error('bad key');
    return unseal(args!.sealed);
  }
  return undefined;
});

vi.mock('@tauri-apps/api/core', () => ({
  invoke: (command: string, args?: Record<string, string>) => mockInvoke(command, args),
}));
vi.mock('@tauri-apps/plugin-dialog', () => ({
  save: (...args: unknown[]) => mockSave(...args),
  open: (...args: unknown[]) => mockOpen(...args),
}));
vi.mock('@tauri-apps/plugin-fs', () => ({
  writeTextFile: (...args: unknown[]) => mockWriteTextFile(...args),
  readTextFile: (...args: unknown[]) => mockReadTextFile(...args),
}));

const PASSPHRASE = 'correct horse battery';

function seedConnection(overrides: Partial<ConnectionData> = {}): void {
  localStorage.setItem('r-shell-connections', JSON.stringify([{
    id: 'conn-1',
    name: 'Prod',
    host: '10.0.0.1',
    port: 22,
    username: 'root',
    protocol: 'SSH',
    authMethod: 'password',
    createdAt: '2026-01-01T00:00:00.000Z',
    password: seal('hunter2'),
    totpSecret: seal('JBSWY3DPEHPK3PXP'),
    ...overrides,
  }]));
}

async function exportToText(secretsPassphrase?: string): Promise<string> {
  mockSave.mockResolvedValue('/tmp/config.json');
  await exportAllConfig({ secretsPassphrase });
  return mockWriteTextFile.mock.calls[0][1] as string;
}

function storedConnection(): ConnectionData {
  return (JSON.parse(localStorage.getItem('r-shell-connections')!) as ConnectionData[])
    .find((c) => c.name === 'Prod')!;
}

beforeEach(() => {
  vi.clearAllMocks();
  localStorage.clear();
  seedConnection();
});

describe('passphrase envelope', () => {
  it('round-trips and hides the plaintext', async () => {
    const envelope = await encryptBundleSecrets({ a: { password: 'hunter2' } }, PASSPHRASE, 'records');
    expect(JSON.stringify(envelope)).not.toContain('hunter2');
    expect(await decryptBundleSecrets(envelope, PASSPHRASE, 'records')).toEqual({ a: { password: 'hunter2' } });
  });

  it('rejects a wrong passphrase', async () => {
    const envelope = await encryptBundleSecrets({}, PASSPHRASE, 'records');
    await expect(decryptBundleSecrets(envelope, 'wrong', 'records')).rejects.toBeInstanceOf(WrongPassphraseError);
  });

  it('rejects data that changed since encryption, even with the right passphrase', async () => {
    const envelope = await encryptBundleSecrets({}, PASSPHRASE, 'records');
    await expect(decryptBundleSecrets(envelope, PASSPHRASE, 'edited')).rejects.toBeInstanceOf(WrongPassphraseError);
  });

  it('accepts the same passphrase typed in another Unicode form', async () => {
    const composed = 'café passphrase';
    const decomposed = 'café passphrase';
    expect(composed).not.toBe(decomposed);
    const envelope = await encryptBundleSecrets({ a: { password: 'x' } }, composed, 'records');
    expect(await decryptBundleSecrets(envelope, decomposed, 'records')).toEqual({ a: { password: 'x' } });
  });

  it('refuses an iteration count that would weaken the key derivation', async () => {
    const envelope = await encryptBundleSecrets({}, PASSPHRASE, 'records');
    await expect(
      decryptBundleSecrets({ ...envelope, iterations: 1 }, PASSPHRASE, 'records'),
    ).rejects.toThrow('unsupported secrets block');
  });
});

describe('export', () => {
  it('writes no secrets block when no connection has a secret', async () => {
    seedConnection({ password: undefined, totpSecret: undefined, authMethod: 'publickey' });
    expect(hasExportableSecrets()).toBe(false);

    const bundle = JSON.parse(await exportToText(PASSPHRASE));

    expect(bundle.data.secrets).toBeUndefined();
    expect(bundle.data.connections.connections).toHaveLength(1);
  });

  it('reports exportable secrets when a connection has one', () => {
    expect(hasExportableSecrets()).toBe(true);
  });

  it('leaves secrets out unless a passphrase is given', async () => {
    const bundle = JSON.parse(await exportToText());
    expect(bundle.data.secrets).toBeUndefined();
    expect(mockInvoke).not.toHaveBeenCalledWith('credential_open', expect.anything());
  });

  it('carries secrets only inside the encrypted block', async () => {
    const text = await exportToText(PASSPHRASE);
    expect(text).not.toContain('hunter2');
    expect(text).not.toContain(seal('hunter2'));

    const bundle = JSON.parse(text);
    expect(bundle.data.connections.connections[0].password).toBeUndefined();
    expect(
      await decryptBundleSecrets(
        bundle.data.secrets,
        PASSPHRASE,
        JSON.stringify(bundle.data.connections.connections),
      ),
    ).toEqual({
      'conn-1': { password: 'hunter2', totpSecret: 'JBSWY3DPEHPK3PXP' },
    });
  });

  it('fails rather than exporting without a secret it cannot read', async () => {
    seedConnection({ password: seal('unreadable') });
    mockSave.mockResolvedValue('/tmp/config.json');
    await expect(exportAllConfig({ secretsPassphrase: PASSPHRASE })).rejects.toBeInstanceOf(UnreadableSecretError);
    expect(mockSave).not.toHaveBeenCalled();
  });
});

describe('import', () => {
  async function importText(text: string, passphrase: string | null) {
    mockOpen.mockResolvedValue('/tmp/config.json');
    mockReadTextFile.mockResolvedValue(text);
    return importAllConfig(false, {
      unlockSecrets: async (_hint, attempt) => {
        if (passphrase !== null) await attempt(passphrase);
      },
    });
  }

  it('restores secrets sealed with the local key', async () => {
    const text = await exportToText(PASSPHRASE);
    localStorage.removeItem('r-shell-connections');

    const result = await importText(text, PASSPHRASE);

    expect(result?.secretsRestored).toBe(1);
    expect(storedConnection().password).toBe(seal('hunter2'));
    expect(storedConnection().totpSecret).toBe(seal('JBSWY3DPEHPK3PXP'));
  });

  it('does not ask for a passphrase when the file has no secrets', async () => {
    const text = await exportToText();
    const unlockSecrets = vi.fn();
    mockOpen.mockResolvedValue('/tmp/config.json');
    mockReadTextFile.mockResolvedValue(text);

    const result = await importAllConfig(false, { unlockSecrets });

    expect(unlockSecrets).not.toHaveBeenCalled();
    expect(result?.connections).toBe(1);
    expect(result?.secretsRestored).toBe(0);
  });

  it('passes the hint to the passphrase prompt, readable without the passphrase', async () => {
    mockSave.mockResolvedValue('/tmp/config.json');
    await exportAllConfig({ secretsPassphrase: PASSPHRASE, secretsHint: 'the usual one' });
    const text = mockWriteTextFile.mock.calls[0][1] as string;
    expect(JSON.parse(text).data.secrets.hint).toBe('the usual one');

    const hints: Array<string | undefined> = [];
    mockOpen.mockResolvedValue('/tmp/config.json');
    mockReadTextFile.mockResolvedValue(text);
    const result = await importAllConfig(false, {
      unlockSecrets: async (hint, attempt) => {
        hints.push(hint);
        await attempt(PASSPHRASE);
      },
    });

    expect(hints).toEqual(['the usual one']);
    expect(result?.secretsRestored).toBe(1);
  });

  it('asks for the passphrase without a hint when the file has none', async () => {
    const text = await exportToText(PASSPHRASE);
    expect(JSON.parse(text).data.secrets.hint).toBeUndefined();

    const hints: Array<string | undefined> = [];
    mockOpen.mockResolvedValue('/tmp/config.json');
    mockReadTextFile.mockResolvedValue(text);
    await importAllConfig(false, {
      unlockSecrets: async (hint, attempt) => {
        hints.push(hint);
        await attempt(PASSPHRASE);
      },
    });

    expect(hints).toEqual([undefined]);
  });

  it('changes nothing on a wrong passphrase', async () => {
    const text = await exportToText(PASSPHRASE);
    seedConnection({ name: 'Existing' });
    const before = localStorage.getItem('r-shell-connections');

    expect(await importText(text, 'wrong')).toBeNull();
    expect(localStorage.getItem('r-shell-connections')).toBe(before);
  });

  it('lets the user retry after a wrong passphrase', async () => {
    const text = await exportToText(PASSPHRASE);
    localStorage.removeItem('r-shell-connections');
    mockOpen.mockResolvedValue('/tmp/config.json');
    mockReadTextFile.mockResolvedValue(text);
    const attempts: boolean[] = [];

    const result = await importAllConfig(false, {
      unlockSecrets: async (_hint, attempt) => {
        attempts.push(await attempt('wrong'));
        attempts.push(await attempt(PASSPHRASE));
      },
    });

    expect(attempts).toEqual([false, true]);
    expect(result?.secretsRestored).toBe(1);
    expect(storedConnection().password).toBe(seal('hunter2'));
  });

  it.each([
    ['host', { host: 'attacker.example' }],
    ['proxy host', { proxyHost: 'attacker.example' }],
    ['username', { username: 'someone-else' }],
  ])('refuses a file whose connection %s was edited, even with the right passphrase', async (_label, edit) => {
    const bundle = JSON.parse(await exportToText(PASSPHRASE));
    Object.assign(bundle.data.connections.connections[0], edit);
    localStorage.removeItem('r-shell-connections');

    expect(await importText(JSON.stringify(bundle), PASSPHRASE)).toBeNull();
    expect(mockInvoke).not.toHaveBeenCalledWith('credential_seal', expect.anything());
    expect(localStorage.getItem('r-shell-connections')).toBeNull();
  });

  it('changes nothing when the passphrase prompt is cancelled', async () => {
    const text = await exportToText(PASSPHRASE);
    seedConnection({ name: 'Existing' });
    const before = localStorage.getItem('r-shell-connections');

    expect(await importText(text, null)).toBeNull();
    expect(localStorage.getItem('r-shell-connections')).toBe(before);
  });
});
