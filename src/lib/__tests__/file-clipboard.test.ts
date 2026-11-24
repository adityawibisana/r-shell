import { describe, it, expect, vi, beforeEach } from 'vitest';

const invoke = vi.fn();
vi.mock('@tauri-apps/api/core', () => ({ invoke: (...args: unknown[]) => invoke(...args) }));

import {
  clearFileClipboard,
  copyToFileClipboard,
  getFileClipboard,
  setFileClipboard,
} from '../file-clipboard';

const files = [{ name: 'a.txt', path: '/srv/a.txt', type: 'file' as const }];

describe('file clipboard staging', () => {
  beforeEach(() => {
    invoke.mockReset();
    setFileClipboard(null);
  });

  it('is staging until the backend reports ready', async () => {
    let resolve!: (v: unknown) => void;
    invoke.mockReturnValueOnce(new Promise((r) => (resolve = r)));
    const done = copyToFileClipboard('c1', 'copy', files);
    expect(getFileClipboard()?.status).toBe('staging');
    expect(invoke).toHaveBeenCalledWith('stage_clipboard', {
      connectionId: 'c1',
      stageToken: getFileClipboard()?.stageToken,
      entries: [{ path: '/srv/a.txt', isDirectory: false }],
    });
    resolve({ status: 'ready', bytes: 3 });
    await expect(done).resolves.toBe('ready');
    expect(getFileClipboard()?.status).toBe('ready');
  });

  it('falls back to a live reference when too large', async () => {
    invoke.mockResolvedValueOnce({ status: 'tooLarge', bytes: 600 * 1024 * 1024 });
    await expect(copyToFileClipboard('c1', 'cut', files)).resolves.toBe('reference');
    expect(getFileClipboard()).toMatchObject({ operation: 'cut', status: 'reference' });
  });

  it('falls back to a live reference when staging fails', async () => {
    invoke.mockRejectedValueOnce('du failed');
    await expect(copyToFileClipboard('c1', 'copy', files)).resolves.toBe('reference');
    expect(getFileClipboard()?.status).toBe('reference');
  });

  it('a newer copy wins over a staging that finishes later', async () => {
    let resolveOld!: (v: unknown) => void;
    invoke.mockReturnValueOnce(new Promise((r) => (resolveOld = r)));
    const old = copyToFileClipboard('c1', 'copy', files);
    invoke.mockResolvedValueOnce({ status: 'ready', bytes: 1 });
    await copyToFileClipboard('c2', 'copy', files);
    resolveOld({ status: 'tooLarge', bytes: 1 });
    await expect(old).resolves.toBeNull();
    const [, first] = invoke.mock.calls[0] as [string, { stageToken: string }];
    expect(getFileClipboard()?.stageToken).not.toBe(first.stageToken);
    expect(getFileClipboard()).toMatchObject({ connectionId: 'c2', status: 'ready' });
  });

  it('clear empties the clipboard and the local stage', async () => {
    invoke.mockResolvedValue({ status: 'ready', bytes: 1 });
    await copyToFileClipboard('c1', 'copy', files);
    clearFileClipboard();
    expect(getFileClipboard()).toBeNull();
    expect(invoke).toHaveBeenLastCalledWith('clear_clipboard_stage');
  });
});
