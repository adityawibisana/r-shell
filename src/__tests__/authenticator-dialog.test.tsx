import React from 'react';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthenticatorDialog } from '../components/authenticator-dialog';
import { AuthenticatorStorageManager } from '../lib/authenticator-storage';

const mocks = vi.hoisted(() => ({
  invoke: vi.fn(),
  writeText: vi.fn(),
}));

vi.mock('@tauri-apps/api/core', () => ({ invoke: mocks.invoke }));
vi.mock('@tauri-apps/plugin-clipboard-manager', () => ({ writeText: mocks.writeText }));
vi.mock('sonner', () => ({
  toast: { error: vi.fn(), info: vi.fn(), success: vi.fn(), warning: vi.fn() },
}));

vi.mock('../components/ui/select', () => ({
  Select: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  SelectContent: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  SelectItem: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  SelectTrigger: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  SelectValue: () => null,
}));

vi.mock('../components/ui/dialog', () => ({
  Dialog: ({ children, open }: { children: React.ReactNode; open: boolean }) =>
    open ? <div>{children}</div> : null,
  DialogContent: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  DialogHeader: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  DialogTitle: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  DialogDescription: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  DialogFooter: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));

vi.mock('../components/ui/alert-dialog', () => ({
  AlertDialog: ({ children, open }: { children: React.ReactNode; open: boolean }) =>
    open ? <div>{children}</div> : null,
  AlertDialogContent: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  AlertDialogHeader: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  AlertDialogFooter: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  AlertDialogTitle: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  AlertDialogDescription: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  AlertDialogCancel: ({ children }: { children: React.ReactNode }) => <button>{children}</button>,
  AlertDialogAction: ({ children, onClick }: { children: React.ReactNode; onClick?: () => void }) => (
    <button data-testid="alert-dialog-action" onClick={onClick}>{children}</button>
  ),
}));

beforeEach(() => {
  localStorage.clear();
  mocks.writeText.mockReset().mockResolvedValue(undefined);
  mocks.invoke.mockReset().mockImplementation(async (command: string, args: Record<string, unknown>) => {
    if (command === 'credential_seal') return `v1:test:${btoa(args.secret as string)}`;
    if (command === 'authenticator_codes') {
      const expiresAt = Math.floor(Date.now() / 1000) + 20;
      return (args.accounts as unknown[]).map(() => ({ code: '123456', expiresAt, error: null }));
    }
    return undefined;
  });
});

afterEach(cleanup);

describe('AuthenticatorDialog', () => {
  it('shows the empty state', () => {
    render(<AuthenticatorDialog open onOpenChange={() => {}} />);
    expect(screen.getByText('No accounts yet')).toBeTruthy();
  });

  it('adds an account from a pasted otpauth:// URI and shows its code', async () => {
    render(<AuthenticatorDialog open onOpenChange={() => {}} />);
    fireEvent.click(screen.getAllByRole('button', { name: /Add account/ })[0]);
    fireEvent.change(screen.getByLabelText('Secret key or otpauth:// link'), {
      target: { value: 'otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&digits=6' },
    });
    expect((screen.getByLabelText('Account') as HTMLInputElement).value).toBe('alice');
    expect((screen.getByLabelText('Service') as HTMLInputElement).value).toBe('GitHub');
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));

    await screen.findByText('123 456');
    const [account] = AuthenticatorStorageManager.getAccounts();
    expect(account).toMatchObject({ name: 'alice', issuer: 'GitHub', secret: `v1:test:${btoa('JBSWY3DPEHPK3PXP')}` });

    fireEvent.click(screen.getByText('123 456'));
    await waitFor(() => expect(mocks.writeText).toHaveBeenCalledWith('123456'));
  });

  it('rejects an invalid secret without saving', () => {
    render(<AuthenticatorDialog open onOpenChange={() => {}} />);
    fireEvent.click(screen.getAllByRole('button', { name: /Add account/ })[0]);
    fireEvent.change(screen.getByLabelText('Secret key or otpauth:// link'), { target: { value: 'nope!' } });
    fireEvent.change(screen.getByLabelText('Account'), { target: { value: 'alice' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(screen.getByText(/Not a valid secret/)).toBeTruthy();
    expect(AuthenticatorStorageManager.getAccounts()).toEqual([]);
  });

  it('marks an imported account without a secret and deletes after confirmation', async () => {
    AuthenticatorStorageManager.importAccounts([{ id: 'a', name: 'alice' }]);
    render(<AuthenticatorDialog open onOpenChange={() => {}} />);
    expect(screen.getByText(/Secret missing/)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
    fireEvent.click(screen.getByTestId('alert-dialog-action'));
    await screen.findByText('No accounts yet');
    expect(AuthenticatorStorageManager.getAccounts()).toEqual([]);
  });
});
