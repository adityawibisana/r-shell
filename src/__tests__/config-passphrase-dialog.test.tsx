import { describe, it, expect, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { ConfigPassphraseDialog } from '../components/settings/config-passphrase-dialog';

function fillExport(passphrase: string, hint: string) {
  fireEvent.change(screen.getByLabelText('Passphrase'), { target: { value: passphrase } });
  fireEvent.change(screen.getByLabelText('Confirm passphrase'), { target: { value: passphrase } });
  fireEvent.change(screen.getByLabelText('Hint (optional)'), { target: { value: hint } });
  fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
}

describe('ConfigPassphraseDialog', () => {
  it('returns the optional hint when exporting', () => {
    const onSubmit = vi.fn();
    render(<ConfigPassphraseDialog mode="export" onSubmit={onSubmit} onCancel={vi.fn()} />);

    fillExport('long enough', '  the usual one  ');

    expect(onSubmit).toHaveBeenCalledWith({ passphrase: 'long enough', hint: 'the usual one' });
  });

  it('allows exporting without a hint', () => {
    const onSubmit = vi.fn();
    render(<ConfigPassphraseDialog mode="export" onSubmit={onSubmit} onCancel={vi.fn()} />);

    fillExport('long enough', '');

    expect(onSubmit).toHaveBeenCalledWith({ passphrase: 'long enough', hint: undefined });
  });

  it('accepts a short passphrase and a hint that contains it', () => {
    const onSubmit = vi.fn();
    render(<ConfigPassphraseDialog mode="export" onSubmit={onSubmit} onCancel={vi.fn()} />);

    fillExport('abc', 'it is abc');

    expect(onSubmit).toHaveBeenCalledWith({ passphrase: 'abc', hint: 'it is abc' });
  });

  it('still refuses a confirmation that does not match', () => {
    const onSubmit = vi.fn();
    render(<ConfigPassphraseDialog mode="export" onSubmit={onSubmit} onCancel={vi.fn()} />);

    fireEvent.change(screen.getByLabelText('Passphrase'), { target: { value: 'abc' } });
    fireEvent.change(screen.getByLabelText('Confirm passphrase'), { target: { value: 'abd' } });
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));

    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getByRole('alert')).toBeTruthy();
  });

  it('stays open and says so when the passphrase is wrong, then allows a retry', async () => {
    const onSubmit = vi.fn().mockResolvedValueOnce(false).mockResolvedValueOnce(true);
    render(<ConfigPassphraseDialog mode="import" onSubmit={onSubmit} onCancel={vi.fn()} />);

    fireEvent.change(screen.getByLabelText('Passphrase'), { target: { value: 'wrong' } });
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect((await screen.findByRole('alert')).textContent).toContain('incorrect');

    fireEvent.change(screen.getByLabelText('Passphrase'), { target: { value: 'right' } });
    expect(screen.queryByRole('alert')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Continue' }));
    expect(onSubmit).toHaveBeenLastCalledWith({ passphrase: 'right', hint: undefined });
  });

  it('shows the file hint when importing, with no hint input', () => {
    render(<ConfigPassphraseDialog mode="import" hint="the usual one" onSubmit={vi.fn()} onCancel={vi.fn()} />);

    expect(screen.getByText('the usual one')).toBeTruthy();
    expect(screen.queryByLabelText('Hint (optional)')).toBeNull();
  });

  it('shows no hint section when the file has none', () => {
    render(<ConfigPassphraseDialog mode="import" onSubmit={vi.fn()} onCancel={vi.fn()} />);

    expect(screen.queryByText('Hint')).toBeNull();
  });
});
