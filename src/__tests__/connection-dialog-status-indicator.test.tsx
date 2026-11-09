/**
 * The status dot beside Save / Connect probes the settings with a throwaway,
 * non-interactive SSH login: gray while testing, green when it logs in (and
 * the probe session is closed again), red when the settings are refused or
 * required fields are missing.
 */
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { ConnectionDialog } from '../components/connection-dialog';

beforeAll(() => {
  Element.prototype.scrollIntoView = () => {};
});

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(),
}));

vi.mock('sonner', () => ({
  toast: { error: vi.fn(), info: vi.fn(), success: vi.fn(), warning: vi.fn() },
}));

vi.mock('../lib/connection-profiles', () => ({
  ConnectionProfileManager: {
    getProfiles: vi.fn(() => []),
  },
}));

import { invoke } from '@tauri-apps/api/core';

const mockInvoke = invoke as unknown as ReturnType<typeof vi.fn>;

const connection = {
  id: 'conn-1',
  name: 'Staging',
  host: 'staging.example.com',
  port: 22,
  username: 'ubuntu',
  protocol: 'SSH' as const,
  authMethod: 'password' as const,
  password: '',
};

function renderDialog(editingConnection: typeof connection | null) {
  return render(
    <ConnectionDialog
      open={true}
      onOpenChange={vi.fn()}
      onConnect={vi.fn()}
      editingConnection={editingConnection}
    />,
  );
}

const indicator = () => screen.getByTestId('connection-status-indicator');

beforeEach(() => {
  localStorage.clear();
  vi.clearAllMocks();
});

describe('ConnectionDialog status indicator', () => {
  it('turns green when the probe logs in, then closes the probe session', async () => {
    mockInvoke.mockImplementation(async (command: string) =>
      command === 'ssh_connect' ? { success: true } : { success: true },
    );
    renderDialog(connection);

    expect(indicator().getAttribute('data-status')).toBe('testing');
    await waitFor(() => expect(indicator().getAttribute('data-status')).toBe('connected'), { timeout: 3000 });

    const connectCall = mockInvoke.mock.calls.find(([c]) => c === 'ssh_connect');
    const probeId = (connectCall?.[1] as { request: { connection_id: string } }).request.connection_id;
    expect(probeId).toMatch(/^probe-/);
    expect(mockInvoke).toHaveBeenCalledWith('ssh_disconnect', { connection_id: probeId });
  });

  it('turns red when the probe is refused', async () => {
    mockInvoke.mockImplementation(async (command: string) =>
      command === 'ssh_connect' ? { success: false, error: 'Authentication failed' } : {},
    );
    renderDialog(connection);

    await waitFor(() => expect(indicator().getAttribute('data-status')).toBe('invalid'), { timeout: 3000 });
    expect(mockInvoke).not.toHaveBeenCalledWith('ssh_disconnect', expect.anything());
  });

  it('is red without dialing when required fields are missing', () => {
    mockInvoke.mockResolvedValue({});
    renderDialog(null);

    expect(indicator().getAttribute('data-status')).toBe('invalid');
    expect(mockInvoke).not.toHaveBeenCalledWith('ssh_connect', expect.anything());
  });
});
