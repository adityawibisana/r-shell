/**
 * Config Export / Import
 *
 * Bundles every piece of user-configurable state (connections, folders,
 * profiles, terminal appearance, editor config, app settings, language)
 * into a single JSON file so the user can move their setup to another
 * machine with one click.
 */

import { save, open as tauriOpen } from '@tauri-apps/plugin-dialog';
import { version as packageVersion } from '../../package.json';
import { readLocalTextFile, writeLocalTextFile } from './local-file-access';
import {
  ConnectionStorageManager,
  type ConnectionData,
  type ConnectionFolder,
} from './connection-storage';
import { SECRET_FIELDS, isSealed, openSecret, sealSecret } from './credential-crypto';
import {
  decryptBundleSecrets,
  encryptBundleSecrets,
  WrongPassphraseError,
  type BundleSecrets,
  type SecretsEnvelope,
} from './config-secrets';
import { ConnectionProfileManager, type ConnectionProfile } from './connection-profiles';
import {
  loadAppearanceSettings,
  saveAppearanceSettings,
  type TerminalAppearanceSettings,
} from './terminal-config';
import {
  loadEditorConfig,
  saveEditorConfig,
  dispatchEditorConfigChanged,
  type EditorConfig,
} from './editor-config';
import {
  APP_SETTINGS_STORAGE_KEY,
  APP_SETTINGS_CHANGED_EVENT,
  stripRemovedSettingsKeys,
} from './keyboard-shortcuts';
import { migrateLegacyShortcutBindings } from './shortcut-registry';

// ── Constants ────────────────────────────────────────────────────────────────

const SCHEMA_VERSION = 1;
const LANGUAGE_STORAGE_KEY = 'r-shell-language';

// ── Types ────────────────────────────────────────────────────────────────────

export interface ConfigBundle {
  version: number;
  exportedAt: string;
  appVersion: string;
  data: {
    connections?: {
      connections: ConnectionData[];
      folders: ConnectionFolder[];
    };
    profiles?: ConnectionProfile[];
    terminalAppearance?: TerminalAppearanceSettings;
    editorConfig?: EditorConfig;
    appSettings?: Record<string, unknown>;
    language?: string;
    /** Connection secrets, present only when the export opted in. */
    secrets?: SecretsEnvelope;
  };
}

export interface ImportResult {
  connections: number;
  profiles: number;
  terminalAppearance: boolean;
  editorConfig: boolean;
  appSettings: boolean;
  language: boolean;
  /** Connections whose secrets were restored from the bundle. */
  secretsRestored: number;
}

export interface ExportOptions {
  /** Include connection secrets, encrypted under this passphrase. */
  secretsPassphrase?: string;
  /** Passphrase reminder, stored unencrypted next to the secrets. */
  secretsHint?: string;
}

export interface ImportOptions {
  /**
   * Called only when the file carries secrets, with the file's hint if it has
   * one. Calls `attempt` with each passphrase the user tries; it resolves false
   * for a wrong one, so the prompt can stay open. Resolving without a successful
   * attempt cancels the import.
   */
  unlockSecrets?: (
    hint: string | undefined,
    attempt: (passphrase: string) => Promise<boolean>,
  ) => Promise<void>;
}

/** A stored secret that cannot be decrypted, so it cannot be exported. */
export class UnreadableSecretError extends Error {
  constructor(readonly connectionName: string) {
    super(`Could not decrypt the saved credentials of "${connectionName}".`);
    this.name = 'UnreadableSecretError';
  }
}

// ── Export ────────────────────────────────────────────────────────────────────

// Secret fields left out of the bundle's connection records. Never exported
// as master-key ciphertext: it could not be opened on another machine, and a
// stolen master key would decrypt every exported credential. Secrets only
// travel in the passphrase-encrypted `data.secrets` block.
const EXPORT_STRIPPED_FIELDS = SECRET_FIELDS;

/** The bundle text that a secrets block is bound to. See config-secrets.ts. */
function secretsAuthenticatedData(connections: ConnectionData[] | undefined): string {
  return JSON.stringify(connections ?? []);
}

/** True when an export with secrets would have anything to protect. */
export function hasExportableSecrets(): boolean {
  return ConnectionStorageManager.getConnections().some((connection) =>
    SECRET_FIELDS.some((field) => {
      const value = connection[field];
      return typeof value === 'string' && value.length > 0;
    }),
  );
}

/**
 * Decrypt every stored connection secret. An unreadable one fails the export:
 * a backup that silently lacks a credential is only found out when it is
 * needed. Profiles are not covered, because importing one drops its secrets.
 */
async function collectConnectionSecrets(connections: ConnectionData[]): Promise<BundleSecrets> {
  const secrets: BundleSecrets = {};
  for (const connection of connections) {
    for (const field of SECRET_FIELDS) {
      const value = connection[field];
      if (typeof value !== 'string' || value.length === 0) continue;
      let plain = value;
      if (isSealed(value)) {
        try {
          plain = await openSecret(value);
        } catch (error) {
          console.error(`[config-export] Failed to decrypt ${field}:`, error);
          throw new UnreadableSecretError(connection.name);
        }
      }
      (secrets[connection.id] ??= {})[field] = plain;
    }
  }
  return secrets;
}

/**
 * Collect all config from localStorage, show a save-dialog, and write the
 * JSON bundle to disk.  Returns `true` when the file was written, `false`
 * when the user cancelled the dialog.
 */
export async function exportAllConfig(options: ExportOptions = {}): Promise<boolean> {
  try {
    // 1. Build the bundle -------------------------------------------------------
    const bundle: ConfigBundle = {
      version: SCHEMA_VERSION,
      exportedAt: new Date().toISOString(),
      appVersion: getAppVersion(),
      data: {},
    };

    // Connections + folders. Secret fields (plaintext AND sealed ciphertext)
    // are stripped from the records.
    const connections = ConnectionStorageManager.getConnections();
    const folders = ConnectionStorageManager.getFolders();
    if (connections.length || folders.length) {
      bundle.data.connections = {
        connections: connections.map((c) => {
          const clone = { ...c } as Record<string, unknown>;
          for (const field of EXPORT_STRIPPED_FIELDS) {
            delete clone[field];
          }
          return clone as unknown as typeof c;
        }),
        folders,
      };
    }

    if (options.secretsPassphrase) {
      const secrets = await collectConnectionSecrets(connections);
      // No block when there is nothing to protect: it would only make every
      // import of this file ask for a passphrase.
      if (Object.keys(secrets).length > 0) {
        bundle.data.secrets = await encryptBundleSecrets(
          secrets,
          options.secretsPassphrase,
          secretsAuthenticatedData(bundle.data.connections?.connections),
        );
        if (options.secretsHint) bundle.data.secrets.hint = options.secretsHint;
      }
    }

    // Connection profiles — strip secrets the same way.
    const profiles = ConnectionProfileManager.getProfiles();
    if (profiles.length) {
      bundle.data.profiles = profiles.map((p) => {
        const clone = { ...p } as Record<string, unknown>;
        for (const field of EXPORT_STRIPPED_FIELDS) {
          delete clone[field];
        }
        return clone as unknown as typeof p;
      });
    }

    // Terminal appearance
    const termAppearance = loadAppearanceSettings();
    bundle.data.terminalAppearance = termAppearance;

    // Editor config
    const editorCfg = loadEditorConfig();
    bundle.data.editorConfig = editorCfg;

    // App settings (raw localStorage blob)
    try {
      const raw = localStorage.getItem(APP_SETTINGS_STORAGE_KEY);
      if (raw) bundle.data.appSettings = JSON.parse(raw) as Record<string, unknown>;
    } catch {
      /* ignore */
    }

    // Language preference
    const lang = localStorage.getItem(LANGUAGE_STORAGE_KEY);
    if (lang) bundle.data.language = lang;

    // 2. Ask where to save -----------------------------------------------------
    const dateStr = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
    const filePath = await save({
      defaultPath: `r-shell-config-${dateStr}.json`,
      filters: [{ name: 'R-Shell Config', extensions: ['json'] }],
    });

    if (!filePath) return false; // cancelled

    // 3. Write ------------------------------------------------------------------
    // The fs plugin may only touch files the user picked, so grant this one.
    await writeLocalTextFile(filePath, JSON.stringify(bundle, null, 2));
    return true;
  } catch (error) {
    console.error('[config-export] Failed:', error);
    throw error;
  }
}

// ── Import ────────────────────────────────────────────────────────────────────

/**
 * Decrypt the bundle's secrets and seal them with this machine's master key,
 * in place on its connection records. Secrets are matched by the bundle's
 * connection id; importing assigns new ids afterwards.
 */
async function restoreConnectionSecrets(
  connections: ConnectionData[],
  secrets: BundleSecrets,
): Promise<number> {
  let restored = 0;
  for (const connection of connections) {
    const stored = secrets[connection.id];
    if (!stored) continue;
    const record = connection as unknown as Record<string, unknown>;
    for (const field of SECRET_FIELDS) {
      const value = stored[field];
      if (typeof value === 'string' && value.length > 0) {
        record[field] = await sealSecret(value);
      }
    }
    restored += 1;
  }
  return restored;
}

/**
 * Open a file-dialog, parse the JSON bundle, optionally merge connections,
 * and write every category into localStorage.  A bundle with secrets is
 * unlocked before the first write, so a failed unlock changes nothing.
 * Returns a summary of what was imported, or `null` when the user cancelled.
 */
export async function importAllConfig(
  merge: boolean = false,
  options: ImportOptions = {},
): Promise<ImportResult | null> {
  try {
    // 1. Pick file --------------------------------------------------------------
    const filePath = await tauriOpen({
      filters: [{ name: 'R-Shell Config', extensions: ['json'] }],
      multiple: false,
      directory: false,
    });

    if (!filePath) return null; // cancelled

    // 2. Read & parse -----------------------------------------------------------
    // The fs plugin may only touch files the user picked, so grant this one.
    const raw = await readLocalTextFile(filePath);
    const bundle = JSON.parse(raw) as ConfigBundle;

    if (typeof bundle.version !== 'number' || !bundle.data) {
      throw new Error('Invalid config file: missing version or data block.');
    }

    const result: ImportResult = {
      connections: 0,
      profiles: 0,
      terminalAppearance: false,
      editorConfig: false,
      appSettings: false,
      language: false,
      secretsRestored: 0,
    };

    const { data } = bundle;

    // 3. Secrets ----------------------------------------------------------------
    if (data.secrets) {
      const envelope = data.secrets;
      const authenticatedData = secretsAuthenticatedData(data.connections?.connections);
      // Widened on purpose: it is only assigned inside the callback below.
      let secrets = null as BundleSecrets | null;
      await options.unlockSecrets?.(
        typeof envelope.hint === 'string' ? envelope.hint : undefined,
        async (passphrase) => {
          try {
            secrets = await decryptBundleSecrets(envelope, passphrase, authenticatedData);
            return true;
          } catch (error) {
            if (error instanceof WrongPassphraseError) return false;
            throw error;
          }
        },
      );
      if (!secrets) return null; // cancelled
      if (Array.isArray(data.connections?.connections)) {
        result.secretsRestored = await restoreConnectionSecrets(
          data.connections.connections,
          secrets,
        );
      }
    }

    // 3a. Connections + folders -------------------------------------------------
    if (data.connections) {
      const importedCount = ConnectionStorageManager.importConnections(
        JSON.stringify(data.connections),
        merge,
      );
      result.connections = importedCount;
    }

    // 3b. Connection profiles ---------------------------------------------------
    if (data.profiles && Array.isArray(data.profiles)) {
      const importedCount = ConnectionProfileManager.importProfiles(
        JSON.stringify(data.profiles),
        merge,
      );
      result.profiles = importedCount;
    }

    // 3c. Terminal appearance ---------------------------------------------------
    if (data.terminalAppearance) {
      saveAppearanceSettings(data.terminalAppearance);
      result.terminalAppearance = true;
    }

    // 3d. Editor config ---------------------------------------------------------
    if (data.editorConfig) {
      saveEditorConfig(data.editorConfig);
      dispatchEditorConfigChanged();
      result.editorConfig = true;
    }

    // 3e. App settings ----------------------------------------------------------
    if (data.appSettings) {
      // Fold the pre-registry flat shortcut keys into `shortcutBindings`
      // BEFORE stripping them, so an export from an older version keeps the
      // user's custom bindings. Then drop keys whose controls were removed
      // (issue #163) so importing an older config cannot resurrect dead
      // settings that nothing consumes.
      migrateLegacyShortcutBindings(data.appSettings);
      stripRemovedSettingsKeys(data.appSettings);
      localStorage.setItem(
        APP_SETTINGS_STORAGE_KEY,
        JSON.stringify(data.appSettings),
      );
      window.dispatchEvent(new Event(APP_SETTINGS_CHANGED_EVENT));
      result.appSettings = true;
    }

    // 3f. Language --------------------------------------------------------------
    if (data.language) {
      localStorage.setItem(LANGUAGE_STORAGE_KEY, data.language);
      result.language = true;
    }

    return result;
  } catch (error) {
    console.error('[config-import] Failed:', error);
    throw error;
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function getAppVersion(): string {
  // The package version is the app version: tauri.conf.json and Cargo.toml
  // are bumped together with it. The previous implementation read
  // `import.meta.env.PACKAGE_VERSION`, which nothing ever defined, so every
  // exported bundle said "unknown".
  return packageVersion;
}
