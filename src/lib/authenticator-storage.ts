/**
 * Authenticator (TOTP) accounts
 *
 * Tools → Authenticator keeps a list of one-time-code accounts, like a phone
 * authenticator app. Follows the SnippetStorageManager pattern: static manager
 * methods over one localStorage key, defensive parsing, and a window event so
 * an open dialog re-reads after every mutation.
 *
 * The secret is sealed with the app master key (`credential_seal`) before it
 * is stored, and codes are computed on the Rust side (`authenticator_codes`)
 * from the sealed value, so the webview only holds a plaintext secret while
 * the user is typing it in.
 */
import { invoke } from '@tauri-apps/api/core';
import { sealSecret } from './credential-crypto';

export type TotpAlgorithm = 'SHA1' | 'SHA256' | 'SHA512';

export const TOTP_ALGORITHMS: readonly TotpAlgorithm[] = ['SHA1', 'SHA256', 'SHA512'];
export const TOTP_DIGITS: readonly number[] = [6, 7, 8];
export const DEFAULT_TOTP_PERIOD = 30;
export const MAX_TOTP_PERIOD = 3600;

export interface AuthenticatorAccount {
  id: string;
  /** Account label, e.g. "alice@example.com". */
  name: string;
  /** Service the account belongs to, e.g. "GitHub". */
  issuer?: string;
  /**
   * Sealed (`v1:`) base32 secret. Absent after importing a config export
   * without its credentials: the account is listed but shows no code until
   * the secret is entered again.
   */
  secret?: string;
  algorithm: TotpAlgorithm;
  digits: number;
  /** Seconds each code stays valid. */
  period: number;
  createdAt: string;
  updatedAt: string;
}

/** Account without its secret, as a config export carries it. */
export type PublicAuthenticatorAccount = Omit<AuthenticatorAccount, 'secret'>;

export interface AuthenticatorAccountInput {
  id?: string;
  name: string;
  issuer?: string;
  /** Plaintext base32 secret; empty keeps the saved one when editing. */
  secret?: string;
  algorithm: TotpAlgorithm;
  digits: number;
  period: number;
}

/** Parameters read from a pasted secret or `otpauth://` URI. */
export interface ParsedTotpInput {
  secret: string;
  name?: string;
  issuer?: string;
  algorithm?: TotpAlgorithm;
  digits?: number;
  period?: number;
}

export interface AuthenticatorCode {
  code: string | null;
  /** Unix time (seconds) at which the code expires. */
  expiresAt: number | null;
  error: string | null;
}

const AUTHENTICATOR_STORAGE_KEY = 'r-shell-authenticator-accounts';

/** Emitted on `window` after any storage mutation. */
export const AUTHENTICATOR_CHANGED_EVENT = 'rshell-authenticator-changed';

/** Strip the formatting setup pages add (spaces, dashes, padding) and upper-case. */
export function normalizeTotpSecret(secret: string): string {
  return secret.replace(/[\s=-]/g, '').toUpperCase();
}

/** True for a non-empty base32 secret (A–Z, 2–7 once normalized). */
export function isValidTotpSecret(secret: string): boolean {
  return /^[A-Z2-7]+$/.test(normalizeTotpSecret(secret));
}

function isAlgorithm(value: unknown): value is TotpAlgorithm {
  return typeof value === 'string' && (TOTP_ALGORITHMS as readonly string[]).includes(value);
}

function isValidDigits(value: unknown): value is number {
  return typeof value === 'number' && TOTP_DIGITS.includes(value);
}

function isValidPeriod(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 1 && value <= MAX_TOTP_PERIOD;
}

/**
 * Read a pasted value: either a bare base32 secret or a Key URI
 * (`otpauth://totp/Issuer:account?secret=…&issuer=…&algorithm=…&digits=…&period=…`).
 * Returns null when it is neither. HOTP URIs are rejected: their codes need
 * a counter, which this tool does not keep.
 */
export function parseTotpInput(input: string): ParsedTotpInput | null {
  const trimmed = input.trim();
  if (!trimmed) return null;
  if (!/^otpauth:\/\//i.test(trimmed)) {
    return isValidTotpSecret(trimmed) ? { secret: normalizeTotpSecret(trimmed) } : null;
  }

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return null;
  }
  // Browsers parse otpauth:// as an opaque URL, so read type and label from
  // the raw text instead of url.host / url.pathname.
  const match = /^otpauth:\/\/([^/?#]+)\/?([^?#]*)/i.exec(trimmed);
  if (!match || match[1].toLowerCase() !== 'totp') return null;

  const secret = url.searchParams.get('secret') ?? '';
  if (!isValidTotpSecret(secret)) return null;
  const result: ParsedTotpInput = { secret: normalizeTotpSecret(secret) };

  let label: string;
  try {
    label = decodeURIComponent(match[2]);
  } catch {
    label = match[2];
  }
  const separator = label.indexOf(':');
  const labelIssuer = separator >= 0 ? label.slice(0, separator).trim() : '';
  const name = (separator >= 0 ? label.slice(separator + 1) : label).trim();
  if (name) result.name = name;
  const issuer = url.searchParams.get('issuer')?.trim() || labelIssuer;
  if (issuer) result.issuer = issuer;

  const algorithm = url.searchParams.get('algorithm')?.toUpperCase();
  if (isAlgorithm(algorithm)) result.algorithm = algorithm;
  const digits = Number(url.searchParams.get('digits'));
  if (isValidDigits(digits)) result.digits = digits;
  const period = Number(url.searchParams.get('period'));
  if (isValidPeriod(period)) result.period = period;
  return result;
}

function isValidAccount(value: unknown): value is AuthenticatorAccount {
  if (typeof value !== 'object' || value === null) return false;
  const account = value as Partial<AuthenticatorAccount>;
  return typeof account.id === 'string' && typeof account.name === 'string';
}

/** Fill defaults for missing or invalid parameters; drop a non-string secret. */
function normalizeAccount(account: AuthenticatorAccount, now: string): AuthenticatorAccount {
  return {
    id: account.id,
    name: account.name.trim(),
    issuer: typeof account.issuer === 'string' && account.issuer.trim() ? account.issuer.trim() : undefined,
    secret: typeof account.secret === 'string' && account.secret ? account.secret : undefined,
    algorithm: isAlgorithm(account.algorithm) ? account.algorithm : 'SHA1',
    digits: isValidDigits(account.digits) ? account.digits : 6,
    period: isValidPeriod(account.period) ? account.period : DEFAULT_TOTP_PERIOD,
    createdAt: typeof account.createdAt === 'string' ? account.createdAt : now,
    updatedAt: typeof account.updatedAt === 'string' ? account.updatedAt : now,
  };
}

function generateAccountId(): string {
  const random = Math.random().toString(36).slice(2, 8);
  return `totp-${Date.now().toString(36)}-${random}`;
}

function persist(accounts: AuthenticatorAccount[]): void {
  try {
    localStorage.setItem(AUTHENTICATOR_STORAGE_KEY, JSON.stringify(accounts));
  } catch (error) {
    console.error('Failed to save authenticator accounts:', error);
  }
}

function notifyChanged(): void {
  try {
    window.dispatchEvent(new Event(AUTHENTICATOR_CHANGED_EVENT));
  } catch {
    // Non-browser environment — ignore.
  }
}

export class AuthenticatorStorageManager {
  /** All accounts in creation order. Corrupt storage degrades to an empty list. */
  static getAccounts(): AuthenticatorAccount[] {
    try {
      const stored = localStorage.getItem(AUTHENTICATOR_STORAGE_KEY);
      if (!stored) return [];
      const parsed = JSON.parse(stored) as unknown;
      if (!Array.isArray(parsed)) return [];
      const now = new Date().toISOString();
      return parsed.filter(isValidAccount).map((account) => normalizeAccount(account, now));
    } catch (error) {
      console.error('Failed to load authenticator accounts:', error);
      return [];
    }
  }

  /** The list without secrets, for a config export. */
  static getPublicAccounts(): PublicAuthenticatorAccount[] {
    return this.getAccounts().map(({ secret: _secret, ...account }) => account);
  }

  /**
   * Create or update an account (upsert by id), sealing a typed secret first.
   * Throws when the name is empty, a new account has no secret, or the
   * secret is not base32; the dialog validates these before calling.
   */
  static async saveAccount(input: AuthenticatorAccountInput): Promise<AuthenticatorAccount> {
    const name = input.name.trim();
    if (!name) throw new Error('Authenticator account name is empty');
    const accounts = this.getAccounts();
    const existingIndex = input.id ? accounts.findIndex((a) => a.id === input.id) : -1;
    const existing = existingIndex >= 0 ? accounts[existingIndex] : undefined;

    let secret = existing?.secret;
    if (input.secret?.trim()) {
      if (!isValidTotpSecret(input.secret)) throw new Error('Authenticator secret is not valid base32');
      secret = await sealSecret(normalizeTotpSecret(input.secret));
    }
    if (!secret) throw new Error('Authenticator secret is required');

    const now = new Date().toISOString();
    const account = normalizeAccount(
      {
        id: existing?.id ?? generateAccountId(),
        name,
        issuer: input.issuer,
        secret,
        algorithm: input.algorithm,
        digits: input.digits,
        period: input.period,
        createdAt: existing?.createdAt ?? now,
        updatedAt: now,
      },
      now,
    );

    // Re-read: sealing awaited, and another window may have written meanwhile.
    const latest = this.getAccounts();
    const index = latest.findIndex((a) => a.id === account.id);
    if (index >= 0) latest[index] = account;
    else latest.push(account);
    persist(latest);
    notifyChanged();
    return account;
  }

  static deleteAccount(id: string): boolean {
    const accounts = this.getAccounts();
    const next = accounts.filter((a) => a.id !== id);
    if (next.length === accounts.length) return false;
    persist(next);
    notifyChanged();
    return true;
  }

  /**
   * Import accounts from a config bundle. Secrets in the untrusted list are
   * ignored; `sealedSecrets` (id → locally sealed secret, restored from the
   * credentials block) supplies them. In merge mode an imported account
   * without a restored secret keeps the one already saved under its id.
   * Returns the number of accounts taken from the input.
   */
  static importAccounts(
    imported: unknown,
    merge: boolean = false,
    sealedSecrets: ReadonlyMap<string, string> = new Map(),
  ): number {
    if (!Array.isArray(imported)) throw new Error('Invalid authenticator accounts format');
    const now = new Date().toISOString();
    const current = merge ? this.getAccounts() : [];
    const valid = imported
      .filter(isValidAccount)
      .filter((account) => account.name.trim())
      .map((account) => {
        const previous = current.find((a) => a.id === account.id);
        return normalizeAccount(
          { ...account, secret: sealedSecrets.get(account.id) ?? previous?.secret },
          now,
        );
      });

    for (const account of valid) {
      const index = current.findIndex((a) => a.id === account.id);
      if (index >= 0) current[index] = account;
      else current.push(account);
    }
    persist(current);
    notifyChanged();
    return valid.length;
  }
}

/** Current codes for the accounts, in order. Accounts without a secret get none. */
export async function fetchAuthenticatorCodes(
  accounts: AuthenticatorAccount[],
): Promise<AuthenticatorCode[]> {
  const withSecret = accounts.filter((a) => a.secret);
  const codes = withSecret.length
    ? await invoke<AuthenticatorCode[]>('authenticator_codes', {
        accounts: withSecret.map((a) => ({
          sealed: a.secret,
          algorithm: a.algorithm,
          digits: a.digits,
          period: a.period,
        })),
      })
    : [];
  let next = 0;
  return accounts.map((a) => (a.secret ? codes[next++] : { code: null, expiresAt: null, error: null }));
}
