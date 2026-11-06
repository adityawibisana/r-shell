/**
 * Passphrase encryption for the secrets of an exported config bundle.
 *
 * Stored secrets are sealed with a master key that only exists in this
 * machine's keychain, so their ciphertext is useless anywhere else. An export
 * with secrets decrypts them and re-encrypts the lot under a key derived from
 * a passphrase the user chooses. The passphrase is never stored; losing it
 * makes the secrets in that file unrecoverable.
 *
 * The readable part of the bundle that decides where secrets get sent (hosts,
 * users, proxies) is authenticated as AES-GCM additional data. Otherwise anyone
 * holding the file could point a connection at their own server without
 * knowing the passphrase, and the restored password would go there.
 */

/** Plain secret values, keyed by connection id and then by field name. */
export type BundleSecrets = Record<string, Record<string, string>>;

export interface SecretsEnvelope {
  v: 1;
  kdf: 'PBKDF2-SHA256';
  iterations: number;
  salt: string;
  nonce: string;
  ciphertext: string;
  /** Passphrase reminder. Readable without the passphrase, so never a secret. */
  hint?: string;
}

// OWASP's recommendation for PBKDF2-HMAC-SHA256.
const PBKDF2_ITERATIONS = 600_000;
// The count comes from the file: bound it so a crafted file cannot weaken the
// key derivation to nothing or hang the app on an absurd count.
const MIN_ITERATIONS = 100_000;
const MAX_ITERATIONS = 10_000_000;

export class WrongPassphraseError extends Error {
  constructor() {
    super('The passphrase is incorrect or the file was modified.');
    this.name = 'WrongPassphraseError';
  }
}

function toBase64(bytes: Uint8Array): string {
  return btoa(Array.from(bytes, (byte) => String.fromCharCode(byte)).join(''));
}

function fromBase64(value: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(value), (char) => char.charCodeAt(0));
}

async function deriveKey(
  passphrase: string,
  salt: Uint8Array<ArrayBuffer>,
  iterations: number,
): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    'raw',
    // Normalized because the same text can arrive as different code points on
    // another OS or input method, which would derive a different key.
    new TextEncoder().encode(passphrase.normalize('NFKC')),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function encryptBundleSecrets(
  secrets: BundleSecrets,
  passphrase: string,
  authenticatedData: string,
): Promise<SecretsEnvelope> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt, PBKDF2_ITERATIONS);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: new TextEncoder().encode(authenticatedData) },
    key,
    new TextEncoder().encode(JSON.stringify(secrets)),
  );
  return {
    v: 1,
    kdf: 'PBKDF2-SHA256',
    iterations: PBKDF2_ITERATIONS,
    salt: toBase64(salt),
    nonce: toBase64(nonce),
    ciphertext: toBase64(new Uint8Array(ciphertext)),
  };
}

export async function decryptBundleSecrets(
  envelope: SecretsEnvelope,
  passphrase: string,
  authenticatedData: string,
): Promise<BundleSecrets> {
  if (
    envelope?.v !== 1 ||
    envelope.kdf !== 'PBKDF2-SHA256' ||
    !Number.isInteger(envelope.iterations) ||
    envelope.iterations < MIN_ITERATIONS ||
    envelope.iterations > MAX_ITERATIONS
  ) {
    throw new Error('Invalid config file: unsupported secrets block.');
  }

  let salt: Uint8Array<ArrayBuffer>;
  let nonce: Uint8Array<ArrayBuffer>;
  let ciphertext: Uint8Array<ArrayBuffer>;
  try {
    salt = fromBase64(envelope.salt);
    nonce = fromBase64(envelope.nonce);
    ciphertext = fromBase64(envelope.ciphertext);
  } catch {
    throw new Error('Invalid config file: corrupt secrets block.');
  }

  const key = await deriveKey(passphrase, salt, envelope.iterations);
  let plaintext: ArrayBuffer;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: new TextEncoder().encode(authenticatedData) },
      key,
      ciphertext,
    );
  } catch {
    throw new WrongPassphraseError();
  }
  return JSON.parse(new TextDecoder().decode(plaintext)) as BundleSecrets;
}
