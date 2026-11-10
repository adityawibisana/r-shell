//! Time-based one-time codes (RFC 6238) for servers that ask for an
//! authenticator code at login. Uses the parameters every authenticator app
//! defaults to: HMAC-SHA1, 30-second steps, 6 digits. The authenticator
//! tool reuses the same generator with the parameters an `otpauth://` URI
//! may choose instead.

use anyhow::{bail, Result};
use hmac::{Hmac, KeyInit, Mac};
use serde::Deserialize;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) const STEP_SECS: u64 = 30;

/// Decode a base32 secret as authenticator apps show it. Case, spaces, dashes
/// and padding don't matter, since people paste these from setup pages. Errors
/// never echo the input: it is a credential.
fn decode_base32(secret: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(secret.len() * 5 / 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in secret.chars() {
        if c.is_whitespace() || c == '-' || c == '=' {
            continue;
        }
        let value = match c.to_ascii_uppercase() {
            c @ 'A'..='Z' => c as u32 - 'A' as u32,
            c @ '2'..='7' => c as u32 - '2' as u32 + 26,
            _ => bail!("The Authenticator secret key is not valid: it may only contain the letters A-Z and the digits 2-7."),
        };
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    if bytes.is_empty() {
        bail!("The Authenticator secret key is empty.");
    }
    Ok(bytes)
}

/// HMAC hash an authenticator account uses (`algorithm` in `otpauth://`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Algorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

macro_rules! hmac_digest {
    ($hash:ty, $key:expr, $counter:expr) => {{
        let mut mac = Hmac::<$hash>::new_from_slice($key)
            .map_err(|_| anyhow::anyhow!("The Authenticator secret key could not be used."))?;
        mac.update(&$counter.to_be_bytes());
        mac.finalize().into_bytes().to_vec()
    }};
}

/// The RFC 4226 code for one counter value, truncated to `digits`.
fn hotp(key: &[u8], counter: u64, digits: u32) -> Result<String> {
    hotp_with(Algorithm::Sha1, key, counter, digits)
}

fn hotp_with(algorithm: Algorithm, key: &[u8], counter: u64, digits: u32) -> Result<String> {
    let digest = match algorithm {
        Algorithm::Sha1 => hmac_digest!(Sha1, key, counter),
        Algorithm::Sha256 => hmac_digest!(Sha256, key, counter),
        Algorithm::Sha512 => hmac_digest!(Sha512, key, counter),
    };
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let word = u32::from_be_bytes([
        digest[offset] & 0x7f,
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]);
    Ok(format!(
        "{:0width$}",
        word % 10u32.pow(digits),
        width = digits as usize
    ))
}

/// The code shown for `now_secs`, and the Unix time at which it expires.
/// Unlike logins, a display never claims steps: it just shows the current one.
pub(crate) fn code_at(
    secret: &str,
    algorithm: Algorithm,
    digits: u32,
    period: u64,
    now_secs: u64,
) -> Result<(String, u64)> {
    if !(6..=8).contains(&digits) {
        bail!("Authenticator codes must have 6 to 8 digits.");
    }
    if period == 0 || period > 3600 {
        bail!("The Authenticator period must be between 1 and 3600 seconds.");
    }
    let key = decode_base32(secret)?;
    let step = now_secs / period;
    Ok((hotp_with(algorithm, &key, step, digits)?, (step + 1) * period))
}

/// Last time step a login used, per secret. Keyed by a hash so the secrets
/// themselves don't outlive the connect that carried them.
static LAST_STEPS: LazyLock<Mutex<HashMap<u64, u64>>> = LazyLock::new(Default::default);

/// Pick the step for a new login attempt, and how many seconds to wait before
/// sending its code. Servers commonly refuse a code they have already seen
/// (`pam_google_authenticator`'s DISALLOW_REUSE), and a second tab to the same
/// host easily lands inside the same 30 seconds. So every attempt takes a step
/// of its own. The next step's code is inside the default acceptance window,
/// but one further ahead is not: that one has to wait until it is only one
/// step ahead.
fn claim_step(secret_id: u64, now_secs: u64, last_steps: &mut HashMap<u64, u64>) -> (u64, u64) {
    let current = now_secs / STEP_SECS;
    let step = match last_steps.get(&secret_id) {
        Some(&last) if last >= current => last + 1,
        _ => current,
    };
    last_steps.insert(secret_id, step);
    let wait = if step > current + 1 {
        (step - 1) * STEP_SECS - now_secs
    } else {
        0
    };
    (step, wait)
}

/// The code for one login attempt, once it is safe to send. Each call moves on
/// to a new step, so a retry after a rejected code never repeats it.
pub(crate) async fn next_login_code(secret: &str) -> Result<String> {
    let key = decode_base32(secret)?;
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow::anyhow!("This computer's clock is set before 1970."))?
        .as_secs();
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    let (step, wait) = claim_step(
        hasher.finish(),
        now_secs,
        &mut LAST_STEPS.lock().unwrap_or_else(|e| e.into_inner()),
    );
    if wait > 0 {
        tokio::time::sleep(Duration::from_secs(wait)).await;
    }
    hotp(&key, step, 6)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// "12345678901234567890" in base32, the RFC 6238 SHA-1 test key.
    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn matches_the_rfc_6238_sha1_vectors() {
        let key = decode_base32(RFC_SECRET).unwrap();
        for (time, expected) in [
            (59u64, "94287082"),
            (1_111_111_109, "07081804"),
            (1_111_111_111, "14050471"),
            (1_234_567_890, "89005924"),
            (2_000_000_000, "69279037"),
            (20_000_000_000, "65353130"),
        ] {
            assert_eq!(hotp(&key, time / STEP_SECS, 8).unwrap(), expected);
        }
    }

    #[test]
    fn matches_the_rfc_6238_sha256_and_sha512_vectors() {
        // RFC 6238 appendix B uses a 32- and a 64-byte ASCII key for these.
        let sha256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
        let sha512 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA";
        for (time, expected256, expected512) in [
            (59u64, "46119246", "90693936"),
            (1_111_111_109, "68084774", "25091201"),
            (1_234_567_890, "91819424", "93441116"),
            (20_000_000_000, "77737706", "47863826"),
        ] {
            assert_eq!(code_at(sha256, Algorithm::Sha256, 8, 30, time).unwrap().0, expected256);
            assert_eq!(code_at(sha512, Algorithm::Sha512, 8, 30, time).unwrap().0, expected512);
        }
    }

    #[test]
    fn displayed_codes_expire_at_the_end_of_their_step() {
        let (code, expires) = code_at(RFC_SECRET, Algorithm::Sha1, 6, 30, 59).unwrap();
        assert_eq!((code.as_str(), expires), ("287082", 60));
        assert_eq!(code_at(RFC_SECRET, Algorithm::Sha1, 6, 60, 59).unwrap().1, 60);
        assert!(code_at(RFC_SECRET, Algorithm::Sha1, 5, 30, 59).is_err());
        assert!(code_at(RFC_SECRET, Algorithm::Sha1, 6, 0, 59).is_err());
    }

    #[test]
    fn six_digit_codes_keep_their_leading_zeros() {
        let key = decode_base32(RFC_SECRET).unwrap();
        assert_eq!(hotp(&key, 59 / STEP_SECS, 6).unwrap(), "287082");
        // The 8-digit vector above is 07081804; six digits leave 081804.
        assert_eq!(hotp(&key, 1_111_111_109 / STEP_SECS, 6).unwrap(), "081804");
    }

    #[test]
    fn decoding_ignores_formatting_and_padding() {
        let expected = decode_base32("MFRGGZDF").unwrap();
        assert_eq!(expected, b"abcde");
        assert_eq!(decode_base32("mfrg gzdf").unwrap(), expected);
        assert_eq!(decode_base32("MFRG-GZDF\n").unwrap(), expected);
        assert_eq!(decode_base32("MFRGG===").unwrap(), b"abc");
    }

    #[test]
    fn decoding_tolerates_trailing_bits_of_unpadded_secrets() {
        // 26 characters carry 130 bits: 16 bytes plus 2 unused bits.
        assert_eq!(decode_base32(&"A".repeat(26)).unwrap().len(), 16);
    }

    #[test]
    fn bad_secrets_are_rejected_without_echoing_them() {
        let err = decode_base32("SECRET1VALUE").unwrap_err().to_string();
        assert!(err.contains("not valid"), "{err}");
        assert!(!err.contains("SECRET1VALUE"), "{err}");
        assert!(decode_base32("  -= ").is_err());
    }

    #[test]
    fn logins_in_one_step_never_share_a_code() {
        let mut steps = HashMap::new();
        // 3010 s is 10 s into step 100.
        assert_eq!(claim_step(1, 3010, &mut steps), (100, 0));
        // The next step's code goes out right away.
        assert_eq!(claim_step(1, 3010, &mut steps), (101, 0));
        // Two ahead waits for step 101 to begin, 20 s later.
        assert_eq!(claim_step(1, 3010, &mut steps), (102, 20));
        // Another secret has its own history.
        assert_eq!(claim_step(2, 3010, &mut steps), (100, 0));
        // Once time has passed the claimed steps, the current one is free.
        assert_eq!(claim_step(1, 3300, &mut steps), (110, 0));
    }
}
