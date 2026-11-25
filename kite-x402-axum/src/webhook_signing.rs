//! HMAC-SHA256 signing for webhook deliveries.
//!
//! A receiver can prove that a delivery came from a holder of the shared
//! secret and was not modified in transit. The signed message is
//! `"{timestamp}.{body}"`, where `timestamp` is the Unix time in seconds sent
//! in [`TIMESTAMP_HEADER`] and `body` is the exact request body bytes. The
//! signature is sent in [`SIGNATURE_HEADER`] as `v1=<lowercase hex>`.
//!
//! Binding the timestamp into the MAC lets receivers reject replays of an old
//! delivery by checking the timestamp against their own clock; use
//! [`verify_signature_at`] to do both checks in one call.

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Header carrying the signature, formatted as `v1=<hex>`.
pub const SIGNATURE_HEADER: &str = "X-Kite-Signature";
/// Header carrying the Unix timestamp (seconds) that was signed.
pub const TIMESTAMP_HEADER: &str = "X-Kite-Timestamp";

const VERSION_PREFIX: &str = "v1=";

type HmacSha256 = Hmac<Sha256>;

fn mac_for(secret: &str, timestamp_secs: u64, body: &[u8]) -> HmacSha256 {
    // HMAC accepts keys of any length, so `new_from_slice` cannot fail.
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(timestamp_secs.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    mac
}

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}

fn from_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() & 1 == 1 {
        return None;
    }
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let high = char::from(pair[0]).to_digit(16)?;
            let low = char::from(pair[1]).to_digit(16)?;
            u8::try_from(high * 16 + low).ok()
        })
        .collect()
}

/// Returns the `X-Kite-Signature` header value (`v1=<hex>`) for a delivery.
#[must_use]
pub fn sign_payload(secret: &str, timestamp_secs: u64, body: &[u8]) -> String {
    let tag = mac_for(secret, timestamp_secs, body)
        .finalize()
        .into_bytes();
    format!("{VERSION_PREFIX}{}", to_hex(&tag))
}

/// Checks a signature header against the secret, timestamp and body.
///
/// The comparison is constant-time. Malformed headers (wrong prefix, odd
/// length, non-hex characters) simply fail verification. This does not look at
/// the clock: use [`verify_signature_at`] to also reject stale timestamps.
#[must_use]
pub fn verify_signature(secret: &str, timestamp_secs: u64, body: &[u8], header: &str) -> bool {
    let Some(hex) = header.trim().strip_prefix(VERSION_PREFIX) else {
        return false;
    };
    let Some(expected) = from_hex(hex) else {
        return false;
    };
    mac_for(secret, timestamp_secs, body)
        .verify_slice(&expected)
        .is_ok()
}

/// Like [`verify_signature`], but also rejects a timestamp more than
/// `tolerance_secs` away from `now_secs` (in either direction), which stops
/// an attacker from replaying a captured delivery later.
#[must_use]
pub fn verify_signature_at(
    secret: &str,
    timestamp_secs: u64,
    body: &[u8],
    header: &str,
    now_secs: u64,
    tolerance_secs: u64,
) -> bool {
    timestamp_secs.abs_diff(now_secs) <= tolerance_secs
        && verify_signature(secret, timestamp_secs, body, header)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "whsec_test";
    const BODY: &[u8] = br#"{"event_id":"evt_1"}"#;

    /// Independently computed with
    /// `printf '1700000000.{"event_id":"evt_1"}' | openssl dgst -sha256 -hmac whsec_test`.
    const KNOWN_TAG: &str = "v1=0344289cae2f5eb6d2640d79205fa65017efc017e224155b7ef95f784061172c";

    #[test]
    fn signature_has_the_documented_shape() {
        let sig = sign_payload(SECRET, 1_700_000_000, BODY);
        let hex = sig.strip_prefix("v1=").expect("v1 prefix");
        assert_eq!(hex.len(), 64);
        assert!(hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }

    #[test]
    fn signing_is_deterministic_and_verifiable() {
        let a = sign_payload(SECRET, 1_700_000_000, BODY);
        let b = sign_payload(SECRET, 1_700_000_000, BODY);
        assert_eq!(a, b);
        assert!(verify_signature(SECRET, 1_700_000_000, BODY, &a));
        assert!(verify_signature(
            SECRET,
            1_700_000_000,
            BODY,
            &format!("  {a}\n")
        ));
    }

    #[test]
    fn any_change_to_secret_timestamp_or_body_breaks_verification() {
        let sig = sign_payload(SECRET, 1_700_000_000, BODY);
        assert!(!verify_signature("other", 1_700_000_000, BODY, &sig));
        assert!(!verify_signature(SECRET, 1_700_000_001, BODY, &sig));
        assert!(!verify_signature(SECRET, 1_700_000_000, b"{}", &sig));
    }

    #[test]
    fn malformed_headers_fail_closed() {
        let good = sign_payload(SECRET, 1, BODY);
        let hex = good.strip_prefix("v1=").unwrap();
        for bad in [
            "",
            "v1=",
            "v1=zz",
            hex,
            &format!("v2={hex}"),
            &format!("v1={}", &hex[..hex.len() - 1]),
            &format!("v1={hex}00"),
            &format!("v1={}", hex.to_uppercase().replace('A', "G")),
        ] {
            assert!(!verify_signature(SECRET, 1, BODY, bad), "{bad:?}");
        }
    }

    #[test]
    fn uppercase_hex_is_accepted() {
        let sig = sign_payload(SECRET, 1, BODY);
        let upper = format!("v1={}", sig.strip_prefix("v1=").unwrap().to_uppercase());
        assert!(verify_signature(SECRET, 1, BODY, &upper));
    }

    #[test]
    fn timestamp_tolerance_applies_in_both_directions() {
        let now = 1_000_000;
        for (ts, ok) in [
            (now, true),
            (now - 300, true),
            (now + 300, true),
            (now - 301, false),
            (now + 301, false),
        ] {
            let sig = sign_payload(SECRET, ts, BODY);
            assert_eq!(
                verify_signature_at(SECRET, ts, BODY, &sig, now, 300),
                ok,
                "ts={ts}"
            );
        }
    }

    #[test]
    fn extreme_timestamps_do_not_overflow() {
        let sig = sign_payload(SECRET, u64::MAX, BODY);
        assert!(verify_signature(SECRET, u64::MAX, BODY, &sig));
        assert!(!verify_signature_at(SECRET, u64::MAX, BODY, &sig, 0, 300));
        assert!(verify_signature_at(
            SECRET,
            u64::MAX,
            BODY,
            &sig,
            u64::MAX,
            0
        ));
    }

    #[test]
    fn matches_an_independently_computed_vector() {
        assert_eq!(sign_payload(SECRET, 1_700_000_000, BODY), KNOWN_TAG);
    }
}
