//! Strict lowercase hex, used for hashes, signatures and keys.
//!
//! Decoding accepts one spelling only (lowercase, exact length), so a value
//! cannot be written two ways. That keeps signed text canonical.

use sha2::{Digest, Sha256};

const DIGITS: &[u8; 16] = b"0123456789abcdef";

pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

/// Decodes exactly `2 * N` lowercase hex digits into `N` bytes.
pub(crate) fn decode_array<const N: usize>(text: &str) -> Option<[u8; N]> {
    let bytes = text.as_bytes();
    if bytes.len() != N * 2 {
        return None;
    }
    let mut out = [0u8; N];
    for (slot, pair) in out.iter_mut().zip(bytes.as_chunks::<2>().0) {
        *slot = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(out)
}

/// SHA-256 of `data` as lowercase hex.
pub(crate) fn sha256(data: &[u8]) -> String {
    encode(Sha256::digest(data).as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_known_values() {
        assert_eq!(encode(&[]), "");
        assert_eq!(encode(&[0x00, 0xff, 0x0a]), "00ff0a");
    }

    #[test]
    fn decodes_what_it_encodes() {
        let bytes = [1u8, 2, 3, 250, 251, 252, 0, 15];
        assert_eq!(decode_array::<8>(&encode(&bytes)), Some(bytes));
    }

    #[test]
    fn decode_rejects_every_non_canonical_spelling() {
        assert_eq!(decode_array::<2>("00FF"), None, "uppercase");
        assert_eq!(decode_array::<2>("00f"), None, "too short");
        assert_eq!(decode_array::<2>("00ff0"), None, "too long");
        assert_eq!(decode_array::<2>("00fg"), None, "not hex");
        assert_eq!(decode_array::<2>("0x00"), None, "prefix");
        assert_eq!(decode_array::<2>(" 0ff "), None, "spaces");
        assert_eq!(decode_array::<2>("00f\u{e9}"), None, "non-ascii");
    }

    #[test]
    fn sha256_matches_the_published_test_vector() {
        // FIPS 180-4 / NIST example: SHA-256("abc").
        assert_eq!(
            sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            sha256(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
