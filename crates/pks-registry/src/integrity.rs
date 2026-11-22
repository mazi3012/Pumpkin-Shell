//! Checksums published by the registries (PRD FR-REG: "Tarballs/wheels
//! verified against dist.integrity / sha256 before serving").
//!
//! npm gives `dist.integrity` (a Subresource Integrity string, such as
//! `sha512-<base64>`) and, for old packages, only `dist.shasum` (SHA-1 in
//! hex). PyPI gives a SHA-256 in hex for every file. The check compares the
//! digest of the bytes served with what the registry published. It is a
//! check that the download is the file the index describes, so SHA-1 is
//! accepted when nothing stronger is published.

use serde_json::Value;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

/// Hash functions that can be checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// A checksum the registry published.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected {
    algorithm: Algorithm,
    /// Standard base64 with padding (Subresource Integrity), or lowercase hex.
    value: String,
    base64: bool,
}

impl Expected {
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }
}

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const HEX: &[u8; 16] = b"0123456789abcdef";

fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for shift in [18u32, 12, 6, 0] {
            out.push(char::from(BASE64[((n >> shift) & 63) as usize]));
        }
        if chunk.len() < 3 {
            let keep = out.len() - (3 - chunk.len());
            out.truncate(keep);
            out.push_str(&"=".repeat(3 - chunk.len()));
        }
    }
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 15)]));
    }
    out
}

fn is_base64_text(text: &str) -> bool {
    !text.is_empty()
        && text.len().is_multiple_of(4)
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
}

fn is_hex_text(text: &str, length: usize) -> bool {
    text.len() == length && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Reads a Subresource Integrity value, which may hold several tokens
/// separated by spaces. The strongest supported algorithm wins
/// (`sha512`, then `sha256`, then `sha1`). `None` when no token can be used.
#[must_use]
pub fn from_sri(text: &str) -> Option<Expected> {
    let mut best: Option<Expected> = None;
    for token in text.split_whitespace() {
        // A token may end in `?options`, which do not change the digest.
        let token = token.split('?').next().unwrap_or("");
        let Some((name, digest)) = token.split_once('-') else {
            continue;
        };
        let (algorithm, length) = match name {
            "sha512" => (Algorithm::Sha512, 88),
            "sha256" => (Algorithm::Sha256, 44),
            "sha1" => (Algorithm::Sha1, 28),
            _ => continue,
        };
        if digest.len() != length || !is_base64_text(digest) {
            continue;
        }
        let rank = |a: Algorithm| match a {
            Algorithm::Sha512 => 2,
            Algorithm::Sha256 => 1,
            Algorithm::Sha1 => 0,
        };
        if best
            .as_ref()
            .is_none_or(|b| rank(algorithm) > rank(b.algorithm))
        {
            best = Some(Expected {
                algorithm,
                value: digest.to_owned(),
                base64: true,
            });
        }
    }
    best
}

/// Reads an npm `shasum`: 40 hex digits of SHA-1.
#[must_use]
pub fn from_shasum(text: &str) -> Option<Expected> {
    is_hex_text(text, 40).then(|| Expected {
        algorithm: Algorithm::Sha1,
        value: text.to_ascii_lowercase(),
        base64: false,
    })
}

/// Reads a PyPI file hash: 64 hex digits of SHA-256.
#[must_use]
pub fn from_sha256_hex(text: &str) -> Option<Expected> {
    is_hex_text(text, 64).then(|| Expected {
        algorithm: Algorithm::Sha256,
        value: text.to_ascii_lowercase(),
        base64: false,
    })
}

/// The checksum an npm version's `dist` object publishes: `integrity` when it
/// has a usable one, otherwise `shasum`.
#[must_use]
pub fn from_npm_dist(dist: &Value) -> Option<Expected> {
    dist.get("integrity")
        .and_then(Value::as_str)
        .and_then(from_sri)
        .or_else(|| {
            dist.get("shasum")
                .and_then(Value::as_str)
                .and_then(from_shasum)
        })
}

enum State {
    Sha1(Sha1),
    Sha256(Sha256),
    Sha512(Sha512),
}

/// Hashes bytes as they stream past, then compares with what was published.
pub struct Verifier {
    expected: Expected,
    state: State,
}

impl Verifier {
    #[must_use]
    pub fn new(expected: &Expected) -> Self {
        let state = match expected.algorithm {
            Algorithm::Sha1 => State::Sha1(Sha1::new()),
            Algorithm::Sha256 => State::Sha256(Sha256::new()),
            Algorithm::Sha512 => State::Sha512(Sha512::new()),
        };
        Self {
            expected: expected.clone(),
            state,
        }
    }

    pub fn update(&mut self, bytes: &[u8]) {
        match &mut self.state {
            State::Sha1(h) => h.update(bytes),
            State::Sha256(h) => h.update(bytes),
            State::Sha512(h) => h.update(bytes),
        }
    }

    /// `true` when the digest of everything fed in equals the published one.
    #[must_use]
    pub fn finish(self) -> bool {
        let digest: Vec<u8> = match self.state {
            State::Sha1(h) => h.finalize().as_slice().to_vec(),
            State::Sha256(h) => h.finalize().as_slice().to_vec(),
            State::Sha512(h) => h.finalize().as_slice().to_vec(),
        };
        let text = if self.expected.base64 {
            base64_encode(&digest)
        } else {
            hex_encode(&digest)
        };
        text == self.expected.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Digests of the bytes "abc", made with Python's hashlib and base64.
    const SHA1_HEX: &str = "a9993e364706816aba3e25717850c26c9cd0d89d";
    const SHA256_HEX: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const SHA512_B64: &str =
        "3a81oZNherrMQXNJriBBMRLm+k6JqX6iCp7u5ktV05ohkpkqJ0/BqDa6PCOj/uu9RU1EI2Q86A4qmslPpUyknw==";
    const SHA256_B64: &str = "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=";
    const SHA1_B64: &str = "qZk+NkcGgWq6PiVxeFDCbJzQ2J0=";

    fn passes(expected: &Expected, data: &[u8]) -> bool {
        let mut v = Verifier::new(expected);
        v.update(data);
        v.finish()
    }

    #[test]
    fn base64_matches_the_rfc_4648_test_vectors() {
        for (input, want) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(input.as_bytes()), want, "{input:?}");
        }
    }

    #[test]
    fn hex_encoding_is_lowercase_and_two_digits_per_byte() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0x0a, 0xb1]), "00ff0ab1");
    }

    #[test]
    fn each_algorithm_accepts_the_right_bytes_and_refuses_others() {
        let sri512 = from_sri(&format!("sha512-{SHA512_B64}")).unwrap();
        let sri256 = from_sri(&format!("sha256-{SHA256_B64}")).unwrap();
        let sri1 = from_sri(&format!("sha1-{SHA1_B64}")).unwrap();
        let shasum = from_shasum(SHA1_HEX).unwrap();
        let hex256 = from_sha256_hex(SHA256_HEX).unwrap();
        for expected in [&sri512, &sri256, &sri1, &shasum, &hex256] {
            assert!(passes(expected, b"abc"), "{expected:?}");
            assert!(!passes(expected, b"abd"), "{expected:?}");
            assert!(!passes(expected, b""), "{expected:?}");
        }
    }

    #[test]
    fn streaming_in_pieces_gives_the_same_answer() {
        let expected = from_sri(&format!("sha512-{SHA512_B64}")).unwrap();
        let mut v = Verifier::new(&expected);
        v.update(b"a");
        v.update(b"");
        v.update(b"bc");
        assert!(v.finish());
    }

    #[test]
    fn the_strongest_token_is_the_one_checked() {
        let both = format!("sha1-{SHA1_B64} sha512-{SHA512_B64} sha256-{SHA256_B64}");
        let expected = from_sri(&both).unwrap();
        assert_eq!(expected.algorithm(), Algorithm::Sha512);
        let weaker = format!("sha1-{SHA1_B64} sha256-{SHA256_B64}");
        assert_eq!(from_sri(&weaker).unwrap().algorithm(), Algorithm::Sha256);
    }

    #[test]
    fn options_after_a_token_are_ignored() {
        let text = format!("sha512-{SHA512_B64}?ext=1");
        assert!(passes(&from_sri(&text).unwrap(), b"abc"));
    }

    #[test]
    fn unusable_values_give_no_checksum() {
        for bad in [
            "",
            "sha512",
            "sha512-",
            "md5-1B2M2Y8AsgTpgAmY7PhCfg==",
            "sha384-short",
            "sha512-tooshort",
            "sha256-!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
        ] {
            assert!(from_sri(bad).is_none(), "{bad:?}");
        }
        assert!(from_shasum("abc").is_none());
        assert!(from_shasum(&"g".repeat(40)).is_none());
        assert!(from_sha256_hex(&"a".repeat(63)).is_none());
    }

    #[test]
    fn upper_case_hex_is_accepted_and_compared_in_lower_case() {
        let expected = from_shasum(&SHA1_HEX.to_ascii_uppercase()).unwrap();
        assert!(passes(&expected, b"abc"));
    }

    #[test]
    fn an_npm_dist_prefers_integrity_and_falls_back_to_shasum() {
        let both = serde_json::json!({
            "integrity": format!("sha512-{SHA512_B64}"),
            "shasum": SHA1_HEX,
        });
        assert_eq!(from_npm_dist(&both).unwrap().algorithm(), Algorithm::Sha512);
        let old = serde_json::json!({ "shasum": SHA1_HEX });
        assert_eq!(from_npm_dist(&old).unwrap().algorithm(), Algorithm::Sha1);
        let broken_integrity = serde_json::json!({
            "integrity": "md5-nonsense",
            "shasum": SHA1_HEX,
        });
        assert_eq!(
            from_npm_dist(&broken_integrity).unwrap().algorithm(),
            Algorithm::Sha1
        );
        assert!(from_npm_dist(&serde_json::json!({})).is_none());
    }
}
