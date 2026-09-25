//! AEAD_CHACHA20_POLY1305 (RFC 8439 §2.8).
//!
//! The 96-bit nonce is `constant | iv` — a 4-byte protocol constant
//! (sender id) followed by an 8-byte IV. The one-time Poly1305 key is
//! ChaCha20 block 0 of `(key, nonce)`; the ciphertext is ChaCha20
//! starting at block 1; the tag authenticates
//!
//! ```text
//! aad ‖ pad16(aad) ‖ ciphertext ‖ pad16(ciphertext)
//! ‖ u64le(len(aad)) ‖ u64le(len(ciphertext))
//! ```
//!
//! Decryption recomputes the tag and compares it to the received tag
//! in constant time (xor-accumulate, single branch) before releasing
//! any plaintext.

use crate::chacha::encrypt as chacha_encrypt;
use crate::poly::{key_gen, mac};

/// 96-bit nonce: `constant` (4) ‖ `iv` (8).
#[must_use]
pub fn make_nonce(constant: &[u8; 4], iv: &[u8; 8]) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(constant);
    n[4..].copy_from_slice(iv);
    n
}

/// `pad16(x)` from RFC 8439 §2.8.1: the zero bytes needed to round `x`
/// up to a multiple of 16 (empty when `x` is already aligned).
fn pad16(len: usize) -> usize {
    (16 - (len % 16)) % 16
}

/// Build the Poly1305 message: padded AAD ‖ padded ciphertext ‖ the
/// two 8-byte little-endian lengths (RFC 8439 §2.8.1).
#[must_use]
pub fn mac_buffer(aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(
        aad.len() + pad16(aad.len()) + ciphertext.len() + pad16(ciphertext.len()) + 16,
    );
    v.extend_from_slice(aad);
    v.extend(std::iter::repeat(0u8).take(pad16(aad.len())));
    v.extend_from_slice(ciphertext);
    v.extend(std::iter::repeat(0u8).take(pad16(ciphertext.len())));
    v.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    v.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    v
}

/// The one-time key used by both `encrypt` and `decrypt` (block 0).
#[must_use]
pub fn otk(key: &[u8; 32], constant: &[u8; 4], iv: &[u8; 8]) -> [u8; 32] {
    key_gen(key, &make_nonce(constant, iv))
}

/// AEAD encryption (RFC 8439 §2.8.1). Returns (ciphertext, 16-byte tag).
#[must_use]
pub fn encrypt(
    key: &[u8; 32],
    constant: &[u8; 4],
    iv: &[u8; 8],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let nonce = make_nonce(constant, iv);
    let k = otk(key, constant, iv);
    let ct = chacha_encrypt(key, 1, &nonce, plaintext);
    let tag = mac(&k, &mac_buffer(aad, &ct));
    (ct, tag)
}

/// Constant-time 16-byte tag comparison (xor-accumulate; the final
/// branch depends on the whole tag, not on a first mismatch position).
fn ct_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// AEAD decryption (RFC 8439 §2.8.1). Recomputes the tag and returns
/// `None` on any mismatch — no plaintext is produced when the tag does
/// not validate.
pub fn decrypt(
    key: &[u8; 32],
    constant: &[u8; 4],
    iv: &[u8; 8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: [u8; 16],
) -> Option<Vec<u8>> {
    let nonce = make_nonce(constant, iv);
    let k = otk(key, constant, iv);
    let expect = mac(&k, &mac_buffer(aad, ciphertext));
    if !ct_eq(&expect, &tag) {
        return None;
    }
    Some(chacha_encrypt(key, 1, &nonce, ciphertext))
}
