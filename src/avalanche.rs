//! Avalanche / diffusion measurements.
//!
//! For a one-bit input flip we count how many output bits change. A
//! good cipher scatters that flip so the count sits near half the
//! output length (64 of 128 tag bits) with no catastrophic bias.
//! Because the inputs are fixed constants, every number in this
//! module is reproducible byte-for-byte on every run.
//!
//! Three contrasts are measured:
//!
//! * **key bit -> tag** (256 rows): one keystream and one MAC key
//!   change at once; the 128-bit tag must avalanche.
//! * **nonce bit -> tag** (96 rows): nonce selects both the MAC key
//!   (block 0) and the encryption stream (blocks 1..); the 128-bit
//!   tag must avalanche.
//! * **plaintext bit -> ciphertext** (1 row): a stream cipher is
//!   *linear* in the plaintext — exactly one ciphertext bit flips.
//! * **plaintext bit -> tag** (1 row): the MAC sees a different
//!   ciphertext, so the tag avalanches anyway.
//!
//! The stream-cipher linearity (exactly 1 bit) versus the MAC
//! avalanche (~64 bits) is the central design contrast: ChaCha20
//! alone gives no integrity at all; Poly1305 over the ciphertext
//! buys it back.

use crate::aead;
use crate::kats::{KEY_80_9F, SUNSCREEN_PT};

/// One avalanche row: `bit` is the input bit flipped, `flipped_bits`
/// the count of changed output bits out of `total_bits`.
#[derive(Debug, Clone)]
pub struct AvalancheRow {
    pub label: String,
    pub bit: usize,
    pub flipped_bits: usize,
    pub total_bits: usize,
}

/// Count the differing bits between two equal-length byte strings.
#[must_use]
pub fn diff_bits(a: &[u8], b: &[u8]) -> usize {
    a.iter()
        .zip(b)
        .map(|(x, y)| (x ^ y).count_ones() as usize)
        .sum()
}

/// Flip bit `bit` (LSB-first within each byte, RFC 8439 §2.8.2 layout)
/// of `bytes`.
#[must_use]
pub fn flip_bit(bytes: &[u8], bit: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[bit / 8] ^= 1 << (bit % 8);
    out
}

/// The fixed battery inputs (RFC 8439 §2.8.2).
fn base() -> ([u8; 4], [u8; 8], Vec<u8>) {
    let const_part: [u8; 4] = [0x07, 0, 0, 0];
    let iv: [u8; 8] = [0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47];
    let aad = [0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7].to_vec();
    (const_part, iv, aad)
}

/// Baseline tag for the fixed message.
fn base_tag() -> ([u8; 4], [u8; 8], Vec<u8>, [u8; 16], Vec<u8>) {
    let (const_part, iv, aad) = base();
    let pt = SUNSCREEN_PT.as_bytes();
    let (ct, tag) = aead::encrypt(&KEY_80_9F, &const_part, &iv, &aad, pt);
    (const_part, iv, aad, tag, ct)
}

/// Flip each of the 256 key bits; count tag bits changed.
#[must_use]
pub fn tag_avalanche_key() -> Vec<AvalancheRow> {
    let (const_part, iv, aad, base, _ct) = base_tag();
    let pt = SUNSCREEN_PT.as_bytes();
    (0..256)
        .map(|bit| {
            let key: Vec<u8> = flip_bit(&KEY_80_9F, bit);
            let key: [u8; 32] = key.try_into().expect("32 bytes");
            let (_ct, tag) = aead::encrypt(&key, &const_part, &iv, &aad, pt);
            let flipped = diff_bits(&base, &tag);
            AvalancheRow {
                label: "key bit".into(),
                bit,
                flipped_bits: flipped,
                total_bits: 128,
            }
        })
        .collect()
}

/// Flip each of the 96 nonce bits; count tag bits changed.
#[must_use]
pub fn tag_avalanche_nonce() -> Vec<AvalancheRow> {
    let (const_part, iv, aad, base, _ct) = base_tag();
    let pt = SUNSCREEN_PT.as_bytes();
    (0..96)
        .map(|bit| {
            let nonce12: Vec<u8> = const_part.iter().chain(iv.iter()).copied().collect();
            let nonce = flip_bit(&nonce12, bit);
            let const_m: [u8; 4] = nonce[..4].try_into().expect("4 bytes");
            let iv_m: [u8; 8] = nonce[4..12].try_into().expect("8 bytes");
            let (_ct, tag) = aead::encrypt(&KEY_80_9F, &const_m, &iv_m, &aad, pt);
            let flipped = diff_bits(&base, &tag);
            AvalancheRow {
                label: "nonce bit".into(),
                bit,
                flipped_bits: flipped,
                total_bits: 128,
            }
        })
        .collect()
}

/// Flip plaintext bit 0; count ciphertext bits changed. Must be
/// exactly 1 (stream-cipher linearity).
#[must_use]
pub fn plaintext_to_ciphertext() -> AvalancheRow {
    let (const_part, iv, aad, _base, base_ct) = base_tag();
    let pt = SUNSCREEN_PT.as_bytes();
    let pt_m = flip_bit(pt, 0);
    let (ct_m, _tag) = aead::encrypt(&KEY_80_9F, &const_part, &iv, &aad, &pt_m);
    AvalancheRow {
        label: "plaintext bit -> ciphertext".into(),
        bit: 0,
        flipped_bits: diff_bits(&base_ct, &ct_m),
        total_bits: pt.len() * 8,
    }
}

/// Flip plaintext bit 0; count tag bits changed. Must avalanche
/// (Poly1305 over the changed ciphertext).
#[must_use]
pub fn plaintext_to_tag() -> AvalancheRow {
    let (const_part, iv, aad, base, _ct) = base_tag();
    let pt = SUNSCREEN_PT.as_bytes();
    let pt_m = flip_bit(pt, 0);
    let (_ct, tag) = aead::encrypt(&KEY_80_9F, &const_part, &iv, &aad, &pt_m);
    AvalancheRow {
        label: "plaintext bit -> tag".into(),
        bit: 0,
        flipped_bits: diff_bits(&base, &tag),
        total_bits: 128,
    }
}

/// (mean, min, max) over a set of rows, in bits.
#[must_use]
pub fn summary(rows: &[AvalancheRow]) -> (f64, usize, usize) {
    let mut min = usize::MAX;
    let mut max = 0usize;
    let mut sum = 0usize;
    for r in rows {
        min = min.min(r.flipped_bits);
        max = max.max(r.flipped_bits);
        sum += r.flipped_bits;
    }
    (sum as f64 / rows.len() as f64, min, max)
}
