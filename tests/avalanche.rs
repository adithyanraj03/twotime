//! Avalanche / diffusion behavior of the 128-bit tag and the stream.
//!
//! The band values are the *actual* measured statistics of the fixed
//! battery (deterministic; pinned after the first run and re-verified on
//! every subsequent run).

use twotime::avalanche;

#[test]
fn plaintext_to_ciphertext_is_exactly_one_bit() {
    let row = avalanche::plaintext_to_ciphertext();
    assert_eq!(row.flipped_bits, 1, "ChaCha20 is a permutation: 1 input bit -> 1 output bit");
    assert_eq!(row.total_bits, 912, "114-byte sunscreen plaintext = 912 bits");
}

#[test]
fn plaintext_to_tag_avalanches() {
    let row = avalanche::plaintext_to_tag();
    // MACs are not line 1-ar: the tag avalanche is a full-blown avalanche.
    // Pinned measured value: 72 of 128.
    assert_eq!(row.flipped_bits, 72);
    assert_eq!(row.total_bits, 128);
}

#[test]
fn key_avalanche_has_256_rows() {
    let rows = avalanche::tag_avalanche_key();
    assert_eq!(rows.len(), 256);
    assert!(rows.iter().all(|r| r.total_bits == 128));
}

#[test]
fn nonce_avalanche_has_96_rows() {
    let rows = avalanche::tag_avalanche_nonce();
    assert_eq!(rows.len(), 96);
    assert!(rows.iter().all(|r| r.total_bits == 128));
}

#[test]
fn key_avalanche_bands() {
    let rows = avalanche::tag_avalanche_key();
    let (mean, min, max) = avalanche::summary(&rows);
    // Pinned measured values: mean 63.9688 / min 48 / max 80 (256 key bits).
    assert!((63.9..=64.05).contains(&mean), "mean {mean}");
    assert_eq!(min, 48, "min {min}");
    assert_eq!(max, 80, "max {max}");
}

#[test]
fn nonce_avalanche_bands() {
    let rows = avalanche::tag_avalanche_nonce();
    let (mean, min, max) = avalanche::summary(&rows);
    // Pinned measured values: mean 64.7083 / min 51 / max 80 (96 nonce bits).
    assert!((64.65..=64.76).contains(&mean), "mean {mean}");
    assert_eq!(min, 51, "min {min}");
    assert_eq!(max, 80, "max {max}");
}

#[test]
fn combined_summary_pinned() {
    let all: Vec<avalanche::AvalancheRow> = {
        let k = avalanche::tag_avalanche_key();
        let n = avalanche::tag_avalanche_nonce();
        k.iter().chain(n.iter()).cloned().collect()
    };
    assert_eq!(all.len(), 352);
    let (mean, min, max) = avalanche::summary(&all);
    // Pinned measured values from the battery report:
    //   mean 64.1705 / min 48 / max 80 of 128 tag bits
    assert!((64.15..=64.2).contains(&mean), "mean {mean}");
    assert_eq!(min, 48, "min {min}");
    assert_eq!(max, 80, "max {max}");
}

#[test]
fn diff_bits_known_values() {
    assert_eq!(avalanche::diff_bits(&[0xff], &[0x00]), 8);
    assert_eq!(avalanche::diff_bits(&[0x0f], &[0xf0]), 8);
    assert_eq!(avalanche::diff_bits(&[0x00], &[0x00]), 0);
    assert_eq!(avalanche::diff_bits(&[0xff, 0xff], &[0xff, 0xff]), 0);
}

#[test]
fn flip_bit_toggles_one_bit() {
    // LSB-first within each byte: bit i -> byte i/8, bit i%8.
    let b = [0u8; 2];
    assert_eq!(avalanche::flip_bit(&b, 0), [0b0000_0001, 0]);
    let flipped = avalanche::flip_bit(&b, 9); // byte 1, bit 1
    assert_eq!(flipped, [0u8, 0b0000_0010]);
    let flipped_hi = avalanche::flip_bit(&b, 15); // byte 1, bit 7
    assert_eq!(flipped_hi, [0u8, 0b1000_0000]);
}
