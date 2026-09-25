//! The two-time pad — reproduced byte-exact.
//!
//! A one-time pad is unbreakable; a pad used **twice** is not. If the
//! same (key, nonce) — hence the same ChaCha20 keystream `K` — encrypts
//! two plaintexts, the keystream cancels out of the XOR of the two
//! ciphertexts:
//!
//! ```text
//! C1 = P1 ⊕ K
//! C2 = P2 ⊕ K
//! ─────────────
//! C1 ⊕ C2 = P1 ⊕ P2        (K vanishes)
//! ```
//!
//! An attacker who knows one plaintext completely (a predictable
//! header, a protocol constant, a guessed template) recovers the other
//! **byte-exact**: `P2 = C1 ⊕ C2 ⊕ P1`. This module builds the
//! scenario deterministically and reproduces every step of the attack
//! as a KAT: the cancellation identity over the full ciphertext length,
//! full recovery, and prefix recovery from a crib.

use crate::chacha::encrypt;

/// Byte-wise XOR of the shorter-length overlap of two byte strings.
#[must_use]
pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    let n = a.len().min(b.len());
    (0..n).map(|i| a[i] ^ b[i]).collect()
}

/// A two-time-pad scenario: two plaintexts encrypted under one
/// (key, nonce) pair, i.e. one reused keystream.
#[derive(Debug, Clone)]
pub struct TwoTimePad {
    pub key: [u8; 32],
    pub nonce: [u8; 12],
    /// First plaintext (the one the attacker eventually knows).
    pub p1: Vec<u8>,
    /// Second plaintext (the target of the attack).
    pub p2: Vec<u8>,
    /// Ciphertext of `p1` under (key, nonce).
    pub c1: Vec<u8>,
    /// Ciphertext of `p2` under the *same* (key, nonce).
    pub c2: Vec<u8>,
}

impl TwoTimePad {
    /// Encrypt both plaintexts with one (key, nonce). Counter starts
    /// at 1 (the AEAD convention; block 0 would be the MAC key).
    #[must_use]
    pub fn new(key: [u8; 32], nonce: [u8; 12], p1: &[u8], p2: &[u8]) -> Self {
        let c1 = encrypt(&key, 1, &nonce, p1);
        let c2 = encrypt(&key, 1, &nonce, p2);
        Self {
            key,
            nonce,
            p1: p1.to_vec(),
            p2: p2.to_vec(),
            c1,
            c2,
        }
    }

    /// The cancellation identity: `C1 ⊕ C2 == P1 ⊕ P2` over the whole
    /// overlap. Returns (byte-exact?, bytes compared).
    #[must_use]
    pub fn keystream_cancellation(&self) -> (bool, usize) {
        let lhs = xor(&self.c1, &self.c2);
        let rhs = xor(&self.p1, &self.p2);
        (lhs == rhs, lhs.len())
    }

    /// Full attack: knowing `p1` completely, recover `p2` byte-exact:
    /// `P2 = P1 ⊕ C1 ⊕ C2`.
    #[must_use]
    pub fn recover_p2_from_p1(&self) -> Vec<u8> {
        xor(&self.p1, &xor(&self.c1, &self.c2))
    }

    /// Crib attack: a prefix of `p1` known to the attacker (length
    /// `crib_len`) yields the same prefix of `p2`, byte-exact.
    /// Returns (recovered prefix of `p2`, bytes recovered).
    #[must_use]
    pub fn recover_p2_prefix(&self, crib_len: usize) -> (Vec<u8>, usize) {
        let recovered = self.recover_p2_from_p1();
        let m = crib_len.min(recovered.len());
        (recovered[..m].to_vec(), m)
    }
}

/// The canonical scenario used by the report and the KATs.
///
/// `p1` is the RFC 8439 "sunscreen" plaintext (114 bytes); `p2` is a
/// second message of the same length. Key = 0x00..0x1f, nonce = the
/// RFC 8439 sunscreen nonce. All inputs are fixed constants, so the
/// entire scenario (ciphertexts, cancellation, recovery) is
/// byte-reproducible on every run.
#[must_use]
pub fn canonical() -> TwoTimePad {
    let key: [u8; 32] = crate::kats::KEY_SEQ;
    let nonce: [u8; 12] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
    ];
    let p1 = crate::kats::SUNSCREEN_PT.as_bytes();
    let p2 = b"The sun never sets on a one-time pad; the two-time pad is a different story. Reuse the key, and the keystream cancels, and both secrets walk out of the cipher in the clear.";
    TwoTimePad::new(key, nonce, p1, p2)
}
