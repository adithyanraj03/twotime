//! Poly1305 one-time authenticator (RFC 8439 §2.5).
//!
//! A 32-byte one-time key `(r, s)` and a message produce a 16-byte tag:
//! the message is processed in 16-byte blocks; each block (with a `0x01`
//! byte appended) is added to the accumulator and the sum multiplied by
//! the clamped `r`, all modulo the prime `P = 2^130 − 5`. The tag is
//! `(acc + s) mod 2^128`.
//!
//! ## Field element size
//!
//! `P = 2^130 − 5` is a 130-bit prime, so a field element `acc < P` can
//! use up to 130 bits — it does **not** fit in a `u128`. We therefore
//! represent a field element as a pair `(lo, hi)` meaning
//! `lo + hi·2^128`, with `lo < 2^128` and `hi < 4` (two spare bits),
//! guaranteeing the value `< 2^130`.
//!
//! ## Reduction
//!
//! The field uses the identity `2^130 ≡ 5 (mod P)`. A product of two
//! `< 2^130` operands is `< 2^261`; we multiply in 32-bit limbs and fold
//! twice: split `m = L + H·2^130`, replace with `L + 5H` (`< 2^134`),
//! split again, replace with `L2 + 5H2` (`< 2^130 + 40`), and do one
//! final conditional subtract of `P`. No big-number library, no
//! allocation, and no `u128` overflow anywhere.

/// The Poly1305 prime `P = 2^130 − 5`, as a field element:
/// `(2^128 − 5) + 3·2^128`. It does not fit in a `u128`.
pub const P: F = F { lo: u128::MAX - 4, hi: 3 };

/// A field element `< 2^130`, as `lo + hi·2^128` (`hi < 4`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct F {
    lo: u128,
    hi: u32,
}

/// Numeric ordering for field elements (compare `hi` first).
impl PartialOrd for F {
    fn partial_cmp(&self, o: &F) -> Option<core::cmp::Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for F {
    fn cmp(&self, o: &F) -> core::cmp::Ordering {
        self.hi.cmp(&o.hi).then_with(|| self.lo.cmp(&o.lo))
    }
}

impl F {
    /// Zero.
    pub const ZERO: F = F { lo: 0, hi: 0 };

    /// Build from a `< 2^128` value.
    #[inline]
    pub const fn from_low(x: u128) -> F {
        F { lo: x, hi: 0 }
    }

    #[inline]
    const fn from_le16(b: [u8; 16]) -> F {
        F { lo: u128::from_le_bytes(b), hi: 0 }
    }

    /// Low 128 bits.
    #[inline]
    pub const fn lo(self) -> u128 {
        self.lo
    }

    /// High 2 bits (value `>> 128`).
    #[inline]
    pub const fn hi(self) -> u32 {
        self.hi
    }

    /// Construct from explicit `(lo, hi)` parts (`hi < 4` expected).
    #[inline]
    pub const fn from_parts(lo: u128, hi: u32) -> F {
        F { lo, hi }
    }

    /// Parse a big-endian hex string (up to 33 digits, value `< 2^130`)
    /// into a field element. The low 32 digits fill `lo`; any leading
    /// digit fills `hi` (must be `< 4`).
    #[must_use]
    pub fn from_hex(s: &str) -> F {
        let s = s.trim();
        let n = s.len();
        let lo_len = 32.min(n);
        let lo = u128::from_str_radix(&s[n - lo_len..], 16).expect("hex lo");
        let hi = if n > lo_len {
            u32::from_str_radix(&s[..n - lo_len], 16).expect("hex hi")
        } else {
            0
        };
        debug_assert!(hi < 4, "field element must be < 2^130");
        F { lo, hi }
    }

    /// `(self + other) mod 2^130` (inputs `< 2^130`, sum `< 2^131`).
    #[inline]
    pub fn add(self, o: F) -> F {
        let s = self.lo.wrapping_add(o.lo);
        let carry = if s < self.lo { 1u32 } else { 0 };
        F { lo: s, hi: self.hi + o.hi + carry }
    }

    /// Five 32-bit limbs (little-endian) of this element:
    /// limbs 0-3 hold `lo`, limb 4 holds `hi` (bits 128..159).
    #[inline]
    fn limbs5(self) -> [u32; 5] {
        [
            self.lo as u32,
            (self.lo >> 32) as u32,
            (self.lo >> 64) as u32,
            (self.lo >> 96) as u32,
            self.hi as u32,
        ]
    }

    /// Multiply two field elements and reduce mod `P`.
    #[inline]
    fn mul(self, o: F) -> F {
        let al = self.limbs5();
        let bl = o.limbs5();
        // 5×5 schoolbook into u128 columns (column < 5·2^64 < 2^67).
        let mut p = [0u128; 9];
        for i in 0..5 {
            for j in 0..5 {
                p[i + j] += (al[i] as u128) * (bl[j] as u128);
            }
        }
        // Normalize to base 2^32 (product < 2^261 < 2^288, so no top carry).
        let mut m = [0u32; 9];
        let mut carry = 0u128;
        for i in 0..9 {
            let v = p[i] + carry;
            m[i] = (v & 0xFFFF_FFFF) as u32;
            carry = v >> 32;
        }
        debug_assert!(carry == 0, "product must fit in 288 bits");
        reduce_limb(m)
    }
}

/// Reduce a normalized 261-bit product (9 base-2^32 limbs) mod `P`,
/// using `2^130 ≡ 5`, in two folds.
#[inline]
fn reduce_limb(m: [u32; 9]) -> F {
    // Split m = L + H·2^130 (130 = 4·32 + 2, so the split straddles limbs).
    // L: low 130 bits  = m[0..3] (128 bits) + low 2 bits of m[4] at bit 128.
    let l0 = (m[0] as u128) | ((m[1] as u128) << 32) | ((m[2] as u128) << 64) | ((m[3] as u128) << 96);
    let l1 = (m[4] & 3) as u32;
    // H: m >> 130, in five 32-bit limbs (< 2^130).
    let h0 = (m[4] >> 2) | ((m[5] & 3) << 30);
    let h1 = (m[5] >> 2) | ((m[6] & 3) << 30);
    let h2 = (m[6] >> 2) | ((m[7] & 3) << 30);
    let h3 = (m[7] >> 2) | ((m[8] & 3) << 30);
    let h4 = m[8] >> 2;
    // H = H0 + H4·2^128.
    let h0v = (h0 as u128) | ((h1 as u128) << 32) | ((h2 as u128) << 64) | ((h3 as u128) << 96);
    let h4v = h4 as u32; // < 4
    // Fold 1: m ≡ L + 5H.
    // 5·H0 (H0 < 2^128) via 64-bit splitting -> (fiveH0_lo, fiveH0_hi).
    let a0l = h0v as u64;
    let a0h = (h0v >> 64) as u64;
    let t0 = 5u128 * (a0l as u128); // < 2^66
    let m0_lo = t0 as u64;
    let c0 = (t0 >> 64) as u64; // < 4
    let t1 = 5u128 * (a0h as u128) + c0 as u128; // < 2^66 + 4
    let m0_mid = t1 as u64;
    let m0_hi = (t1 >> 64) as u32; // < 4
    let five_h0_lo = (m0_lo as u128) | ((m0_mid as u128) << 64);
    let five_h_hi = m0_hi + 5u32 * h4v; // < 4 + 20
    // S1 = L + 5H  =  (l0 + five_h0_lo) + (l1 + five_h_hi)·2^128  (< 2^134).
    let s0 = l0.wrapping_add(five_h0_lo);
    let sc = if s0 < l0 { 1u32 } else { 0 };
    let s1 = l1 + five_h_hi + sc; // < 4 + 24 + 1 < 30
    // Fold 2: S1 = L2 + H2·2^130, L2 = s0 + (s1&3)·2^128, H2 = s1>>2 (< 8).
    let h2 = s1 >> 2;
    let add = 5u128 * h2 as u128; // < 40 < 2^128
    let mut r0 = s0.wrapping_add(add);
    let rc = if r0 < s0 { 1u32 } else { 0 };
    let mut r1 = (s1 & 3) + rc; // < 4
    // S2 = r0 + r1·2^128  <  2^130 + 40.  Final: subtract P if >= P.
    // P = 2^130 − 5 = (2^128 − 5) + 3·2^128  =>  P_lo = 2^128−5, P_hi = 3.
    let p_lo = u128::MAX - 4;
    let p_hi = 3u32;
    let ge = if r1 > p_hi {
        true
    } else if r1 < p_hi {
        false
    } else {
        r0 >= p_lo
    };
    if ge {
        let (n0, borrow) = if r0 >= p_lo {
            (r0 - p_lo, 0u32)
        } else {
            (r0.wrapping_sub(p_lo), 1u32)
        };
        r0 = n0;
        r1 = r1 - p_hi - borrow;
    }
    F { lo: r0, hi: r1 }
}

/// Clamp the first 16 key bytes into a valid `r`
/// (RFC 8439 §2.5: r[3],r[7],r[11],r[15] &= 15; r[4],r[8],r[12] &= 252).
/// Returns `(r, s)`: `r` as a field element, `s` as a `< 2^128` value.
#[must_use]
pub fn split_key(key: &[u8; 32]) -> (F, u128) {
    let mut r = [0u8; 16];
    r.copy_from_slice(&key[0..16]);
    r[3] &= 15;
    r[7] &= 15;
    r[11] &= 15;
    r[15] &= 15;
    r[4] &= 252;
    r[8] &= 252;
    r[12] &= 252;
    let s = u128::from_le_bytes(key[16..32].try_into().unwrap());
    (F::from_le16(r), s)
}

/// Parse a 1..=16-byte block of message into the block integer with
/// the `0x01` byte appended at position `len` (RFC 8439 §2.5). For a
/// full 16-byte block this is `2^128 + low` (129 bits), so the result
/// is a field element, not a `u128`.
#[inline]
fn block_value(block: &[u8]) -> F {
    debug_assert!((1..=16).contains(&block.len()));
    let mut lo = 0u128;
    for (i, &b) in block.iter().enumerate() {
        lo |= (b as u128) << (8 * i);
    }
    if block.len() == 16 {
        // 2^128 + lo  ->  hi = 1
        F { lo, hi: 1 }
    } else {
        lo |= 1u128 << (8 * block.len()); // < 2^128 (len <= 15)
        F { lo, hi: 0 }
    }
}

/// One accumulator step: `acc -> (acc + block) * r mod P`.
///
/// Exposed (and KAT'd) because RFC 8439 §2.5.2 publishes the
/// intermediate accumulator after every block.
#[must_use]
pub fn acc_step(acc: F, r: F, block: &[u8]) -> F {
    let b = block_value(block); // < 2^129
    acc.add(b).mul(r)
}

/// Poly1305 MAC over `msg` with the 32-byte one-time `key`
/// (RFC 8439 §2.5). Returns the 16-byte tag (little-endian `acc + s`).
#[must_use]
pub fn mac(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let (r, s) = split_key(key);
    let mut acc = F::ZERO;
    for block in msg.chunks(16) {
        acc = acc_step(acc, r, block);
    }
    let tag = acc.lo().wrapping_add(s);
    tag.to_le_bytes()
}

/// Poly1305 MAC with a pre-split `(r, s)` key pair — the entry point
/// for the RFC 8439 Appendix A.3 #5-#11 vectors, which hand over `r`
/// and `s` directly (each a 128-bit little-endian value). `r` must
/// already satisfy the clamping constraints (the published vectors do).
#[must_use]
pub fn mac_rs(r: u128, s: u128, msg: &[u8]) -> [u8; 16] {
    let rf = F::from_low(r);
    debug_assert!(rf <= P, "r must be clamped (< P)");
    let mut acc = F::ZERO;
    for block in msg.chunks(16) {
        acc = acc_step(acc, rf, block);
    }
    let tag = acc.lo().wrapping_add(s);
    tag.to_le_bytes()
}

/// The accumulator field element after each 16-byte block of `msg`,
/// KAT'd against the intermediate values published in RFC 8439 §2.5.2.
#[must_use]
pub fn acc_trace(key: &[u8; 32], msg: &[u8]) -> Vec<F> {
    let (r, _s) = split_key(key);
    let mut acc = F::ZERO;
    let mut trace = Vec::new();
    for block in msg.chunks(16) {
        acc = acc_step(acc, r, block);
        trace.push(acc);
    }
    trace
}

/// The low 128 bits of a field element — the value, when `hi == 0`
/// (i.e. the element is `< 2^128`). Use [`F::from_hex`] / comparison
/// for full 130-bit values.
#[must_use]
pub fn f_value(f: F) -> u128 {
    debug_assert!(f.hi() == 0, "f_value is only exact when hi == 0");
    f.lo()
}

/// Generate the one-time Poly1305 key from (ChaCha20 key, 12-byte nonce)
/// (RFC 8439 §2.6): block 0 of ChaCha20, first 32 bytes.
#[must_use]
pub fn key_gen(key: &[u8; 32], nonce: &[u8; 12]) -> [u8; 32] {
    let block = crate::chacha::chacha20_block(key, 0, nonce);
    let mut k = [0u8; 32];
    k.copy_from_slice(&block[..32]);
    k
}
