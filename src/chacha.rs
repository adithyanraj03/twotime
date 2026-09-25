//! ChaCha20 stream cipher (RFC 8439 §2).
//!
//! * [`quarter_round`] — the single add/XOR/rotate operation on four
//!   32-bit words (RFC 8439 §2.1).
//! * [`chacha20_block`] — the 64-byte block function: constants | key |
//!   counter | nonce, 20 rounds, add the original state (RFC 8439 §2.3).
//! * [`encrypt`] / [`keystream`] — the stream cipher (RFC 8439 §2.4).
//!
//! All arithmetic is carryless modulo 2^32 (`wrapping_add`); rolls are
//! `rotate_left`. Everything is `std`-only and deterministic.

/// The four ChaCha20 constants, "expand 32-byte key" in little-endian
/// words (RFC 8439 §2.3).
pub const SIGMA: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

/// One quarter round (RFC 8439 §2.1):
///
/// ```text
/// a += b;  d ^= a;  d <<<= 16;
/// c += d;  b ^= c;  b <<<= 12;
/// a += b;  d ^= a;  d <<<=  8;
/// c += d;  b ^= c;  b <<<=  7;
/// ```
#[must_use]
pub fn quarter_round(a: u32, b: u32, c: u32, d: u32) -> [u32; 4] {
    let mut a = a;
    let mut b = b;
    let mut c = c;
    let mut d = d;
    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(16);
    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(12);
    a = a.wrapping_add(b);
    d ^= a;
    d = d.rotate_left(8);
    c = c.wrapping_add(d);
    b ^= c;
    b = b.rotate_left(7);
    [a, b, c, d]
}

/// The 16-word state.
pub type State = [u32; 16];

/// Initialize the state from (key, counter, nonce) (RFC 8439 §2.3).
///
/// `nonce` is the full 12-byte (96-bit) nonce; word 12 is the block
/// counter, words 13-15 are the nonce read as little-endian u32s.
fn init_state(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> State {
    let u32le = |b: &[u8]| -> u32 {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    };
    let mut s = State::default();
    s[0..4].copy_from_slice(&SIGMA);
    s[4] = u32le(&key[0..4]);
    s[5] = u32le(&key[4..8]);
    s[6] = u32le(&key[8..12]);
    s[7] = u32le(&key[12..16]);
    s[8] = u32le(&key[16..20]);
    s[9] = u32le(&key[20..24]);
    s[10] = u32le(&key[24..28]);
    s[11] = u32le(&key[28..32]);
    s[12] = counter;
    s[13] = u32le(&nonce[0..4]);
    s[14] = u32le(&nonce[4..8]);
    s[15] = u32le(&nonce[8..12]);
    s
}

/// One column + one diagonal round (RFC 8439 §2.3).
fn inner_block(s: &mut State) {
    macro_rules! qr {
        ($a:expr, $b:expr, $c:expr, $d:expr) => {
            let [x, y, z, w] = quarter_round(s[$a], s[$b], s[$c], s[$d]);
            s[$a] = x;
            s[$b] = y;
            s[$c] = z;
            s[$d] = w;
        };
    }
    // column round
    qr!(0, 4, 8, 12);
    qr!(1, 5, 9, 13);
    qr!(2, 6, 10, 14);
    qr!(3, 7, 11, 15);
    // diagonal round
    qr!(0, 5, 10, 15);
    qr!(1, 6, 11, 12);
    qr!(2, 7, 8, 13);
    qr!(3, 4, 9, 14);
}

/// The ChaCha20 block function (RFC 8439 §2.3): 20 rounds (10
/// column/diagonal pairs), then add the original state, serialized
/// little-endian. Returns the 64-byte block.
///
/// The caller may pass the *full* 12-byte nonce; the block counter is
/// separate (it is word 12 of the state, not part of the 96-bit nonce).
#[must_use]
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let original = init_state(key, counter, nonce);
    let mut s = original;
    for _ in 0..10 {
        inner_block(&mut s);
    }
    for i in 0..16 {
        s[i] = s[i].wrapping_add(original[i]);
    }
    let mut out = [0u8; 64];
    for (i, w) in s.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

/// Generate `n` keystream bytes starting at block `counter`
/// (RFC 8439 §2.4).
pub fn keystream(key: &[u8; 32], counter: u32, nonce: &[u8; 12], n: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n);
    let mut c = counter;
    while out.len() < n {
        let block = chacha20_block(key, c, nonce);
        let take = (64usize).min(n - out.len());
        out.extend_from_slice(&block[..take]);
        c = c.wrapping_add(1);
    }
    out
}

/// Encrypt (or decrypt — ChaCha20 is an involution) `data` with the
/// keystream starting at block `counter` (RFC 8439 §2.4).
#[must_use]
pub fn encrypt(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &[u8]) -> Vec<u8> {
    let ks = keystream(key, counter, nonce, data.len());
    data.iter().zip(ks).map(|(p, k)| p ^ k).collect()
}

/// Apply a quarter round in place on a whole 16-word state at the given
/// indices (RFC 8439 §2.2). Exposed so the §2.2.1 KAT can be checked.
pub fn quarter_round_state(s: &mut State, x: usize, y: usize, z: usize, w: usize) {
    let [a, b, c, d] = quarter_round(s[x], s[y], s[z], s[w]);
    s[x] = a;
    s[y] = b;
    s[z] = c;
    s[w] = d;
}
