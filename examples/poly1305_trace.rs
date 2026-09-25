//! Debug/research: trace the Poly1305 accumulator through the 130-bit field
//! for the RFC 8439 §2.5.2 message, and show the two-time pad in one shot.
//!
//! Run with: cargo run --release --example poly1305_trace

/// Parse a space-separated hex string into 32 bytes.
fn hex32(s: &str) -> [u8; 32] {
    let t: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    let v: Vec<u8> = (0..t.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&t[i..i + 2], 16).unwrap())
        .collect();
    v.try_into().unwrap()
}

fn main() {
    // --- 1. Poly1305 accumulator trace (RFC 8439 §2.5.2 key + msg) -----
    // The §2.5.2 example key/message; the trace must reproduce the RFC's
    // three published (unpadded, 33-digit) accumulators and the tag.
    let key = hex32("85 d6 be 78 57 55 6d 33 7f 44 52 fe 42 d5 06 a8 \
                    01 03 80 8a fb 0d b2 fd 4a bf f6 af 41 49 f5 1b");
    let msg = b"Cryptographic Forum Research Group";

    let (r, s) = twotime::poly::split_key(&key);
    println!("r = {}", twotime::crypto::to_hex(&r.lo().to_le_bytes()));
    println!("s = {}", twotime::crypto::to_hex(&s.to_le_bytes()));

    let trace = twotime::poly::acc_trace(&key, msg);
    for (i, acc) in trace.iter().enumerate() {
        let hex = if acc.hi() > 0 {
            format!("{:x}{:032x}", acc.hi(), acc.lo())
        } else {
            format!("{:x}", acc.lo())
        };
        println!("acc after block {} : {} (RFC-style, unpadded)", i + 1, hex);
    }
    let tag = twotime::poly::mac(&key, msg);
    println!("tag                : {}", twotime::crypto::to_hex(&tag));

    // The full 130-bit acc + s (what the RFC prints before serialization).
    let (sum_lo, carry) = trace[2].lo().overflowing_add(s);
    let sum_hi = trace[2].hi() + carry as u32;
    let sum = twotime::poly::F::from_parts(sum_lo, sum_hi);
    println!("acc + s (130-bit)  : {:x}{:032x}", sum.hi(), sum.lo());

    // --- 2. The two-time pad, one shot --------------------------------
    let tt = twotime::twotime::canonical();
    let (cancel_ok, n) = tt.keystream_cancellation();
    let recovered = tt.recover_p2_from_p1();
    println!();
    println!("two-time pad: C1^C2 == P1^P2 over {} bytes: {}", n, cancel_ok);
    println!(
        "P2 recovered byte-exact: {}",
        recovered == tt.p2[..recovered.len()]
    );

    // --- 3. One avalanche row each -------------------------------------
    let pt_ct = twotime::avalanche::plaintext_to_ciphertext();
    let pt_tag = twotime::avalanche::plaintext_to_tag();
    println!(
        "avalanche: pt bit 0 -> ct {} of {} bits; pt bit 0 -> tag {} of 128 bits",
        pt_ct.flipped_bits, pt_ct.total_bits, pt_tag.flipped_bits
    );
}
