//! The verification report — one pure function of the embedded
//! constants. Running it twice (in one process or across processes)
//! must yield byte-identical text: no clock, no environment, no RNG.

use crate::avalanche;
use crate::forgery;
use crate::kats;
use crate::twotime;

fn pad(s: &str, w: usize) -> String {
    if s.len() >= w {
        s.to_string()
    } else {
        format!("{s:width$}", width = w)
    }
}

fn bar(s: &mut String, title: &str) {
    s.push('\n');
    s.push_str(&"=".repeat(80));
    s.push('\n');
    s.push_str(title);
    s.push_str(&"=".repeat(80));
    s.push('\n');
}

/// Render the full verification report (byte-stable).
#[must_use]
pub fn render_report() -> String {
    let mut s = String::new();

    bar(&mut s, "TWOTIME VERIFICATION REPORT");
    s.push_str("ChaCha20-Poly1305 AEAD (RFC 8439), Rust std-only.\n");
    s.push_str(&format!("version    : twotime {}\n", crate::VERSION));
    s.push_str("core       : ChaCha20 20 rounds (RFC 8439 2.1-2.4), Poly1305 mod 2^130-5\n");
    s.push_str("               (2.5), AEAD_CHACHA20_POLY1305 (2.8); tag compare constant-time\n");
    s.push_str("multiply   : u128 schoolbook, 160-bit operand split (131-bit acc+block bound)\n");
    s.push_str("determinism: pure function of embedded RFC vectors (no clock, no env, no RNG)\n");
    s.push_str(&"=".repeat(80));
    s.push('\n');

    // --- Section 1: KAT battery ---------------------------------------
    let checks = kats::run_all();
    let pass = checks.iter().filter(|c| c.ok).count();
    let fail = checks.len() - pass;

    bar(&mut s, "SECTION 1 - RFC 8439 KAT BATTERY (all published vectors)");
    for (i, c) in checks.iter().enumerate() {
        let verdict = if c.ok { "PASS" } else { "FAIL" };
        s.push_str(&format!(
            "[{verdict:>4}] {:<42} {}\n",
            pad(&format!("#{} {}", i + 1, c.name), 42),
            c.detail
        ));
    }
    s.push_str(&format!(
        "\nKAT total: {} checks, {} pass, {} fail\n",
        checks.len(),
        pass,
        fail
    ));

    // --- Section 2: two-time pad --------------------------------------
    bar(&mut s, "SECTION 2 - TWO-TIME PAD ATTACK (byte-exact reproduction)");
    let tt = twotime::canonical();
    s.push_str(&format!(
        "p1 (known)   : {} bytes  \"{}\"\n",
        tt.p1.len(),
        String::from_utf8_lossy(&tt.p1[..tt.p1.len().min(60)])
    ));
    s.push_str(&format!(
        "p2 (target)  : {} bytes  \"{}\"\n",
        tt.p2.len(),
        String::from_utf8_lossy(&tt.p2[..tt.p2.len().min(60)])
    ));
    let (cancel_ok, cancel_n) = tt.keystream_cancellation();
    s.push_str(&format!(
        "C1^C2 == P1^P2 over {cancel_n} bytes: {} (keystream cancels)\n",
        if cancel_ok { "byte-exact" } else { "MISMATCH" }
    ));
    let recovered = tt.recover_p2_from_p1();
    let rec_ok = recovered == tt.p2[..recovered.len()];
    s.push_str(&format!(
        "full recovery P2 = P1^C1^C2: {} ({} bytes)\n",
        if rec_ok { "byte-exact match" } else { "MISMATCH" },
        recovered.len()
    ));
    let (prefix, m) = tt.recover_p2_prefix(16);
    let prefix_ok = prefix == tt.p2[..m];
    s.push_str(&format!(
        "crib (16-byte prefix of P1) -> P2 prefix: {} ({} bytes, {})\n",
        crate::crypto::to_hex(&prefix),
        m,
        if prefix_ok { "byte-exact" } else { "MISMATCH" }
    ));

    // --- Section 3: forgery battery ------------------------------------
    bar(&mut s, "SECTION 3 - FORGERY-REJECTION BATTERY");
    let results = forgery::battery();
    let ok_n = results.iter().filter(|r| r.ok).count();
    for r in &results {
        let verdict = if r.ok { "OK" } else { "BAD" };
        let decision = if r.accepted { "accepted" } else { "rejected" };
        let role = if r.is_control { "control " } else { "forgery " };
        s.push_str(&format!(
            "[{verdict:>3}] {role} {decision:<8} {}\n",
            r.name
        ));
    }
    s.push_str(&format!("\nForgery battery: {} cases, {} correct decisions\n", results.len(), ok_n));

    // --- Section 4: avalanche ------------------------------------------
    bar(&mut s, "SECTION 4 - AVALANCHE / DIFFUSION (128-bit tag)");
    let key_rows = avalanche::tag_avalanche_key();
    let nonce_rows = avalanche::tag_avalanche_nonce();
    let pt_ct = avalanche::plaintext_to_ciphertext();
    let pt_tag = avalanche::plaintext_to_tag();

    let all: Vec<avalanche::AvalancheRow> = key_rows
        .iter()
        .chain(nonce_rows.iter())
        .cloned()
        .collect();
    let (mean, min, max) = avalanche::summary(&all);
    s.push_str("352 one-bit flips of key (256) / nonce (96):\n");
    s.push_str(&format!(
        "  mean {mean:.2} / min {min} / max {max} of 128 tag bits\n\n"
    ));

    // compact table: 8 rows of 8 key bits each
    s.push_str("  key bit -> flipped tag bits (rows of 8):\n");
    for chunk in key_rows.chunks(8) {
        s.push_str("    ");
        for r in chunk {
            s.push_str(&format!("{:>3} ", r.flipped_bits));
        }
        s.push('\n');
    }
    s.push_str("  nonce bit -> flipped tag bits (rows of 8):\n");
    for chunk in nonce_rows.chunks(8) {
        s.push_str("    ");
        for r in chunk {
            s.push_str(&format!("{:>3} ", r.flipped_bits));
        }
        s.push('\n');
    }
    s.push_str(&format!(
        "\n  contrast  : plaintext bit 0 -> ciphertext: {} of {} bits (linearity = exactly 1)\n",
        pt_ct.flipped_bits, pt_ct.total_bits
    ));
    s.push_str(&format!(
        "              plaintext bit 0 -> tag        : {} of 128 bits (MAC avalanches)\n",
        pt_tag.flipped_bits
    ));

    // --- footer ----------------------------------------------------------
    s.push('\n');
    s.push_str(&"=".repeat(80));
    s.push_str("Determinism: this report is a pure function of the embedded RFC 8439\n");
    s.push_str("vectors. The attestation artifact (attestation.txt) proves it: the\n");
    s.push_str("report and PDF dossier are generated twice, SHA-256 hashed, and the\n");
    s.push_str("digests must match. (c) 2026 Adithya N Raj.\n");
    s.push_str(&"=".repeat(80));
    s.push('\n');

    s
}
