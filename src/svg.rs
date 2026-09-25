//! The SMIL animation: the two-time-pad attack in six frames.
//!
//! Frame story:
//!   0. setup    — two plaintexts, one (key, nonce)
//!   1. C1       — P1 ⊕ K
//!   2. C2       — P2 ⊕ K   (the *same* K)
//!   3. cancel   — C1 ⊕ C2: the keystream vanishes
//!   4. exposed  — P1 ⊕ P2 in the clear; attacker knows P1
//!   5. recovered— P2 = P1 ⊕ C1 ⊕ C2, byte-exact
//!
//! The animation is pure SMIL (discrete opacity switching, looping)
//! and every byte shown is computed from the fixed canonical scenario,
//! so the file is reproducible. The contact sheet renders the same
//! frames as a static grid.

use std::fmt::Write;

use crate::twotime;

const W: f64 = 760.0;
const H: f64 = 320.0;
const OX: f64 = 24.0;
const OY: f64 = 40.0;

const PAPER: &str = "#F7F6F1";
const INK: &str = "#252524";
const MUTED: &str = "#676662";
const HAIR: &str = "#DCDAD1";
const GREEN: &str = "#22AC80";
const INDIGO: &str = "#5B51C7";
const BRICK: &str = "#A74221";
const ORANGE: &str = "#E8833A";

/// Short hex of the first `n` bytes.
fn hex8(b: &[u8], n: usize) -> String {
    let m = n.min(b.len());
    crate::crypto::to_hex(&b[..m])
}

fn row(s: &mut String, y: f64, text: &str, color: &str, size: f64) {
    let _ = write!(
        s,
        "<text x=\"{OX:.0}\" y=\"{y:.0}\" font-family=\"Courier,monospace\" font-size=\"{size:.0}\" fill=\"{color}\">{text}</text>"
    );
}

/// One frame of the animation. All byte values are computed from the
/// canonical scenario (deterministic).
fn frame(i: usize, tt: &twotime::TwoTimePad) -> String {
    let k8 = hex8(&twotime::xor(&tt.c1, &tt.p1), 8);
    let c1_8 = hex8(&tt.c1, 8);
    let c2_8 = hex8(&tt.c2, 8);
    let p1_8 = hex8(&tt.p1, 8);
    let p2_8 = hex8(&tt.p2, 8);
    let d8 = hex8(&twotime::xor(&tt.c1, &tt.c2), 8);
    let mut s = String::new();
    let _ = write!(s, "<rect x=\"0\" y=\"0\" width=\"{W:.0}\" height=\"{H:.0}\" fill=\"{PAPER}\"/>");
    let _ = write!(
        s,
        "<text x=\"{OX:.0}\" y=\"22\" font-family=\"Courier,monospace\" font-size=\"13\" fill=\"{INK}\" font-weight=\"bold\">two-time pad — frame {i}/5: {}",
        match i {
            0 => "setup: one (key, nonce) for two messages",
            1 => "C1 = P1 XOR K",
            2 => "C2 = P2 XOR K  (K is reused)",
            3 => "C1 XOR C2: the keystream cancels",
            4 => "P1 XOR P2 is exposed; P1 is known",
            5 => "P2 = P1 XOR C1 XOR C2 — recovered",
            _ => "out of range",
        }
    );
    let _ = write!(
        s,
        "<line x1=\"{OX:.0}\" y1=\"30\" x2=\"{:.0}\" y2=\"30\" stroke=\"{HAIR}\" stroke-width=\"1\"/>",
        W - OX
    );

    let y = OY;
    match i {
        0 => {
            row(&mut s, y, &format!("P1 ({} B)  \"Ladies and Gentlemen of the class of '99: ...\"", tt.p1.len()), INK, 12.0);
            row(&mut s, y + 22.0, &format!("P2 ({} B)  \"The sun never sets on a one-time pad; ...\"", tt.p2.len()), INK, 12.0);
            row(&mut s, y + 44.0, "key   = 00 01 02 ... 1e 1f   (one 32-byte key)", MUTED, 12.0);
            row(&mut s, y + 66.0, "nonce = 00 00 00 00 00 00 00 4a 00 00 00 00   (one 12-byte nonce)", MUTED, 12.0);
            row(&mut s, y + 96.0, "ONE keystream K is derived from (key, nonce) — and reused for both.", BRICK, 12.0);
        }
        1 => {
            row(&mut s, y, &format!("K      = {k8} ...  ({n} B keystream)", n = tt.p1.len()), INDIGO, 12.0);
            row(&mut s, y + 22.0, &format!("P1     = {p1_8} ..."), INK, 12.0);
            row(&mut s, y + 44.0, &format!("C1 = P1 XOR K = {c1_8} ...  ({n} B ciphertext)", n = tt.c1.len()), GREEN, 12.0);
            row(&mut s, y + 76.0, "attacker sees C1, but without K or P1 nothing is known.", MUTED, 12.0);
        }
        2 => {
            row(&mut s, y, &format!("K      = {k8} ...  (SAME keystream)"), INDIGO, 12.0);
            row(&mut s, y + 22.0, &format!("P2     = {p2_8} ..."), INK, 12.0);
            row(&mut s, y + 44.0, &format!("C2 = P2 XOR K = {c2_8} ...  ({n} B ciphertext)", n = tt.c2.len()), GREEN, 12.0);
            row(&mut s, y + 76.0, "the pad is now used TWICE — the one-time pad is broken.", BRICK, 12.0);
        }
        3 => {
            row(&mut s, y, "C1 XOR K = P1", INK, 12.0);
            row(&mut s, y + 22.0, "C2 XOR K = P2", INK, 12.0);
            row(&mut s, y + 44.0, "─────────────────────────────", HAIR, 12.0);
            row(&mut s, y + 66.0, "C1 XOR C2 = P1 XOR P2     (K XOR K = 0 — it vanishes)", ORANGE, 13.0);
            row(&mut s, y + 96.0, "no key material is involved in the subtraction.", MUTED, 12.0);
        }
        4 => {
            row(&mut s, y, &format!("D = C1 XOR C2 = {d8} ...  (byte-exact)"), ORANGE, 12.0);
            row(&mut s, y + 22.0, "D = P1 XOR P2", INK, 12.0);
            row(&mut s, y + 44.0, "attacker knows P1 (predictable header / template / crib)", MUTED, 12.0);
            row(&mut s, y + 66.0, "P2 = D XOR P1", GREEN, 13.0);
        }
        5 => {
            let recovered = tt.recover_p2_from_p1();
            row(&mut s, y, &format!("P2[0..16] = {} ...", hex8(&recovered, 16)), GREEN, 13.0);
            row(&mut s, y + 44.0, "matches the real P2 byte-for-byte over the full overlap.", INK, 12.0);
            row(&mut s, y + 76.0, "two pads, one keystream: both secrets walk out in the clear.", BRICK, 12.0);
        }
        _ => {}
    }

    // footer
    let _ = write!(
        s,
        "<text x=\"{OX:.0}\" y=\"{:.0}\" font-family=\"Courier,monospace\" font-size=\"9\" fill=\"{MUTED}\">twotime — ChaCha20-Poly1305 (RFC 8439), std-only  (c) 2026 Adithya N Raj</text>",
        H - 12.0
    );
    s
}

/// The SMIL animation (loops; each frame is visible for 0.9 s).
#[must_use]
pub fn render_anim(frames: usize) -> String {
    let tt = twotime::canonical();
    let n = frames.min(6);
    let total = n as f64 * 0.9;
    let mut s = String::new();
    let _ = write!(
        s,
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{W:.0}\" height=\"{H:.0}\" viewBox=\"0 0 {W:.0} {H:.0}\">"
    );
    for i in 0..n {
        let ks = i as f64 / n as f64;
        let ke = (i + 1) as f64 / n as f64;
        let _ = write!(
            s,
            "<g opacity=\"0\"><animate attributeName=\"opacity\" calcMode=\"discrete\" values=\"0;1;0\" keyTimes=\"0;{ks:.9};{ke:.9}\" dur=\"{total:.6}s\" repeatCount=\"indefinite\"/>"
        );
        let _ = write!(s, "{}", frame(i, &tt));
        s.push_str("</g>");
    }
    s.push_str("</svg>");
    s
}

/// The static contact sheet: `cols x rows` grid of the six frames.
#[must_use]
pub fn render_contact_sheet(cols: usize) -> String {
    let tt = twotime::canonical();
    let n = 6usize;
    let cols = cols.max(1);
    let rows = (n + cols - 1) / cols;
    let gap: f64 = 10.0;
    let title_h: f64 = 26.0;
    let width = 12.0 + cols as f64 * W + (cols - 1) as f64 * gap;
    let height = title_h + rows as f64 * H + (rows - 1) as f64 * gap + 12.0;
    let mut s = String::new();
    let _ = write!(
        s,
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width:.0}\" height=\"{height:.0}\" viewBox=\"0 0 {width:.0} {height:.0}\">"
    );
    let _ = write!(
        s,
        "<rect x=\"0\" y=\"0\" width=\"{width:.0}\" height=\"{height:.0}\" fill=\"{PAPER}\"/>"
    );
    let _ = write!(
        s,
        "<text x=\"12\" y=\"18\" font-family=\"Courier,monospace\" font-size=\"14\" fill=\"{INK}\" font-weight=\"bold\">two-time pad attack — contact sheet (6 frames)</text>"
    );
    for i in 0..n {
        let cx = 12.0 + (i % cols) as f64 * (W + gap);
        let cy = title_h + (i / cols) as f64 * (H + gap);
        let _ = write!(
            s,
            "<g transform=\"translate({cx:.0},{cy:.0})\"><rect x=\"0\" y=\"0\" width=\"{W:.0}\" height=\"{H:.0}\" fill=\"none\" stroke=\"{HAIR}\" stroke-width=\"1\"/>"
        );
        let body = frame(i, &tt);
        // the frame's own background rect is at 0,0; wrap in the translate
        let _ = write!(s, "{body}");
        s.push_str("</g>");
    }
    let _ = write!(
        s,
        "<text x=\"12\" y=\"{:.0}\" font-family=\"Courier,monospace\" font-size=\"9\" fill=\"{MUTED}\">twotime — deterministic reproduction  (c) 2026 Adithya N Raj</text>",
        height - 8.0
    );
    s.push_str("</svg>");
    s
}
