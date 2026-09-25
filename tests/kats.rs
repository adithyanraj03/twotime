//! KAT pinning: every published RFC 8439 vector, individually.

use twotime::kats;

#[test]
fn full_battery_all_pass() {
    let checks = kats::run_all();
    let bad: Vec<_> = checks.iter().filter(|c| !c.ok).collect();
    assert!(
        bad.is_empty(),
        "KAT failures: {:?}",
        bad.iter().map(|c| (c.name.clone(), c.detail.clone())).collect::<Vec<_>>()
    );
}

#[test]
fn check_count_is_43() {
    assert_eq!(kats::check_count(), 43);
}

#[test]
fn kat_quarter_round_passes() {
    assert!(kats::kat_quarter_round().ok);
}

#[test]
fn kat_quarter_round_state_passes() {
    assert!(kats::kat_quarter_round_state().ok);
}

#[test]
fn kat_block_function_passes() {
    assert!(kats::kat_block_function().ok);
}

#[test]
fn kat_sunscreen_passes() {
    let (ks, ct) = kats::kat_sunscreen();
    assert!(ks.ok, "keystream: {}", ks.detail);
    assert!(ct.ok, "ciphertext: {}", ct.detail);
}

#[test]
fn kat_poly1305_passes() {
    let checks = kats::kat_poly1305();
    assert_eq!(checks.len(), 5);
    assert!(checks.iter().all(|c| c.ok),
        "failures: {:?}",
        checks.iter().filter(|c| !c.ok).map(|c| c.detail.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn kat_poly1305_keygen_passes() {
    assert!(kats::kat_poly1305_keygen().ok);
}

#[test]
fn kat_aead_passes() {
    let (otk, rs, ct, tag, buf) = kats::kat_aead();
    for (name, c) in [("otk", &otk), ("r/s", &rs), ("ct", &ct), ("tag", &tag), ("buffer", &buf)] {
        assert!(c.ok, "{name}: {}", c.detail);
    }
}

#[test]
fn kat_aead_keystream_passes() {
    assert!(kats::kat_aead_keystream().ok);
}

#[test]
fn kat_a1_passes() {
    let checks = kats::kat_a1();
    assert_eq!(checks.len(), 5);
    assert!(checks.iter().all(|c| c.ok));
}

#[test]
fn kat_a2_passes() {
    let checks = kats::kat_a2();
    assert_eq!(checks.len(), 3);
    assert!(checks.iter().all(|c| c.ok));
}

#[test]
fn kat_a3_passes() {
    let checks = kats::kat_a3();
    assert_eq!(checks.len(), 11);
    assert!(checks.iter().all(|c| c.ok),
        "failures: {:?}",
        checks.iter().filter(|c| !c.ok).map(|c| c.detail.clone()).collect::<Vec<_>>()
    );
}

#[test]
fn kat_a4_passes() {
    let checks = kats::kat_a4();
    assert_eq!(checks.len(), 3);
    assert!(checks.iter().all(|c| c.ok));
}

#[test]
fn kat_a5_passes() {
    let (otk, buf, tag, pt) = kats::kat_a5();
    for (name, c) in [("otk", &otk), ("buffer", &buf), ("tag", &tag), ("plaintext", &pt)] {
        assert!(c.ok, "{name}: {}", c.detail);
    }
}
