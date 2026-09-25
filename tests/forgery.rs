//! Forgery-rejection battery (13 cases: 1 control + 12 forgeries).

use twotime::forgery;

#[test]
fn case_count_is_13() {
    assert_eq!(forgery::case_count(), 13);
    assert_eq!(forgery::battery().len(), 13);
}

#[test]
fn control_is_accepted() {
    let res = forgery::battery();
    let control = res.iter().find(|r| r.is_control).expect("one control case");
    assert!(control.accepted, "control must be accepted");
    assert!(control.ok);
}

#[test]
fn all_forgeries_rejected() {
    let res = forgery::battery();
    let forgeries: Vec<_> = res.iter().filter(|r| !r.is_control).collect();
    assert_eq!(forgeries.len(), 12);
    for f in &forgeries {
        assert!(!f.accepted, "forgery '{}' was accepted: {}", f.name, f.name);
        assert!(f.ok, "{}", f.name);
    }
}

#[test]
fn battery_inputs_match_rfc_2_8_2() {
    let in_ = forgery::inputs();
    assert_eq!(in_.const_part, [0x07, 0, 0, 0]);
    assert_eq!(in_.iv, [0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47]);
    assert_eq!(in_.pt.len(), 114);
    assert_eq!(in_.ct.len(), 114);
    // The control (ct, tag) is the §2.8.2 vector itself.
    let tag: [u8; 16] = hex("1a e1 0b 59 4f 09 e2 6a 7e 90 2e cb d0 60 06 91").try_into().unwrap();
    assert_eq!(in_.tag, tag);
    assert_eq!(in_.ct[..8], hex("d3 1a 8d 34 64 8e 60 db 7b 86 af bc 53 ef 7e c2")[..8]);
}

fn hex(s: &str) -> Vec<u8> {
    let t: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    (0..t.len()).step_by(2).map(|i| u8::from_str_radix(&t[i..i + 2], 16).unwrap()).collect()
}
