mod common;

use common::engine;
use proptest::prelude::*;

fn redacted_sample(e: &parda_engine::Engine) -> String {
    e.redact(
        "नमस्ते Ravi Kumar 🙏, mail ravi.k@gmail.com; Ravi Kumar again. RAVI and ravi.",
        "global",
    )
    .unwrap()
    .text
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn stream_restore_any_chunking(cuts in proptest::collection::vec(0usize..200, 0..20)) {
        let (_d, e) = engine();
        let red = redacted_sample(&e);
        let mut pts: Vec<usize> = cuts
            .into_iter()
            .map(|c| c.min(red.len()))
            .filter(|&c| red.is_char_boundary(c))
            .collect();
        pts.sort();
        pts.dedup();
        let mut sr = e.stream_restorer("global");
        let mut out = String::new();
        let mut prev = 0;
        for p in pts {
            out.push_str(&sr.push(&red[prev..p]));
            prev = p;
        }
        out.push_str(&sr.push(&red[prev..]));
        out.push_str(&sr.finish());
        prop_assert_eq!(out, e.restore(&red, "global"));
    }

    #[test]
    fn redact_restore_roundtrip(words in proptest::collection::vec(
        prop_oneof![
            Just("Ravi Kumar"), Just("ravi.k@gmail.com"), Just("+91 98765 43210"),
            Just("ABCPE1234F"), Just("hello"), Just("नमस्ते"), Just("🙏"), Just("the plan"),
            Just("Ravi"), Just("KUMAR"), Just("4111 1111 1111 1111"), Just("192.168.1.20"),
        ],
        0..12,
    )) {
        let (_d, e) = engine();
        let text = words.join(" ");
        let red = e.redact(&text, "global").unwrap();
        prop_assert_eq!(e.restore(&red.text, "global"), text);
    }
}

#[test]
fn single_byte_chunks() {
    let (_d, e) = engine();
    let red = redacted_sample(&e);
    let mut sr = e.stream_restorer("global");
    let mut out = String::new();
    let mut buf = [0u8; 4];
    for c in red.chars() {
        out.push_str(&sr.push(c.encode_utf8(&mut buf)));
    }
    out.push_str(&sr.finish());
    assert_eq!(out, e.restore(&red, "global"));
}
