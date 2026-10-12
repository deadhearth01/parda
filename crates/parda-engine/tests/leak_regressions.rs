//! Regression tests for leak paths found in the v0.1 whole-branch review
//! (review A). Each test reproduces the reviewer's failure scenario.

mod common;

use common::*;
use parda_engine::DEFAULT_MAX_FRAGMENT_BYTES;

/// Values the dictionary and rule tiers must find wherever they sit.
const VALUES: &[&str] = &[
    "9876543210",
    "+91 98765 43210",
    "ravi.k@gmail.com",
    "ABCPE1234F",
    "2345 6789 0124",
    "4111 1111 1111 1111",
    "GB82 WEST 1234 5698 7654 32",
    "Ravi Kumar",
    "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789abcd",
];

/// Filler styles around the value: no separator at all (minified JSON /
/// long log lines are hard-split), spaces only, and newlines.
fn filler(style: usize, len: usize) -> String {
    let unit = match style {
        0 => "#",
        1 => "lorem ipsum dolor ",
        _ => "lorem ipsum\n",
    };
    unit.repeat(len / unit.len() + 1)[..len].to_string()
}

/// Review A finding 1: a value straddling a fragment boundary must not leak,
/// at any offset, with or without whitespace or newlines around it.
#[test]
fn value_straddling_a_fragment_boundary_never_leaks() {
    let (_d, e) = engine();
    let boundary = DEFAULT_MAX_FRAGMENT_BYTES;
    for style in 0..3 {
        for value in VALUES {
            let from = boundary - value.len() - 2;
            for at in from..=boundary + 2 {
                // A separator on each side so the value is word-bounded.
                let text = format!(
                    "{}\"{value}\"{}",
                    filler(style, at - 1),
                    filler(style, 2 * boundary)
                );
                let r = e.redact(&text, "global").unwrap();
                assert!(
                    !r.text.contains(value),
                    "style {style}: {value:?} at byte {at} leaked"
                );
                assert_eq!(e.restore(&r.text, "global"), text, "{value:?} at {at}");
            }
        }
    }
}

/// Review A finding 1 (model tier): model windows overlap, so a name the
/// model finds is found wherever a window edge falls.
#[test]
fn model_name_across_a_window_edge_is_found() {
    let ml = NameMl::new(&["Anna Schmidt"]);
    let (_d, e) = engine_with(
        ml_config(parda_core::Mode::Strict, 1000),
        Some(ml as std::sync::Arc<dyn parda_core::MlDetector>),
    );
    let name = "Anna Schmidt";
    for style in 0..3 {
        // The first window ends somewhere below DEFAULT_MAX_FRAGMENT_BYTES.
        for at in (1500..=DEFAULT_MAX_FRAGMENT_BYTES + 4).step_by(3) {
            let text = format!(
                "{} {name} {}",
                filler(style, at - 1),
                filler(style, 2 * DEFAULT_MAX_FRAGMENT_BYTES)
            );
            let r = e.redact(&text, "global").unwrap();
            assert!(!r.text.contains("Schmidt"), "style {style}, at {at}");
            assert!(!r.text.contains("Anna "), "style {style}, at {at}");
        }
    }
}

/// Review A finding 13: a detector returning bad spans must not panic the
/// engine; the spans are dropped.
#[test]
fn invalid_model_spans_do_not_panic() {
    let (_d, e) = engine_with(
        ml_config(parda_core::Mode::Strict, 1000),
        Some(std::sync::Arc::new(BadSpanMl) as std::sync::Arc<dyn parda_core::MlDetector>),
    );
    let t = "नमस्ते Ravi Kumar, see you";
    let r = e.redact(t, "global").unwrap();
    assert!(!r.text.contains("Ravi"));
    assert_eq!(e.restore(&r.text, "global"), t);
}
