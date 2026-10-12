//! Property tests: detectors never panic and only return in-bounds spans on
//! UTF-8 character boundaries, for arbitrary text.

use parda_detect::{AllowList, Detector, DictionaryDetector, PersonBlock, RuleDetector, RulesFile};
use proptest::prelude::*;

fn rules() -> RuleDetector {
    RuleDetector::new(&["global", "india", "us_uk", "secrets"].map(String::from), true)
}

fn text() -> impl Strategy<Value = String> {
    prop_oneof![
        "\\PC{0,300}",
        // PII-shaped fragments glued to arbitrary Unicode.
        proptest::collection::vec(
            prop_oneof![
                Just("ravi.k@gmail.com".to_string()),
                Just("+91 98765 43210".to_string()),
                Just("2345 6789 0124".to_string()),
                Just("ABCPE1234F".to_string()),
                Just("4111 1111 1111 1111".to_string()),
                Just("sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789".to_string()),
                Just("192.168.1.20".to_string()),
                Just("Ravi Kumar".to_string()),
                "\\PC{0,12}",
            ],
            0..12,
        )
        .prop_map(|v| v.join(" ")),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn rules_spans_are_valid(t in text()) {
        for d in rules().detect(&t) {
            prop_assert!(d.span.start < d.span.end && d.span.end <= t.len());
            prop_assert!(t.is_char_boundary(d.span.start) && t.is_char_boundary(d.span.end));
        }
    }

    #[test]
    fn dictionary_and_allow_list_spans_are_valid(t in text(), name in "\\PC{1,20}") {
        let rf = RulesFile {
            person: vec![PersonBlock { name: name.clone(), ..Default::default() },
                         PersonBlock { name: "Ravi Kumar".into(), ..Default::default() }],
            allow: vec![name],
            ..Default::default()
        };
        let dets = DictionaryDetector::new(&rf).detect(&t);
        for d in &dets {
            prop_assert!(d.span.end <= t.len());
            prop_assert!(t.is_char_boundary(d.span.start) && t.is_char_boundary(d.span.end));
        }
        let kept = AllowList::new(&rf.allow).filter(&t, dets.clone());
        prop_assert!(kept.len() <= dets.len());
    }
}
