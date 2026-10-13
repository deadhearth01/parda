mod common;

use std::sync::Arc;

use common::*;
use parda_core::{Action, EntityKind, MlDetector, Mode, Style};
use parda_engine::EngineError;

#[test]
fn redacts_and_restores_roundtrip() {
    let (_d, e) = engine();
    let t = "Mail Ravi Kumar at ravi.k@gmail.com or +91 98765 43210, PAN ABCPE1234F.";
    let r = e.redact(t, "global").unwrap();
    assert!(!r.text.contains("Ravi"), "{}", r.text);
    assert!(!r.text.contains("ravi.k@"), "{}", r.text);
    assert!(!r.text.contains("98765"), "{}", r.text);
    assert!(!r.text.contains("ABCPE1234F"), "{}", r.text);
    assert_eq!(e.restore(&r.text, "global"), t);
    let kinds: Vec<_> = r.replaced.iter().map(|x| x.kind.clone()).collect();
    assert!(kinds.contains(&EntityKind::Person) && kinds.contains(&EntityKind::Email));
}

#[test]
fn deterministic_across_calls() {
    let (_d, e) = engine();
    let a = e.redact("Ravi Kumar", "global").unwrap().text;
    let b = e.redact("Ravi Kumar", "global").unwrap().text;
    assert_eq!(a, b);
    assert_ne!(a, "Ravi Kumar");
}

#[test]
fn restore_case_variants_and_first_name() {
    let (_d, e) = engine();
    let r = e.redact("Ravi Kumar", "global").unwrap().text;
    let first = r.split_whitespace().next().unwrap();
    let echoed = format!(
        "{} said hi. {}'s plan. {}",
        r.to_uppercase(),
        first,
        first.to_lowercase()
    );
    let back = e.restore(&echoed, "global");
    assert!(
        back.contains("RAVI KUMAR") && back.contains("Ravi's plan") && back.contains("ravi"),
        "{back}"
    );
}

#[test]
fn case_variants_share_a_surrogate() {
    let (_d, e) = engine();
    let a = e.redact("Ravi Kumar", "global").unwrap().text;
    let b = e.redact("RAVI KUMAR", "global").unwrap().text;
    assert_eq!(b, a.to_uppercase());
    assert_eq!(e.restore(&b, "global"), "RAVI KUMAR");
    assert_eq!(e.restore(&a, "global"), "Ravi Kumar");
}

#[test]
fn first_name_alone_is_consistent_with_full_name() {
    let (_d, e) = engine();
    let full = e.redact("Ravi Kumar", "global").unwrap().text;
    let first = e.redact("Ravi", "global").unwrap().text;
    assert_eq!(first, full.split_whitespace().next().unwrap());
}

#[test]
fn devanagari_context_safe() {
    let (_d, e) = engine();
    let t = "नमस्ते Ravi Kumar, ईमेल ravi.k@gmail.com 🙏";
    let r = e.redact(t, "global").unwrap();
    assert!(!r.text.contains("Ravi"));
    assert_eq!(e.restore(&r.text, "global"), t);
}

#[test]
fn scopes_are_separate() {
    let (_d, e) = engine();
    let a = e.redact("Ravi Kumar", "one").unwrap().text;
    assert_eq!(e.restore(&a, "two"), a);
    assert_eq!(e.restore(&a, "one"), "Ravi Kumar");
}

#[test]
fn block_action_errors() {
    let mut c = rules_only_config();
    c.detect.actions.insert(EntityKind::Secret, Action::Block);
    let (_d, e) = engine_with(c, None);
    let err = e
        .redact(
            "key sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789abcd",
            "global",
        )
        .unwrap_err();
    assert!(
        matches!(err, EngineError::Blocked(ref k) if k == &vec![EntityKind::Secret]),
        "{err:?}"
    );
}

#[test]
fn warn_and_ignore_leave_text() {
    let mut c = rules_only_config();
    c.detect.actions.insert(EntityKind::Email, Action::Warn);
    c.detect.actions.insert(EntityKind::Person, Action::Ignore);
    let (_d, e) = engine_with(c, None);
    let r = e.redact("Ravi Kumar ravi.k@gmail.com", "global").unwrap();
    assert_eq!(r.text, "Ravi Kumar ravi.k@gmail.com");
    assert_eq!(r.warned, vec![EntityKind::Email]);
}

#[test]
fn strict_mode_ml_failure_refuses() {
    let ml = StubMl::new(0, true);
    let (_d, e) = engine_with(
        ml_config(Mode::Strict, 250),
        Some(ml.clone() as Arc<dyn MlDetector>),
    );
    let err = e.redact("Ravi Kumar lives here", "global").unwrap_err();
    assert!(matches!(err, EngineError::MlUnavailable(_)), "{err:?}");

    let (_d2, e2) = engine_with(
        ml_config(Mode::Fast, 250),
        Some(StubMl::new(0, true) as Arc<dyn MlDetector>),
    );
    let r = e2.redact("Ravi Kumar lives here", "global").unwrap();
    assert!(r.ml_skipped);
    assert!(!r.text.contains("Ravi"));
}

#[test]
fn strict_mode_without_model_refuses() {
    let (_d, e) = engine_with(ml_config(Mode::Strict, 250), None);
    assert!(matches!(
        e.redact("hello there", "global").unwrap_err(),
        EngineError::MlUnavailable(_)
    ));
}

#[test]
fn ml_timeout_respected() {
    let (_d, e) = engine_with(
        ml_config(Mode::Strict, 50),
        Some(StubMl::new(500, false) as Arc<dyn MlDetector>),
    );
    let started = std::time::Instant::now();
    assert!(matches!(
        e.redact("Ravi Kumar lives here", "global").unwrap_err(),
        EngineError::MlUnavailable(_)
    ));
    assert!(started.elapsed().as_millis() < 400);

    let (_d2, e2) = engine_with(
        ml_config(Mode::Fast, 50),
        Some(StubMl::new(500, false) as Arc<dyn MlDetector>),
    );
    let r = e2.redact("Ravi Kumar lives here", "global").unwrap();
    assert!(r.ml_skipped);
}

#[test]
fn late_ml_result_is_reused() {
    let ml = StubMl::new(150, false);
    let (_d, e) = engine_with(
        ml_config(Mode::Fast, 20),
        Some(ml.clone() as Arc<dyn MlDetector>),
    );
    assert!(
        e.redact("Ravi Kumar lives here", "global")
            .unwrap()
            .ml_skipped
    );
    std::thread::sleep(std::time::Duration::from_millis(400));
    let r = e.redact("Ravi Kumar lives here", "global").unwrap();
    assert!(
        !r.ml_skipped,
        "second call should use the cached late result"
    );
    assert_eq!(ml.calls(), 1);
}

#[test]
fn cache_hit_skips_ml() {
    let ml = StubMl::new(0, false);
    let (_d, e) = engine_with(
        ml_config(Mode::Strict, 250),
        Some(ml.clone() as Arc<dyn MlDetector>),
    );
    e.redact("Ravi Kumar lives here", "global").unwrap();
    e.redact("Ravi Kumar lives here", "global").unwrap();
    assert_eq!(ml.calls(), 1);
    assert!(e.stats().cache_hits >= 1);
}

#[test]
fn redact_many_batches_ml_once() {
    let ml = StubMl::new(0, false);
    let (_d, e) = engine_with(
        ml_config(Mode::Strict, 250),
        Some(ml.clone() as Arc<dyn MlDetector>),
    );
    let out = e
        .redact_many(
            &["Ravi Kumar here", "mail ravi.k@gmail.com", "nothing"],
            "global",
        )
        .unwrap();
    assert_eq!(out.len(), 3);
    assert_eq!(ml.calls(), 1);
    assert_eq!(out[2].text, "nothing");
}

#[test]
fn large_input_fast() {
    let (_d, e) = engine();
    let t = "Contact ravi.k@gmail.com about order 12345.\n".repeat(25_000);
    let s = std::time::Instant::now();
    let r = e.redact(&t, "global").unwrap();
    assert!(s.elapsed().as_secs() < 5, "{:?}", s.elapsed());
    assert!(!r.text.contains("ravi.k@"));
}

#[test]
fn token_style() {
    let mut c = rules_only_config();
    c.replace.style = Style::Token;
    let (_d, e) = engine_with(c, None);
    let t = "Write to ravi.k@gmail.com and amit@corp.in, cc ravi.k@gmail.com";
    let r = e.redact(t, "global").unwrap();
    assert!(
        r.text.contains("[EMAIL_1]") && r.text.contains("[EMAIL_2]"),
        "{}",
        r.text
    );
    assert_eq!(r.text.matches("[EMAIL_1]").count(), 2);
    assert_eq!(e.restore(&r.text, "global"), t);
}

#[test]
fn surrogate_echo_in_input_gets_its_own_mapping() {
    let (_d, e) = engine();
    let sur = e.redact("Ravi Kumar", "global").unwrap().text;
    // The user now writes the surrogate name about someone else entirely.
    let t = format!("{sur} and Ravi Kumar met");
    let r = e.redact(&t, "global").unwrap();
    assert_eq!(e.restore(&r.text, "global"), t);
    // Only the real Ravi Kumar is shown as `sur`; the look-alike got its own.
    assert_eq!(r.text.matches(&sur).count(), 1, "{} vs {sur}", r.text);
    assert!(r.text.ends_with(&format!("and {sur} met")), "{}", r.text);
}

#[test]
fn reload_rules_changes_detection() {
    let (_d, e) = engine();
    assert_eq!(
        e.redact("Meet Zubin Wadia", "global").unwrap().text,
        "Meet Zubin Wadia"
    );
    let mut rules = e.rules();
    rules.person.push(parda_detect::PersonBlock {
        name: "Zubin Wadia".into(),
        ..Default::default()
    });
    e.reload_rules(rules);
    assert!(
        !e.redact("Meet Zubin Wadia", "global")
            .unwrap()
            .text
            .contains("Zubin")
    );
}

#[test]
fn allow_list_is_respected() {
    let (_d, e) = engine();
    let mut rules = e.rules();
    rules.allow.push("ravi.k@gmail.com".into());
    e.reload_rules(rules);
    let r = e.redact("mail ravi.k@gmail.com", "global").unwrap();
    assert_eq!(r.text, "mail ravi.k@gmail.com");
}

#[test]
fn mappings_persist_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let open = || {
        parda_engine::Engine::open(
            parda_engine::EngineOptions {
                config: rules_only_config(),
                rules: rules(),
                data_dir: dir.path().to_path_buf(),
                use_keyring: false,
            },
            None,
        )
        .unwrap()
    };
    let a = open().redact("Ravi Kumar", "global").unwrap().text;
    let e2 = open();
    assert_eq!(e2.redact("Ravi Kumar", "global").unwrap().text, a);
    assert_eq!(e2.restore(&a, "global"), "Ravi Kumar");
}

#[test]
fn scan_reports_without_vault_writes() {
    let (_d, e) = engine();
    let dets = e.scan("Ravi Kumar, ravi.k@gmail.com").unwrap();
    assert_eq!(dets.len(), 2);
    assert!(e.vault().stats().unwrap().is_empty());
}

#[test]
fn stream_holds_back_only_partial_prefix() {
    let (_d, e) = engine();
    let sur = e.redact("Ravi Kumar", "global").unwrap().text;
    let (head, tail) = sur.split_at(3);
    let mut sr = e.stream_restorer("global");
    assert_eq!(sr.push(&format!("Hello {head}")), "Hello ");
    assert_eq!(sr.push(&format!("{tail}!")), "Ravi Kumar!");
    assert_eq!(sr.finish(), "");
}

#[test]
fn paused_protection_passes_text_through_but_still_restores() {
    let (_d, e) = engine();
    let sur = e.redact("Ravi Kumar", "global").unwrap().text;
    let mut c = e.config();
    c.protection.enabled = false;
    e.set_config(c);
    let t = "Mail Ravi Kumar at ravi.k@gmail.com";
    let r = e.redact(t, "global").unwrap();
    assert!(r.paused);
    assert_eq!(r.text, t);
    assert!(r.replaced.is_empty());
    // Surrogates sent earlier keep mapping back while paused.
    assert_eq!(e.restore(&format!("Hi {sur}"), "global"), "Hi Ravi Kumar");
    let mut c = e.config();
    c.protection.enabled = true;
    e.set_config(c);
    let r = e.redact(t, "global").unwrap();
    assert!(!r.paused && !r.text.contains("Ravi"));
}

#[test]
fn default_style_is_tags_and_they_round_trip() {
    let mut c = parda_core::Config::default();
    c.detect.model = "none".into();
    let (_d, e) = engine_with(c, None);
    let t = "Mail ravi.k@gmail.com, call +91 98765 43210, Aadhaar 2345 6789 0124";
    let r = e.redact(t, "global").unwrap();
    assert!(
        r.text.contains("[EMAIL_1]")
            && r.text.contains("[PHONE_1]")
            && r.text.contains("[AADHAAR_1]"),
        "{}",
        r.text
    );
    assert_eq!(e.restore(&r.text, "global"), t);
    // The AI may echo a tag in another case.
    assert_eq!(
        e.restore("Sent to [email_1].", "global"),
        "Sent to ravi.k@gmail.com."
    );
}

#[test]
fn rules_only_texts_skip_the_model_but_not_the_rules() {
    // The model "finds" a name wherever it sees "abc".
    let ml = NameMl::new(&["abc"]);
    let (_d, e) = engine_with(
        ml_config(Mode::Strict, 250),
        Some(ml.clone() as Arc<dyn MlDetector>),
    );
    let rs = e
        .redact_many_tiered(
            &["abc text", "abc-123", "ravi@example.com", "Ravi Kumar"],
            &[false, true, true, true],
            "global",
        )
        .unwrap();
    assert!(!rs[0].text.contains("abc"), "{}", rs[0].text);
    // An identifier is not shown to the model…
    assert_eq!(rs[1].text, "abc-123");
    // …but the rule and dictionary tiers still see it.
    assert!(!rs[2].text.contains("ravi@"), "{}", rs[2].text);
    assert!(!rs[3].text.contains("Ravi"), "{}", rs[3].text);
    // The same string as text afterwards does go to the model (separate
    // cache entries).
    let r = e
        .redact_many_tiered(&["abc-123"], &[false], "global")
        .unwrap();
    assert!(!r[0].text.contains("abc"), "{}", r[0].text);
    // Only identifiers: no model is needed, even in strict mode.
    let (_d2, e2) = engine_with(ml_config(Mode::Strict, 250), None);
    let r = e2
        .redact_many_tiered(&["abc-123"], &[true], "global")
        .unwrap();
    assert_eq!(r[0].text, "abc-123");
}
