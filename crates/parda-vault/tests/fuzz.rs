//! Property tests: surrogate generation never panics, is deterministic and
//! never returns the input, for every kind and arbitrary values.

use parda_core::EntityKind;
use parda_vault::SurrogateGen;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn every_kind_any_value(real in "\\PC{1,60}", seed in any::<[u8; 32]>(), attempt in 0u32..4) {
        let g = SurrogateGen::new();
        for kind in EntityKind::all().chain([EntityKind::Custom("Thing".into())]) {
            let a = g.generate(&kind, &real, seed, attempt);
            prop_assert!(!a.is_empty());
            prop_assert!(!a.eq_ignore_ascii_case(&real), "{kind}: {real:?} -> {a:?}");
            prop_assert_eq!(&a, &g.generate(&kind, &real, seed, attempt));
        }
    }
}
