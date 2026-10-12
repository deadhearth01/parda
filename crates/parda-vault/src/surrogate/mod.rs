//! Deterministic, format-preserving surrogates.
//!
//! `generate(kind, real, seed, attempt)` always returns the same stand-in for
//! the same inputs: the seed comes from the vault key (`VaultKey::seed`), so a
//! value maps to one surrogate across sessions without the mapping having to
//! be looked up first. `attempt` re-rolls on a collision.
//!
//! Names keep their word count, case and origin (an Indian name gets an
//! Indian stand-in); identifiers keep their layout and checksum; addresses,
//! organisations and custom kinds become typed tokens (`⟦ADDRESS_42⟧`).

mod case;
mod ids;
mod names;

pub use case::{CasePattern, apply_case, case_pattern};
pub use names::is_indian_name;

use parda_core::EntityKind;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// A typed placeholder: `token(&EntityKind::Person, 1)` → `⟦PERSON_1⟧`.
pub fn token(kind: &EntityKind, n: u32) -> String {
    format!("⟦{}_{n}⟧", kind.label())
}

fn rng_for(seed: [u8; 32], attempt: u32) -> ChaCha20Rng {
    let mut h = blake3::Hasher::new();
    h.update(b"parda-surrogate-v1");
    h.update(&seed);
    h.update(&attempt.to_le_bytes());
    ChaCha20Rng::from_seed(*h.finalize().as_bytes())
}

/// Token number in `1..=9999` derived from the seed and attempt.
fn token_number(seed: [u8; 32], attempt: u32) -> u32 {
    let mut h = blake3::Hasher::new();
    h.update(b"parda-token-v1");
    h.update(&seed);
    h.update(&attempt.to_le_bytes());
    let b = h.finalize();
    let n = u32::from_le_bytes([
        b.as_bytes()[0],
        b.as_bytes()[1],
        b.as_bytes()[2],
        b.as_bytes()[3],
    ]);
    n % 9999 + 1
}

/// Generates surrogates. Cheap to construct; the word lists are shared.
#[derive(Debug, Clone, Copy, Default)]
pub struct SurrogateGen;

impl SurrogateGen {
    pub fn new() -> Self {
        SurrogateGen
    }

    /// A stand-in for `real`, deterministic in `(kind, real, seed, attempt)`
    /// and never equal (ignoring case) to `real`.
    pub fn generate(&self, kind: &EntityKind, real: &str, seed: [u8; 32], attempt: u32) -> String {
        let mut rng = rng_for(seed, attempt);
        for _ in 0..16 {
            let s = match kind {
                EntityKind::Person => names::person(real, &mut rng),
                EntityKind::Email => ids::email(real, &mut rng),
                EntityKind::Phone => ids::phone(real, &mut rng),
                EntityKind::Aadhaar => ids::aadhaar(real, &mut rng),
                EntityKind::CreditCard => ids::card(real, &mut rng),
                EntityKind::Pan => ids::pan(real, &mut rng),
                EntityKind::Gstin => ids::gstin(real, &mut rng),
                EntityKind::Upi => ids::upi(real, &mut rng),
                EntityKind::IpAddress => ids::ip(real, &mut rng),
                EntityKind::MacAddress => ids::mac(real, &mut rng),
                EntityKind::Iban => ids::iban(real, &mut rng),
                EntityKind::BankAccount => ids::bank_account(real, &mut rng),
                EntityKind::Ifsc => ids::ifsc(real, &mut rng),
                EntityKind::IndianVehicleReg | EntityKind::DrivingLicence => {
                    ids::keep_state_prefix(real, &mut rng)
                }
                EntityKind::VoterId | EntityKind::Passport => ids::shape(real, &mut rng),
                EntityKind::UsSsn => ids::us_ssn(real, &mut rng),
                EntityKind::UkNino => ids::uk_nino(real, &mut rng),
                EntityKind::DateOfBirth => ids::date(real, &mut rng),
                EntityKind::Secret => ids::secret(real, &mut rng),
                EntityKind::Url => ids::url(real, &mut rng),
                EntityKind::Address | EntityKind::Organization | EntityKind::Custom(_) => {
                    return token(kind, token_number(seed, attempt));
                }
            };
            if !s.eq_ignore_ascii_case(real) && !s.is_empty() {
                return s;
            }
        }
        // Nothing in the value could be varied (e.g. punctuation only).
        token(kind, token_number(seed, attempt))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn person_keeps_token_count_and_case() {
        let g = SurrogateGen::new();
        let s = g.generate(&EntityKind::Person, "RAVI KUMAR", seed(1), 0);
        assert_eq!(s.split_whitespace().count(), 2);
        assert_eq!(s, s.to_uppercase());
        assert_ne!(s, "RAVI KUMAR");
    }

    #[test]
    fn indian_name_gets_indian_surrogate() {
        let g = SurrogateGen::new();
        for n in 0..20 {
            let s = g.generate(&EntityKind::Person, "Priya Sharma", seed(n), 0);
            assert!(s.split_whitespace().all(is_indian_name), "{s}");
        }
    }

    #[test]
    fn deterministic() {
        let g = SurrogateGen::new();
        assert_eq!(
            g.generate(&EntityKind::Person, "Ravi", seed(3), 0),
            g.generate(&EntityKind::Person, "Ravi", seed(3), 0)
        );
    }

    #[test]
    fn aadhaar_valid_and_spaced() {
        let g = SurrogateGen::new();
        let s = g.generate(&EntityKind::Aadhaar, "2345 6789 0124", seed(4), 0);
        assert_eq!(s.len(), 14);
        let d: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
        assert!(parda_core::validators::verhoeff(&d));
        assert!(('2'..='9').contains(&d.chars().next().unwrap()));
        assert_ne!(d, "234567890124");
    }

    #[test]
    fn card_luhn_same_shape() {
        let g = SurrogateGen::new();
        let s = g.generate(&EntityKind::CreditCard, "4111 1111 1111 1111", seed(5), 0);
        assert_eq!(s.len(), 19);
        assert!(s.starts_with('4'));
        assert!(parda_core::validators::luhn(&s.replace(' ', "")));
    }

    #[test]
    fn pan_keeps_holder_type() {
        let g = SurrogateGen::new();
        let s = g.generate(&EntityKind::Pan, "ABCPE1234F", seed(6), 0);
        assert!(parda_core::validators::pan(&s));
        assert_eq!(&s[3..4], "P");
    }

    #[test]
    fn gstin_valid_same_state() {
        let g = SurrogateGen::new();
        let real = "27AAPFU0939F1ZV";
        let s = g.generate(&EntityKind::Gstin, real, seed(7), 0);
        assert!(parda_core::validators::gstin(&s));
        assert_eq!(&s[..2], "27");
    }

    #[test]
    fn email_keeps_public_domain() {
        let g = SurrogateGen::new();
        let s = g.generate(&EntityKind::Email, "ravi.k@gmail.com", seed(8), 0);
        assert!(s.ends_with("@gmail.com"));
        assert_ne!(s, "ravi.k@gmail.com");
    }

    #[test]
    fn email_private_domain_replaced() {
        let s = SurrogateGen::new().generate(&EntityKind::Email, "ravi@acme-secret.in", seed(9), 0);
        assert!(!s.contains("acme-secret"));
        assert!(s.ends_with(".example"));
    }

    #[test]
    fn phone_keeps_shape() {
        let s = SurrogateGen::new().generate(&EntityKind::Phone, "+91 98765 43210", seed(10), 0);
        assert!(s.starts_with("+91 "));
        assert_eq!(s.len(), 15);
        assert!(matches!(s.as_bytes()[4], b'6'..=b'9'));
    }

    #[test]
    fn upi_keeps_handle() {
        let s = SurrogateGen::new().generate(&EntityKind::Upi, "ravi.k@okaxis", seed(11), 0);
        assert!(s.ends_with("@okaxis"));
    }

    #[test]
    fn secret_keeps_prefix_len() {
        let real = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789";
        let s = SurrogateGen::new().generate(&EntityKind::Secret, real, seed(12), 0);
        assert!(s.starts_with("sk-ant-api03-"));
        assert_eq!(s.len(), real.len());
        assert_ne!(s, real);
    }

    #[test]
    fn ip_private_stays_private() {
        let s = SurrogateGen::new().generate(&EntityKind::IpAddress, "192.168.1.20", seed(13), 0);
        assert!(s.starts_with("192.168.") || s.starts_with("10."));
    }

    #[test]
    fn address_uses_token() {
        let s = SurrogateGen::new().generate(&EntityKind::Address, "12 MG Road, Pune", seed(14), 0);
        assert!(s.starts_with("⟦ADDRESS_"));
    }

    #[test]
    fn attempt_changes_output() {
        let g = SurrogateGen::new();
        assert_ne!(
            g.generate(&EntityKind::Person, "Ravi", seed(15), 0),
            g.generate(&EntityKind::Person, "Ravi", seed(15), 1)
        );
    }

    #[test]
    fn token_format() {
        assert_eq!(token(&EntityKind::Person, 1), "⟦PERSON_1⟧");
        assert_eq!(token(&EntityKind::IpAddress, 7), "⟦IP_ADDRESS_7⟧");
    }

    #[test]
    fn every_kind_differs_from_real_and_is_stable() {
        let samples: &[(EntityKind, &str)] = &[
            (EntityKind::Person, "Siobhan Fitzgerald"),
            (EntityKind::Email, "ravi@corp.in"),
            (EntityKind::Phone, "+1 (415) 555-0132"),
            (EntityKind::Url, "https://x.corp.in/a?token=abc"),
            (EntityKind::IpAddress, "8.8.8.8"),
            (EntityKind::MacAddress, "00:1A:2B:3C:4D:5E"),
            (EntityKind::CreditCard, "5500-0000-0000-0004"),
            (EntityKind::Iban, "DE89 3704 0044 0532 0130 00"),
            (EntityKind::BankAccount, "001234567890"),
            (EntityKind::Ifsc, "HDFC0001234"),
            (EntityKind::Aadhaar, "234567890124"),
            (EntityKind::Pan, "ABCPE1234F"),
            (EntityKind::Gstin, "27AAPFU0939F1ZV"),
            (EntityKind::Upi, "9876543210@ybl"),
            (EntityKind::VoterId, "ABC1234567"),
            (EntityKind::DrivingLicence, "MH1220110012345"),
            (EntityKind::IndianVehicleReg, "KA05MN1234"),
            (EntityKind::Passport, "K1234567"),
            (EntityKind::UsSsn, "123-45-6789"),
            (EntityKind::UkNino, "AB123456C"),
            (EntityKind::DateOfBirth, "12/05/1988"),
            (
                EntityKind::Secret,
                "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            ),
            (EntityKind::Organization, "Acme Corp"),
            (EntityKind::Custom("EmployeeId".into()), "EMP-4471"),
        ];
        let g = SurrogateGen::new();
        for (kind, real) in samples {
            for n in 0..10 {
                let a = g.generate(kind, real, seed(n), 0);
                assert!(!a.eq_ignore_ascii_case(real), "{kind}: {a}");
                assert_eq!(a, g.generate(kind, real, seed(n), 0), "{kind}");
            }
        }
    }
}
