use super::Rule;
use parda_core::{EntityKind as K, validators};

pub(super) fn rules() -> Vec<Rule> {
    vec![
        Rule::new(
            K::Aadhaar,
            r"[2-9][0-9]{3}(?: [0-9]{4}){2}|[2-9][0-9]{3}(?:-[0-9]{4}){2}|[2-9][0-9]{11}",
            Some(validators::verhoeff),
            &["aadhaar", "aadhar", "uid", "आधार"],
            0.8,
        ),
        Rule::new(
            K::Pan,
            r"[A-Z]{5}[0-9]{4}[A-Z]",
            Some(validators::pan),
            &["pan"],
            0.8,
        ),
        Rule::new(
            K::Gstin,
            r"[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z][1-9A-Z]Z[0-9A-Z]",
            Some(validators::gstin),
            &["gst", "gstin"],
            0.8,
        ),
        Rule::new(
            K::Upi,
            r"(?i)[\w.-]{2,}@[a-z]{2,}",
            None,
            &["upi", "pay", "payment"],
            0.7,
        ),
        Rule::new(
            K::Ifsc,
            r"[A-Z]{4}0[A-Z0-9]{6}",
            None,
            &["ifsc", "bank"],
            0.8,
        ),
        Rule::new(
            K::VoterId,
            r"[A-Z]{3}[0-9]{7}",
            None,
            &["voter", "epic"],
            0.7,
        ),
        Rule::new(
            K::IndianVehicleReg,
            r"[A-Z]{2}[ -]?[0-9]{1,2}[ -]?[A-Z]{1,3}[ -]?[0-9]{4}",
            None,
            &["vehicle", "registration", "car"],
            0.7,
        ),
        Rule::new(
            K::DrivingLicence,
            r"[A-Z]{2}[ -]?[0-9]{2}[ -]?(?:19|20)[0-9]{2}[0-9]{7}",
            None,
            &["dl", "licence", "license"],
            0.7,
        ),
        Rule::new(
            K::Phone,
            r"(?:\+91[ -]?)?[6-9][0-9]{4}[ -]?[0-9]{5}",
            None,
            &["phone", "mobile", "call"],
            0.7,
        ),
    ]
}
