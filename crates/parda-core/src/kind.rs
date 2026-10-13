//! The kinds of personal or secret data parda knows how to find.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A category of sensitive data. Serialized as its variant name
/// (`"Person"`, `"Aadhaar"`, …); parsing ignores case and separators, and
/// unknown names become [`EntityKind::Custom`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum EntityKind {
    Person,
    Email,
    Phone,
    Address,
    Url,
    IpAddress,
    MacAddress,
    CreditCard,
    Iban,
    BankAccount,
    Ifsc,
    Aadhaar,
    Pan,
    Gstin,
    Upi,
    VoterId,
    DrivingLicence,
    IndianVehicleReg,
    Passport,
    UsSsn,
    UkNino,
    DateOfBirth,
    Secret,
    Organization,
    Custom(String),
}

const NAMED: &[(&str, EntityKind)] = &[
    ("Person", EntityKind::Person),
    ("Email", EntityKind::Email),
    ("Phone", EntityKind::Phone),
    ("Address", EntityKind::Address),
    ("Url", EntityKind::Url),
    ("IpAddress", EntityKind::IpAddress),
    ("MacAddress", EntityKind::MacAddress),
    ("CreditCard", EntityKind::CreditCard),
    ("Iban", EntityKind::Iban),
    ("BankAccount", EntityKind::BankAccount),
    ("Ifsc", EntityKind::Ifsc),
    ("Aadhaar", EntityKind::Aadhaar),
    ("Pan", EntityKind::Pan),
    ("Gstin", EntityKind::Gstin),
    ("Upi", EntityKind::Upi),
    ("VoterId", EntityKind::VoterId),
    ("DrivingLicence", EntityKind::DrivingLicence),
    ("IndianVehicleReg", EntityKind::IndianVehicleReg),
    ("Passport", EntityKind::Passport),
    ("UsSsn", EntityKind::UsSsn),
    ("UkNino", EntityKind::UkNino),
    ("DateOfBirth", EntityKind::DateOfBirth),
    ("Secret", EntityKind::Secret),
    ("Organization", EntityKind::Organization),
];

/// `name` lower-cased without `_`, `-` and spaces: "IP_ADDRESS" → "ipaddress".
pub(crate) fn fold(name: &str) -> String {
    name.chars()
        .filter(|c| !matches!(c, '_' | '-' | ' '))
        .flat_map(char::to_lowercase)
        .collect()
}

impl EntityKind {
    /// Every built-in kind, in declaration order.
    pub fn all() -> impl Iterator<Item = EntityKind> {
        NAMED.iter().map(|(_, k)| k.clone())
    }

    /// The built-in kind called `name`, ignoring case and `_` / `-` / space
    /// separators (`secret`, `IP_ADDRESS`, `credit-card`); `None` for any
    /// other name.
    pub fn builtin(name: &str) -> Option<EntityKind> {
        let folded = fold(name.trim());
        NAMED
            .iter()
            .find(|(n, _)| fold(n) == folded)
            .map(|(_, k)| k.clone())
    }

    /// Built-in kind names, comma separated (for error messages).
    pub fn builtin_names() -> String {
        NAMED.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")
    }

    /// Upper-snake label used in placeholder tokens, e.g. `IP_ADDRESS`.
    pub fn label(&self) -> String {
        let name = self.to_string();
        let mut out = String::with_capacity(name.len() + 4);
        for (i, ch) in name.chars().enumerate() {
            if ch.is_ascii_uppercase() && i > 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_uppercase());
        }
        out
    }
}

impl fmt::Display for EntityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let EntityKind::Custom(name) = self {
            return f.write_str(name);
        }
        let name = NAMED
            .iter()
            .find(|(_, k)| k == self)
            .map(|(n, _)| *n)
            .unwrap_or("Custom");
        f.write_str(name)
    }
}

impl FromStr for EntityKind {
    type Err = std::convert::Infallible;

    /// Built-in names match ignoring case and separators (see
    /// [`EntityKind::builtin`]); anything else is a custom kind.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(EntityKind::builtin(s).unwrap_or_else(|| EntityKind::Custom(s.to_string())))
    }
}

impl Serialize for EntityKind {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for EntityKind {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(s.parse().expect("infallible"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_parse_roundtrip() {
        for k in EntityKind::all() {
            assert_eq!(k.to_string().parse::<EntityKind>().unwrap(), k);
        }
        assert_eq!(
            "Thing".parse::<EntityKind>().unwrap(),
            EntityKind::Custom("Thing".into())
        );
    }

    #[test]
    fn builtin_names_ignore_case_and_separators() {
        for (name, kind) in [
            ("secret", EntityKind::Secret),
            ("SECRET", EntityKind::Secret),
            ("ip_address", EntityKind::IpAddress),
            ("IP_ADDRESS", EntityKind::IpAddress),
            ("credit-card", EntityKind::CreditCard),
            ("Date Of Birth", EntityKind::DateOfBirth),
        ] {
            assert_eq!(name.parse::<EntityKind>().unwrap(), kind, "{name}");
            assert_eq!(EntityKind::builtin(name), Some(kind), "{name}");
        }
        assert_eq!(EntityKind::builtin("secrets"), None);
        assert_eq!(
            "Codename".parse::<EntityKind>().unwrap(),
            EntityKind::Custom("Codename".into())
        );
    }

    #[test]
    fn labels() {
        assert_eq!(EntityKind::IpAddress.label(), "IP_ADDRESS");
        assert_eq!(EntityKind::Person.label(), "PERSON");
        assert_eq!(
            EntityKind::Custom("employee id".into()).label(),
            "EMPLOYEE ID"
        );
    }
}
