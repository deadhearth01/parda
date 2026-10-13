//! The local root CA and the per-host leaf certificates it signs.
//!
//! The CA is generated on this machine and never leaves it. Leaf certificates
//! are made on demand for listed AI hosts only, kept in memory and reused.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SerialNumber,
};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::ServerCertVerifier;
use rustls::sign::CertifiedKey;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use time::{Duration, OffsetDateTime};

const CA_NAME: &str = "parda local interception CA";
const CA_VALIDITY_DAYS: i64 = 3653;
const LEAF_VALIDITY_DAYS: i64 = 365;
/// Leaves are re-issued this long before they expire.
const LEAF_RENEW_MARGIN_DAYS: i64 = 7;
/// Upper bound on cached leaves; the cache starts over when it is reached.
const LEAF_CACHE_MAX: usize = 1024;

struct CachedLeaf {
    key: Arc<CertifiedKey>,
    renew_after: OffsetDateTime,
}

/// parda's local root certificate authority.
pub struct Ca {
    cert_pem: String,
    cert_der: CertificateDer<'static>,
    issuer: Issuer<'static, KeyPair>,
    leaves: Mutex<HashMap<String, CachedLeaf>>,
}

impl Ca {
    /// A fresh CA: ECDSA P-256 key, 10-year validity.
    pub fn generate() -> Result<Ca> {
        let key = KeyPair::generate().context("generating the CA key")?;
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, CA_NAME);
        params
            .distinguished_name
            .push(DnType::OrganizationName, "parda");
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::days(1);
        params.not_after = now + Duration::days(CA_VALIDITY_DAYS);
        params.serial_number = Some(random_serial());
        let cert = params.self_signed(&key).context("signing the CA")?;
        let issuer = Issuer::new(params, key);
        Self::assemble(cert.pem(), cert.der().clone(), issuer)
    }

    /// Reload a CA from its certificate and private key (both PEM). Fails if
    /// the key is not the one the certificate was made for.
    pub fn from_pem(cert_pem: &str, key_pem: &str) -> Result<Ca> {
        let key = KeyPair::from_pem(key_pem).context("reading the CA key")?;
        let cert_der = CertificateDer::from_pem_slice(cert_pem.as_bytes())
            .map_err(|e| anyhow!("reading the CA certificate: {e}"))?;
        let issuer =
            Issuer::from_ca_cert_der(&cert_der, key).context("reading the CA certificate")?;
        let ca = Self::assemble(cert_pem.to_string(), cert_der, issuer)?;
        // Prove the key belongs to the certificate: a leaf it signs must
        // verify under the certificate.
        let probe = ca.issue("parda-self-check.invalid")?;
        ca.check_leaf(&probe, "parda-self-check.invalid")
            .context("the CA key does not match the CA certificate")?;
        Ok(ca)
    }

    fn assemble(
        cert_pem: String,
        cert_der: CertificateDer<'static>,
        issuer: Issuer<'static, KeyPair>,
    ) -> Result<Ca> {
        Ok(Ca {
            cert_pem,
            cert_der,
            issuer,
            leaves: Mutex::new(HashMap::new()),
        })
    }

    pub fn cert_pem(&self) -> String {
        self.cert_pem.clone()
    }

    pub fn key_pem(&self) -> String {
        self.issuer.key().serialize_pem()
    }

    /// The CA certificate in DER form.
    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert_der
    }

    /// The leaf certificate (with its key) for `host`, cached per host
    /// (case-insensitive). SAN = host, EKU serverAuth, valid for one year.
    pub fn leaf_for(&self, host: &str) -> Result<Arc<CertifiedKey>> {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        let now = OffsetDateTime::now_utc();
        {
            let leaves = self.leaves.lock().unwrap_or_else(|p| p.into_inner());
            if let Some(hit) = leaves.get(&host)
                && now < hit.renew_after
            {
                return Ok(hit.key.clone());
            }
        }
        let key = self.issue(&host)?;
        let mut leaves = self.leaves.lock().unwrap_or_else(|p| p.into_inner());
        if leaves.len() >= LEAF_CACHE_MAX {
            leaves.clear();
        }
        let entry = leaves.entry(host).or_insert(CachedLeaf {
            key,
            renew_after: now + Duration::days(LEAF_VALIDITY_DAYS - LEAF_RENEW_MARGIN_DAYS),
        });
        Ok(entry.key.clone())
    }

    /// Sign a fresh leaf for `host` (no cache).
    fn issue(&self, host: &str) -> Result<Arc<CertifiedKey>> {
        let key = KeyPair::generate().context("generating a leaf key")?;
        let mut params = CertificateParams::new(vec![host.to_string()])
            .with_context(|| format!("invalid host name for a certificate: {host:?}"))?;
        params.distinguished_name.push(DnType::CommonName, host);
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.use_authority_key_identifier_extension = true;
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::hours(1);
        params.not_after = now + Duration::days(LEAF_VALIDITY_DAYS);
        params.serial_number = Some(random_serial());
        let cert = params
            .signed_by(&key, &self.issuer)
            .context("signing a leaf certificate")?;
        let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let signer = rustls::crypto::ring::sign::any_supported_type(&der)
            .map_err(|e| anyhow!("loading a leaf key: {e}"))?;
        Ok(Arc::new(CertifiedKey::new(
            vec![cert.der().clone()],
            signer,
        )))
    }

    /// Verify `leaf` as a server certificate for `name` under this CA alone.
    fn check_leaf(&self, leaf: &CertifiedKey, name: &str) -> Result<()> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(self.cert_der.clone())
            .map_err(|e| anyhow!("CA certificate unusable as a root: {e}"))?;
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()?;
        verifier
            .verify_server_cert(
                &leaf.cert[0],
                &leaf.cert[1..],
                &ServerName::try_from(name.to_string())?,
                &[],
                UnixTime::now(),
            )
            .map_err(|e| anyhow!("{e}"))?;
        Ok(())
    }
}

/// A random positive 128-bit serial number.
fn random_serial() -> SerialNumber {
    let mut bytes: [u8; 16] = rand::random();
    bytes[0] &= 0x7f;
    bytes[0] |= 0x01;
    SerialNumber::from_slice(&bytes)
}

impl std::fmt::Debug for Ca {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ca").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::WebPkiServerVerifier;
    use rustls::client::danger::ServerCertVerifier;
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, ServerName, UnixTime};

    /// Does `leaf` verify as a server certificate for `name` under `ca_pem`?
    fn verifies(ca_pem: &str, leaf: &CertifiedKey, name: &str) -> bool {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(ca_pem.as_bytes()).unwrap())
            .unwrap();
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();
        verifier
            .verify_server_cert(
                &leaf.cert[0],
                &leaf.cert[1..],
                &ServerName::try_from(name.to_string()).unwrap(),
                &[],
                UnixTime::now(),
            )
            .is_ok()
    }

    #[test]
    fn leaf_verifies_for_its_host_only() {
        let ca = Ca::generate().unwrap();
        let leaf = ca.leaf_for("chat.test").unwrap();
        assert!(verifies(&ca.cert_pem(), &leaf, "chat.test"));
        assert!(!verifies(&ca.cert_pem(), &leaf, "other.test"));
        // A different CA does not vouch for it.
        let stranger = Ca::generate().unwrap();
        assert!(!verifies(&stranger.cert_pem(), &leaf, "chat.test"));
    }

    #[test]
    fn leaves_are_cached_per_host_case_insensitively() {
        let ca = Ca::generate().unwrap();
        let a = ca.leaf_for("chat.test").unwrap();
        let b = ca.leaf_for("CHAT.Test").unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        let c = ca.leaf_for("x.chat.test").unwrap();
        assert!(!Arc::ptr_eq(&a, &c));
    }

    #[test]
    fn pem_round_trip_signs_leaves_the_original_cert_vouches_for() {
        let ca = Ca::generate().unwrap();
        assert!(ca.cert_pem().contains("BEGIN CERTIFICATE"));
        assert!(ca.key_pem().contains("PRIVATE KEY"));
        let again = Ca::from_pem(&ca.cert_pem(), &ca.key_pem()).unwrap();
        assert_eq!(again.cert_pem(), ca.cert_pem());
        let leaf = again.leaf_for("claude.ai").unwrap();
        assert!(verifies(&ca.cert_pem(), &leaf, "claude.ai"));
    }

    #[test]
    fn from_pem_rejects_a_key_that_is_not_the_cas() {
        let a = Ca::generate().unwrap();
        let b = Ca::generate().unwrap();
        assert!(Ca::from_pem(&a.cert_pem(), &b.key_pem()).is_err());
        assert!(Ca::from_pem("not a cert", &a.key_pem()).is_err());
    }

    #[test]
    fn leaf_is_a_one_year_server_auth_certificate() {
        use x509_parser::prelude::*;
        let ca = Ca::generate().unwrap();
        let leaf = ca.leaf_for("chat.test").unwrap();
        let (_, x) = X509Certificate::from_der(&leaf.cert[0]).unwrap();
        let days =
            (x.validity().not_after.timestamp() - x.validity().not_before.timestamp()) / 86_400;
        assert!((365..=367).contains(&days), "validity {days} days");
        let eku = x.extended_key_usage().unwrap().unwrap().value;
        assert!(eku.server_auth);
        assert!(!x.is_ca());
        let san = x.subject_alternative_name().unwrap().unwrap().value;
        assert!(
            san.general_names
                .iter()
                .any(|n| matches!(n, GeneralName::DNSName("chat.test")))
        );
        // The CA itself is a CA, valid ~10 years.
        let ca_der = CertificateDer::from_pem_slice(ca.cert_pem().as_bytes()).unwrap();
        let (_, c) = X509Certificate::from_der(&ca_der).unwrap();
        assert!(c.is_ca());
        let years = (c.validity().not_after.timestamp() - c.validity().not_before.timestamp())
            / (365 * 86_400);
        assert!(years >= 10);
    }

    #[test]
    fn ip_hosts_get_an_ip_san() {
        let ca = Ca::generate().unwrap();
        let leaf = ca.leaf_for("127.0.0.1").unwrap();
        assert!(verifies(&ca.cert_pem(), &leaf, "127.0.0.1"));
    }
}
