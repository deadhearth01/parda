//! Adding parda's root certificate to (and removing it from) the user's OS
//! trust store. The OS shows its own confirmation or password dialog; parda
//! never handles that password. Certificates are addressed by their SHA-1
//! fingerprint, never by name, so another certificate with the same name is
//! never touched.

use std::path::{Path, PathBuf};

use anyhow::Context;
use base64::Engine as _;
use sha1::{Digest, Sha1};

use crate::system::{Platform, Runner};

fn login_keychain() -> PathBuf {
    let home = directories::BaseDirs::new()
        .map(|b| b.home_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap_or_default()));
    home.join("Library/Keychains/login.keychain-db")
}

/// Upper-case hex SHA-1 of the DER certificate in a PEM file (the
/// "thumbprint" both macOS and Windows tools accept).
pub fn fingerprint(pem: &Path) -> anyhow::Result<String> {
    let text =
        std::fs::read_to_string(pem).with_context(|| format!("reading {}", pem.display()))?;
    let b64: String = text
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END CERTIFICATE-----"))
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .context("the certificate file is not a PEM certificate")?;
    Ok(Sha1::digest(&der)
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect())
}

/// Whether the certificate at `pem` is trusted by the OS for this user.
pub fn is_trusted(r: &mut dyn Runner, platform: Platform, pem: &Path) -> bool {
    match platform {
        Platform::MacOs => r
            .run("security", &["verify-cert", "-c", &pem.to_string_lossy()])
            .is_ok(),
        Platform::Windows => fingerprint(pem).is_ok_and(|fp| {
            r.run("certutil", &["-user", "-verifystore", "Root", &fp])
                .is_ok()
        }),
        Platform::Linux => false,
    }
}

/// Ask the OS to trust the certificate at `pem` for the current user.
pub fn install(r: &mut dyn Runner, platform: Platform, pem: &Path) -> anyhow::Result<()> {
    let pem_s = pem.to_string_lossy();
    match platform {
        Platform::MacOs => {
            let keychain = login_keychain();
            r.run(
                "security",
                &[
                    "add-trusted-cert",
                    "-r",
                    "trustRoot",
                    "-k",
                    &keychain.to_string_lossy(),
                    &pem_s,
                ],
            )?;
        }
        Platform::Windows => {
            r.run("certutil", &["-user", "-addstore", "Root", &pem_s])?;
        }
        Platform::Linux => anyhow::bail!(
            "Linux has no per-user trust store every app reads. Add the certificate to the system store:\n  \
             Debian/Ubuntu: sudo cp '{pem_s}' /usr/local/share/ca-certificates/parda.crt && sudo update-ca-certificates\n  \
             Fedora/RHEL:   sudo cp '{pem_s}' /etc/pki/ca-trust/source/anchors/parda.pem && sudo update-ca-trust\n\
             and import it in Firefox/Chromium certificate settings."
        ),
    }
    Ok(())
}

/// Remove exactly this certificate (and its trust setting) from the OS store.
pub fn uninstall(r: &mut dyn Runner, platform: Platform, pem: &Path) -> anyhow::Result<()> {
    match platform {
        Platform::MacOs => {
            let fp = fingerprint(pem)?;
            let keychain = login_keychain();
            // -t also removes the user trust settings for this certificate.
            r.run(
                "security",
                &[
                    "delete-certificate",
                    "-Z",
                    &fp,
                    "-t",
                    &keychain.to_string_lossy(),
                ],
            )?;
        }
        Platform::Windows => {
            let fp = fingerprint(pem)?;
            r.run("certutil", &["-user", "-delstore", "Root", &fp])?;
        }
        Platform::Linux => anyhow::bail!(
            "remove parda's certificate from the system store: Debian/Ubuntu: \
             sudo rm /usr/local/share/ca-certificates/parda.crt && sudo update-ca-certificates --fresh; \
             Fedora/RHEL: sudo rm /etc/pki/ca-trust/source/anchors/parda.pem && sudo update-ca-trust"
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Rec(Vec<String>);
    impl Runner for Rec {
        fn run(&mut self, program: &str, args: &[&str]) -> anyhow::Result<String> {
            self.0.push(format!("{program} {}", args.join(" ")));
            Ok(String::new())
        }
    }

    fn pem() -> (tempfile::TempDir, PathBuf, String) {
        let ca = parda_intercept::Ca::generate().unwrap();
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("parda-ca.pem");
        std::fs::write(&p, ca.cert_pem()).unwrap();
        let fp: String = Sha1::digest(ca.cert_der().as_ref())
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect();
        (d, p, fp)
    }

    #[test]
    fn fingerprint_is_the_sha1_of_the_der() {
        let (_d, p, fp) = pem();
        assert_eq!(fingerprint(&p).unwrap(), fp);
        assert_eq!(fp.len(), 40);
    }

    #[test]
    fn macos_trusts_in_the_login_keychain_and_removes_by_fingerprint() {
        let (_d, p, fp) = pem();
        let mut r = Rec::default();
        install(&mut r, Platform::MacOs, &p).unwrap();
        assert!(r.0[0].starts_with("security add-trusted-cert -r trustRoot -k "));
        assert!(r.0[0].contains("login.keychain-db"));
        r.0.clear();
        uninstall(&mut r, Platform::MacOs, &p).unwrap();
        assert_eq!(r.0.len(), 1);
        assert!(r.0[0].starts_with(&format!("security delete-certificate -Z {fp} -t ")));
    }

    #[test]
    fn windows_uses_the_user_root_store_by_thumbprint() {
        let (_d, p, fp) = pem();
        let mut r = Rec::default();
        install(&mut r, Platform::Windows, &p).unwrap();
        assert!(r.0[0].starts_with("certutil -user -addstore Root "));
        uninstall(&mut r, Platform::Windows, &p).unwrap();
        assert_eq!(r.0[1], format!("certutil -user -delstore Root {fp}"));
        assert!(is_trusted(&mut r, Platform::Windows, &p));
        assert_eq!(r.0[2], format!("certutil -user -verifystore Root {fp}"));
    }

    #[test]
    fn linux_explains_instead_of_guessing() {
        let (_d, p, _) = pem();
        let mut r = Rec::default();
        let e = install(&mut r, Platform::Linux, &p).unwrap_err();
        assert!(
            e.to_string().contains("update-ca-certificates")
                && e.to_string().contains("update-ca-trust")
        );
        assert!(r.0.is_empty());
    }
}
