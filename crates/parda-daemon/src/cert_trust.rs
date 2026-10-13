//! Adding parda's root certificate to (and removing it from) the user's OS
//! trust store. The OS shows its own confirmation or password dialog; parda
//! never handles that password.

use std::path::Path;

use parda_intercept::CA_NAME;

use crate::sysproxy::{Platform, Runner};

fn login_keychain() -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    format!("{home}/Library/Keychains/login.keychain-db")
}

/// Whether the certificate at `pem` is trusted by the OS.
pub fn is_trusted(r: &mut dyn Runner, platform: Platform, pem: &Path) -> bool {
    let pem = pem.to_string_lossy();
    match platform {
        Platform::MacOs => r.run("security", &["verify-cert", "-c", &pem]).is_ok(),
        Platform::Windows => r
            .run("certutil", &["-user", "-verifystore", "Root", CA_NAME])
            .is_ok(),
        Platform::Linux => false,
    }
}

/// Ask the OS to trust the certificate at `pem` for the current user.
pub fn install(r: &mut dyn Runner, platform: Platform, pem: &Path) -> anyhow::Result<()> {
    let pem = pem.to_string_lossy();
    match platform {
        Platform::MacOs => {
            r.run(
                "security",
                &[
                    "add-trusted-cert",
                    "-r",
                    "trustRoot",
                    "-k",
                    &login_keychain(),
                    &pem,
                ],
            )?;
        }
        Platform::Windows => {
            r.run("certutil", &["-user", "-addstore", "Root", &pem])?;
        }
        Platform::Linux => anyhow::bail!(
            "Linux has no per-user trust store that every app reads. Add {pem} to your system store \
             (e.g. `sudo cp {pem} /usr/local/share/ca-certificates/parda.crt && sudo update-ca-certificates`) \
             and import it in Firefox/Chromium certificate settings."
        ),
    }
    Ok(())
}

/// Remove the certificate from the OS trust store.
pub fn uninstall(r: &mut dyn Runner, platform: Platform, pem: &Path) -> anyhow::Result<()> {
    let pem = pem.to_string_lossy();
    match platform {
        Platform::MacOs => {
            // Drop the trust setting, then the certificate itself.
            let _ = r.run("security", &["remove-trusted-cert", &pem]);
            r.run(
                "security",
                &["delete-certificate", "-c", CA_NAME, &login_keychain()],
            )?;
        }
        Platform::Windows => {
            r.run("certutil", &["-user", "-delstore", "Root", CA_NAME])?;
        }
        Platform::Linux => anyhow::bail!(
            "remove /usr/local/share/ca-certificates/parda.crt and run `sudo update-ca-certificates --fresh`"
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

    #[test]
    fn macos_trusts_in_the_login_keychain_and_removes_by_name() {
        let mut r = Rec::default();
        install(&mut r, Platform::MacOs, Path::new("/x/parda-ca.pem")).unwrap();
        assert!(r.0[0].starts_with("security add-trusted-cert -r trustRoot -k "));
        assert!(r.0[0].ends_with("login.keychain-db /x/parda-ca.pem"));
        r.0.clear();
        uninstall(&mut r, Platform::MacOs, Path::new("/x/parda-ca.pem")).unwrap();
        assert_eq!(r.0[0], "security remove-trusted-cert /x/parda-ca.pem");
        assert!(r.0[1].starts_with(&format!("security delete-certificate -c {CA_NAME} ")));
    }

    #[test]
    fn windows_uses_the_user_root_store() {
        let mut r = Rec::default();
        install(&mut r, Platform::Windows, Path::new("C:/p/parda-ca.pem")).unwrap();
        assert_eq!(r.0[0], "certutil -user -addstore Root C:/p/parda-ca.pem");
        uninstall(&mut r, Platform::Windows, Path::new("C:/p/parda-ca.pem")).unwrap();
        assert_eq!(r.0[1], format!("certutil -user -delstore Root {CA_NAME}"));
    }

    #[test]
    fn linux_explains_instead_of_guessing() {
        let mut r = Rec::default();
        let e = install(&mut r, Platform::Linux, Path::new("/x/parda-ca.pem")).unwrap_err();
        assert!(e.to_string().contains("update-ca-certificates"));
        assert!(r.0.is_empty());
    }
}
