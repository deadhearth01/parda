//! Regression guard: parda's upstream client must never trust the OS
//! certificate store, because that store will hold parda's own CA once the
//! user runs `parda ca install`. `upstream_client_builder()` asks reqwest
//! for its built-in webpki (Mozilla) roots only, but a crate elsewhere in
//! the workspace could still unify a reqwest/rustls feature that loads the
//! OS store. This test fails as soon as such a loader enters Cargo.lock.

/// Crates that load or verify against the OS trust store.
const OS_ROOT_LOADERS: &[&str] = &[
    "rustls-native-certs",
    "rustls-platform-verifier",
    "native-tls",
    "tokio-native-tls",
    "hyper-tls",
    "openssl-probe",
];

/// Known, reviewed users of macOS security-framework (none load TLS roots):
/// keyring stores the vault key in the login keychain.
const SECURITY_FRAMEWORK_USERS: &[&str] = &["keyring", "security-framework"];

/// Problems found in a Cargo.lock text: OS root loaders present, and
/// unreviewed users of security-framework.
fn os_trust_problems(lock: &str) -> Vec<String> {
    let mut problems = Vec::new();
    for block in lock.split("[[package]]").skip(1) {
        let mut name = None;
        let mut deps = Vec::new();
        let mut in_deps = false;
        for line in block.lines().map(str::trim) {
            if in_deps {
                if line.starts_with(']') {
                    in_deps = false;
                } else {
                    // ` "security-framework 2.11.1",` → security-framework
                    let dep = line.trim_matches(|c| c == '"' || c == ',');
                    deps.push(dep.split(' ').next().unwrap_or("").to_string());
                }
            } else if let Some(v) = line.strip_prefix("name = ") {
                name = Some(v.trim_matches('"').to_string());
            } else if line.starts_with("dependencies = [") {
                in_deps = true;
            }
        }
        let Some(name) = name else { continue };
        if OS_ROOT_LOADERS.contains(&name.as_str()) {
            problems.push(format!(
                "{name} is in Cargo.lock: it loads or verifies against the OS trust store"
            ));
        }
        if deps.iter().any(|d| d == "security-framework")
            && !SECURITY_FRAMEWORK_USERS.contains(&name.as_str())
        {
            problems.push(format!(
                "{name} depends on security-framework and is not a reviewed user \
                 (see SECURITY_FRAMEWORK_USERS)"
            ));
        }
    }
    problems
}

#[test]
fn workspace_has_no_os_root_store_loader() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock");
    let lock = std::fs::read_to_string(path).expect("workspace Cargo.lock");
    let problems = os_trust_problems(&lock);
    assert!(
        problems.is_empty(),
        "parda's upstream client could end up trusting the OS store (and so parda's own CA): {problems:?}"
    );
}

#[test]
fn the_guard_catches_os_root_store_loaders() {
    let lock = r#"
[[package]]
name = "reqwest"
version = "0.12.28"
dependencies = [
 "rustls-native-certs",
 "webpki-roots",
]

[[package]]
name = "rustls-native-certs"
version = "0.8.1"
dependencies = [
 "security-framework 3.5.1",
]

[[package]]
name = "keyring"
version = "3.6.3"
dependencies = [
 "security-framework 2.11.1",
]

[[package]]
name = "security-framework"
version = "3.5.1"
"#;
    let problems = os_trust_problems(lock);
    assert_eq!(problems.len(), 2, "{problems:?}");
    assert!(problems.iter().any(|p| p.contains("rustls-native-certs")));
    assert!(
        problems
            .iter()
            .any(|p| p.contains("security-framework") && p.contains("rustls-native-certs"))
    );
}
