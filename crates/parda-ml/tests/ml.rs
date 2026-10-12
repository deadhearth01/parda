use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;

use parda_core::EntityKind;
use parda_ml::{ModelManager, catalog, default_model_id, find_model, ml_labels};

#[test]
fn catalog_default_is_permissive_and_present() {
    let d = find_model(default_model_id()).expect("default model in catalog");
    assert!(["apache-2.0", "mit"].contains(&d.license), "{}", d.license);
    for m in catalog() {
        assert!(!m.files.is_empty(), "{} has no files", m.id);
        for f in m.files {
            assert!(f.url.starts_with("https://"), "{}: {}", m.id, f.url);
        }
    }
}

#[test]
fn label_map_covers_people_and_leaves_formats_to_rules() {
    let labels = ml_labels();
    let kind = |l: &str| labels.iter().find(|(x, _)| *x == l).map(|(_, k)| k.clone());
    assert_eq!(kind("person"), Some(EntityKind::Person));
    assert_eq!(kind("address"), Some(EntityKind::Address));
    // Checksum-bearing identifiers are the rule tier's job.
    assert!(kind("aadhaar number").is_none());
    assert!(
        kind("organization").is_none(),
        "organizations are not redacted by default in v0.1"
    );
}

fn write(dir: &Path, name: &str, bytes: &[u8]) {
    std::fs::create_dir_all(dir.join(name).parent().unwrap()).unwrap();
    std::fs::write(dir.join(name), bytes).unwrap();
}

#[test]
fn import_verifies_manifest_and_installs() {
    let src = tempfile::tempdir().unwrap();
    let root = tempfile::tempdir().unwrap();
    write(src.path(), "model_quint8.onnx", b"onnx-bytes");
    write(src.path(), "tokenizer.json", b"{}");
    write(src.path(), "gliner_config.json", b"{}");
    let manifest = serde_json::json!({ "files": {
        "model_quint8.onnx": { "sha256": parda_ml::sha256_hex(b"onnx-bytes"), "size": 10 },
        "tokenizer.json": { "sha256": parda_ml::sha256_hex(b"{}"), "size": 2 },
        "gliner_config.json": { "sha256": parda_ml::sha256_hex(b"{}"), "size": 2 },
    }});
    write(src.path(), "manifest.json", manifest.to_string().as_bytes());

    let mm = ModelManager::new(root.path());
    mm.import("parda-pii-edge", src.path()).unwrap();
    assert!(mm.is_installed("parda-pii-edge"));
    assert!(
        mm.model_dir("parda-pii-edge")
            .join("model_quint8.onnx")
            .exists()
    );

    // Tampered file is rejected.
    write(src.path(), "tokenizer.json", b"{\"evil\":1}");
    let root2 = tempfile::tempdir().unwrap();
    let err = ModelManager::new(root2.path())
        .import("parda-pii-edge", src.path())
        .unwrap_err();
    assert!(err.to_string().contains("sha256"), "{err}");
}

/// Serve `body` once on 127.0.0.1 and return the URL.
fn serve_once(body: Vec<u8>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf);
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(head.as_bytes());
            let _ = s.write_all(&body);
        }
    });
    format!("http://{addr}/file")
}

#[test]
fn download_checks_sha256() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("f.bin");
    let ok_url = serve_once(b"hello".to_vec());
    parda_ml::download_verified(
        &ok_url,
        &dest,
        &parda_ml::sha256_hex(b"hello"),
        5,
        &|_, _| {},
    )
    .unwrap();
    assert_eq!(std::fs::read(&dest).unwrap(), b"hello");

    let bad_url = serve_once(b"hellO".to_vec());
    let dest2 = dir.path().join("g.bin");
    let err = parda_ml::download_verified(
        &bad_url,
        &dest2,
        &parda_ml::sha256_hex(b"hello"),
        5,
        &|_, _| {},
    )
    .unwrap_err();
    assert!(err.to_string().contains("sha256"), "{err}");
    assert!(
        !dest2.exists(),
        "partial/bad file must not be left in place"
    );
}

/// Runs only when PARDA_TEST_MODEL_DIR points at an installed GLiNER model dir.
#[test]
#[ignore]
fn gliner_detects_indian_and_global_names() {
    let Ok(dir) = std::env::var("PARDA_TEST_MODEL_DIR") else {
        return;
    };
    let det =
        parda_ml::GlinerDetector::load(Path::new(&dir), 0.5, parda_ml::ExecutionProvider::Cpu)
            .unwrap();
    use parda_core::MlDetector;
    let texts = [
        "Please call Venkatesh Iyer tomorrow.",
        "Email Siobhan O'Brien about the refund.",
        "नमस्ते, मैं Ravi Kumar हूँ 🙏",
    ];
    let out = det.detect_batch(&texts).unwrap();
    for (t, dets) in texts.iter().zip(&out) {
        assert!(
            dets.iter().any(|d| d.kind == EntityKind::Person),
            "no person in {t:?}: {dets:?}"
        );
        for d in dets {
            assert!(t.is_char_boundary(d.span.start) && t.is_char_boundary(d.span.end));
        }
    }
    let span = &out[0]
        .iter()
        .find(|d| d.kind == EntityKind::Person)
        .unwrap()
        .span;
    assert_eq!(&texts[0][span.start..span.end], "Venkatesh Iyer");
}
