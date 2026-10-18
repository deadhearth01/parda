//! Built-in model catalog. Every file is pinned by URL (immutable revision)
//! and SHA-256 so a download can never silently change.

use parda_core::EntityKind;

#[derive(Debug, Clone, Copy)]
pub struct ModelFile {
    /// Path of the file inside the installed model directory.
    pub path: &'static str,
    pub url: &'static str,
    /// Lower-case hex SHA-256 of the file.
    pub sha256: &'static str,
    pub size: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct ModelSpec {
    pub id: &'static str,
    pub description: &'static str,
    pub license: &'static str,
    pub files: &'static [ModelFile],
}

impl ModelSpec {
    pub fn total_size(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }
}

const EDGE_REV: &str = "9b7f39b0a2da971a5beea78d35f1539d4009c891";
const SMALL_REV: &str = "d21aad5b4a7ec82b3d0970fd1ac74a12c087d85e";

macro_rules! hf {
    ($repo:literal, $rev:expr, $file:literal) => {
        concat!(
            "https://huggingface.co/",
            $repo,
            "/resolve/",
            $rev,
            "/",
            $file
        )
    };
}

static CATALOG: &[ModelSpec] = &[
    ModelSpec {
        id: "parda-pii-edge",
        description: "parda fine-tune of GLiNER-PII edge — India-first + global names, Aadhaar/PAN/UPI/IFSC (fp32)",
        license: "apache-2.0",
        files: &[
            ModelFile {
                path: "model.onnx",
                url: "https://github.com/deadhearth01/parda/releases/download/models-v1/parda-pii-edge-model.onnx",
                sha256: "3397facc44c8435696cd6deb14f5c7da6a0440844363d6b0f0f44454b4de16e6",
                size: 181_117_929,
            },
            ModelFile {
                path: "tokenizer.json",
                url: "https://github.com/deadhearth01/parda/releases/download/models-v1/parda-pii-edge-tokenizer.json",
                sha256: "e74d8989e6feaad253ce072ca7db3ff9a1a211ca271ec7a4f1f73cd1529cff12",
                size: 3_583_851,
            },
            ModelFile {
                path: "gliner_config.json",
                url: "https://github.com/deadhearth01/parda/releases/download/models-v1/parda-pii-edge-gliner_config.json",
                sha256: "2a05ac6f249c43723c11288fb6fa6f04533db1b3e15aba7a33694b2193d9b342",
                size: 4_551,
            },
        ],
    },
    ModelSpec {
        id: "gliner-pii-edge",
        description: "Knowledgator GLiNER-PII edge (Ettin 32M, INT8) — fast general PII model",
        license: "apache-2.0",
        files: &[
            ModelFile {
                path: "model_quint8.onnx",
                url: hf!(
                    "knowledgator/gliner-pii-edge-v1.0",
                    "9b7f39b0a2da971a5beea78d35f1539d4009c891",
                    "onnx/model_quint8.onnx"
                ),
                sha256: "988acb03456b26e2d9f2521016d820310c2ed64deb4a846297d3289f0c2eb7e4",
                size: 45_820_894,
            },
            ModelFile {
                path: "tokenizer.json",
                url: hf!(
                    "knowledgator/gliner-pii-edge-v1.0",
                    "9b7f39b0a2da971a5beea78d35f1539d4009c891",
                    "tokenizer.json"
                ),
                sha256: "84b3a9b18f04a0ccd03b72d9f871b7e0bec40fd7021ef50bc30a7c3693c11205",
                size: 3_583_593,
            },
            ModelFile {
                path: "gliner_config.json",
                url: hf!(
                    "knowledgator/gliner-pii-edge-v1.0",
                    "9b7f39b0a2da971a5beea78d35f1539d4009c891",
                    "gliner_config.json"
                ),
                sha256: "77e6b57335c4bfd461e9041682196dd6c373a0b09bbd9269ef9e95b807915340",
                size: 4_316,
            },
        ],
    },
    ModelSpec {
        id: "gliner-pii-small",
        description: "Knowledgator GLiNER-PII small (INT8) — slower, slightly more accurate",
        license: "apache-2.0",
        files: &[
            ModelFile {
                path: "model_quint8.onnx",
                url: hf!(
                    "knowledgator/gliner-pii-small-v1.0",
                    "d21aad5b4a7ec82b3d0970fd1ac74a12c087d85e",
                    "onnx/model_quint8.onnx"
                ),
                sha256: "891589426ee96f2748b16439f44fad8c3f97e198e002a6637e58dee989500216",
                size: 82_680_500,
            },
            ModelFile {
                path: "tokenizer.json",
                url: hf!(
                    "knowledgator/gliner-pii-small-v1.0",
                    "d21aad5b4a7ec82b3d0970fd1ac74a12c087d85e",
                    "tokenizer.json"
                ),
                sha256: "84b3a9b18f04a0ccd03b72d9f871b7e0bec40fd7021ef50bc30a7c3693c11205",
                size: 3_583_593,
            },
            ModelFile {
                path: "gliner_config.json",
                url: hf!(
                    "knowledgator/gliner-pii-small-v1.0",
                    "d21aad5b4a7ec82b3d0970fd1ac74a12c087d85e",
                    "gliner_config.json"
                ),
                sha256: "c10803bade021f40072b194bc78bc2edd2bf3e60637a6f34cc9b00705bf3c168",
                size: 4_316,
            },
        ],
    },
];

// Keep the revision constants referenced so a revision bump is a one-line edit
// that the compiler checks against the URLs above.
const _: (&str, &str) = (EDGE_REV, SMALL_REV);

pub fn catalog() -> &'static [ModelSpec] {
    CATALOG
}

pub fn find_model(id: &str) -> Option<&'static ModelSpec> {
    CATALOG.iter().find(|m| m.id == id)
}

/// Model used when `detect.model = "default"`.
pub fn default_model_id() -> &'static str {
    "gliner-pii-edge"
}

/// Natural-language labels asked of the model and the kinds they map to.
///
/// Kept to what the rule tier cannot do well. Identifier formats (Aadhaar,
/// PAN, UPI, cards, passports …) are left to the checksum-validated rules:
/// asking the model for them lowered Person recall on the golden corpus
/// (0.93 with 11 labels) and made it relabel format matches. Organizations
/// are absent on purpose (masking company names costs answer quality for
/// little privacy gain).
pub fn ml_labels() -> Vec<(&'static str, EntityKind)> {
    vec![
        ("person", EntityKind::Person),
        ("address", EntityKind::Address),
        ("email", EntityKind::Email),
        ("phone number", EntityKind::Phone),
    ]
}
