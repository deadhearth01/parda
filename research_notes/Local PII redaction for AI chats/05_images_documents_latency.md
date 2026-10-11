# Notes: image PII, document PII, and the latency budget

## Latency budget = what the user already waits for
- LLM time-to-first-token (kunalganglani.com, 2026-03 test, medium prompt, streaming): Gemini 2.5 Flash ~450 ms, Claude Haiku 4.5 ~597 ms, Claude Sonnet 4 ~900 ms, GPT-4.1 ~1,100 ms, GPT-4.1 Mini ~2,400 ms. Reasoning/frontier models much longer (AA: GPT-5.5 high TTFT 27.9 s; Gemini 3.5 Flash 15–18 s).
- Nielsen: <1 s keeps flow. => A text-redaction overhead of 1–30 ms is 0.1–5% of TTFT (imperceptible). Image/doc processing should be done BEFORE send (at attach/paste time, while user types the prompt) so the send path adds ~0.

## Native OCR (fast, zero model download)
- Apple Vision VNRecognizeTextRequest: `.fast` (live camera) vs `.accurate`; runs on Neural Engine; blakecrosley.com (2026-05): "returns results in 100–300 ms locally". atomicrobot: fast ≈ instant, accurate ≈ 3 s on one large image (older device). WWDC25 adds RecognizeDocumentsRequest (paragraphs, tables). Vision also: face rectangles/landmarks, barcode/QR (VNDetectBarcodesRequest, ms), document segmentation, saliency.
- Windows AI Text Recognition API (Microsoft.Windows.AI.Imaging): "run exclusively on devices with an NPU", faster+more accurate than legacy Windows.Media.Ocr; legacy Windows.Media.Ocr available on all Win10/11 as fallback. Returns words/lines/polygons/confidence.
- Linux: no system OCR => bundle ONNX OCR.

## Portable OCR (ONNX)
- PP-OCRv6 (arXiv 2606.13108, 2026-06): tiny 1.5M params (det 0.43M + rec 1.1M), small, medium 34.5M. 50 languages (tiny omits Japanese). End-to-end per-image seconds (Table 9, incl. I/O): Apple M4 ONNX Runtime — tiny 0.35 s, small 1.29 s, medium 5.55 s; Intel Xeon 8350C ONNX — tiny 0.22, small 0.61; OpenVINO tiny 0.20. Detection CPU ONNX @2048px: tiny 317 ms, small 654 ms. Lower hallucination than VLMs (93.2% vs 80.6% Qwen3-VL-235B).
- faster-paddle (PyPI, Rust + ORT, PP-OCRv6 tiny/small/medium bundled; batch OCR; det_max_side param) — shows a Rust path exists.
- RapidOCR (ONNX PaddleOCR, multi-platform). monkt/paddleocr-onnx on HF.
- VLM OCR (PaddleOCR-VL 0.9B, GLM-OCR, MinerU) top OmniDocBench but too heavy for real time.

## Visual PII detection WITHOUT OCR (key finding)
- WebPII (arXiv 2603.17357, 2026-03, Nathan Zhao): 44,865 annotated synthetic e-commerce UI screenshots; taxonomy incl. transaction-level IDs; "anticipatory detection for partially-filled forms". Trained detector **WebRedact: mAP@50 0.753 vs 0.357 for OCR-text-extraction baseline, at ~20 ms CPU latency**. Dataset + model released.
- => For screenshots, a direct object-detector (YOLO-style) on pixels beats OCR→NER on both accuracy and speed. Use OCR+NER as second pass for long text/doc images.
- MultiPriv (ICML 2026) — multilingual multimodal PII dataset & VLM privacy-reasoning benchmark (images with faces, ID numbers, plates). DualTAP (ECCV 2026) — protector for mobile MLLM agents.
- VizWiz-Priv dataset (private objects in photos from blind users); Privacy-aware VLMs (arXiv 2405.17423).
- Faces: YuNet (~75K params, 228 KB ONNX, Apache-2.0, "millisecond-level" on CPU; paper benchmarks via ONNX Runtime CPU); BlazeFace 0.6 ms on mobile GPU; SCRFD more accurate, larger. Apple Vision face rectangles built in.
- License plates: YOLO-family detectors (many papers/datasets); Indian plate formats too.
- Barcodes/QR can carry PII (payment UPI QR, boarding passes) => decode & treat payload as text.

## Presidio Image Redactor (reference design)
- Beta, "not production ready". Tesseract OCR → Presidio analyzer on text → map entities to OCR word boxes → paint boxes. DICOM pixel redaction separate from metadata scrub. Python + spaCy lg.

## Documents
- pdf_oxide (Rust+Python, MIT): 0.8 ms mean text extraction (5× PyMuPDF, 100% pass on 3,830 PDFs), char/span bboxes, reading order, image extraction, forms/annotations, incremental save, **"True/destructive redaction + document sanitization" (#231)**. No AGPL (PyMuPDF/MuPDF are AGPL — avoid for permissive OSS).
- `mupdf` Rust crate exists (AGPL concern). pypdfium2 Apache-2.0 4.1 ms.
- Office: DOCX/XLSX/PPTX are ZIP+XML — text runs can be rewritten in place; must also scrub comments, tracked changes (w:ins/w:del), headers/footers, footnotes, alt-text, embedded images (→ image pipeline), docProps/core.xml (author, lastModifiedBy), custom XML. Microsoft "Document Inspector" lists these hidden-data categories.
- Docling (IBM), MarkItDown (MS), Unstructured: good for conversion but Python & slower (markitdown 108 ms/PDF in pdf_oxide table).
- Scanned PDFs → rasterize page → image pipeline (OCR boxes) → burn-in redaction → rebuild PDF (drop original image + text layer).
- Metadata: EXIF/GPS/XMP/IPTC in JPEG/PNG/HEIC/WebP; PDF Info dict + XMP; Office docProps. Tools: exiftool (reference), mat2 (metadata anonymisation toolkit). Re-encode or chunk-strip.

## Small local LLM anonymizer (alternative / fallback tier)
- Eternis "Anonymizer SLM" (HF blog 2025-08-27): Qwen3 0.6B/1.7B/4B fine-tuned (SFT → DPO → GRPO w/ GPT-4.1 judge). Scores (0–10 judge): 4B 9.55, 1.7B 9.20, 0.6B 5.96 vs GPT-4.1 9.77. TTFT <250 ms; total <1 s (1.7B), <2 s (4B) on Mac with quantization + speculative decoding. Rules: names → culturally similar; companies → same industry/size fictional; small towns → synthetic; dates shifted consistently; money ×0.8–1.25; IDs format-valid random. Public figures kept. App: Silo.
- PAPILLON (prompt rewriting by local 8B): quality 85%, 7.5% leakage — free-form rewriting is worse than surgical replacement.
- => SLM is too slow for the hot path but useful as (a) optional "deep mode" for long/ambiguous text, (b) offline teacher to generate training data/distill into a fast encoder.

## Transformer speed on accelerators
- Apple ml-ane-transformers: DistilBERT optimized for ANE → up to 10× faster, 14× less memory; 3.47 ms at 0.454 W on iPhone 13 (Apple ML Research 2022). => a DistilBERT-class PII tagger can run in single-digit ms on Apple silicon ANE if converted with ANE-friendly layout.
- Windows Copilot+ NPUs (Hexagon/Intel/AMD) via DirectML/QNN/OpenVINO EPs.

## Additions: screen/visual PII models (fetched 2026-10-11)
- WebPII project page (webpii.github.io): 44,865 images, 10 e-commerce sites, 19 page types, 993,461 boxes. Held-out Amazon layouts:
  | Method | mAP@50 | Latency |
  | OCR + Presidio | 0.183 | 1,300 ms |
  | LayoutLMv3 + GPT-4o-mini | 0.357 | 2,900 ms |
  | WebRedact | 0.753 | 20 ms (30 FPS) |
  | WebRedact-large | 0.842 | 312 ms |
  License of released model not stated on page — verify before bundling.
- screenpipe/pii-image-redactor (HF): RF-DETR ONNX ~109 MB, 12 classes (private_person/email/phone/address/url/company/repo/handle/channel/id/date, secret). ScreenLeak region zero-leak 98.9% vs Gemini 3.1 Pro 4.2%, GPT-5.5 3.2%, Google DLP 2.6%, Claude Opus 4.7 2.1%, Presidio 0.5% (IoU≥0.30; in-distribution upper bound). ~120 ms p50 Apple Silicon CoreML; same ONNX on CoreML/DirectML/CUDA/CPU. **License CC BY-NC 4.0 (non-commercial)**.
- screenpipe/pii-redactor (HF, text): token classifier for AX-tree dumps, OCR'd screen text, computer-use traces. 278 MB INT8 ONNX, **~9 ms p50 CPU**, offline; Transformers.js q8 in browser. ScreenLeak (n=422 strings) zero-leak: Gemini 3.1 Pro 91.0, GPT-5.5 90.7, Claude Opus 4.7 87.8, **this 86.7**, Google DLP 37.7, Presidio 35.4. Tip: redact per fragment (one AX node/OCR line) — big blobs degrade recall. **CC BY-NC 4.0**. Benchmark: github.com/screenpipe/screenleak.
- => Two strong reference designs exist but non-commercial licenses => an Apache/MIT project must train its own (WebPII data + synthetic UI generation + ScreenLeak for eval) or make these optional user-downloaded models.

## Indian PII data
- somukandula/maskara-indian-pii-200k (HF dataset, "Maskara v2"): synthetic Indian PII incl. Hinglish/WhatsApp style, locales en-IN/hi-IN/en-US, labels PERSON_NAME, PHONE, EMAIL, UPI_ID, PAN_CARD, AADHAAR, VEHICLE_REG, DRIVER_LICENSE, DATE_OF_BIRTH, ADDRESS; includes hard negatives. License to verify.
- indic-pii (PyPI) — lightweight Indian-specific PII regex library (page didn't load; unverified).
- arXiv 2504.12308 "Unmasking the Reality of PII Masking Models" (Singh 2025) — diverse PII dataset to test open-source maskers (not read).
- UPI IDs (name@okbank, @ybl, @upi) are a key India-specific identifier not in Presidio's list.

## WebRedact caveat (from paper §2.4/§3, arXiv 2603.17357v1 HTML)
- Trained on only **2 coarse classes: text (all text elements incl. PII fields, product descriptions, order info) and image (product images)** — it localizes content regions, it does not classify PII types. Pairs naturally with OCR+NER on the detected regions for typing/surrogates.
- 640×640 input (base), 1280×1280 (large); OpenVINO CPU; GPU <5 ms (base), ~13 ms (large) on RTX 30xx. Tesseract OCR alone = 453 ms.
- Partial-fill images mAP 0.943 (anticipatory detection works best while user is typing). English e-commerce only.
