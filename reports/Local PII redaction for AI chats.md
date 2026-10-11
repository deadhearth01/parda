# Local PII redaction for AI chats

**Deep-dive v2 · research date 2026-10-11**

**Question.** How do we build an open-source, local-only tool that filters personal data (names, contacts, IDs, secrets, **plus PII inside images and documents**) *in real time* before it reaches any cloud LLM or AI agent? It must:

- add almost no latency compared to sending without it
- run on Windows, macOS and Linux
- install with one command
- be managed from a TUI
- be better than everything that exists today

Raw notes behind this report live in `research_notes/Local PII redaction for AI chats/` (files 01–06).

---

## 1. Executive summary

1. **Nobody covers the whole problem.** Existing tools each solve one slice:
   - text-only API proxies (rdx, pii-hole, token-proxy, LocalAI MITM)
   - browser extensions for web chat UIs
   - Mac-only clipboard apps (Clipmask, Redactify)
   - enterprise DLP that **blocks** instead of redacting, is slow (Microsoft Purview's paste check takes ~2 s), and rarely inspects pasted screenshots or images

   No open-source, cross-platform tool handles **text + images + documents across agents, browsers and desktop apps with one shared vault**. That gap is the opportunity.

2. **Hiding the latency is an architecture problem, not just a model problem.** Fast LLMs take ~450–900 ms before their first token; reasoning models take seconds. Users also spend seconds typing a prompt *after* pasting or attaching something. If all heavy detection runs **when content enters the composer** (copy, paste, attach, keystroke), the send-time cost is close to zero:
   - a hash lookup plus µs-level regex for text
   - nothing at all for already-scanned images and documents

   For agents that send content without a human pause, the plan is a ~1–10 ms text path and a ~20–120 ms image path. That is a small fraction of the model's own TTFT.

3. **Images need a different detector, not just OCR.** On screenshots, a direct visual detector beats OCR→NER on both speed and accuracy:
   - WebRedact: 0.753 mAP@50 at ~20 ms CPU, vs 0.183 at 1.3 s for OCR+Presidio
   - screenpipe's image model: 98.9% "region zero-leak", ~120 ms on Apple Silicon (in-distribution)

   Best pipeline: visual detector → OCR **only inside detected regions** (native Apple Vision / Windows AI OCR / PP-OCRv6-tiny) → text engine for typing and surrogates → faces (YuNet) → QR/barcodes → metadata stripping.

4. **Documents are mostly a parsing and sanitization problem.** pdf_oxide (MIT, Rust) extracts PDF text in ~0.8 ms mean and supports true destructive redaction. Office files are ZIP+XML that can be rewritten run by run. Scanned pages go through the image pipeline. Hidden data (comments, tracked changes, author fields, EXIF/GPS) must be stripped too.

5. **Text detection is solvable to "very good" only by layering.**
   - user dictionaries and person blocks
   - checksum-validated regex packs, including **India: Aadhaar, PAN, GSTIN, UPI, Voter ID, vehicle numbers**
   - a small fast encoder (≈9 ms CPU class)
   - an optional heavier model (GLiNER2-PII / OpenAI Privacy Filter) or a local small LLM for "deep mode"

   Cross-domain accuracy of every single model is still mediocre (F1 ~0.4–0.55 out of distribution), so layering and user review matter.

6. **Licensing shapes the model plan.** The best screen-specific models (screenpipe text and image) are **CC BY-NC (non-commercial)**. Use Apache-2.0 models by default (OpenAI Privacy Filter, GLiNER2-PII, PP-OCRv6, YuNet), offer the NC models as optional user downloads, and **train and distill your own small models** on open data (ai4privacy, Nemotron-PII, Maskara-Indian-PII, WebPII) to own the quality curve.

7. **Recommended build:** a single **Rust** daemon and CLI with:
   - ONNX Runtime (`ort`) using CoreML/ANE, DirectML/NPU, CUDA/OpenVINO or CPU
   - a **ratatui** TUI
   - **`dist`** installers (`curl | sh`, `irm | iex`, Homebrew, winget, MSI)
   - adapters: API proxy, MITM proxy, browser extension (via Native Messaging), clipboard and hotkey (text **and images**), file "sanitize & copy", accessibility composer guard, CLI filter

---

## 2. Requirements → design principles

| Requirement | Design principle |
|---|---|
| Text + image + document PII | One **engine** with three pipelines that share one **vault**, so "Ravi Kumar" maps to the same surrogate in a prompt, in a screenshot and in a PDF |
| Real time, ~zero added latency | **Shift-left**: scan at copy/paste/attach/type time. Send time is a cache hit. Fast deterministic tier first. Accelerators. Streaming restore with minimal hold-back |
| Local only | All models run on-device; no telemetry; works offline; nothing to sign up for |
| Cross-platform | Rust single binary; per-OS adapters behind traits; same ONNX models on all OSes |
| One-command install | `dist`-generated installers; first-run `pii setup` wizard downloads models |
| Better than existing | Coverage (agents + web + desktop + files) × modalities (text/image/doc) × reversibility (restore real values in answers, streams and tool calls) × transparency (TUI shows exactly what the model saw) |
| TUI-managed | ratatui app: dashboard, live feed, inspector (incl. image previews), rules, vault, surfaces, models, doctor |

---

## 3. Landscape: what exists (and what each lacks)

### 3.1 Text redaction for AI

| Tool | How | Good at | Missing |
|---|---|---|---|
| **claude-code-redact (`rdx`)** (Apache-2.0, Python) | `ANTHROPIC_BASE_URL` proxy; hooks mode | Person blocks (~30 name variants, case-preserving), format-preserving fakes, entropy/context secrets, optional Presidio, VS Code "what Claude sees" view, per-project rules | Anthropic-only, Python, no images/docs, no TUI, no desktop/web coverage |
| **pii-hole** (Docker) | Base-URL proxy + Claude Code plugin | Deterministic tokens, SSE restore incl. tool calls, dashboard, guard hook | Presidio FR/EN only, Docker, no images/docs |
| **token-proxy** (zolderio) | Anthropic proxy | **Context-preserving surrogates** (same-ASN IPs), 80-char SSE tail buffer | Single provider, niche |
| **LocalAI MITM** | `HTTPS_PROXY` + local CA | Works with subscription-login CLIs; NER detector; block mode | Heavy server; masks only (no restore); CA handling is manual |
| **LiteLLM + Presidio**, **Grepture** (OSS proxy + EU SaaS) | Gateway | Multi-provider | Server-style, not a desktop tool |
| **Presidio** (MIT) | Python framework | 50+ recognizers incl. **IN_AADHAAR (checksum), IN_PAN, IN_VOTER, IN_PASSPORT, IN_VEHICLE_REGISTRATION, IN_GSTIN**; pluggable NER | Python, ~15 ms/text, offsets broke 36% of round-trips in one test; vault is DIY |
| **LLM Guard** | Python scanners | Anonymize + Vault + Deanonymize | Slow (100 ms–5 s per model scanner); development slowed |
| **privalyse-mask** (MIT, early) | Library | Semantic placeholders (`{Date_March_1990}`, `{Email_at_company.com}`) | No streaming yet |
| **Browser extensions** (PasteSecure, PiiBlock, PrivacyScrubber, DataAnonymiser…) | DOM hooks | Web chat UIs | Web only; trust problems (malicious "AI" extensions with 900k installs exfiltrated chats in Jan 2026) |
| **Clipmask** (Mac, closed, freemium) | Clipboard + ⌥⌘V | Pinned desktop apps | Mac-only, closed, text only, no restore |
| **Silo / Anonymizer SLM** (Eternis) | Local Qwen3 1.7B/4B rewrites PII | Culturally similar surrogates, date shifting; judge score 9.2–9.55/10 vs GPT-4.1 9.77 | <1–2 s per query; app-specific |

### 3.2 Image and document redaction

| Tool / model | What | Numbers | Notes |
|---|---|---|---|
| **WebRedact** (WebPII, arXiv 2603.17357) | Object detector on screenshots | **0.753 mAP@50 @ ~20 ms CPU**; large 0.842 @ 312 ms; OCR+Presidio 0.183 @ 1.3 s; LayoutLMv3+GPT-4o-mini 0.357 @ 2.9 s | Trained on 2 coarse classes (text regions / images), English e-commerce only. License: verify |
| **screenpipe/pii-image-redactor** | RF-DETR ONNX, 12 PII classes, ~109 MB | **98.9% region zero-leak** on ScreenLeak vs Gemini 3.1 Pro 4.2%, GPT-5.5 3.2%, Presidio 0.5%; ~120 ms p50 CoreML | In-distribution upper bound. **CC BY-NC 4.0** |
| **screenpipe/pii-redactor** (text) | INT8 token classifier for AX trees / OCR lines / computer-use traces | **~9 ms p50 CPU**, 278 MB; ScreenLeak zero-leak 86.7% vs GPT-5.5 90.7%, Presidio 35.4% | **CC BY-NC 4.0**; works best per fragment |
| **Presidio Image Redactor** | Tesseract OCR → Presidio → paint boxes; DICOM | Beta, "not production ready" | Reference design only |
| **Redactify** (Mac/iOS) | Vision OCR + CoreML faces; flattens docs | App Store | Closed |
| **Predact / PII Tools / PII Anomalyzer / Justee / Doc-Redaction** | Document redaction apps | — | Desktop/doc focused, mostly closed or Python |
| **Enterprise AI DLP** (Purview, Strac, LayerX, Jazz…) | Endpoint / browser / proxy | Purview paste check ~2 s; Entra network scan ≤3 MB, **no OCR**, fails open | Mostly **block/warn**, rarely redact. **Pasted screenshots and images rarely covered** (jazz.security matrix). Paid and cloud-tied |

**Takeaway:** a local, open-source tool that redacts (not just blocks) text, screenshots and documents in milliseconds would be first of its kind.

---

## 4. Where data leaves the machine: every interception option

| # | Surface | Mechanism | Covers | OS notes | Verdict |
|---|---|---|---|---|---|
| A | **API base-URL proxy** | `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` → `127.0.0.1` | Claude Code, Codex, SDKs, Cursor custom endpoints, Open WebUI, LibreChat, Ollama-compatible | All | **Must-have** (agents) |
| B | **HTTPS MITM proxy** | `HTTPS_PROXY` + local CA; only allow-listed AI hosts are decrypted, everything else is tunnelled | Subscription-login CLIs (Claude Pro/Max, Codex), Electron apps that honour the system proxy | CA install: Keychain / certutil / update-ca-certificates; Node needs `NODE_EXTRA_CA_CERTS` | **Must-have**, opt-in |
| C | **Browser extension** | MV3 content script on AI origins only; hooks typing, paste, drop, file input; talks to the daemon via **Native Messaging** (no open port that web pages could hit) | chatgpt.com, claude.ai, gemini, perplexity, copilot… text **and file/image uploads**; restores answers in the page | Chrome / Edge / Firefox / Brave | **Must-have** (web) |
| D | **Clipboard + global hotkey** | Scan on copy (text **and images**); "paste-safe" hotkey | **Any** app incl. **certificate-pinned ChatGPT desktop** | Wayland needs data-control protocol / portal shortcuts | **Must-have** (desktop) |
| E | **File "sanitize & copy"** | Finder Quick Action / Explorer context menu / Nautilus script / CLI / watched "outbox" folder | Drag-and-drop uploads of PDFs, DOCX, images into any app | All | **High value** |
| F | **Accessibility composer guard** | AX (macOS) / UIA (Windows) / AT-SPI2 (Linux) via **xa11y** (Rust) watches the focused AI app input; highlights PII; replaces on hotkey | Native desktop chat apps | AXValue set works for native fields; Electron/Chromium inputs are unreliable → fall back to select-all + paste-safe | **Phase 2** |
| G | **CLI filter** | `pii redact < in > out`, `pii wrap -- <cmd>` | Scripts, pipes, logs | All | Cheap, include |
| H | **Agent hooks / MCP** | Claude Code hooks can **block, not rewrite** (anthropics/claude-code#29434 closed "not planned"); MCP never sees outgoing prompts | Guard rails ("block if proxy is down"), explicit `redact_*` tools | — | Complementary only |
| — | Not reachable locally | Cloud-side agent work (Cowork cloud sessions, server-side web fetch, remote MCP connectors) | — | — | Document as a limitation |

**Pinned apps:** the ChatGPT macOS app pins TLS. OpenAI removed the last enterprise exception in April 2026, so MITM (B) **cannot** see it. Cover it with D, E and F.

---

## 5. Detection engine: all options, with recommendations

### 5.1 Text

| Tier | Options | Latency | Recommendation |
|---|---|---|---|
| 0. **User knowledge** | Personal/company dictionaries, person blocks with ~30 variants (rdx idea), allow-lists | µs (Aho-Corasick) | **Yes.** Highest precision; the fix for regional names models miss |
| 1. **Deterministic** | Regex + checksums (Luhn, Verhoeff/Aadhaar, IBAN mod-97, GSTIN), libphonenumber, emails, IP/MAC, URLs, secrets (AWS/GitHub/OpenAI/Anthropic/JWT/PEM, entropy, `password=`), **UPI IDs**, PAN, Voter ID, DL, vehicle reg | ~0.1 ms/text | **Yes.** Port Presidio's recognizer specs to Rust; add India pack |
| 2a. **Fast encoder** (hot path) | Distilled ModernBERT/Ettin-class or DeBERTa-small token classifier, INT8; screenpipe-class models run ~9 ms on CPU; DistilBERT on Apple ANE runs 3.47 ms (Apple research) | ~3–15 ms | **Yes.** Ship your own Apache-2.0 distilled model (see §9) |
| 2b. **Rich model** (async / deep) | **GLiNER2-PII** (Apache-2.0, 42 labels, custom labels at runtime, best OOD F1 0.471 on SPY in Fastino's test); **OpenAI Privacy Filter** (Apache-2.0, 8 labels, F1 96% in-dist, email ~0.99, 128k context, runs in browser); knowledgator GLiNER-PII (edge→large) | 120–200 ms CPU; less on GPU/NPU | Use for **pre-scan while typing**, documents, and "deep mode" |
| 2c. **Local small LLM** | Anonymizer-style Qwen3 1.7B/4B (judge 9.2–9.55/10; TTFT <250 ms; total <1–2 s) | 0.5–2 s | Optional "max privacy" mode and **teacher for distillation**; never on the hot path |
| 3. **Merge + policy** | Widest-span merge, allow-lists, per-type action: mask / surrogate / block / warn; confidence thresholds per type | µs | **Yes** |
| 4. **Human-in-the-loop** | Inline highlights (extension), TUI inspector, "send anyway" | — | **Yes**, for trust |

Facts to design around:

- No model generalizes well across domains. Best cross-domain average F1 is ≈0.54 (Piiranha) / 0.535 (GLiNER v1) on M1 Pro tests. OpenAI Privacy Filter drops from 96% to ~18% F1 on real web data (Tonic). PIIBench's best system scored 0.14.
- Token-classifier offsets from BPE tokenizers include a leading space. Trim them, or round-trip restore breaks.
- Model thresholds differ (GLiNER-large best at 0.7; knowledgator recommends 0.3). Expose them per type and tune on your own eval set.

### 5.2 Images (screenshots, photos, scans)

| Stage | Options | Latency | Recommendation |
|---|---|---|---|
| 1. **Metadata** | Strip EXIF/GPS/XMP/IPTC, PNG text chunks, HEIC metadata (exiftool/mat2 as reference) | <1 ms | Always |
| 2. **Visual PII region detector** | Own detector trained on **WebPII** + synthetic UI renders (anticipatory partial-fill detection works best, 0.943 mAP); screenpipe image model as **optional NC download**; YOLO/RF-DETR family | **~20 ms CPU** (640px) to ~120 ms | **Yes.** First pass on every image; finds candidate regions fast |
| 3. **OCR inside regions only** | **Apple Vision** (`VNRecognizeTextRequest`, ANE, ~100–300 ms full image); **Windows AI Text Recognition** (NPU; legacy `Windows.Media.Ocr` fallback); **PP-OCRv6-tiny** ONNX (1.5M params, 0.22–0.35 s full image on CPU; Apache-2.0) for Linux and fallback | Crops ⇒ much less than full-image | **Yes.** Crop-OCR is the speed trick |
| 4. **Text engine on OCR spans** | Same tiers as §5.1 (use per-line fragments) | ms | Yes, gives types and surrogates |
| 5. **Faces** | Apple Vision face rectangles; **YuNet** (~75K params, 228 KB, Apache-2.0, ms-level CPU); SCRFD for higher accuracy | 1–5 ms | On by default for photos |
| 6. **Barcodes/QR** | Apple Vision barcodes; `rxing`/zxing ports | ms | Decode → run text engine (UPI QR, boarding passes) |
| 7. **Other visual identifiers** | License plates (YOLO), ID-card / signature detectors, handwriting | 10–30 ms | Phase 2 |
| 8. **Render** | **Solid fill** (never blur/pixelate text: Depix/Unredacter recover it); or **surrogate re-render** (paint background, draw the vault surrogate "Arjun Mehta" in matching size) so the model reads consistent fake text that maps back in its answer | ms | Solid by default; surrogate re-render is a **unique feature** |

### 5.3 Documents

| Type | Approach | Speed | Notes |
|---|---|---|---|
| **Text PDFs** | **pdf_oxide** (MIT): spans with bboxes, reading order, **true/destructive redaction**, sanitization, incremental save | ~0.8 ms mean text extraction | Avoid MuPDF/PyMuPDF (AGPL) for a permissive project |
| **Scanned PDFs** | Rasterize page → image pipeline (§5.2) → rebuild page (drop original image and text layer) | ~0.2–1 s/page CPU | Parallel per page; progressive |
| **DOCX / XLSX / PPTX** | Unzip → rewrite text runs in `document.xml`, sheets, slides with surrogates (keep formatting) → also scrub **comments, tracked changes (`w:ins`/`w:del`), headers/footers, footnotes, alt-text, embedded images (→ image pipeline), `docProps/core.xml` author/lastModifiedBy, custom XML** | ms per part | The same categories as Office's Document Inspector |
| **CSV / JSON / code / logs / Markdown** | Structure-aware: per-cell / per-key scanning; column-type inference (a column of Aadhaar numbers → whole column) | µs–ms | Big speed win on tables |
| **Output choices** | (a) sanitized file in the original format, (b) **sanitized Markdown text** (fewer tokens, less risk), (c) block | — | User picks per surface |

---

## 6. Replacement and restoration (the "intelligence-preserving" part)

| Strategy | Example | Best for |
|---|---|---|
| Typed token | `⟦PERSON_1⟧` | Maximum safety; Llama-class models did best with plain masks (Pasch & Cha 2025) |
| Contextual placeholder | `{Date_March_1990}`, `{Email_at_company.com}`, `{Phone_IN_mobile}` | Keeps reasoning (age, domain, country); GPT-4o benefited from context cues |
| **Realistic surrogate** | `Ravi Kumar → Arjun Mehta` (same gender/region/length), valid-format fake phone/PAN/Aadhaar (checksum-valid fakes from a reserved range), same-country IPs | Agents and code: avoids the "model hallucinates a realistic name to fix the placeholder" failure seen with Claude (token-proxy) |
| Shift / scale | Dates shifted consistently; amounts ×0.8–1.25 | Finance and timelines (Anonymizer SLM rules) |
| Block | Refuse | Secrets, full card numbers, Aadhaar (configurable) |

Restoration requirements, all of which are differentiators:

- **Deterministic per scope** (session / project / global), so multi-turn agents that resend history stay coherent. Case-preserving (`JOHN → ARJUN`).
- **Streaming restore**: an Aho-Corasick matcher over active surrogates holds back only the *longest possible partial match*, not a fixed 80 chars.
- **Restore inside `tool_use` JSON args** so the agent writes real values to disk, and keep JSON-schema validity (`format: email` gets a valid fake email).
- **Mask system prompts and tool results too.** One commercial gateway documents that it never masks system prompts and skips output masking when streaming. Ours shouldn't.
- Images and documents use the same vault, so a surrogate rendered into a screenshot is also restored when the model quotes it.

---

## 7. The near-zero-latency playbook

**Budget reality** (measured or vendor-published numbers):

| Operation | Typical cost |
|---|---|
| LLM time-to-first-token, fast models (Gemini 2.5 Flash ~450 ms, Claude Haiku 4.5 ~597 ms, Sonnet 4 ~900 ms, GPT-4.1 ~1.1 s) | **450–1,100 ms** |
| Reasoning / frontier models TTFT | seconds to minutes |
| Regex + checksum tier | ~0.1 ms |
| Small INT8 encoder (CPU) / DistilBERT on ANE | ~9 ms / ~3.5 ms |
| GLiNER-class model (CPU) | 120–200 ms |
| Visual PII detector (CPU, 640px) | ~20 ms (WebRedact) – ~120 ms (screenpipe, CoreML) |
| Apple Vision OCR (full image) | ~100–300 ms |
| PP-OCRv6-tiny (full image, CPU) | ~220–350 ms |
| PDF text extraction (pdf_oxide) | ~0.8 ms mean |
| Microsoft Purview paste check (for comparison) | ~2,000 ms |

**Techniques (combine all):**

1. **Shift-left scanning.** Scan on *copy* (clipboard watcher), *paste/drop/attach* (extension, accessibility), and *keystroke* (debounced, sentence-incremental). By the time the user presses Enter, results are cached.
2. **Content-hash cache.** Agents resend the full history each turn; paragraph/blob hashes make repeated content cost ~0.
3. **Tiered and speculative.** Run the deterministic tier synchronously (µs). Run the ML tiers in parallel. If an ML result for new text isn't ready, either wait (strict mode, bounded to ~15 ms with a fast encoder) or send with tier-0/1 only (fast mode, user-selectable).
4. **Crop, don't scan.** Detector first (~20 ms), then OCR only on detected regions; downscale to model resolution; tile large images across cores.
5. **Accelerators.** `ort` execution providers: CoreML/ANE (Mac), DirectML/QNN/NPU (Windows Copilot+), CUDA/TensorRT/OpenVINO (Linux/Windows). Native OS OCR where available. INT8/FP16 models. Models stay resident and warm. Thread pinning.
6. **Proxy hygiene.** HTTP/2, keep-alive pools to upstream, pass-through streaming, zero-copy for non-AI hosts. Warm upstream connections can offset the proxy hop.
7. **Streaming restore with minimal hold-back** (see §6).
8. **Progressive documents.** Page 1 is ready in ms; the rest streams while the user types; big files are processed in parallel.
9. **SLOs to publish in CI:** added p95 send-path latency ≤ 5 ms for text; ≤ 0 ms for attachments scanned before send; image detector ≤ 50 ms CPU; text-PDF page ≤ 20 ms.

---

## 8. Proposed architecture

```
 ┌──────────────── Inputs (adapters) ───────────────────────────────────────────────┐
 │ A API proxy  B MITM proxy  C Browser ext (Native Messaging)  D Clipboard/hotkey  │
 │ E File sanitize&copy  F Accessibility composer guard  G CLI  H hooks/MCP guard   │
 └───────────────┬──────────────────────────────────────────────────────────────────┘
                 ▼
 ┌──────────────────────── pii daemon (Rust, one binary) ───────────────────────────┐
 │  Router ─► Text pipeline ─────► T0 dict ─► T1 regex/checksum ─► T2a fast encoder │
 │        │                               └──(async)─► T2b GLiNER2/OPF ─► T2c SLM   │
 │        ├► Image pipeline ─► meta strip ─► visual detector ─► crop-OCR ─► text    │
 │        │                     └► faces ─► barcodes ─► render (fill / surrogate)   │
 │        └► Document pipeline ─► PDF (pdf_oxide) / OOXML / CSV / scanned→image     │
 │                                                                                  │
 │  Policy engine (per surface/app/type) · Vault (encrypted, deterministic, TTL)    │
 │  Content-hash cache · Stream restorer (Aho-Corasick) · Audit (counts by default) │
 │  ort EPs: CoreML/ANE · DirectML/NPU · CUDA/OpenVINO · CPU                        │
 └───────────────┬──────────────────────────────────────────────────────────────────┘
                 ▼
          `pii tui` (ratatui)   ·   `pii` CLI   ·   local control API (Unix socket / named pipe)
```

---

## 9. Model strategy and licensing

| Model / asset | Use | License | Ship how |
|---|---|---|---|
| OpenAI Privacy Filter | Text tier 2b; browser fallback (Transformers.js, WebGPU q4) | Apache-2.0 | Optional download |
| GLiNER2-PII (`fastino/gliner2-privacy-filter-PII-multi`; community ONNX exports) | Text tier 2b, custom labels | Apache-2.0 (per Fastino); check each ONNX re-export | Default "rich" model |
| knowledgator GLiNER-PII edge/small/base | Low-RAM alternative | Verify | Optional |
| **Own distilled encoder** (ModernBERT/Ettin-small or DeBERTa-small) | Text tier 2a, hot path | Apache-2.0 (yours) | **Bundled** |
| **Own visual PII detector** (YOLO/RF-DETR on WebPII + synthetic UIs + doc scans) | Image stage 2 | Yours (check WebPII data license) | **Bundled** |
| screenpipe pii-redactor / pii-image-redactor | Best-in-class screen text/image (in-dist) | **CC BY-NC 4.0** | User opt-in download only, flagged non-commercial |
| WebRedact | Screenshot regions | Verify | Optional |
| PP-OCRv6 tiny/small | OCR on Linux / fallback | PaddleOCR Apache-2.0 (verify model card) | Download |
| Apple Vision / Windows AI OCR | Native OCR | OS APIs | Built in |
| YuNet | Faces | Apache-2.0 | Bundled (228 KB) |
| pdf_oxide | PDF parse/redact | MIT | Crate |

**Training your own models (the long-term moat):**

- **Data:** ai4privacy pii-masking-300k/400k, NVIDIA Nemotron-PII, Gretel finance, **Maskara Indian PII 200k** (Hinglish, UPI, PAN, Aadhaar; verify license), WebPII (screens), and synthetic AX-tree / OCR-line fragments (screenpipe showed this distribution matters). Add your own Indian-names set and hard negatives (public figures, product names).
- **Teacher → student:** label with an ensemble (GLiNER2-PII + OPF + rules) plus a local 4B SLM / LLM judge. Distill into a ≤100M-param encoder exported to ONNX INT8 and an ANE-friendly CoreML package.
- **Evaluation suite:** ScreenLeak (screens), WebPII (screenshots), SPY (legal/medical OOD), ai4privacy, Nemotron-PII, Maskara (India), PIIBench. Report **zero-leak rate**, recall, over-redaction, and latency per release.

---

## 10. Feature list that beats existing tools

**Coverage**
- Agents (API + MITM), web chat UIs (extension), pinned desktop apps (clipboard + accessibility), files (sanitize & copy), CLI. All on Windows/macOS/Linux.
- Text, **images** (screenshots, photos, scans) and **documents** (PDF, DOCX, XLSX, PPTX, CSV, JSON).

**Quality**
- Layered detection with user dictionaries and person blocks, an India/US/EU recognizer pack with checksums, and a fast encoder with optional rich models.
- Surrogates that preserve meaning (gender/locale/format), restored in answers, **streams**, **tool calls**, and **screenshots** (surrogate re-render).

**Speed**
- Shift-left scanning, hash cache, crop-OCR, hardware acceleration, published latency SLOs.

**Trust**
- 100% local, no telemetry, open source, reproducible builds.
- Minimal-permission extension (AI origins only, Native Messaging).
- Encrypted vault with TTL; audit logs store counts only by default.

**Control (TUI)**
- Dashboard, live feed, **inspector with before/after image previews** (terminal graphics via sixel/kitty/iTerm2 where supported), rules, vault, surfaces, models, doctor.
- Policy per app/site/surface.

**Dev-friendly**
- `pii redact|restore|wrap|scan`, JSON output, a local control API, a VS Code "what the model sees" view (rdx idea).

**India-first extras**
- Aadhaar (Verhoeff), PAN, GSTIN, UPI ID, Voter ID, DL, vehicle reg, IFSC + account numbers, Hinglish/WhatsApp-style text.

---

## 11. Tech stack

| Concern | Choice |
|---|---|
| Core | Rust (tokio), single static binary |
| ML runtime | `ort` (ONNX Runtime) with CoreML / DirectML / QNN / CUDA / TensorRT / OpenVINO / CPU EPs; `tokenizers` |
| Native OCR / vision | macOS Vision via `objc2` bindings; Windows AI Text Recognition / `Windows.Media.Ocr` via `windows` crate; PP-OCRv6 ONNX elsewhere |
| Image | `image`, `fast_image_resize`; metadata stripping (`img-parts`-style chunk removal) |
| Documents | `pdf_oxide`; `zip` + `quick-xml` for OOXML; `calamine` for reading spreadsheets |
| Proxy | `hyper`/`axum`, `rustls`, `rcgen` (local CA), HTTP/2, SSE/WebSocket passthrough |
| Clipboard / hotkeys / accessibility | `arboard` (+ `wayland-data-control`), `global-hotkey`, **xa11y** (AX / UIA / AT-SPI2) |
| Vault | SQLite with SQLCipher or `redb`; key in OS keychain (`keyring`) |
| TUI | `ratatui` + crossterm (+ image widget for previews) |
| Extension | TypeScript MV3, Native Messaging host |
| Packaging | **`dist`** (cargo-dist v0.33): `curl … \| sh`, `powershell -c "irm … \| iex"`, Homebrew, MSI/winget, GitHub Releases CI; models fetched on first run with SHA-256 pinning |
| Autostart | launchd / Windows Task Scheduler or service / systemd user unit |

---

## 12. Roadmap

| Milestone | Scope |
|---|---|
| **M1 Core text engine** | Tier 0/1 (incl. India pack), vault, surrogates, `pii redact/restore`, eval harness and golden corpus |
| **M2 Agent proxy** | Anthropic + OpenAI (+ Gemini) wire formats, SSE restore, tool-call restore, **base64 image blocks and PDF document blocks** in requests, Claude Code/Codex setup helper |
| **M3 TUI + installers** | ratatui app, live feed, rules editor; `dist` releases for 3 OSes; `pii doctor` |
| **M4 ML text** | `ort` + GLiNER2-PII/OPF; hardware EPs; hash cache; first distilled fast encoder |
| **M5 Image pipeline** | Metadata strip, visual detector, crop-OCR (Vision / Windows AI / PP-OCRv6), faces, QR, solid fill + surrogate re-render |
| **M6 Clipboard + files** | Copy-time scanning for text **and images**, paste-safe hotkey, Finder/Explorer "sanitize & copy" |
| **M7 Documents** | PDF true redaction, OOXML rewrite + hidden-data scrub, scanned PDFs, CSV/JSON structure mode |
| **M8 Browser extension** | Typing/paste/drop/upload interception, inline highlights, answer restore, Native Messaging |
| **M9 MITM mode** | Local CA lifecycle (install/rotate/uninstall), host allow-list, WebSocket handling |
| **M10 Accessibility guard** | xa11y-based composer guard for native AI apps |
| **Continuous** | Own visual detector and encoder training; public leaderboard on ScreenLeak / WebPII / SPY / Maskara; latency SLO gates in CI |

---

## 13. Risks and open questions

- **Accuracy ceiling.** Out-of-distribution text and screens remain hard. In-distribution "98.9% / 96%" numbers are upper bounds. Present the tool as a strong safety net, not a compliance guarantee. Under GDPR, pseudonymised data is still personal data.
- **Regional names and Hinglish.** Model cards flag under-detection. Dictionaries plus Indian training data are essential.
- **Image restoration limits.** A model can't "un-redact" pixels. Surrogate re-render keeps answers consistent, but the model may still misread layouts.
- **Pinned apps / Wayland / Electron accessibility quirks.** These need per-platform fallbacks (clipboard, paste-safe).
- **MITM CA.** The private key is a master credential. Opt-in only, 0600 permissions, easy uninstall, allow-listed hosts only.
- **Vault security.** It holds the real values: encrypted at rest, TTL, wipe command, no plaintext logs by default.
- **Licenses.** Avoid AGPL (MuPDF) and NC models in the default bundle. Verify WebPII/WebRedact, Maskara and knowledgator terms before use.
- **Extension supply-chain trust.** Minimal permissions, reproducible builds, store + sideload checksums.
- **Name/brand.** Check crates.io, Homebrew, winget, npm, Chrome Web Store before choosing.

---

## Sources

**Text models and benchmarks**
- OpenAI Privacy Filter: https://huggingface.co/openai/privacy-filter · https://openai.com/index/introducing-openai-privacy-filter/
- Tonic OPF benchmark: https://www.tonic.ai/blog/benchmarking-openai-privacy-filter-pii-detection · arXiv 2608.02616
- GLiNER vs OPF eval: https://heyneo.com/blog/pii-filter-model-eval
- Cross-domain benchmark (M1 Pro): https://albertsikkema.com/python/security/privacy/2026/06/01/benchmarking-open-source-pii-detection.html
- GLiNER2-PII: https://fastino.ai/blog/gliner2-pii-open-source-privacy-filtering-with-pii-detection · https://huggingface.co/fastino/gliner2-privacy-filter-PII-multi
- knowledgator GLiNER-PII: https://huggingface.co/knowledgator/gliner-pii-small-v1.0
- PII Engineer (Rust GLiNER2): https://users.rust-lang.org/t/building-a-production-multilingual-pii-detection-system-in-rust-with-gliner2/139964
- Anonymizer SLM: https://huggingface.co/blog/pratyushrt/anonymizerslm
- Apple ANE transformers: https://machinelearning.apple.com/research/neural-engine-transformers · https://jesserobbins.com/research/ane-tpu-deep-research/
- Presidio entities: https://presidio.dataprivacystack.org/supported_entities/
- Maskara Indian PII dataset: https://huggingface.co/datasets/somukandula/maskara-indian-pii-200k

**Images, screens and documents**
- WebPII / WebRedact: https://arxiv.org/abs/2603.17357 · https://webpii.github.io/
- screenpipe text model: https://huggingface.co/screenpipe/pii-redactor
- screenpipe image model: https://huggingface.co/screenpipe/pii-image-redactor
- PP-OCRv6: https://arxiv.org/html/2606.13108v1 · faster-paddle: https://pypi.org/project/faster-paddle/
- Apple Vision: https://blakecrosley.com/blog/vision-framework-built-in
- Windows AI OCR: https://learn.microsoft.com/en-us/windows/ai/apis/text-recognition
- YuNet: https://huggingface.co/cstr/yunet-GGUF
- Presidio Image Redactor: https://presidio.dataprivacystack.org/image-redactor/
- pdf_oxide: https://docs.rs/pdf_oxide
- Never pixelate text: https://bishopfox.com/blog/unredacter-tool-never-pixelation

**Existing tools and interception**
- rdx: https://github.com/paroque28/claude-code-redact
- pii-hole: https://symfolidity.com/en/articles/claude-code-hooks-anonymize-prompts/
- token-proxy: https://www.reddit.com/r/LLMDevs/comments/1sm61t9/
- LocalAI MITM: https://localai.io/docs/features/mitm-proxy/
- ChatGPT pinning: https://lumia.security/blog/openai-limits-data-inspection-for-most-organizations
- Claude Code / Cowork proxying: https://generalanalysis.com/guides/how-to-secure-claude-cowork
- Hooks can't rewrite: https://github.com/anthropics/claude-code/issues/29434
- HN Local Privacy Firewall: https://news.ycombinator.com/item?id=46206591
- Clipmask: https://predact.app/clipmask/ · Redactify: https://news.ycombinator.com/item?id=47744106
- Grepture comparison (vendor): https://grepture.com/compare/best-pii-redaction-apis-for-llms
- Masking failure modes: https://www.truefoundry.com/blog/ai-data-masking
- privalyse-mask: https://github.com/privalyse/privalyse-mask
- Privacy vs utility: https://aclanthology.org/2025.privatenlp-main.3/
- AI DLP coverage matrix: https://jazz.security/dlp-explained/dlp-basics/how-to-stop-sensitive-data-going-into-ai-tools/
- Extension risk (CSA): https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-browser-extension-security-gaps-2026041/
- Strac Chrome DLP: https://www.strac.io/integrations/chrome-dlp
- xa11y accessibility: https://crowecawcaw.github.io/general/2026/05/30/accessibility-for-computer-use.html · https://t8r.tech/t/macos-accessibility-ui-tree

**Latency and engineering**
- LLM TTFT: https://www.kunalganglani.com/blog/llm-api-latency-benchmarks-2026
- ort EPs: https://ort.pyke.io/perf/execution-providers
- dist: https://axodotdev.github.io/cargo-dist/
- arboard: https://github.com/1Password/arboard
- ratatui: https://ratatui.rs/
