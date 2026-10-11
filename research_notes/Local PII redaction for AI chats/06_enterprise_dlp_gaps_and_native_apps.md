# Notes: enterprise AI-DLP gaps, native-app text capture, extension threats

## What enterprise AI DLP catches/misses (jazz.security, updated Oct 2026; vendor but well-cited)
- Coverage matrix by path (typed / pasted / upload / pasted screenshot / CLI & IDE / agents) across endpoint agent, browser ext/managed browser, endpoint DLP, TLS proxy, vendor plan, AI gateway.
- **Pasted screenshots and images: "rarely" covered** by browser ext/endpoint DLP; OCR mostly only on uploaded files. Proxies pass images through. Claude's (enterprise inference) hooks skip image-only content.
- Microsoft Purview Endpoint DLP: no typed-text activity; paste check skips text <30 chars; **paste check "takes 2 seconds to evaluate before allowing the paste action."** Typed-prompt blocking only in Edge for Business (19 apps). Entra network path scans ≤3 MB, **no OCR**, fails open.
- OWASP Top 10 for LLM Apps 2026: regex/blocklists fall to cross-lingual, base64, hex encodings; text-as-image bypasses text filters.
- OpenAI: some ChatGPT/Codex features use WebSockets; inspection must not rewrite/close them; QUIC hides more (Cisco: disable QUIC for DLP). SSL inspection can break the Mac app (pinning).
- Anthropic: inference hooks (beta, Claude Enterprise) send each prompt to a customer-run security server for allow/deny before the model runs.
- Survey (Univ. Melbourne + KPMG 2025, 48,340 people): ~half of AI users uploaded company info to public AI tools; more common where banned (67%).
- => Friction (2 s pastes, blocks) drives users around controls. An OSS tool that **redacts instead of blocks** and adds ~0 ms wins adoption.

## Browser-extension threat context (CSA research note, 2026-04)
- Jan 2026: two malicious Chrome extensions impersonating AITOPIA (900k installs) exfiltrated full ChatGPT/DeepSeek histories.
- LayerX 2025: 99% enterprise users have ≥1 extension; >50% high/critical permissions; >20% have a GenAI extension; 26% sideloaded. 77% of employees paste data into GenAI; 82% via personal accounts. LayerX: 40% of files uploaded to AI platforms contain PII/PCI.
- => Our extension must be minimal-permission (only AI chat origins), open-source, reproducible builds, no remote code, signed; heavy logic in local daemon.

## Native desktop apps: accessibility APIs
- xa11y (crowecawcaw.github.io, 2026-05-30): Rust library with Playwright-style API driving apps via accessibility tree on Windows (UIA), macOS (AXUIElement), Linux (AT-SPI2); Python/JS bindings. UIA reads whole tree at once; macOS batch reads; AT-SPI2 per-call.
- macOS write path (t8r.tech, 2026-04): AXValue set works for native AppKit fields; Chrome/Electron/CEF inputs may need AXValueAttribute or AXText or don't honor it; AXPress on Chromium returns success but does nothing. Needs Accessibility permission (AXIsProcessTrustedWithOptions). AXUIElement not Send/Sync in Rust.
- screenpipe's text model is trained on AX-tree dumps — confirms AX text is a viable PII surface.
- => "Native composer guard": watch focused text field of AI desktop apps (ChatGPT, Claude, Copilot) via AX/UIA; highlight PII; on hotkey or on Enter interception, replace value with redacted text (works reliably for native fields; Electron apps need fallback = select-all + paste redacted via clipboard).

## Images in API traffic
- Agents (Claude Code reading screenshots, computer use) send images as base64 content blocks inside /v1/messages; OpenAI image_url data URIs; Files APIs upload multipart. => proxy can decode, run image pipeline, re-encode, and fix content-length — in-line.
