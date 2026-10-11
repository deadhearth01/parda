# Notes: where to intercept text on a user's machine (system-wide coverage)

## 1. Base-URL proxy (OpenAI/Anthropic-compatible local endpoint)
- Client sets ANTHROPIC_BASE_URL / OPENAI_BASE_URL to http://127.0.0.1:PORT. Proxy holds or forwards API key.
- Works: Claude Code, Codex CLI, SDKs, Open WebUI, LibreChat, Cursor (custom base URL), Ollama-compatible clients.
- Used by rdx, pii-hole, token-proxy, LiteLLM, Grepture.
- Limitation (LocalAI docs): subscription-auth clients (Claude Pro/Max login) may not work when the proxy is the API endpoint; MITM mode solves this.

## 2. Explicit HTTPS MITM proxy with local CA (HTTPS_PROXY)
- Source: https://localai.io/docs/features/mitm-proxy/ (LocalAI, Ettore Di Giacinto).
- Generate private CA on first start; client sets HTTPS_PROXY and trusts CA (NODE_EXTRA_CA_CERTS for Node CLIs). Only allowlisted hosts (api.anthropic.com, api.openai.com) are TLS-terminated; everything else is a blind CONNECT tunnel.
- Redacts /v1/messages and /v1/chat/completions bodies; streaming SSE goes through a StreamFilter; block action returns HTTP 400 pii_blocked.
- Works with subscription auth (CLI keeps its own credential). h2 ALPN.
- Security: CA key is master credential (0600); bind to 127.0.0.1; no CA rotation in MVP.
- "Cert pinning kills MITM. Neither Claude Code nor Codex CLI pins certificates today."
- Claude Code officially documents HTTP_PROXY/HTTPS_PROXY/NO_PROXY + custom CA; no SOCKS (generalanalysis.com guide, 2026-04-30; code.claude.com/docs/en/network-config).
- Claude Desktop/Cowork: Electron app; may be routable via OS system proxy + CA in OS store, but each path must be validated; Cowork defaults to cloud execution so local proxy can't see cloud sandbox traffic.

## 3. Pinned native apps — MITM impossible
- ChatGPT macOS app pins TLS (SPKI allowlist). Lumia Security: OpenAI removed most enterprise exceptions by 2026-02-13 and the last (WellPoint) by 2026-04-23 -> "no certificates are now allowed by default." App refuses to start with an untrusted root.
- => For ChatGPT desktop (and likely other pinned apps), interception must happen BEFORE the text enters the app: clipboard, keyboard/IME, accessibility text field rewrite, or "compose in our UI then paste".

## 4. Browser extension (web UIs: chatgpt.com, claude.ai, gemini, perplexity...)
- Content script hooks textarea/contenteditable + paste events + fetch/XHR; can also restore placeholders in rendered answers.
- Can run models in-browser: openai/privacy-filter via Transformers.js (WebGPU, q4); GLiNER.js via onnxruntime-web. Or call a localhost daemon (HN Local Privacy Firewall used FastAPI on localhost).
- Fragile to site DOM changes; trust concerns around extensions (HN thread).

## 5. Clipboard layer (app-agnostic, works with pinned apps)
- Clipmask (macOS): scans every copy, ⌥⌘V pastes redacted. HN commenter: Keyboard Maestro hotkey that sanitizes on paste; idea to sanitize at copy time to hide inference latency.
- Cross-platform: needs clipboard read/write + global hotkey per OS (Wayland restricts global hotkeys/clipboard access for unfocused apps — to verify).

## 6. Agent hooks / MCP
- Claude Code hooks (UserPromptSubmit, PreToolUse, PostToolUse) can block or add context but NOT rewrite prompts/tool results (anthropics/claude-code#29434 closed "not planned"; pii-hole article). Useful as a guard ("block if proxy down"), not as the redactor.
- MCP server never sees outgoing prompts — wrong interception point (pii-hole article). Can expose "scan/redact this text" tools.

## 7. Server-side/cloud paths you can't see locally
- Cowork cloud sessions, server-side web fetch/search, remote MCP connectors originate in vendor cloud — no local tool can redact them.

## Implication for a cross-platform tool
- Needs multiple "adapters" over one shared engine: (a) base-URL proxy, (b) MITM proxy w/ CA install helper, (c) browser extension talking to local daemon, (d) clipboard/hotkey sanitizer for pinned native apps, (e) CLI `pipe` filter, (f) agent hooks as guard rails. One engine + one vault so the same name maps to the same surrogate everywhere.
