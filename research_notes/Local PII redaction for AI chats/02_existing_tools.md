# Notes: existing tools for redacting PII before it reaches LLMs

## A. API proxies (base-URL override) — best for agents/CLIs/SDKs
### claude-code-redact (`rdx`) — github.com/paroque28/claude-code-redact (Apache-2.0, ~4 stars, Python/uv)
- Proxy via ANTHROPIC_BASE_URL=http://localhost:8642. Redacts outbound, un-redacts inbound.
- Two strategies: format-preserving (real name -> fake name, user-defined) and auto-token (`__RDX_KEY_a1b2c3d4__`).
- "Person blocks": define a person once -> ~30 auto variants (j.smith, JOHN_SMITH, jsmith, initials) with case preservation (JOHN->JANE).
- Detection layers: explicit rules, person blocks, 16 built-in secret regexes, entropy detection, context detection (password=, Bearer), optional Presidio NLP.
- Multi-project: detects project from Claude Code system prompt cwd; per-project rules & mapping cache.
- Security model: zero logging by default; reverse map only in memory; deterministic SHA-256 tokens; tells Claude about redaction via RDX.md appended to CLAUDE.md.
- Modes: proxy, "awareness" (no un-redact), hooks-only. VS Code extension showing what Claude sees. 487+ tests.
- Gaps: Anthropic-only, Python, no TUI, no system-wide/GUI coverage, no cross-platform installer.

### pii-hole — github.com/JeremieSamson/pii-hole (article 2026-07-17, symfolidity.com)
- "Pi-hole for prompts". Docker one-liner, ANTHROPIC_BASE_URL=http://127.0.0.1:8055. Presidio + spaCy FR+EN, merge widest span; regex for sk-/ghp_/AKIA/JWT.
- Deterministic tokens [EMAIL_1] stable for process lifetime (crucial because clients resend full history each turn).
- Streaming: buffers to reassemble tokens split across SSE chunks; restores inside tool calls too (so agent writes real value to files).
- Claude Code plugin: /piihole:start|status|log; UserPromptSubmit bash hook blocks pasted secrets if proxy is down.
- Web dashboard at /dashboard (per-type counters, recent redactions); SQLite audit log with real values (sensitive itself).
- Author's analysis: hooks can't rewrite prompts (UserPromptSubmit can only block/add context); MCP never sees outgoing prompts (wrong interception point); browser extension covers only web. => proxy is the right point for agents.

### token-proxy (zolderio) — github.com/zolderio/token-proxy (reddit r/LLMDevs, 2026-04)
- Key finding: naive placeholders like [User_Email_1] break reasoning — Claude "fixed" syntax by hallucinating realistic names. Random fakes break semantics (e.g., impossible-travel detection on IPs).
- Solution: context-preserving pseudonymization — ASN/geo-aware IP replacement (MaxMind GeoLite2), internal vs external domain categories.
- SSE tail buffer: holds last 80 chars per chunk to unmask pseudonyms split across chunks.
- Anthropic adapter only.

### Others seen (not deep-dived)
- LiteLLM proxy + Presidio guardrail (docs.litellm.ai/docs/proxy/guardrails/pii_masking_v2) — supports masking; used with Claude Code via labs.secengai.com walkthrough.
- Grepture — open-source proxy + EU SaaS; regex <2 ms; reversible; 30+ secret patterns. (Vendor; its comparison page wrongly says LLM Guard lacks reversibility.)
- SovereignGuard (dev.to, 2026-03) — open source gateway.
- PrivacyScrubber "PII MCP server" for Cursor/Claude Code/Copilot.
- PII Shield — local anonymization for Claude Cowork (LinkedIn).

## B. Libraries / frameworks
- Microsoft Presidio (MIT; Python): analyzer + anonymizer, recognizer registry, pluggable NER (spaCy default, can plug GLiNER/transformers), deanonymize operators exist but mapping storage DIY. ~15 ms/text with spaCy on M1 Pro. Offset issues with reversibility (64% round-trip in one benchmark).
- LLM Guard (Protect AI; Python): Anonymize input scanner + Vault + Deanonymize output scanner (reversible). Model-based scanners add 100 ms–5 s each; development has slowed (stationx 2026 review calls it "dead tool that still works").
- Phileas (philterd) — Java alternative to Presidio.

## C. Browser extensions (web chat UIs only)
- HN "Local Privacy Firewall" (Show HN, ~111 pts): Chrome ext intercepts prompt; regex in-extension; NER via local BERT on FastAPI localhost.
- PrivacyScrubber, PasteSecure (updated 2026-09-22), PiiBlock, DataAnonymiser (restores in AI answer), redact.tools, Caviard-style tools. All "100% local".
- HN commenters: (1) "latency introduced by even the littlest inference is enough friction to make you ditch the process"; (2) extensions are over-permissive and get sold to shady buyers -> trust problem; (3) want replacement with dummy data, not just warnings; (4) want app-agnostic solutions (Keyboard Maestro hotkey paste-sanitize; sanitize on copy instead of paste to hide latency).
- Suggestion from thread: realistic surrogate names ("Mary Smith" -> "Samantha Robertson") and highlight what was hidden.

## D. Desktop / clipboard (app-agnostic)
- Clipmask (predact.app) — macOS menu-bar clipboard manager; detects PII on every ⌘C on-device (Neural Engine model; Apple Silicon only, macOS 14+); ⌥⌘V pastes redacted; encrypted local history. Freemium (500 trial limit). Closed source.
- Predact — documents/PDF/images redaction (paid).
- Redactify — macOS/iOS app; Vision OCR + CoreML face detection; flattens docs; clipboard auto-clean in review.
- Secure Redact (App Store), Elephas (Mac AI app that redacts before cloud).
- None are cross-platform + open-source.

## E. Agent-platform gap
- anthropics/claude-code#29434 (2026-02-27) "Mechanism to redact secrets/PII from the context window" — closed as not planned. Hooks can block/detect but cannot sanitize prompts or tool results. => third-party proxy remains the only full-coverage route for Claude Code.

## F. Commercial / cloud (not local; for context)
- Private AI (enterprise, on-prem option), Strac (SaaS DLP), Nightfall, Lakera, AWS Comprehend, Google DLP, Azure. Not suitable for "never leaves my machine".
