# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - unreleased

### Added
- Three detection tiers: personal dictionary with name variants, rule packs with checksum validation (global, India, US/UK, secrets), on-device GLiNER-PII model (ONNX).
- Deterministic, format-preserving surrogates (Indian/Western names, Aadhaar, PAN, GSTIN, UPI, IFSC, cards, IBAN, phones, e-mails, IPs, keys …) stored in an encrypted vault (XChaCha20-Poly1305, OS keyring).
- Restore of real values, case-preserving and first-name aware, including streaming restore that is exact for any chunking.
- Agent proxy for Anthropic Messages, OpenAI Chat Completions and OpenAI Responses, with SSE streaming, tool calls, signed thinking blocks untouched, Host/Origin guards and fail-closed strict mode.
- Clipboard paste-safe hotkey, restore-on-copy and scan-on-copy for chat apps.
- Daemon with local IPC, login service install (launchd, systemd user, Windows logon task).
- `parda` CLI (`setup`, `doctor`, `redact`, `restore`, `scan`, `rules`, `vault`, `model`, `service`, `env`, `tui`) and a ratatui dashboard.
- Golden corpus, evaluation and latency harness (`parda-bench`).
