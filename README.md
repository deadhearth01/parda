<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo/parda-logo-dark.svg">
    <img src="assets/logo/parda-logo.svg" alt="parda" width="360">
  </picture>
</p>

<p align="center"><b>A curtain between your personal data and the cloud AI.</b><br>
Local, real-time PII filter for AI agents and chat apps — names, contacts, IDs and secrets never leave your machine, and answers come back with the real values.</p>

<p align="center">
  <a href="https://github.com/deadhearth01/parda/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/deadhearth01/parda/actions/workflows/ci.yml/badge.svg"></a>
  <a href="#license"><img alt="License: Apache-2.0 OR MIT" src="https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue"></a>
  <a href="https://github.com/deadhearth01/parda/releases"><img alt="Release" src="https://img.shields.io/github/v/release/deadhearth01/parda?include_prereleases"></a>
</p>

---

*parda* (पर्दा, Hindi/Urdu for "curtain") sits between you and Claude, ChatGPT, Codex and friends. Before text leaves your computer it swaps personal data for **realistic stand-ins** — `Ravi Kumar` becomes `Arjun Mehta`, `ravi.k@gmail.com` becomes `arjun.mehta@gmail.com`, an Aadhaar number becomes another *checksum-valid* Aadhaar number — and when the answer comes back, it puts the real values back. The AI works with consistent, believable data; it never sees yours.

```text
you ──► "Email Ravi Kumar at ravi.k@gmail.com"            ──► parda ──► "Email Arjun Mehta at arjun.mehta@gmail.com" ──► AI
you ◄── "Done — I emailed Ravi Kumar at ravi.k@gmail.com" ◄── parda ◄── "Done — I emailed Arjun Mehta at arjun.mehta…" ◄── AI
```

- **Local only.** No cloud service, no telemetry. The mapping vault is encrypted on disk.
- **Real time.** Rules run in microseconds; the name model in ~10 ms per paragraph; repeated text is cached (agents resend history every turn).
- **India-first, global too.** Aadhaar, PAN, GSTIN, UPI, IFSC, Voter ID, vehicle registration, Indian phone formats — plus emails, phones, cards, IBAN, SSN, NINO, IPs, API keys, JWTs and private keys.
- **Streams stay streams.** Server-sent events are rewritten on the fly, even when a name is split across chunks.
- **Agents and chat apps.** A local proxy for Claude Code, Codex and the Anthropic/OpenAI SDKs; a paste-safe hotkey for ChatGPT/Claude/Gemini web and desktop apps.

## Quick start (60 seconds)

```sh
# 1. install (macOS / Linux)
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/deadhearth01/parda/releases/latest/download/parda-installer.sh | sh
#    Windows (PowerShell)
#    powershell -c "irm https://github.com/deadhearth01/parda/releases/latest/download/parda-installer.ps1 | iex"
#    or from source: cargo install --git https://github.com/deadhearth01/parda parda

# 2. set up: config, name model (~50 MB), start at login, agent settings
parda setup

# 3. point your agent at parda
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787     # Claude Code, Anthropic SDKs
export OPENAI_BASE_URL=http://127.0.0.1:8787/v1     # Codex, OpenAI SDKs

# 4. watch it work (keyboard or mouse; tab 6 has every setting)
parda tui
```

Need to send something unfiltered for a moment? `parda off` (or `p` in the TUI) pauses protection on
every surface; `parda on` resumes it. The TUI header turns red while it is off.

Chat apps: copy your text, then press **⌘⌥V** (macOS) / **Ctrl+Alt+V** (Windows, Linux) instead of paste. parda pastes a redacted version and puts your original back on the clipboard. Copying the AI's answer restores the real names automatically.

Try it without any AI:

```sh
$ parda redact "Send the offer letter to Priya Sharma, priya.s@outlook.com, PAN ABCPE1234F, Aadhaar 2345 6789 0124"
Send the offer letter to Aarav Inamdar, niranjan.d@outlook.com, PAN RSUPB5085A, Aadhaar 5197 5053 4127
$ parda redact "Hi, I'm Venkatesh Iyer from Pune; call me on +91 98765 43210." | parda restore -
Hi, I'm Venkatesh Iyer from Pune; call me on +91 98765 43210.
$ parda scan "Call +91 98765 43210, mail ravi.k@gmail.com, card 4111 1111 1111 1111"
Phone                  5..20    0.90  +91 98765 43210
Email                 27..43    1.00  ravi.k@gmail.com
CreditCard            50..69    1.00  4111 1111 1111 1111
```

The stand-in PAN keeps the holder type (`P`, a person), the stand-in Aadhaar passes the Verhoeff checksum, and the public mail domain is kept.

## How it works

```text
          ┌────────────────────────────── parda daemon ───────────────────────────────┐
agents ──►│ proxy :8787 ─┐                                                             │──► api.anthropic.com
 (HTTP)   │              ├─► engine ─ T0 your names & terms (Aho-Corasick)              │    api.openai.com
clipboard►│ clipboard ───┘           ─ T1 rules + checksums (Verhoeff, Luhn, GSTIN, IBAN) │
          │                          ─ T2 GLiNER-PII model (ONNX, on-device)            │
          │                          ─ merge → policy → encrypted vault → surrogates     │
cli / tui►│ local socket (IPC)       ◄─ events (kinds & counts, never values)            │
          └────────────────────────────────────────────────────────────────────────────┘
```

1. **Detect** in three tiers: your own dictionary (people you name in `rules.toml`, with variants like `R. Sharma`, `ravi.sharma`), rule packs with checksum validation, and an on-device NER model for the names and addresses rules cannot catch.
2. **Replace** each value with a deterministic, format-preserving surrogate stored in an encrypted vault (XChaCha20-Poly1305, key in your OS keychain). The same person gets the same stand-in every time, so the AI's reasoning stays consistent across a conversation.
3. **Restore** real values in answers, tool calls (e.g. the `to:` of a `send_email` tool) and streaming deltas — including case variants (`ARJUN MEHTA`) and first-name-only mentions.

More: [architecture](docs/architecture.md) · [configuration](docs/configuration.md) · [agents](docs/agents.md) · [clipboard](docs/clipboard.md) · [FAQ](docs/faq.md)

## What is covered

| Surface | How | v0.1 |
|---|---|---|
| Claude Code, Anthropic SDKs | `ANTHROPIC_BASE_URL` → proxy (`/v1/messages`, streaming, tools, thinking untouched) | ✅ |
| Codex CLI, OpenAI SDKs, OpenAI-compatible tools | `OPENAI_BASE_URL` → proxy (`/v1/chat/completions`, `/v1/responses`) | ✅ |
| ChatGPT / Claude / Gemini apps & websites | paste-safe hotkey, restore-on-copy | ✅ |
| Images, PDFs, Office documents | forwarded **unscanned** (event shown; set `unscanned_media = "block"` to refuse) | ⏳ |
| Typing directly into a website | not intercepted — use paste-safe | ⏳ |

## Privacy guarantees and limits

- Text is processed on your machine only. parda makes no network calls except forwarding your own API traffic to the upstream you configured and downloading models you ask for (SHA-256 pinned).
- **Fail-closed by default** (`mode = "strict"`): if the name model fails or is missing, requests are refused rather than sent unredacted. `mode = "fast"` continues with rules only.
- Logs and the live feed contain kinds, counts and timings — never values.
- Detection is not perfect: unusual names, names the model has not seen in context, and PII inside images are the main gaps. Add the people you care most about with `parda rules add-person "Full Name"`; dictionary entries are always masked. Run `parda scan` on representative text to check.
- A model that already knows a public fact may still infer it; parda protects *your* data, not public knowledge.

## The model

The name/address detector is a small on-device GLiNER model run with ONNX Runtime. parda ships two: [knowledgator/gliner-pii-edge-v1.0](https://huggingface.co/knowledgator/gliner-pii-edge-v1.0) (Apache-2.0, INT8, ~9 ms per paragraph) and **parda-pii-edge**, our India-first fine-tune of it, which reaches person recall 1.00 on Indian and global names, precision 1.00 and zero leaked values on the golden corpus (base: 0.97 / 0.955, 0.92, 0.995). See [bench/README.md](bench/README.md), the [model card](MODEL_CARD.md) and the [data card](DATA_CARD.md). `parda model list` shows the options; `parda model import` installs your own export.

## Commands

```text
parda setup | doctor | status | tui | on | off | stop
parda redact|restore|scan [TEXT|-] [--scope S] [--json]
parda paste-safe
parda rules show|edit|add-person NAME|allow TERM
parda model list|pull ID|use ID|import DIR
parda vault stats|wipe [--scope S]|reset
parda service install|uninstall|status
parda env claude|codex|openai
parda daemon
```

## Building from source

```sh
git clone https://github.com/deadhearth01/parda && cd parda
cargo build --release -p parda            # add --features coreml on macOS for the Neural Engine
cargo test --workspace
```

Rust 1.89+ (edition 2024). See [CONTRIBUTING.md](CONTRIBUTING.md).

## Roadmap

Image OCR redaction · PDF/DOCX pipeline · browser extension for typed input · more providers (Gemini, Bedrock) · INT8 `parda-pii-edge` (smaller, faster; needs an ONNX Runtime upgrade) · GUI.

## License

Dual-licensed under [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option. Models are downloaded separately and keep their own (permissive) licenses.
