<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo/parda-logo-dark.svg">
    <img src="assets/logo/parda-logo.svg" alt="parda" width="360">
  </picture>
</p>

<p align="center"><b>A curtain between your personal data and the cloud AI.</b><br>
A local, real-time PII filter for AI chats and agents. Names, phone numbers, IDs and secrets are swapped for tags like <code>[NAME_1]</code> on your machine before anything is sent, and the real values come back in the answers you read.</p>

<p align="center">
  <a href="https://github.com/deadhearth01/parda/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/deadhearth01/parda/actions/workflows/ci.yml/badge.svg"></a>
  <a href="#license"><img alt="License: Apache-2.0 OR MIT" src="https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue"></a>
  <a href="https://github.com/deadhearth01/parda/releases"><img alt="Release" src="https://img.shields.io/github/v/release/deadhearth01/parda?include_prereleases"></a>
</p>

---

*parda* (पर्दा — Hindi/Urdu for "curtain") is a small program that runs on your computer and stands between you and ChatGPT, Claude, Gemini, Codex, Claude Code and other AI tools.

**What you type**

```text
Send the offer letter to Priya Sharma, priya.s@outlook.com, PAN ABCPE1234F, Aadhaar 2345 6789 0124
```

**What the AI company receives**

```text
Send the offer letter to [NAME_1], [EMAIL_1], PAN [PAN_1], Aadhaar [AADHAAR_1]
```

**What the AI answers**

```text
Sure — I've drafted it for [NAME_1] and will mail [EMAIL_1].
```

**What you see**

```text
Sure — I've drafted it for Priya Sharma and will mail priya.s@outlook.com.
```

The AI still understands the task — it knows `[NAME_1]` is a person and `[EMAIL_1]` an e-mail address — but your real data never leaves your machine.

---

## Contents

- [In plain words](#in-plain-words)
- [Why are there OpenAI and Anthropic URLs in the setup?](#why-are-there-openai-and-anthropic-urls-in-the-setup)
- [Where parda protects you](#where-parda-protects-you)
- [Quick start](#quick-start)
- [What it finds](#what-it-finds)
- [How it works — technical deep dive](#how-it-works--technical-deep-dive)
- [The on-device model](#the-on-device-model)
- [Privacy guarantees and honest limits](#privacy-guarantees-and-honest-limits)
- [Configuration](#configuration) · [Commands](#commands) · [Building](#building-from-source) · [Project layout](#project-layout) · [Roadmap](#roadmap) · [License](#license)

---

## In plain words

- **It runs only on your computer.** There is no parda server and no account, and nothing is sent to us. The "AI" part of parda is a tiny language model (≈32 million parameters, about the size of a photo album) that runs on your CPU in a few milliseconds.
- **It replaces before sending, and restores after receiving.** Each piece of personal data becomes a numbered tag. The same person always gets the same tag, so the AI can still reason about "[NAME_1] and [NAME_2] met on Monday". When the answer comes back, parda swaps the tags back so you read normal text.
- **It's on by default and has an off switch.** `parda off` (or `p` in the dashboard) lets text through unfiltered for a moment; `parda on` resumes. The dashboard header turns red while it is off.
- **It fails safe.** If the name detector breaks, parda refuses to send rather than sending your data unprotected (you can change this).
- **It's India-first and works globally.** It knows Aadhaar, PAN, GSTIN, UPI, IFSC, Voter ID and Indian phone formats, plus e-mails, cards, IBANs, SSNs, API keys and names from every region.

---

## Why are there OpenAI and Anthropic URLs in the setup?

Because **parda is not an AI and does not call any AI itself.** It is a *checkpoint* on the road between your AI tool and the AI company.

```text
WITHOUT parda   Claude Code ──────────────────────────────────────────► api.anthropic.com

WITH parda      Claude Code ──► parda (127.0.0.1:8787, on your Mac) ──► api.anthropic.com
                                 └ finds and tags personal data here,
                                   with the small on-device model + rules
```

- **`ANTHROPIC_BASE_URL=http://127.0.0.1:8787` / `OPENAI_BASE_URL=http://127.0.0.1:8787/v1`** tell your AI tool to send its requests *to parda on your own machine* instead of straight to the provider. That address never leaves your computer.
- **`proxy.anthropic_upstream` / `proxy.openai_upstream`** in parda's config are where parda forwards the *already-filtered* request afterwards: the same AI company your tool would have used anyway. You can point them at any compatible service (OpenRouter, a company gateway, a local Ollama).
- **The API keys belong to your tools, not to parda.** Claude Code or Codex adds your key to its request as usual. parda passes it through untouched; it never stores, logs or needs a key. Codex's `env_key = "OPENAI_API_KEY"` setting just tells Codex where *its* key is. If you only use chat websites or apps, you need no key and no URL at all.
- **Filtering happens entirely locally**, before the request continues to the provider. The provider URLs are only the destination, never a detector.

---

## Where parda protects you

| Where you talk to AI | How parda gets in the way | Status |
|---|---|---|
| **Claude Code, Codex CLI, Anthropic / OpenAI SDKs, OpenAI-compatible tools** | Set the tool's base URL to parda (one environment variable). Every request, streamed answer and tool call is filtered. | ✅ ready |
| **Any chat website or desktop app** (ChatGPT, Claude, Gemini, Copilot, Perplexity, DeepSeek …) | **System-wide interception:** an auto-proxy rule sends *only AI sites* through parda, which filters what you type in real time. Needs a one-time certificate approval. Banking, mail and every other site are never touched. | 🚧 in development |
| **Any app, today** | **Paste-safe hotkey:** copy your text, press ⌘⌥V (macOS) / Ctrl+Alt+V instead of ⌘V; parda pastes the tagged version. Copying the AI's answer puts the real values back on your clipboard. | ✅ ready |
| **Scripts and pipes** | `parda redact` / `parda restore` on the command line. | ✅ ready |
| Images, PDFs, Office files inside requests | Forwarded **unscanned** with a warning (or refused with `unscanned_media = "block"`). | ⏳ planned |

---

## Quick start

> Binary releases are being prepared. Until the first release is published, build from source (5 minutes, see [Building from source](#building-from-source)).

```bash
# 1. install (after the first release; macOS / Linux)
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/deadhearth01/parda/releases/latest/download/parda-installer.sh | sh
#    Windows (PowerShell):
#    powershell -c "irm https://github.com/deadhearth01/parda/releases/latest/download/parda-installer.ps1 | iex"

# 2. set up: writes the config, downloads the on-device model, optionally starts parda at login
parda setup

# 3. use it with a coding agent / CLI
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787     # Claude Code, Anthropic SDKs
export OPENAI_BASE_URL=http://127.0.0.1:8787/v1     # Codex CLI, OpenAI SDKs
#    (parda env claude | parda env codex prints the exact lines and the config-file equivalents)

# 4. watch it work — dashboard with live feed and every setting (keyboard or mouse)
parda            # alone in a terminal opens the dashboard (same as `parda tui`)
```

**The dashboard.** `parda` opens it; if the daemon is not running it says so and `s` starts it in the
background (the login service if `parda service install` set one up, else a detached `parda daemon`).
`:` or Ctrl-K opens a command palette with every action; `1`–`6` / Tab switch tabs; arrows or `hjkl`,
`g`/`G`, PgUp/PgDn move; `/` filters Live, Rules and Vault; Enter opens details; Esc backs out; `?`
lists every key; the bottom line always shows the keys that work right now. Live pauses with Space and
filters by surface (`f`) and kind (`t`) — kinds and counts only, never values. Settings are edited in
place: switches toggle, choices cycle, numbers and addresses open a validated inline editor. Mouse
works throughout. `NO_COLOR=1` gives a monochrome screen, `PARDA_ASCII=1` plain ASCII borders, and
`parda tui --dump` prints every tab as text.

Try it without any AI:

```console
$ parda redact "hey my aadhar number is 123456789, call me on +91 98765 43210"
hey my aadhar number is [AADHAAR_1], call me on [PHONE_1]

$ echo "Sure — I've drafted it for [NAME_1] and will mail [EMAIL_1]." | parda restore -
Sure — I've drafted it for Priya Sharma and will mail priya.s@outlook.com.

$ parda scan "Call +91 98765 43210, mail ravi.k@gmail.com, card 4111 1111 1111 1111"
Phone                  5..20    0.90  +91 98765 43210
Email                 27..43    1.00  ravi.k@gmail.com
CreditCard            50..69    1.00  4111 1111 1111 1111
```

Prefer realistic fake values over tags? `replace.style = "surrogate"` (or Settings → *replacement style*) turns `Priya Sharma` into `Meera Seshadri` and an Aadhaar into another checksum-valid Aadhaar. Answers read more naturally, but you can't see at a glance what was replaced.

---

## What it finds

| Group | Examples | How |
|---|---|---|
| People | Indian, global, initials (`K. Venkatesh`), "Last, First", ALL CAPS | on-device model + your own list |
| Contact | e-mail, phone (+91, US, UK, international), postal address | rules + model |
| Indian IDs | Aadhaar (Verhoeff checksum), PAN, GSTIN (checksum), UPI ID, IFSC, Voter ID, driving licence, vehicle number | rules with validation |
| Finance | card numbers (Luhn), IBAN (mod-97), bank account numbers | rules with validation |
| Other IDs | passport, US SSN, UK NINO, date of birth (when labelled) | rules |
| Secrets | OpenAI / Anthropic / AWS / GitHub / Slack / Google keys, JWTs, private keys, `password=…` | rules + entropy |
| Anything you name | people and terms in `rules.toml` (with variants like `R. Sharma`, `ravi.sharma`) | dictionary |

A value introduced by its own name is masked even when it is not a valid ID: `my aadhar number is 123456789` → `[AADHAAR_1]` (typos and partial numbers are still personal data).

---

## How it works — technical deep dive

```text
                 ┌──────────────────────────────── parda daemon (one process) ─────────────────────────────────┐
 Claude Code ───►│ agent proxy 127.0.0.1:8787 ──┐                                                               │──► api.anthropic.com
 Codex, SDKs     │  Anthropic / OpenAI Chat /   │                                                               │    api.openai.com
                 │  OpenAI Responses, SSE        │      ┌─────────────── engine ───────────────┐                 │    (or any compatible
 browsers, apps ►│ interception 127.0.0.1:8788 ─┼─────►│ 1 detect  dictionary · rules · model │                 │     upstream)
 (AI hosts only) │  (in development)            │      │ 2 policy  redact / block / warn / ignore               │
 clipboard ─────►│ paste-safe + restore-on-copy ┘      │ 3 tag     [NAME_1] … via encrypted vault│                │
                 │                                     │ 4 restore answers, streams, tool calls │                │
 parda CLI/TUI ─►│ local socket (IPC)  ◄── events: kinds, counts, latency — never values        │                │
                 └─────────────────────────────────────────────────────────────────────────────────────────────┘
```

### 1. Detection — three tiers

| Tier | What | Cost |
|---|---|---|
| **T0 dictionary** | People and terms you list in `rules.toml`. Each person expands to variants (full name, first, last, `first.last`, `firstlast`, `f.last`, initials) matched with Aho-Corasick (leftmost-longest, case-insensitive, Unicode-aware word boundaries). | µs |
| **T1 rules** | Compiled regexes plus validators: Verhoeff (Aadhaar), Luhn (cards), mod-97 (IBAN), mod-36 (GSTIN), PAN holder type, phone digit counts, IP parsing, Shannon entropy for unknown secrets. Context words boost scores, and "keyed" rules catch values introduced by their name. | µs per KB, linear |
| **T2 model** | A token-classification GLiNER model running in ONNX Runtime (see [the model](#the-on-device-model)): names, addresses and context-dependent values the rules cannot see. | ~3–10 ms per paragraph |

- The dictionary and rules run over the **whole** text, so nothing can hide across chunk boundaries.
- The model runs over **overlapping windows** (≤ 2000 bytes, 256-byte overlap) cut at paragraph, line or sentence boundaries, batched in one inference call.
- Model results are cached per window by content hash, so agents that resend the whole conversation every turn only pay for new text.

### 2. Policy and merging

Every finding has a kind and a tier. Per-kind actions (`redact`, `block`, `warn`, `ignore`) are applied to **all** findings *before* overlaps are resolved, so a URL marked `ignore` cannot hide an e-mail inside it, and a blocked kind always blocks. Overlaps then resolve by trust: dictionary > checksum-validated rule > model > unvalidated rule, then longer span, then score. A URL never swallows the personal data inside it; those parts are replaced in place.

### 3. Tags and the vault

- **Tags** are `[LABEL_N]`: `[NAME_1]`, `[EMAIL_2]`, `[PHONE_1]`, `[AADHAAR_1]`, `[PAN_1]`, `[CARD_1]`, `[ACCOUNT_1]`, `[ADDRESS_1]`, `[SECRET_1]` …
- A value always gets the same tag within a *scope* (default `global`), so a person mentioned on Monday in Claude Code and on Tuesday in the clipboard is still `[NAME_1]`.
- A candidate tag is never one that already appears in your text.
- **Vault:** SQLite at `<data dir>/vault.db`.
  - Real values are encrypted with XChaCha20-Poly1305. The associated data binds each ciphertext to its own row (scope, kind and lookup hash), so rows cannot be swapped.
  - Lookups use an HMAC of the value, never the value itself.
  - The 256-bit key lives in the macOS Keychain, Windows Credential Manager or Linux Secret Service, or in a `0600` key file. parda never mints a new key while encrypted data exists.
  - Mappings expire after `vault.ttl_days` (30).
- **Self-check:** before anything is sent, parda restores its own output and checks it reproduces your exact input. If it doesn't, the replacement is redone, and if it still fails the request is refused rather than sent.

### 4. Restoration — answers, streams and tool calls

- A per-scope Aho-Corasick automaton over all tags and stand-ins swaps them back, including case variants the AI may produce (`[name_1]`) and word-boundary-safe partial mentions.
- **Streaming:** answers arrive as server-sent events in small pieces, and a tag can be split across pieces (`[NA` … `ME_1]`). A streaming restorer holds back only the shortest suffix that could still become a tag, so output is exact for any chunking and still streams with minimal delay.
- **Tool calls:** arguments the AI streams as partial JSON (e.g. the `to:` of a `send_email` tool) are restored with JSON escaping, so a real value containing quotes or newlines never breaks the tool call.

### 5. The agent proxy

- **Endpoints:** Anthropic Messages (incl. `count_tokens`, batches), OpenAI Chat Completions, Responses (incl. side endpoints), completions and embeddings.
- **Fields:** every text-bearing field is walked — system prompts, messages, tool results, tool-call inputs (including server and MCP tools), document titles, tool descriptions and shell/patch outputs.
- **Never modified:** signed `thinking` blocks and identifiers.
- **Request bodies:** gzip/deflate/br/zstd bodies are decoded first. A body parda cannot parse is refused (400), never forwarded. Requests with text to an endpoint parda does not understand are refused by default (opt-in pass-through list available).
- **Streaming:** SSE is rewritten incrementally on a blocking pool; held-back text is flushed in order before each block or choice ends.
- **Guards:**
  - binds loopback only (non-loopback listen addresses are refused unless explicitly allowed);
  - rejects non-loopback peers, browser `Origin` headers and DNS-rebinding `Host` values.
- **Auth:** API keys pass through untouched and are never logged.

### 6. System-wide interception (in development)

- **Routing:** a PAC (proxy auto-config) rule sends **only listed AI hosts** to parda; everything else goes direct and is never decrypted.
- **Decryption:** for AI hosts, parda terminates TLS with a local root certificate that you approve once in your OS. It is generated on your machine and its private key never leaves it.
- **Filtering:** request bodies are tagged and responses restored, including streams.
- **Forwarding:** requests go to the real site with full certificate verification.
- **Turning it on:** `parda ca create`, then `parda ca install` (your OS asks you to approve the certificate), then `parda intercept on` — it checks the certificate is trusted, starts the listener in the daemon and points every enabled network service's automatic proxy setting at parda, printing what it changed. Firefox uses its own settings; `on` prints the two to set.
- **Checking it:** `parda intercept status` shows the certificate, the listener, each network service's current setting and the site list, and changes nothing. `parda doctor` warns when the system still sends AI sites to parda while nothing listens.
- **Turning it off:** `parda intercept off` restores your previous network settings exactly (it also works with the daemon stopped or after a crash). A setting you changed yourself meanwhile is left as it is; one that cannot be put back keeps parda filtering and makes the command fail, so you can run it again. Without saved settings (data folder cleaned, another `PARDA_HOME`) it switches off any parda automatic proxy setting it finds; if the saved file is damaged, `parda intercept off --forget` does that and moves the file aside.
- **When parda isn't running:** the PAC file is unreachable and the system goes direct, so a stopped parda never breaks your internet. The dashboard shows whether protection is active.

### 7. Clipboard paste-safe

The hotkey handler:

1. reads the clipboard;
2. tags it and puts the tagged text on the clipboard;
3. waits until you release the hotkey's modifier keys;
4. sends ⌘V / Ctrl+V;
5. after 1 s, puts your original back — only if the clipboard still holds parda's text.

Stale requests (older than 2 s) are dropped, so a slow scan can never paste into a window you have since switched to. Restore-on-copy watches for copied answers containing tags and swaps the real values back.

### 8. Daemon, dashboard and CLI

- **One daemon process** hosts the proxy, interception, clipboard and engine.
- **CLI and dashboard:** the `parda` CLI and the ratatui dashboard (`parda` alone, or `parda tui`: command palette, filterable live feed, every setting editable in place, mouse) talk to it over a local socket; the dashboard does its socket work on a background thread and redraws only when something changed — a `0700` Unix socket, or a per-user named pipe with an owner-only ACL on Windows.
- **Logging:** events carry kinds, counts and timings, never values.
- **Start at login:** `parda service install` sets this up with launchd (macOS), a systemd user unit (Linux) or Task Scheduler (Windows).

### Performance (Apple M4, CPU)

| Step | Time |
|---|---|
| Rule scan, 256 words | 0.02 ms |
| Rules over a 1 MB agent request | 15 ms |
| Base model (INT8), 64 / 256 words | 9 / 37 ms |
| parda-pii-edge (fp32), 64 / 256 words | 43 / 160 ms |
| Proxy, 16 concurrent requests (rules + model) | p50 50 ms, 0 errors, 0 leaks |
| Repeated text (cache hit) | model skipped |

---

## The on-device model

parda's model is **`parda-pii-edge`**, an India-first fine-tune of [knowledgator/gliner-pii-edge-v1.0](https://huggingface.co/knowledgator/gliner-pii-edge-v1.0). It is a GLiNER token-classification model on a 32M-parameter Ettin encoder, small enough to run on any laptop CPU with no GPU and no internet.

- **Training data:** 20,000 synthetic examples (60% Indian, 40% global) across 14 writing styles — Hinglish WhatsApp, KYC forms, tickets, résumés, code, logs and more — with checksum-valid IDs and held-out test names. No real person's data was used. See the [data card](DATA_CARD.md).
- **Results through parda** (213 hand-written cases, never seen in training; [details](bench/README.md)):

| | Base model | **parda-pii-edge** |
|---|---|---|
| Person recall, Indian names | 0.946 | **0.968** |
| Person recall, global names | 0.964 | **1.000** |
| Person precision | 0.934 | **1.000** |
| Address recall / precision | 0.75 / 0.27 | **1.00 / 1.00** |
| Cases with zero leaked values | 0.986 | **0.991** |

- **Why not a big LLM?** Filtering must be instant, private and run on every keystroke-sized message; a 32M model does that in milliseconds on a CPU, while rules with checksums handle structured IDs perfectly. Big generative models are slower, need more memory, and would themselves be another place your data goes.
- **Why fp32?** The INT8 version is 3× smaller, but the ONNX Runtime bundled today mis-executes it; it ships once the runtime is upgraded. Full story in the [model card](MODEL_CARD.md).

`parda model list` shows installed models; `parda model use parda-pii-edge` switches to it; `parda model import DIR` installs your own export (training scripts are in [`training/`](training/)).

---

## Privacy guarantees and honest limits

**Guarantees**

- Text is processed only on your machine.
- parda's only network traffic is:
  - forwarding your own AI traffic to the provider you configured (or that the site you're using talks to);
  - downloading the models you ask for, which are SHA-256 pinned.
- **Fail-closed by default** (`detect.mode = "strict"`): if the model fails or times out, the request is refused instead of being sent unfiltered.
- Logs, events and the dashboard never show values unless you turn on `privacy.log_values` (the dashboard asks you to confirm).

**Limits — please read**

- **No detector is perfect.** Unusual names in long, dense messages can be missed: about 1 in 100 hand-written test cases still leaks one value. Add the people who matter most with `parda rules add-person "Full Name"`; dictionary entries are always masked.
- **Pictures and files** inside requests are not scanned yet.
- **Typing directly into chat websites and apps** is protected only once system-wide interception ships; until then, use paste-safe.
- **The AI can still infer public facts.** parda hides *your* data, not public knowledge.

---

## Configuration

`config.toml` (path shown by `parda doctor`). Every key is optional. Highlights:

```toml
[protection]
enabled = true            # master switch (parda on / off)

[replace]
style = "token"           # "token" → [NAME_1] … | "surrogate" → realistic stand-ins

[detect]
mode = "strict"           # strict: refuse if the model fails · fast: rules only
model = "parda-pii-edge"  # or "default" (base model) or "none"
packs = ["global", "india", "us_uk", "secrets"]

[detect.actions]          # per kind: redact (default) | block | warn | ignore
Secret = "block"

[proxy]
listen = "127.0.0.1:8787"
anthropic_upstream = "https://api.anthropic.com"   # where filtered requests go
openai_upstream = "https://api.openai.com"
```

Full reference: [docs/configuration.md](docs/configuration.md). Every option is also in the dashboard's Settings tab.

---

## Commands

```text
parda                      # in a terminal: the dashboard (else this help)
parda setup | doctor | status | tui [--dump] | on | off | stop
parda redact | restore | scan [TEXT|-] [--scope S] [--json]
parda paste-safe
parda rules show | edit | add-person NAME | allow TERM
parda model list | pull ID | use ID | import DIR
parda vault stats | wipe [--scope S] | reset
parda service install | uninstall | status
parda env claude | codex | openai
parda daemon
```

---

## Building from source

```bash
git clone https://github.com/deadhearth01/parda && cd parda
cargo build --release -p parda          # add --features coreml (macOS) / directml (Windows) for hardware acceleration
cargo test --workspace
./target/release/parda setup
```

Rust 1.89+ (edition 2024). See [CONTRIBUTING.md](CONTRIBUTING.md).

## Project layout

| Crate | Role |
|---|---|
| `parda-core` | entity kinds, findings, configuration, validators |
| `parda-detect` | dictionary and rule tiers |
| `parda-ml` | model catalog, verified downloads, GLiNER runtime (vendored `gline-rs`, patched) |
| `parda-vault` | encrypted mapping store, key storage, tag and stand-in generators |
| `parda-engine` | detect → policy → tag → self-check → restore, caches, streaming restorer |
| `parda-proxy` | agent API proxy (Anthropic, OpenAI Chat, OpenAI Responses) |
| `parda-intercept` | system-wide HTTPS interception for AI hosts (in development) |
| `parda-clip` | clipboard watcher, paste-safe, hotkey |
| `parda-ipc`, `parda-daemon` | local socket protocol, the background daemon, login service |
| `parda-tui`, `parda-cli` | dashboard and the `parda` command |
| `parda-bench` | golden-corpus evaluation, latency and load tests, mock AI server |
| `training/` | synthetic data generator, fine-tuning, ONNX export (Python) |

## Roadmap

System-wide interception for every chat website and desktop app (in progress) · INT8 model (3× smaller and faster, needs an ONNX Runtime upgrade) · images and PDFs · more providers (Gemini, Bedrock) · native-script names (Devanagari, Tamil, Bengali …).

## License

Dual-licensed under [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option. Models are downloaded separately and keep their own permissive licenses (Apache-2.0).
