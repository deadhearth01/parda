# Architecture

parda is one binary. `parda daemon` is a long-running process that owns everything stateful; `parda` subcommands and `parda tui` are thin clients that talk to it over a local socket and fall back to an in-process engine when it is not running.

```text
 clients:  parda tui ──┐   parda redact/scan/… ──┐   parda paste-safe ──┐
                       ▼                          ▼                      ▼
             ┌────────────────────── IPC (parda-ipc, NDJSON) ─────────────────────┐
             │                         parda daemon                               │
 agents ───► │  proxy (parda-proxy) ─┐                                            │──► api.anthropic.com
 (HTTP)      │  clipboard (parda-clip)┼─► Engine (detect + ML + vault + restore) ─│    api.openai.com
 OS clip ◄──►│                        ┘    events ─► broadcast ─► TUI / logs       │
             └────────────────────────────────────────────────────────────────────┘
```

## Crates

| Crate | Responsibility |
|---|---|
| `parda-core` | `EntityKind`, `Span`, `Detection`, overlap merge policy, configuration, validators (Luhn, Verhoeff, IBAN, GSTIN, PAN), the `MlDetector` trait |
| `parda-detect` | T0 `DictionaryDetector` (person blocks → name variants, Aho-Corasick), T1 `RuleDetector` (rule packs `global`, `india`, `us_uk`, `secrets`), `AllowList` |
| `parda-ml` | Model catalog with pinned SHA-256s, verified downloads/imports, `GlinerDetector` (ONNX Runtime via a vendored `gline-rs`), execution-provider selection |
| `parda-vault` | Encrypted mapping store (SQLite + XChaCha20-Poly1305 + keyed HMAC index), key storage (OS keyring or 0600 key file), deterministic format-preserving `SurrogateGen` |
| `parda-engine` | Fragmenting, detection cache, ML worker with a time budget, merge → allow-list → actions, surrogate assignment, `restore`, `StreamRestorer` |
| `parda-proxy` | axum proxy: guards, routing, Anthropic / OpenAI Chat / OpenAI Responses adapters, SSE rewriting |
| `parda-clip` | Clipboard watcher, paste-safe, restore-on-copy, global hotkey |
| `parda-ipc` | Request/response/event protocol over Unix sockets / named pipes |
| `parda-daemon` | Wiring, paths, logging, event conversion, service install |
| `parda-tui` | ratatui dashboard |
| `parda` (`crates/parda-cli`) | The command-line interface |
| `parda-bench` | Golden-corpus evaluation, latency harness, mock upstream |

## Redaction pipeline

```text
redact_many(texts, scope)
  for each text: split into fragments (paragraph → line → sentence → word, ≤ 2000 bytes)
  for each fragment: detection cache (BLAKE3 of fragment + rules epoch)
      miss → T0 dictionary + T1 rules (µs)
           + T2 model for every unseen fragment, batched on the ML worker thread
             (budget = detect.ml_timeout_ms per 4 KiB of new text; late results still fill the ML cache)
           → absorb names inside e-mails/URLs → merge (dictionary > validated rule > model > plain rule,
             then longer span, then score) → allow-list
  surrogate-echo guard: text that already looks like one of this scope's surrogates gets its own mapping
  per-kind action: redact | block (whole request refused) | warn | ignore
  surrogates from the vault index; new ones are generated deterministically and stored before use
```

`strict` mode refuses the request when the model fails or times out; `fast` mode continues with T0 + T1 and does not cache that result, so the next request gets another chance at the model.

## Surrogates

The seed of a surrogate is `HMAC(vault key, scope ‖ kind ‖ normalised value)`, so a value maps to the same stand-in across sessions. On a collision the generator re-rolls (`attempt + 1`); after 64 attempts it falls back to a numbered token (`⟦PERSON_12⟧`).

- **Names** keep their word count, honorifics, initials and letter case, and draw from Indian or Western lists depending on the original. Each name word is also stored on its own (`Ravi → Arjun`), and an existing word mapping is reused when another name shares that word, so "Ravi" is the same stand-in in "Ravi Kumar" and "Ravi Verma".
- **Case variants** of a value share a stand-in, re-cased (`RAVI KUMAR → ARJUN MEHTA`).
- **Identifiers** keep layout, separators and checksums (Aadhaar Verhoeff, card Luhn, GSTIN mod-36, IBAN mod-97), and the non-identifying parts: public mail domains, UPI handles, state codes, IFSC bank codes, key prefixes like `sk-ant-api03-`.
- **Addresses, organisations, custom terms** become typed tokens in v0.1.

## Restore

Per scope, an Aho-Corasick automaton over all surrogates (leftmost-longest, ASCII case-insensitive) finds word-bounded occurrences; if the longest one sits inside a bigger word, a shorter surrogate at the same position is tried. The real value is re-cased to match what the model wrote. The streaming `StreamRestorer` emits everything except the longest tail that could still become a surrogate; for any chunking its output equals the non-streaming restore (property-tested).

## Proxy

- Guards: `Host` must be loopback (DNS rebinding); requests with an `Origin` header are refused unless allow-listed (browser CSRF). No CORS headers are sent.
- Requests to `/v1/messages` (and `count_tokens`, `batches`), `/v1/complete`, `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`, `/v1/responses` (and its side endpoints) and `/v1/conversations` are rewritten (the body must be a JSON object; decoding, parsing and redaction run on a blocking thread). Other paths pass through only if their body holds no text; a body with text on an unknown path is refused unless the path is listed in `proxy.passthrough_paths` (forwarded unfiltered, with a warning event per request).
- Every redactable string of a request is collected by a provider walker and redacted in one engine batch (one model call), then written back. `thinking` / `redacted_thinking` blocks (signed) and unknown block types are never modified.
- Responses: JSON bodies are restored; SSE streams are parsed event by event and each content block / choice / output item gets its own stream restorer, flushed with a synthetic delta just before its stop/done event. Upstream errors are passed through with their strings restored.

## Daemon and IPC

The daemon listens on `<runtime>/parda.sock` (directory 0700) or the named pipe `parda-<user>` on Windows, speaking newline-delimited JSON with a version handshake. Clients: `Status`, `Redact`, `Restore`, `Scan`, `PasteSafe`, `Subscribe` (event stream), `RulesGet/Set`, `VaultStats/Wipe`, `ConfigGet/Set`, `Reload`, `Shutdown`.
