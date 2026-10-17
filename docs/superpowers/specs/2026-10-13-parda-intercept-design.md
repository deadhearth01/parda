# parda intercept — design spec

*Date: 2026-10-13 · Status: approved direction (owner chose "system-wide HTTPS interception" and "tags like [NAME_1]"); details decided by implementer under delegation.*

## 1. Intent

| | |
|---|---|
| **Outcome** | Whatever you use to chat with an AI — a browser tab (ChatGPT, Claude, Gemini, Copilot, Perplexity, DeepSeek …), a desktop app (ChatGPT, Claude), or a CLI — personal data in what you type is replaced by tags such as `[NAME_1]`, `[EMAIL_2]`, `[AADHAAR_1]` before it leaves the machine, and the real values reappear in the answers you see. In real time, with no copy/paste step. |
| **How** | parda runs a local HTTPS interception proxy. A proxy auto-config (PAC) file sends **only AI hosts** to it; everything else goes direct and is never decrypted. For AI hosts parda terminates TLS with a locally generated root certificate the user trusts once, rewrites request bodies (redact) and response bodies (restore), and forwards to the real server with normal certificate verification. |
| **Constraints** | Local only. Never decrypt non-AI traffic. No silent system changes — every system-level step (trusting the certificate, switching the proxy) is an explicit `parda` command the user runs and can undo. Same engine, vault and policy as the agent proxy. |
| **Success** | (1) On chatgpt.com and claude.ai in Chrome and Safari, a message containing a name, phone, e-mail and Aadhaar reaches the server with tags only (verified from parda's upstream-side capture) and the page shows the real values in the answer. (2) Non-AI sites are untouched (CONNECT tunnelled, no certificate change visible). (3) Added latency on a chat send ≤ model time + 20 ms. (4) `parda intercept off` restores the previous network settings exactly. |

## 2. Scope

### In
- `parda-intercept` crate: CONNECT proxy on `127.0.0.1:8788` (config `intercept.listen`), host policy, TLS termination (rustls) with per-host leaf certificates signed by the parda CA (rcgen, cached in memory), HTTP/1.1 to the client (ALPN offers `http/1.1` only), HTTP/1.1 or h2 to the upstream via reqwest with system/webpki roots.
- Generic redaction of requests to AI hosts (§4): JSON (string values and object keys; identifier-shaped values under identifier keys skip only the ML model), `application/x-www-form-urlencoded` (values, keys, value-less pieces), query strings, text bodies, multipart text fields (base64 included), JSON and form encoding sniffed whatever the content type, URL queries inside strings, `Referer` query and fragment removed. Compressed request bodies decoded (gzip/deflate/br/zstd). Multipart file parts and binary bodies: forwarded, counted as unscanned media (warn event); `intercept.unscanned = "allow" | "block"`. *(Updated 2026-10-17, Task 2 fix round 1.)*
- Generic restoration of responses (§5), only on the user's own endpoints: JSON string leaves; SSE (`text/event-stream`) — per event, per JSON path, a `StreamRestorer` so a tag split across deltas restores exactly; NDJSON line streams; `text/plain`. Gemini-style `)]}'` length-prefixed frames restored with recomputed lengths, JSON inside strings at its own level. HTML and other types are not rewritten. *(Updated 2026-10-14 per controller ruling: no `text/html` restore; JSON-safe restore only. Updated 2026-10-17: restore only on allowlisted endpoints or streamed sends.)*
- Site adapters for keys that must never be touched and quirks: chatgpt.com, claude.ai, gemini.google.com, copilot.microsoft.com, perplexity.ai, chat.deepseek.com, chat.mistral.ai, grok.com, meta.ai, poe.com (list in config, user-extensible).
- WebSocket upgrades to AI hosts: tunnelled without inspection, warn event (Copilot uses WebSockets — documented limitation for v1 of intercept).
- CA lifecycle: `parda ca create | path | install | uninstall | status`. Key stored 0600 in the data dir (encrypted with the vault key); certificate 10-year validity, name constraints are not used (browsers ignore them on roots inconsistently).
- System wiring: `parda intercept on | off | status`.
  - macOS: generates a PAC file served by the daemon at `http://127.0.0.1:8788/parda.pac`, sets it for every enabled network service with `networksetup -setautoproxyurl`, remembers the previous setting in `intercept-state.json`, restores it on `off`. Certificate trust via `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db` (macOS shows its own password dialog).
  - Windows: PAC via `HKCU\…\Internet Settings\AutoConfigURL` + `InternetSetOption` refresh; certificate via `certutil -user -addstore Root` (Windows shows its own confirmation).
  - Linux: GNOME `gsettings` proxy autoconfig URL; certificate instructions (system store requires sudo) — documented, not automated.
  - Firefox: uses its own settings; `parda intercept on` prints the two prefs to set (`network.proxy.autoconfig_url`, `security.enterprise_roots.enabled`).
- Tags: replacement style `token`, format `[{LABEL}_{N}]` with friendly labels (Person → NAME, Email → EMAIL, Phone → PHONE, Aadhaar → AADHAAR, Pan → PAN, CreditCard → CARD, BankAccount → ACCOUNT, Address → ADDRESS, Upi → UPI, Secret → SECRET …). Restoration accepts the exact tag and case variants. Every surface, intercept included, uses the global `replace.style` (default `token`). *(Superseded 2026-10-13: an earlier draft had a separate `intercept.style` and a configurable `replace.token_format`; the controller ruled for one global style; the tag format is fixed, as already shipped by parda-vault.)*
- TUI/CLI: intercept status on the dashboard and Settings tab (on/off, CA trusted?, hosts); events per surface `intercept`.

### Out (later)
- HTTP/2 or HTTP/3 to the client; QUIC (browsers do not use QUIC through a proxy, so not needed).
- WebSocket frame inspection.
- Apps that pin certificates (they will fail to connect while intercept is on for their host; documented, host can be removed from the list).
- Image/file content.

## 3. Architecture

```
browser / desktop app ──PAC──► AI host?  no ──► DIRECT (untouched)
                                         yes ─► parda intercept 127.0.0.1:8788
                                                  CONNECT host:443
                                                  ├─ host not in list → blind TCP tunnel
                                                  └─ host in list → TLS (parda CA leaf)
                                                        request: decode → redact (engine, scope intercept:<host>) → forward (rustls, verified)
                                                        response: decode → restore (JSON / SSE per path / text) → client
```

- Runs inside the daemon (shares `Engine`, events, config); `intercept.enabled` starts the listener. The PAC endpoint is served by the same listener (plain GET `/parda.pac`).
- Scope: `intercept.scope` (default `"per-host"`): each listed site gets its own vault scope `intercept:<host>`, so a site's answers can only restore tags issued for text sent to that same site (a restore oracle across sites or surfaces is closed). Any other value is a fixed scope name (`"global"` shares tags with the clipboard and the CLI). *(Updated 2026-10-14 per controller ruling; earlier draft: default `"global"`.)*
- Fail mode: the PAC gives listed hosts no `DIRECT` fallback, so while a browser holds the PAC and parda is stopped, AI sites fail rather than go out unfiltered. Plain `http://` to a listed host is answered with a redirect to `https://`, and `ws://` to a listed host is refused. If the PAC itself cannot be fetched (parda was never started, or the OS dropped the cached file), the OS goes DIRECT; the TUI and `parda status` say whether intercept is active. *(Updated 2026-10-13 per Task 1 rulings; earlier draft: DIRECT fallback.)*
- While parda runs, a request it cannot filter is refused and never forwarded unfiltered (the site shows a network error; parda's event explains). Refusal messages carry a code and kinds, never request text:

  | Status, code | When |
  |---|---|
  | 400 `parda_unparseable_body` | body typed as JSON that does not parse; a JSON key repeated anywhere (also JSON in strings, forms, queries, sniffed bodies); two keys that redaction makes equal; multipart without a boundary, not splitting per RFC 2046, or with the boundary in its preamble or epilogue |
  | 400 `parda_not_utf8` | form, `text/*` or JSON body declaring a charset other than UTF-8/US-ASCII; form or `text/*` body not UTF-8 or holding NUL bytes |
  | 413 `parda_body_too_large` | decoded body over the cap |
  | 415 `parda_unsupported_encoding` | unknown `content-encoding` |
  | 415 `parda_unscanned_blocked` | unscanned part with `intercept.unscanned = "block"` |
  | 503 `parda_ml_unavailable` | strict mode and the ML detector failed |
  | 403 `parda_blocked` | a `block` action (names kinds only) |
  | 500 `parda_internal` | other engine errors |

## 4. Request redaction rules (generic)

- JSON: walk all string leaves; identifier-shaped values (≤ 64 chars of `[A-Za-z0-9_.:/+=-]`) under keys matching identifier patterns (`id`, `*_id`, `*Id`, `uuid`, `model`, `token`, `*_token`, `nonce`, `signature`, `timestamp`, `create_time`, `parent`, `parent_message_id`, `conversation_id`, `organization_uuid`, `locale`, `timezone`, `client_*`, `arkose*`, `sentinel*`) and identifier-shaped values that look like identifiers (UUIDs, hex ≥ 16, base64 ≥ 32 chars, URLs to a listed host) skip only the ML model: the dictionary and rule tiers still redact an e-mail, phone, ID number or key in them, and anything not identifier-shaped is redacted like text under any key (one engine call per request via `Engine::redact_many_tiered`). Site adapters add skip keys. *(Updated 2026-10-14 per controller ruling: skipping never hides personal data.)*
- Strings that themselves contain JSON (e.g. Gemini `f.req`) are parsed and walked recursively (depth ≤ 4); beyond that, or when they do not parse, they are redacted as plain text.
- JSON object keys are scanned at every depth (identifier-shaped keys skip only the ML model); a key with a finding is renamed in place, key order kept.
- `application/x-www-form-urlencoded` and query strings: decode, redact values, keys and value-less pieces with the same rules, re-encode what changed (unchanged pairs keep their bytes).
- Sniffing, whatever the content type: a body that parses as a JSON object or array is walked as JSON; so is a body not declared as a form whose non-blank lines are each a JSON value (NDJSON), or that is one JSON string (each line walked as JSON, separators kept; a number or literal line read as text; strings and keys also read decoded as a form, and number literals read as text, a found one becoming a JSON string, so the whole-body readings of a text body are kept), and a text or untyped body that starts with `{`, `[` or `"`, holds a backslash and is neither is refused (`400 parda_unparseable_body`: never read with JSON escapes taken literally) *(updated 2026-10-17, final review and R8)*; a text or untyped UTF-8 body using only form-encoder characters with an `=`, `+` or `%XX` is walked as a form. A form or `text/*` body that is not UTF-8, holds NUL bytes (UTF-16 of ASCII is valid UTF-8) or declares another charset is refused; an untyped one like that is binary (unscanned). *(Updated 2026-10-17, fix round 1b.)*
- `http(s)://` URLs inside any visited string: their query is decoded and redacted with the form rules, in the same engine batch, and re-encoded only when it changed.
- `Referer` on requests (and upgrades) to listed hosts loses its query and fragment.
- `multipart/form-data`: delimiters per RFC 2046 (`--boundary` then `--`, or optional spaces/tabs and CRLF); text and JSON fields without a filename are redacted, base64 ones decoded and re-encoded; files, other types, other charsets, fields with NUL bytes and other transfer encodings are unscanned.
- Content-Length recomputed; `content-encoding` removed after decoding. Headers other than `Referer` are not changed. *(Updated 2026-10-17, Task 2 fix round 1.)*

## 5. Response restoration

- Only tags/stand-ins of the site's own scope are touched (per-host scopes, §3).
- Only the user's own answers (`sites.rs`, decided per method and path; everything else passes through with its tags, so shared conversations, GPT/bot descriptions and public pages never get the viewer's values):
  - chatgpt.com / chat.openai.com, claude.ai, gemini.google.com: answers to POST on the send endpoints (chatgpt `/backend-api/conversation`, `/backend-api/f/conversation`; claude `/api/organizations/*/chat_conversations/*/completion`, `…/retry_completion`; Gemini `…/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate`, also under `/u/*/`) and to GET on the history endpoints (chatgpt `/backend-api/conversation/*`, `/backend-api/conversations`; claude `/api/organizations/*/chat_conversations[/*]`). Gemini `batchexecute` is never restored, so Gemini history shows tags.
  - Every other listed host: only streamed answers to POST (`text/event-stream`, NDJSON types, or several JSON values under a JSON type); never a single JSON document, a text body, or any GET.
  - Paths match on the path only (no query or fragment), each segment percent-decoded once, literals ASCII-case-insensitive, `*` = one segment; a path with an empty, `.` or `..` segment, or a `/`, `%`, `\`, `;` or control character left after decoding, matches nothing.
- Never inside URLs (`parda_wire::urlguard`, a state machine that must never end a URL before the renderer does): CommonMark link/image destinations (`<…>` to an unescaped `>` or line ending; bare to ASCII space/control or an unbalanced `)`; backslash escapes; Unicode whitespace never ends one), reference definitions after any `]:`, autolinks `<scheme:…>` and `www.`, every attribute value inside an HTML tag (unquoted values end only at TAB, LF, FF, CR, SPACE), CSS `url(…)`/`image-set(…)` (quotes honoured) and `@import` (to an unquoted `;`). Defence in depth: the engine's url-safe restore never restores a tag whose preceding run of non-ASCII-whitespace text holds any of `/ ? = & % \ : @`, follows `www.`, or exceeds 2 KiB. Applied on every restore path (JSON leaves, SSE, NDJSON, text, streamed JSON fragments), with guard state kept across chunks, events, forced flushes and unknown patch ops.
- JSON-safe: real values land only inside parsed JSON strings (re-serialised), JSON-escaped in streamed JSON fragments (`partial_json`, `arguments`, or JSON text streamed under an unknown key), or in plain text; JSON inside strings is restored at its own level; data that looks like JSON (`{`, `[`, `"`) but does not parse — and a body or NDJSON line that is not valid JSON — passes through unrestored, never as text. A string that is clearly JSON (reaches a string or an object) but does not parse is left alone. Text streamed under an unknown key or a chatgpt.com patch path is held until its start tells: JSON text once it reaches a string or an object (decided on the first 1 KiB, so never by how it was split), plain text otherwise; JSON text that stops being JSON passes through from there, and unchanged text in JSON fragments goes out exactly as it came. *(Updated 2026-10-17, fix round 1b.)*
- Bounded: one SSE event, NDJSON line or Google frame is held up to 16 MiB; a larger one goes out as it came and the rest of that answer passes through unrestored. Each byte is scanned once (no rescanning of growing buffers). Per stream, restorer keys are at most 512 bytes and one item starts at most 1024 new restorers (other leaves are restored on their own); past 4096 restorers or 16 MiB of kept previous values the longest-unused idle ones are dropped. An upstream error mid-stream first sends what was held back.
- Google `)]}'` frames: the length prefix (UTF-16 code units, counted from right after the digits) is recomputed after restoring the frame; a frame that does not parse passes through unrestored.
- SSE: events parsed incrementally; for each `data:` payload that is JSON, string leaves are restored with a `StreamRestorer` keyed by the event's JSON path (plus the `p` path field of chatgpt.com delta-encoding when present); non-JSON data lines use one restorer per stream. Flush on stream end.
- `accept-encoding: identity` is forced upstream for AI hosts so responses can be rewritten; responses are streamed (no full buffering) except JSON documents ≤ 16 MiB on endpoints where documents are restored. A JSON body that turns out to hold several values in a row switches to the NDJSON path.

## 6. Security

- CA private key never leaves the machine; 0600; encrypted at rest with the vault key; regenerating it requires `parda ca create --force` and re-trust.
- Leaf certificates only for hosts in `intercept.hosts`; requests for other hosts are tunnelled byte-for-byte (parda never sees their plaintext).
- Upstream TLS verified with platform roots; a verification failure is passed to the client as a 502 (never downgraded).
- The listener binds loopback only; Host/SNI must match the CONNECT target.
- Logs/events: host, path, counts, latency — never values.

## 7. Testing

- Unit: PAC generation, host matching (suffixes, subdomains), identifier-key skipping, JSON-in-string walking, form encoding, SSE per-path restore under arbitrary chunking, tag format and restore.
- Integration (no network): local fake "AI site" HTTPS server with its own test CA as upstream, parda intercept in front with its CA; a reqwest client configured with the proxy and parda's CA sends chatgpt-shaped and claude-shaped requests; assert upstream saw tags only and the client got real values; non-listed host is tunnelled (client sees the fake site's own certificate).
- Manual E2E (owner's Mac): `parda ca install`, `parda intercept on`, chat on chatgpt.com and claude.ai in Chrome and Safari; `parda intercept off` restores settings.

## 8. Decisions log

| Decision | Choice | Why |
|---|---|---|
| Routing | PAC listing AI hosts only | Never touch non-AI traffic; easy to undo |
| Client protocol | HTTP/1.1 via ALPN | Simple, every browser supports it through a proxy |
| Redaction | Generic walker + per-site skip lists | Private web APIs change often; generic survives most changes |
| Tag format | `[NAME_1]` style (owner choice) | Visible, short, model-friendly |
| Fail mode | Non-AI hosts DIRECT; listed hosts have no DIRECT fallback (Task 1 ruling) | A dead proxy must not break the internet, and AI sites must not go out unfiltered; status shows protection state |
| Restore authorization | Own send/history endpoints of known sites; streamed POST answers elsewhere (Task 2 ruling I5) | Content other users wrote must never get the viewer's real values |
| Desktop apps | Covered when they honour system proxy + trust store | Pinned apps documented as limitation |
