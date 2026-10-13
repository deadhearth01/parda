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
- Generic redaction of request bodies to AI hosts: JSON (string leaves, minus identifier-like keys), `application/x-www-form-urlencoded` (values), `text/plain`. Compressed request bodies decoded (gzip/deflate/br/zstd). Multipart file parts and binary bodies: forwarded, counted as unscanned media (warn event); `intercept.unscanned = "allow" | "block"`.
- Generic restoration of responses: JSON string leaves; SSE (`text/event-stream`) — per event, per JSON path, a `StreamRestorer` so a tag split across deltas restores exactly; NDJSON line streams; `text/plain`. Gemini-style `)]}'` prefixed JSON-in-text handled by restoring raw text with the plain restorer.
- Site adapters for keys that must never be touched and quirks: chatgpt.com, claude.ai, gemini.google.com, copilot.microsoft.com, perplexity.ai, chat.deepseek.com, chat.mistral.ai, grok.com, meta.ai, poe.com (list in config, user-extensible).
- WebSocket upgrades to AI hosts: tunnelled without inspection, warn event (Copilot uses WebSockets — documented limitation for v1 of intercept).
- CA lifecycle: `parda ca create | path | install | uninstall | status`. Key stored 0600 in the data dir (encrypted with the vault key); certificate 10-year validity, name constraints are not used (browsers ignore them on roots inconsistently).
- System wiring: `parda intercept on | off | status`.
  - macOS: generates a PAC file served by the daemon at `http://127.0.0.1:8788/parda.pac`, sets it for every enabled network service with `networksetup -setautoproxyurl`, remembers the previous setting in `intercept-state.json`, restores it on `off`. Certificate trust via `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db` (macOS shows its own password dialog).
  - Windows: PAC via `HKCU\…\Internet Settings\AutoConfigURL` + `InternetSetOption` refresh; certificate via `certutil -user -addstore Root` (Windows shows its own confirmation).
  - Linux: GNOME `gsettings` proxy autoconfig URL; certificate instructions (system store requires sudo) — documented, not automated.
  - Firefox: uses its own settings; `parda intercept on` prints the two prefs to set (`network.proxy.autoconfig_url`, `security.enterprise_roots.enabled`).
- Tags: replacement style `token` with a configurable format; new default token format `[{LABEL}_{N}]` with friendly labels (Person → NAME, Email → EMAIL, Phone → PHONE, Aadhaar → AADHAAR, Pan → PAN, CreditCard → CARD, BankAccount → ACCOUNT, Address → ADDRESS, Upi → UPI, Secret → SECRET …). Restoration accepts the exact tag and case variants. The intercept surface defaults to tags; the agent proxy keeps the global `replace.style`. Config: `replace.style` (global), `intercept.style` (overrides for intercept; default `token`), `replace.token_format`.
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
                                                        request: decode → redact (engine, scope "chat") → forward (rustls, verified)
                                                        response: decode → restore (JSON / SSE per path / text) → client
```

- Runs inside the daemon (shares `Engine`, events, config); `intercept.enabled` starts the listener. The PAC endpoint is served by the same listener (plain GET `/parda.pac`).
- Scope: `intercept.scope` (default `"global"`, same as clipboard) so a name has the same tag in the browser, the clipboard and the CLI.
- Fail mode: if parda is not running, the PAC URL is unreachable and the OS falls back to DIRECT — AI sites work unprotected (documented; TUI and `parda status` say whether intercept is active). While parda runs, strict mode refuses a send whose redaction fails (the site shows a network error; parda's event explains).

## 4. Request redaction rules (generic)

- JSON: walk all string leaves; skip keys matching identifier patterns (`id`, `*_id`, `*Id`, `uuid`, `model`, `token`, `*_token`, `nonce`, `signature`, `timestamp`, `create_time`, `parent`, `parent_message_id`, `conversation_id`, `organization_uuid`, `locale`, `timezone`, `client_*`, `arkose*`, `sentinel*`) and values that look like identifiers (UUIDs, base64 ≥ 40 chars without spaces, URLs to the same host). Site adapters add/override skip keys.
- Strings that themselves contain JSON (e.g. Gemini `f.req`) are parsed and walked recursively (depth ≤ 4).
- `application/x-www-form-urlencoded`: decode, redact values with the same rules, re-encode.
- Content-Length recomputed; `content-encoding` removed after decoding.

## 5. Response restoration

- Only tags/stand-ins of the scope are touched, so restoring every string is safe.
- SSE: events parsed incrementally; for each `data:` payload that is JSON, string leaves are restored with a `StreamRestorer` keyed by the event's JSON path (plus the `p` path field of chatgpt.com delta-encoding when present); non-JSON data lines use one restorer per stream. Flush on stream end.
- `accept-encoding: identity` is forced upstream for AI hosts so responses can be rewritten; responses are streamed (no full buffering) except JSON ≤ 16 MiB.

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
| Fail mode | DIRECT when parda is down | A dead proxy must not break the internet; status shows protection state |
| Desktop apps | Covered when they honour system proxy + trust store | Pinned apps documented as limitation |
