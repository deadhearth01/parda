# parda intercept Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** System-wide, real-time protection for AI chats in browsers and desktop apps: a local HTTPS interception proxy (AI hosts only, via PAC) that replaces personal data with `[NAME_1]`-style tags in requests and restores real values in responses.

**Architecture:** New crate `parda-intercept` (CONNECT proxy, CA + leaf certificates, TLS termination, generic body transforms) hosted by the daemon next to the agent proxy; reuses the engine, body decoding and SSE parsing from `parda-proxy`; CLI commands for CA trust and system proxy wiring.

**Tech Stack:** tokio, hyper 1 (server, HTTP/1.1), tokio-rustls / rustls 0.23, rcgen 0.14, reqwest (rustls), serde_json; macOS `networksetup` / `security`, Windows registry + `certutil`.

**Spec:** `docs/superpowers/specs/2026-10-13-parda-intercept-design.md`

## Global Constraints

- Never decrypt traffic for hosts outside `intercept.hosts`; tunnel it byte-for-byte.
- Upstream TLS always verified; failures surface as 502, never downgraded.
- Listener binds loopback only (`127.0.0.1:8788` default).
- No system change without an explicit user command; every change reversible (`parda intercept off`, `parda ca uninstall`).
- Logs/events never contain values.
- All builds on the SSD: `source scripts/dev-env.sh`, `CARGO_BUILD_JOBS ≤ 2` while other work runs.

## Review Focus

1. A request to an AI host whose body parda cannot parse must not reach the upstream unredacted (refuse, like the agent proxy).
2. Streaming answers must stay streaming (first bytes before upstream finishes) and tags split across SSE deltas must restore exactly.
3. Non-listed hosts must see no change at all (their own certificate reaches the client).
4. `intercept off` after a crash must still restore network settings (state file).
5. Identifier-like JSON fields (ids, tokens, model names) must never be altered.

---

### Task 1: `parda-intercept` core — CA, leaf certificates, CONNECT, TLS, host policy, PAC

**Files:** `crates/parda-intercept/{Cargo.toml, src/lib.rs, src/ca.rs, src/hosts.rs, src/pac.rs, src/server.rs, src/transform.rs}`, `tests/intercept.rs`.

**Interfaces (produces):**
- `pub struct Ca` — `Ca::generate() -> Result<Ca>`, `Ca::from_pem(cert_pem, key_pem)`, `fn cert_pem(&self) -> String`, `fn key_pem(&self) -> String`, `fn leaf_for(&self, host: &str) -> Result<Arc<rustls::sign::CertifiedKey>>` (cached per host; SAN = host; validity 1 year; EKU serverAuth).
- `pub struct HostList` — `HostList::new(&[String])`, `fn matches(&self, host: &str) -> bool` (exact or subdomain of an entry, case-insensitive, no port).
- `pub fn pac(hosts: &HostList, proxy: SocketAddr) -> String` — JavaScript PAC returning `PROXY 127.0.0.1:PORT` for listed hosts, `DIRECT` otherwise.
- `pub trait BodyTransform: Send + Sync + 'static { fn request(&self, host: &str, path: &str, headers: &http::HeaderMap, body: Bytes) -> Result<Bytes, Refusal>; fn response_stream(&self, host: &str, path: &str, content_type: &str) -> Box<dyn StreamTransform>; }` and `pub trait StreamTransform: Send { fn push(&mut self, chunk: &[u8]) -> Bytes; fn finish(&mut self) -> Bytes; }`; `pub struct Refusal { pub status: u16, pub message: String }`.
- `pub struct InterceptState { ca, hosts, transform: Arc<dyn BodyTransform>, events: broadcast::Sender<InterceptEvent>, upstream: reqwest::Client }`; `pub async fn serve(listener: TcpListener, state: Arc<InterceptState>) -> anyhow::Result<()>`.
- `pub struct InterceptEvent { host, path, status, counts: BTreeMap<String,u32>, added_ms, refused: Option<String>, unscanned: u32 }`.

- [ ] Tests first (`tests/intercept.rs`, no network): a fake upstream HTTPS server (own test CA via rcgen) on 127.0.0.1; an `InterceptState` whose upstream reqwest client trusts the test CA and resolves `chat.test` / `other.test` to 127.0.0.1 (`reqwest::ClientBuilder::resolve`); a client reqwest with `.proxy(Proxy::all("http://127.0.0.1:PORT"))`, trusting the parda CA, resolving both names.
  - listed host `chat.test`: request body transformed (use a test transform that uppercases "secret") reaches upstream transformed; response transformed back; client sees parda leaf cert (verify via the CA it trusts).
  - unlisted host `other.test`: client must trust the *test upstream* CA to succeed (proves byte tunnel) and body arrives unchanged.
  - transform refusal → client gets the refusal status, upstream receives nothing.
  - SSE response streamed: first chunk reaches client before upstream closes (upstream sleeps 500 ms between events).
  - `GET http://127.0.0.1:PORT/parda.pac` returns the PAC; PAC text routes `chat.test` and `x.chat.test` to the proxy and `example.com` DIRECT.
  - Upstream with a certificate not trusted by parda's upstream client → client gets 502.
- [ ] Implement: hyper server per accepted TCP connection; `CONNECT host:port` → if `HostList::matches` then reply 200 and TLS-accept with `rustls::ServerConfig` using a `ResolvesServerCert` that calls `ca.leaf_for(sni)` (reject SNI ≠ CONNECT host), ALPN `http/1.1`, then serve HTTP/1.1 on the TLS stream; else reply 200 and `copy_bidirectional` to `host:port`. Plain `GET /parda.pac` → PAC. Other plain-HTTP requests → 405.
  - Inside TLS: build upstream URL `https://{host}{path_and_query}`, copy end-to-end headers (drop hop-by-hop, `content-length`, `content-encoding`; set `accept-encoding: identity`), body via `transform.request` (bodies ≤ 64 MiB), stream the response through `transform.response_stream` (hyper `Body::from_stream`).
  - WebSocket upgrade requests (`connection: upgrade`) on listed hosts: tunnel the upgraded connection raw after relaying the 101 (emit `unscanned` event).
- [ ] clippy, fmt, commit.

### Task 2: Engine-backed transforms (generic JSON / form / SSE) + tag format

**Files:** `crates/parda-intercept/src/{engine_transform.rs, walk.rs, sites.rs}`; `crates/parda-core/src/config.rs` (`[intercept]` section: `enabled=false, listen, hosts, style="token", scope="global", unscanned="allow"`; `replace.token_format = "[{LABEL}_{N}]"`); `crates/parda-core/src/kind.rs` (`tag_label()`); parda-vault surrogate token function uses the format; engine supports per-call style override.

- [ ] Tests first: identifier keys untouched; JSON-in-string walked; form-encoded redacted; compressed bodies decoded (reuse parda-proxy decoding module, moved to a shared place if needed); unparseable JSON to a listed host → refusal 400 `parda_unparseable_body`; SSE per-path restore under arbitrary chunking for chatgpt-style (`{"p":"/message/content/parts/0","o":"append","v":"..."}` and `{"v":"..."}` continuation) and claude-style (`{"type":"completion","completion":"..."}` / `content_block_delta`) events; tags `[NAME_1]` produced and restored (also `[name_1]`).
- [ ] Implement; site skip lists for the hosts in the spec.

### Task 3: Daemon wiring + events + TUI

- [ ] Daemon starts the intercept listener when `intercept.enabled`; loads or creates the CA (encrypted with the vault key); events surface `intercept` in Live/Dashboard; Settings rows for intercept on/off, style, unscanned.

### Task 4: CLI — `parda ca …`, `parda intercept on|off|status`

- [ ] `parda ca create|path|install|uninstall|status` (macOS `security add-trusted-cert -r trustRoot -k login keychain` / `security remove-trusted-cert`; Windows `certutil -user -addstore Root` / `-delstore`; Linux prints instructions).
- [ ] `parda intercept on`: ensure CA exists and is trusted (else explain), set `intercept.enabled = true`, save previous auto-proxy settings to `intercept-state.json`, set PAC URL for each enabled network service (`networksetup -listallnetworkservices`, `-getautoproxyurl`, `-setautoproxyurl`, `-setautoproxystate on`); Windows registry `AutoConfigURL`. `off` restores exactly from the state file. `status` reports CA trust, PAC active, listener up, hosts.
- [ ] Tests: state file round-trip; command lines generated (no execution in tests).

### Task 5: Manual end-to-end on the owner's Mac + docs

- [ ] `parda ca install` (owner approves macOS dialog), `parda intercept on`, chat on chatgpt.com / claude.ai in Chrome + Safari, ChatGPT and Claude desktop apps; capture upstream-side counts; fix site skip lists; `parda intercept off`.
- [ ] README/docs: "Protect every AI chat" section, limitations (pinned apps, WebSockets, Firefox prefs).
