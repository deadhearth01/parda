# Configuration

`config.toml` lives in the config directory (`parda doctor` prints it; `PARDA_HOME=/some/dir` puts everything under one folder). Every key is optional; this is the full default:

```toml
[protection]
enabled = true                     # master switch: false sends text as typed (answers still restored)

[proxy]
enabled = true
listen = "127.0.0.1:8787"
anthropic_upstream = "https://api.anthropic.com"
openai_upstream = "https://api.openai.com"   # any OpenAI-compatible server works
unscanned_media = "allow"                    # allow | block — images / binary documents
allowed_origins = []                         # web origins allowed to call the proxy
allow_non_loopback = false                   # accept non-localhost Host headers
max_body_bytes = 67108864
passthrough_paths = []                       # paths forwarded unfiltered, e.g. ["/api/*"] (see below)

[detect]
mode = "strict"                    # strict: refuse if the model fails · fast: continue with rules
packs = ["global", "india", "us_uk", "secrets"]
dates = false                      # dates of birth are still caught next to "DOB", "born" …
model = "default"                  # catalog id, "default", or "none" (rules + your names only)
ml_threshold = 0.4                 # lower = more recall; 0.4 chosen on the golden corpus
ml_timeout_ms = 250                # per 4 KiB of not-yet-seen text, capped at 30 s
execution_provider = "auto"        # auto | cpu | coreml | directml | cuda

[detect.actions]                   # per kind: redact | block | warn | ignore
# Secret = "block"
# Organization = "ignore"

[replace]
style = "token"                    # token: [NAME_1], [EMAIL_2], [AADHAAR_1] … | surrogate: realistic stand-ins

[vault]
ttl_days = 30                      # mappings unused this long are deleted (0 = keep)
use_keyring = true                 # vault key in the OS keychain; else data/vault.key (0600)

[clipboard]
enabled = true
poll_ms = 300
hotkey = "default"                 # Cmd+Alt+V on macOS, Ctrl+Alt+V elsewhere; e.g. "ctrl+shift+p"
restore_on_copy = true
scope = "global"

[intercept]                        # AI websites and desktop apps (see "Intercept" below)
enabled = false
listen = "127.0.0.1:8788"
hosts = ["chatgpt.com", "chat.openai.com", "claude.ai", "gemini.google.com", "copilot.microsoft.com",
         "perplexity.ai", "chat.deepseek.com", "chat.mistral.ai", "grok.com", "meta.ai", "poe.com"]
scope = "per-host"                 # each site its own scope; or a fixed name, e.g. "global"
unscanned = "allow"                # allow | block — file uploads and binary bodies
skip_keys = []                     # extra JSON / form keys never changed, e.g. ["trace_tag"]

[privacy]
log_values = false
```

Kinds: `Person Email Phone Address Url IpAddress MacAddress CreditCard Iban BankAccount Ifsc Aadhaar Pan Gstin Upi VoterId DrivingLicence IndianVehicleReg Passport UsSsn UkNino DateOfBirth Secret Organization`, plus any custom kind you use in `rules.toml`.
Built-in names ignore case and `_` / `-` / spaces (`secret`, `IP_ADDRESS` work); any other key is
taken as a custom kind exactly as written, so it must match the `kind` in `rules.toml`. A key one or
two letters away from a built-in name (`Aadhar`, `Pasport`) is almost certainly a typo: it names a
custom kind nothing detects, and the built-in kind keeps its default action.

### Endpoints parda does not know

parda redacts the endpoints it knows (Messages, Chat Completions, Responses, legacy completions,
embeddings, batches, conversations). A request with text in its body to any **other** path is
refused (`400 parda_unknown_endpoint`) because parda cannot tell which fields carry text; bodies
without text (`{}` for a cancel call, `GET /v1/models`) pass through.

`proxy.passthrough_paths` opts specific paths in. An entry is an exact path (`"/v1/files"`) or, when
it ends in `*`, a prefix (`"/api/*"` matches `/api/generate` and `/api/chat`, not `/api`). Matching
uses the normalised path (`//api/%67enerate` is `/api/generate`). Requests to a listed path are
forwarded **unchanged and unfiltered**, and each one raises a warning event ("passed through
unfiltered (proxy.passthrough_paths)") in the TUI, `parda status` and the log. Endpoints parda knows
how to redact are never passed through, even if listed. Example for Ollama's native API:

```toml
[proxy]
openai_upstream = "http://127.0.0.1:11434"
passthrough_paths = ["/api/*"]
```

### Intercept

`[intercept]` filters what you type into AI websites (and desktop apps that use the system proxy).
Only the listed hosts and their subdomains are decrypted; everything else is tunnelled untouched.
Tags follow `replace.style` (there is no separate style for intercept).

- **Scope**: with `scope = "per-host"` (the default) each listed site gets its own vault scope,
  `intercept:<host>` (for example `intercept:chatgpt.com`). A site's answers can only restore tags
  that were issued for text sent to that same site — never names you sent to another site, the
  clipboard or the agent proxy. Any other value is a fixed scope shared by every site (`global` also
  shares tags with the clipboard and the agent proxy).
- **Requests**: every string is checked. JSON string values are redacted; identifier fields — keys
  such as `id`, `*_id`, `*Id`, `uuid`, `model`, `token`, `nonce`, `timestamp`, `parent*`, `client_*`,
  `type`, `role`, `status` (plus `skip_keys` and a built-in list per site), and values that look like
  identifiers (UUIDs, long hex or base64 strings, links to the site itself) — skip only the name
  model, and only when the value is identifier-shaped (up to 64 characters of `A-Z a-z 0-9 _ . : / +
  = -`). The dictionary and rule tiers still see them, so an e-mail, phone number, Aadhaar or key is
  redacted wherever it sits; a value with a space or an `@` is redacted under any key. JSON carried
  inside a string (Gemini's `f.req`) is opened and filtered, four levels deep; deeper, it is filtered
  as plain text. Form bodies, query strings and `text/plain` bodies are filtered; multipart text fields
  are filtered and file parts count as unscanned. Compressed bodies are decoded first. A body that
  claims to be JSON but is not is refused (`400 parda_unparseable_body`) rather than sent unfiltered.
  In `detect.mode = "strict"` a failed name detector refuses the send (`503`); a `block` action
  refuses it with `403`.
- **Answers**: JSON, NDJSON, server-sent-event streams and plain text get the real values back,
  including tags split across stream events. Real values only land inside JSON strings (escaped as
  JSON) or plain text. **A tag inside a URL is never restored** — in `http(s)://…` links, markdown
  link and image targets, `href=` / `src=` values and CSS `url(…)` — so a prompt-injected image or
  link cannot carry your real data to another server. HTML pages and other types pass through
  unchanged.

## Changing settings

- **TUI** (`parda tui`, tab 6 *Settings*): every option above as a list. ↑↓ or the mouse wheel selects,
  Enter / Space / click changes the value, ← or right-click goes back. Options marked ↻ take effect
  after the daemon restarts. Turning on `privacy.log_values` asks for confirmation.
- **Protection switch**: `p` anywhere in the TUI, a click on the header switch, or `parda off` /
  `parda on`. While off, every surface (proxy, paste-safe, `parda redact`) passes text through
  unchanged and records a warning event; stand-ins sent earlier are still restored in answers.
- **By hand**: edit `config.toml`, then `parda` picks it up on the next daemon start (or send a reload
  from the TUI by changing any setting).

## rules.toml

```toml
# People always masked, with automatic variants (Ravi Sharma, R. Sharma, ravi.sharma, ravisharma, …)
[[person]]
name = "Ravi Kumar Sharma"
aliases = ["RK", "Ravi bhai"]
emails = ["ravi@example.com"]
handles = ["@ravik"]

# Literal terms always masked
[[term]]
text = "Project Falcon"
kind = "Organization"

# Never masked (your product names, public figures …)
allow = ["Acme Corp", "Narendra Modi"]
```

Edit with `parda rules edit`, or `parda rules add-person "Name"` / `parda rules allow "Term"`; the daemon reloads on save.

## Scopes

Mappings live in scopes. The proxy uses `global` unless a request carries `x-parda-scope: <name>`; the clipboard uses `clipboard.scope`. Different scopes give the same person different stand-ins; `parda vault wipe --scope <name>` forgets one.

## Files

| Path | Contents |
|---|---|
| `config.toml`, `rules.toml` | your settings |
| `data/vault.db` | mappings — real values encrypted, surrogates in clear |
| `data/vault.key` | vault key, only when the OS keyring is unavailable (0600) |
| `data/models/<id>/` | downloaded models |
| `run/parda.sock`, `run/proxy.addr` | daemon socket and proxy address |
| `logs/parda.*.log` | daily logs, 7 kept; kinds/counts/timings only |
