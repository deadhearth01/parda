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
skip_keys = []                     # extra identifier keys, e.g. ["trace_tag"]: identifier-shaped
                                   # values under them skip only the name model (rules still apply)

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
- **Requests** to a listed site:
  - *What is read.* Every JSON string value and every JSON object key, at any depth (a key that holds
    a name is renamed where it stands). Form and query-string values, keys and value-less pieces
    (`?Ravi%20Kumar`). Text bodies. Multipart text fields, including base64-encoded ones. Compressed
    bodies are decoded first.
  - *Whatever the content type says.* A body that is a JSON object or array is read as JSON (sites
    post JSON as `text/plain`, as a form, or as `application/octet-stream`). So is a body (not
    declared as a form) of JSON values one per line (NDJSON: batched telemetry, a Sentry envelope),
    and one that is a lone JSON string: each line is read as JSON, so an escape such as
    `\n9876543210` cannot hide a number. Such a body also keeps the readings a text body gets: its
    strings and keys are read decoded as a form too (`+` is a space), and its numbers as text (a
    number found this way becomes a JSON string holding its tag). A text or untyped body that
    starts like JSON (`{`, `[`, `"`) and holds a backslash but is not JSON (or JSON lines) is
    refused. A text or untyped body
    written in form encoding (`prompt=Ravi+Kumar&mail=ravi%40example.com`) is read as a form, so `+`
    and `%40` cannot hide a name or an e-mail.
  - *URLs inside strings.* The query of every `http(s)://` link in any of these strings is decoded,
    filtered with the same rules and encoded again (telemetry often carries the page URL, prompt
    included).
  - *Identifiers.* Keys such as `id`, `*_id`, `*Id`, `uuid`, `model`, `token`, `nonce`,
    `timestamp`, `parent*`, `client_*`, `type`, `role`, `status` (plus `skip_keys` and a built-in
    list per site), and values that look like identifiers (UUIDs, long hex or base64 strings, links
    to the site itself), skip only the name model, and only when the value is identifier-shaped (up
    to 64 characters of `A-Z a-z 0-9 _ . : / + = -`). The dictionary and rule tiers still see them,
    so an e-mail, phone number, Aadhaar or key is redacted wherever it sits; a value with a space or
    an `@` is redacted under any key.
  - *JSON inside a string* (Gemini's `f.req`) is opened and filtered, four levels deep; deeper, it
    is filtered as plain text.
  - *`Referer`.* Its query and fragment are removed. A page opened with the prompt in its address
    (`chatgpt.com/?q=…`, `perplexity.ai/search?q=…`) would otherwise send the prompt again with
    every request it makes.
  - *Not read, counted as unscanned* (with `unscanned = "block"` the request is refused,
    `415 parda_unscanned_blocked`): file parts; multipart fields that are not text or JSON, are not
    UTF-8 (a declared charset other than UTF-8, or NUL bytes, as UTF-16 has), or use another
    transfer encoding (quoted-printable); bodies of other types that are not JSON (images, binary
    data); untyped bodies that are not UTF-8 or hold NUL bytes; WebSocket (and other protocol
    upgrade) connections, whose frames are tunnelled without inspection, so with `"block"` the
    upgrade request is refused before it reaches the site. Headers other than `Referer` are
    forwarded as they are.
  - *Refused, never sent unfiltered.* The message names the problem and never quotes the request.

    | Status and code | When |
    |---|---|
    | `400 parda_unparseable_body` | a body typed as JSON that is not JSON; a text or untyped body that starts like JSON and holds a backslash but is not JSON (or JSON lines); a JSON key given twice (anywhere, JSON inside strings, forms and queries included); two keys that redaction would make the same; a multipart body without a boundary, that does not split as RFC 2046 says, or whose preamble or epilogue holds the boundary |
    | `400 parda_not_utf8` | a form, `text/*` or JSON body declaring a charset other than UTF-8 or US-ASCII; a form or `text/*` body that is not UTF-8 or holds NUL bytes (UTF-16) |
    | `413 parda_body_too_large` | a body too large to filter |
    | `415 parda_unsupported_encoding` | a `content-encoding` parda cannot decode |
    | `415 parda_unscanned_blocked` | an unscanned part (a file, binary data, a WebSocket upgrade) while `unscanned = "block"` |
    | `503 parda_ml_unavailable` | `detect.mode = "strict"` and the name detector failed |
    | `403 parda_blocked` | a kind whose action is `block` (the message names kinds, not values) |
    | `500 parda_internal` | anything else that went wrong while filtering |

- **Answers** get the real values back only where they are the user's own:
  - *chatgpt.com, chat.openai.com, claude.ai, gemini.google.com:* only the answers to sending a
    message (chatgpt `/backend-api/conversation` and `/backend-api/f/conversation`; claude
    `…/chat_conversations/*/completion` and `…/retry_completion`; Gemini `StreamGenerate`), and the
    user's own history (chatgpt `GET /backend-api/conversation/*` and `/backend-api/conversations`;
    claude `GET /api/organizations/*/chat_conversations[/*]`). Gemini history comes from
    `batchexecute`, which is never restored, so **old Gemini chats show tags**.
  - *Every other listed site:* only answers to a `POST` that stream (server-sent events, NDJSON, or
    several JSON values in a row). A single JSON document, a text body or anything a `GET` returns
    keeps its tags.
  - Shared conversations, GPT or bot descriptions and public pages therefore keep their tags: a
    page someone else wrote cannot make your browser show (or send on) your real values. Paths are
    matched decoded once, case-insensitively, without the query; a path with an empty, `.` or `..`
    segment, an encoded `/`, `%` or `\`, a `;` or a control character matches nothing.
  - *Formats.* JSON, NDJSON, server-sent-event streams, Google's `)]}'` frames (lengths recomputed)
    and plain text, including tags split across stream events. Real values only land inside JSON
    strings (escaped as JSON) or plain text; data that looks like JSON but does not parse passes
    through with its tags. A streamed text is JSON text once it reaches a string or an object
    (`{"`, `["`), not because it starts with a bracket (`[NAME_1] said`, `[1] see` are text); JSON
    text that turns into prose goes on unrestored. HTML pages and other types pass through
    unchanged. A single event, line or frame larger than 16 MiB passes through, with the rest of
    that answer, unrestored.
  - **A tag inside a URL is never restored**, so a prompt-injected image or link cannot carry your
    real data to another server. URLs are read as markdown renderers and browsers read them:
    markdown link and image targets (`](…)`, `](<…>)`, backslash escapes, spaces in `<…>`) and
    reference definitions (`[r]: …`, also inside quotes and lists), autolinks (`<https:…>`,
    `www.…`), every attribute value inside an HTML tag, and CSS `url(…)`, `image-set(…)` and
    `@import`. On top of that, a tag is never restored when the text before it, back to the last
    ASCII space or line break, holds any of `/ ? = & % \ : @`, follows `www.` or is longer than
    2 KiB, so `key=[NAME_1]` and `path/[NAME_1]` keep their tags too. Unicode spaces never end a
    URL.
- **Known limit.** parda filters what reaches the listed hosts over the network. The site's own page
  scripts see what you type before it is sent, and anything they send to other (unlisted) hosts,
  such as third-party analytics, is not filtered.

**The listener** runs inside the daemon while `enabled = true`, and only with the root certificate
from `parda ca create` (parda never creates one on its own; without it the daemon warns "no CA" and
does not listen). It binds `listen` (loopback only), writes the address it got to `intercept.addr` in
the runtime folder and serves the PAC file at `http://<listen>/parda.pac`. Changes apply without a
daemon restart:

- `hosts`, `scope`, `unscanned` and `skip_keys` go to the running listener. A site *added* to
  `hosts` is filtered only once your browsers and the OS fetch the PAC file again (restart the
  browser, or `parda intercept off` then `parda intercept on`); until then it may go there direct,
  and the daemon warns about it.
- `enabled` starts or stops the listener. `listen` moves it — but the system proxy keeps the PAC
  address `parda intercept on` set, so run `parda intercept on` again after changing it (the daemon,
  `parda status`, `parda intercept status`, `parda doctor` and the TUI warn that AI sites fail to load
  until you do).
- A new or replaced certificate (`parda ca create`, `parda ca create --force`) starts or restarts
  the listener: the daemon checks the files every 2 s and before each status answer, and `parda ca
  create` prints what the daemon then reports (listening, or why not). `parda ca uninstall` is
  refused while intercept is in use — `parda intercept off` first.

The TUI dashboard (and the daemon's status) shows whether it listens and whether the system proxy
points at it; if the system proxy still points at parda while nothing listens, AI sites fail to load
(by design: they are never sent unfiltered) — run `parda intercept off` to restore your previous
settings.

## Changing settings

- **TUI** (`parda tui`, tab 6 *Settings*): every option above as a list. ↑↓ or the mouse wheel selects,
  Enter / Space / click changes the value, ← or right-click goes back. Options marked ↻ take effect
  after the daemon restarts (the AI-sites rows apply at once). Turning on `privacy.log_values` asks
  for confirmation.
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
