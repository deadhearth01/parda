# Configuration

`config.toml` lives in the config directory (`parda doctor` prints it; `PARDA_HOME=/some/dir` puts everything under one folder). Every key is optional; this is the full default:

```toml
[proxy]
enabled = true
listen = "127.0.0.1:8787"
anthropic_upstream = "https://api.anthropic.com"
openai_upstream = "https://api.openai.com"   # any OpenAI-compatible server works
unscanned_media = "allow"                    # allow | block — images / binary documents
allowed_origins = []                         # web origins allowed to call the proxy
allow_non_loopback = false                   # accept non-localhost Host headers
max_body_bytes = 67108864

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
style = "surrogate"                # surrogate (realistic stand-ins) | token (⟦PERSON_1⟧)

[vault]
ttl_days = 30                      # mappings unused this long are deleted (0 = keep)
use_keyring = true                 # vault key in the OS keychain; else data/vault.key (0600)

[clipboard]
enabled = true
poll_ms = 300
hotkey = "default"                 # Cmd+Alt+V on macOS, Ctrl+Alt+V elsewhere; e.g. "ctrl+shift+p"
restore_on_copy = true
scope = "global"

[privacy]
log_values = false
```

Kinds: `Person Email Phone Address Url IpAddress MacAddress CreditCard Iban BankAccount Ifsc Aadhaar Pan Gstin Upi VoterId DrivingLicence IndianVehicleReg Passport UsSsn UkNino DateOfBirth Secret Organization`, plus any custom kind you use in `rules.toml`.

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
