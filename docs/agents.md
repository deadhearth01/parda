# Using parda with AI agents

The proxy listens on `http://127.0.0.1:8787`. Point a tool's API base URL at it; your API key passes through untouched and is never stored.

## Claude Code

```sh
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
claude
```

To make it permanent, add to `~/.claude/settings.json`:

```json
{ "env": { "ANTHROPIC_BASE_URL": "http://127.0.0.1:8787" } }
```

Everything Claude Code sends — your prompts, files it reads, command output, tool results — is redacted; tool calls coming back (file edits, shell commands, e-mails) carry the real values again. Extended-thinking blocks are signed by the API and pass through unmodified.

## Codex CLI

```sh
export OPENAI_BASE_URL=http://127.0.0.1:8787/v1
codex
```

or a provider in `~/.codex/config.toml`:

```toml
model_provider = "parda"

[model_providers.parda]
name = "OpenAI via parda"
base_url = "http://127.0.0.1:8787/v1"
env_key = "OPENAI_API_KEY"
wire_api = "responses"
```

## SDKs

```python
from anthropic import Anthropic
client = Anthropic(base_url="http://127.0.0.1:8787")

from openai import OpenAI
client = OpenAI(base_url="http://127.0.0.1:8787/v1")
```

Both SDKs also read `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL`.

## Other OpenAI-compatible servers

Set `proxy.openai_upstream` to the server's base URL (OpenRouter, Ollama, vLLM, LM Studio, Azure-style gateways that accept `/v1/chat/completions`), restart the daemon, and point clients at parda as above.

Ollama's native API (`/api/chat`, `/api/generate`) is not one parda can redact, so requests with text to it are refused by default. If you accept sending those unfiltered, list them: `passthrough_paths = ["/api/*"]` (see [configuration](configuration.md)); every such request raises a warning.

## Separate scopes per project

Send `x-parda-scope: my-project` on requests (most SDKs accept default headers) to keep a project's stand-ins separate from everything else.

## What happens when …

| Situation | Response |
|---|---|
| The name model is missing or fails (strict mode) | `503`, error type `parda_ml_unavailable`; nothing is sent |
| A kind set to `block` is present | `400`, `parda_blocked` |
| Images / PDFs in the request | forwarded unscanned and reported in the TUI; `unscanned_media = "block"` refuses them (`400 parda_unscanned_media`) |
| The upstream returns an error | passed through, with surrogates in the message restored |
| A web page tries to call the proxy | `403` (Origin guard) |
| Text sent to an endpoint parda does not know | `400`, `parda_unknown_endpoint` (unless the path is in `proxy.passthrough_paths`) |
| A request body that is not a JSON object, or not JSON | `400`, `parda_unparseable_body` |
| More than 256 distinct `x-parda-scope` values | `429`, `parda_too_many_scopes` for new scopes; existing ones keep working |
