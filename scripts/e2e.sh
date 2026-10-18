#!/usr/bin/env bash
# End-to-end test: real daemon + proxy + mock LLM upstream (+ clipboard on macOS).
#
#   scripts/e2e.sh                 # uses target/release binaries (builds them)
#   E2E_MODEL=none scripts/e2e.sh  # rules-only engine (no model download)
#   E2E_CLIPBOARD=0 scripts/e2e.sh # skip clipboard checks (headless CI)
#   E2E_LOAD=0 scripts/e2e.sh      # skip the load test
#
# Writes a Markdown report to $E2E_REPORT (default: target/e2e-report.md)
# and exits non-zero if any check fails.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
MODEL="${E2E_MODEL:-default}"
CLIP="${E2E_CLIPBOARD:-$([ "$(uname)" = Darwin ] && echo 1 || echo 0)}"
LOAD="${E2E_LOAD:-1}"
PROXY_PORT="${E2E_PROXY_PORT:-18787}"
MOCK_PORT="${E2E_MOCK_PORT:-19901}"
REPORT="${E2E_REPORT:-$ROOT/target/e2e-report.md}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/parda-e2e.XXXXXX")"
export PARDA_HOME="$WORK/home" PARDA_QUIET=1

if [ -z "${PARDA_BIN:-}" ]; then
  cargo build --release -q -p parda -p parda-bench || exit 1
  BIN="$ROOT/target/release"
else
  BIN="$PARDA_BIN"
fi
PARDA="$BIN/parda"
BENCH="$BIN/parda-bench"

PASS=0; FAIL=0; LOG=""
pass() { PASS=$((PASS + 1)); LOG+="| ✅ | $1 |"$'\n'; echo "PASS  $1"; }
fail() { FAIL=$((FAIL + 1)); LOG+="| ❌ | $1 — $2 |"$'\n'; echo "FAIL  $1: $2"; }
check() { if eval "$2"; then pass "$1"; else fail "$1" "${3:-check failed}"; fi; }

cleanup() {
  "$PARDA" stop >/dev/null 2>&1
  [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null
  [ -n "${DAEMON_PID:-}" ] && wait "$DAEMON_PID" 2>/dev/null
  [ -n "${CLIP_SAVED+x}" ] && printf '%s' "$CLIP_SAVED" | pbcopy
  [ "${E2E_KEEP:-0}" = 1 ] && echo "kept $WORK" || rm -rf "$WORK"
}
trap cleanup EXIT

# --- set up -----------------------------------------------------------------
mkdir -p "$PARDA_HOME/data/models"
cat > "$PARDA_HOME/config.toml" <<EOF
[proxy]
listen = "127.0.0.1:$PROXY_PORT"
anthropic_upstream = "http://127.0.0.1:$MOCK_PORT"
openai_upstream = "http://127.0.0.1:$MOCK_PORT"

[detect]
model = "$MODEL"
# The load test runs 16 concurrent requests on small CI runners; with the
# default 250 ms budget, queued model calls time out and strict mode
# (correctly) refuses them. Give the model room so the test measures
# throughput rather than the budget.
ml_timeout_ms = ${E2E_ML_TIMEOUT_MS:-2000}

[vault]
use_keyring = false

[clipboard]
enabled = $([ "$CLIP" = 1 ] && echo true || echo false)
poll_ms = 100
EOF
cat > "$PARDA_HOME/rules.toml" <<'EOF'
[[person]]
name = "Zubin Wadia"
EOF
if [ "$MODEL" != none ]; then
  if [ -n "${E2E_MODEL_DIR:-}" ]; then
    cp -R "$E2E_MODEL_DIR" "$PARDA_HOME/data/models/gliner-pii-edge"
  else
    "$PARDA" model pull gliner-pii-edge >/dev/null 2>&1 || { echo "model download failed"; exit 1; }
  fi
fi

"$BENCH" mock-upstream --port "$MOCK_PORT" --log "$WORK/upstream.log" 2>/dev/null &
MOCK_PID=$!
"$PARDA" daemon --no-hotkey > "$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 200); do "$PARDA" status 2>/dev/null | grep -q "^daemon: *running" && break; sleep 0.1; done
check "daemon starts and answers status" '"$PARDA" status | grep -q "^daemon: *running"'

URL="http://127.0.0.1:$PROXY_PORT"
H=(-H "content-type: application/json" -H "x-api-key: test" -H "anthropic-version: 2023-06-01")
REAL_NAME="Venkatesh Iyer"
REAL_MAIL="venkatesh.iyer@gmail.com"
REAL_PHONE="+91 98765 43210"
REAL_AADHAAR="2345 6789 0124"
REAL_PAN="ABCPE1234F"
MSG="Hi, I am $REAL_NAME, mail $REAL_MAIL, phone $REAL_PHONE, Aadhaar $REAL_AADHAAR, PAN $REAL_PAN. Also ask Zubin Wadia."
[ "$MODEL" = none ] && REAL_NAME="Zubin Wadia"

no_leak() { ! grep -qF -e "$REAL_NAME" -e "$REAL_MAIL" -e "$REAL_PHONE" -e "$REAL_AADHAAR" -e "$REAL_PAN" -e "Zubin Wadia" "$WORK/upstream.log"; }
has_all() { grep -qF "$REAL_MAIL" <<<"$1" && grep -qF "$REAL_PHONE" <<<"$1" && grep -qF "$REAL_AADHAAR" <<<"$1" && grep -qF "$REAL_PAN" <<<"$1" && grep -qF "$REAL_NAME" <<<"$1"; }

# --- Anthropic ----------------------------------------------------------------
body=$(jq -n --arg m "$MSG" '{model:"m",max_tokens:64,system:"You assist Zubin Wadia.",messages:[{role:"user",content:$m}]}')
out=$(curl -s "${H[@]}" "$URL/v1/messages" -d "$body")
check "anthropic JSON: answer has real values back" 'has_all "$out"' "$out"
check "anthropic JSON: upstream never saw real values" no_leak "$(tail -c 400 "$WORK/upstream.log")"

body=$(jq -n --arg m "$MSG" '{model:"m",max_tokens:64,stream:true,messages:[{role:"user",content:$m}]}')
sse=$(curl -sN "${H[@]}" "$URL/v1/messages" -d "$body")
text=$(grep '^data:' <<<"$sse" | sed 's/^data: //' | jq -rj 'select(.type=="content_block_delta") | .delta.text // empty')
check "anthropic SSE: streamed text restored across chunks" 'has_all "$text"' "$text"
check "anthropic SSE: message_stop delivered" 'grep -q message_stop <<<"$sse"'

# --- OpenAI chat + responses --------------------------------------------------
body=$(jq -n --arg m "$MSG" '{model:"gpt",messages:[{role:"user",content:$m}]}')
out=$(curl -s -H "content-type: application/json" -H "authorization: Bearer t" "$URL/v1/chat/completions" -d "$body")
check "openai chat JSON restored" 'has_all "$(jq -r ".choices[0].message.content" <<<"$out")"' "$out"
body=$(jq -n --arg m "$MSG" '{model:"gpt",stream:true,messages:[{role:"user",content:$m}]}')
sse=$(curl -sN -H "content-type: application/json" "$URL/v1/chat/completions" -d "$body")
text=$(grep '^data: {' <<<"$sse" | sed 's/^data: //' | jq -rj '.choices[0].delta.content // empty')
check "openai chat SSE restored" 'has_all "$text"' "$text"
check "openai chat SSE keeps [DONE]" 'grep -q "data: \[DONE\]" <<<"$sse"'
body=$(jq -n --arg m "$MSG" '{model:"gpt",stream:true,input:$m}')
sse=$(curl -sN -H "content-type: application/json" "$URL/v1/responses" -d "$body")
text=$(grep '^data:' <<<"$sse" | sed 's/^data: //' | jq -rj 'select(.type=="response.output_text.delta") | .delta')
check "openai responses SSE restored" 'has_all "$text"' "$text"
check "upstream never saw real values (all providers)" no_leak

# --- guards --------------------------------------------------------------------
code=$(curl -s -o /dev/null -w '%{http_code}' -H "origin: https://evil.example" "${H[@]}" "$URL/v1/messages" -d '{}')
check "browser Origin refused (403)" '[ "$code" = 403 ]' "got $code"
code=$(curl -s -o /dev/null -w '%{http_code}' -H "host: attacker.example" "${H[@]}" "$URL/v1/messages" -d '{}')
check "non-loopback Host refused (403)" '[ "$code" = 403 ]' "got $code"

# --- CLI over IPC ----------------------------------------------------------------
red=$("$PARDA" redact "$MSG")
check "CLI redact via daemon hides values" '! has_all "$red" && ! grep -qF "$REAL_PAN" <<<"$red"' "$red"
check "CLI restore via daemon round-trips" '[ "$("$PARDA" restore "$red")" = "$MSG" ]'
check "status reports filtered values" '"$PARDA" status | grep -q "proxy:.*values redacted"'
dump=$("$PARDA" tui --dump)
check "TUI dashboard shows counts by kind and tier" 'grep -q "Filtered by kind" <<<"$dump" && grep -q "found by" <<<"$dump" && grep -q "Email" <<<"$dump"' "$dump"
check "TUI live feed lists proxy events" 'grep -q "anthropic /v1/messages" <<<"$dump"'

# --- clipboard (macOS) ---------------------------------------------------------
if [ "$CLIP" = 1 ] && command -v pbcopy >/dev/null; then
  CLIP_SAVED="$(pbpaste 2>/dev/null)"
  sur=$("$PARDA" redact "Zubin Wadia")
  printf 'Thanks %s, see you.' "$sur" | pbcopy
  for _ in $(seq 1 30); do [ "$(pbpaste)" = "Thanks Zubin Wadia, see you." ] && break; sleep 0.1; done
  check "clipboard restore-on-copy puts real values back" '[ "$(pbpaste)" = "Thanks Zubin Wadia, see you." ]' "$(pbpaste)"
fi

# --- load ------------------------------------------------------------------------
LOADTXT=""
if [ "$LOAD" = 1 ]; then
  "$BENCH" load --url "$URL" --concurrency 16 --requests 1000 --out "$WORK/load-json.json" 2> "$WORK/load-json.txt"
  "$BENCH" load --url "$URL" --concurrency 16 --requests 300 --stream --out "$WORK/load-sse.json" 2> "$WORK/load-sse.txt"
  "$BENCH" load --url "http://127.0.0.1:$MOCK_PORT" --concurrency 16 --requests 1000 --out "$WORK/load-direct.json" 2> "$WORK/load-direct.txt"
  check "load (1000 JSON): no errors, no leaks" '[ "$(jq ".errors + .leaks" "$WORK/load-json.json")" = 0 ]' "$(cat "$WORK/load-json.txt")"
  check "load (300 SSE): no errors, no leaks" '[ "$(jq ".errors + .leaks" "$WORK/load-sse.json")" = 0 ]' "$(cat "$WORK/load-sse.txt")"
  LOADTXT="$(printf '%s\n%s\n%s' "proxy JSON:   $(grep -h "requests (" "$WORK/load-json.txt")" "proxy SSE:    $(grep -h "requests (" "$WORK/load-sse.txt")" "direct mock:  $(grep -h "requests (" "$WORK/load-direct.txt")")"
fi
check "daemon log has no raw values" '! grep -qF -e "$REAL_MAIL" -e "$REAL_PAN" -e "Zubin Wadia" "$WORK/daemon.log" "$PARDA_HOME"/logs/*'

STATUS="$("$PARDA" status)"
"$PARDA" stop >/dev/null
for _ in $(seq 1 50); do kill -0 "$DAEMON_PID" 2>/dev/null || break; sleep 0.1; done
check "parda stop shuts the daemon down" '! kill -0 "$DAEMON_PID" 2>/dev/null'

mkdir -p "$(dirname "$REPORT")"
{
  echo "# parda end-to-end report"
  echo
  echo "- date: $(date -u +%Y-%m-%dT%H:%MZ) · host: $(uname -sm) · model: $MODEL · clipboard: $CLIP"
  echo "- result: **$PASS passed, $FAIL failed**"
  echo
  echo "| | check |"
  echo "|---|---|"
  printf '%s' "$LOG"
  if [ -n "$LOADTXT" ]; then
    echo
    echo "## Load"
    echo
    echo '```text'
    echo "$LOADTXT"
    echo '```'
  fi
  echo
  echo "## parda status after the run"
  echo
  echo '```text'
  echo "$STATUS"
  echo '```'
  echo
  echo "## parda tui --dump (dashboard)"
  echo
  echo '```text'
  sed -n '/──── Dashboard/,/──── Live/p' <<<"$dump" | sed '$d'
  echo '```'
} > "$REPORT"
echo "report: $REPORT"
echo "$PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
