# Contributing to parda

Thanks for helping! parda handles people's private data, so the bar for correctness is high and the rules below matter.

## Ground rules

- **Never put real personal data** in issues, pull requests, tests, fixtures or logs. Use obviously synthetic values (`Ravi Kumar`, `ravi.k@example.com`, checksum-valid but invented IDs). The `PII leak` issue template asks for synthetic reproductions only.
- Logs, events and error messages must not contain raw values (`privacy.log_values` is the only exception).
- No telemetry, no network calls beyond the user's own upstream traffic and explicit model downloads.
- Only permissively licensed code and models (Apache-2.0, MIT, BSD). No CC BY-NC, no AGPL.

## Development

```sh
cargo build --workspace
cargo test --workspace                      # model tests are #[ignore]d: see below
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
```

Model-dependent tests: `parda model pull gliner-pii-edge` (or copy a model directory), then

```sh
PARDA_TEST_MODEL_DIR=~/.local/share/parda/models/gliner-pii-edge cargo test -p parda-ml -- --ignored
cargo run -p parda-bench --release -- eval --model gliner-pii-edge --models <models dir>
```

Layout and design: [docs/architecture.md](docs/architecture.md). The engine's invariants are covered by property tests (`crates/parda-engine/tests/stream_prop.rs`): keep them passing.

## Adding a recognizer

1. Add the rule to the right pack in `crates/parda-detect/src/rules/` (with a validator if the format has a checksum).
2. Add positive lines to `bench/golden/rules.jsonl` and hard negatives to `bench/golden/negatives.jsonl`.
3. If the kind is new, add a format-preserving generator in `crates/parda-vault/src/surrogate/ids.rs`.

## Pull requests

- One topic per PR, with tests. Conventional commit messages (`feat(engine): …`, `fix(proxy): …`).
- Describe user-visible behaviour changes in `CHANGELOG.md` under *Unreleased*.
- CI must be green on macOS, Linux and Windows.

By contributing you agree that your contribution is dual-licensed under Apache-2.0 and MIT, like the project.
