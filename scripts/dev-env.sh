# Source this file: `source scripts/dev-env.sh`
# Keeps every build artefact, toolchain, cache and temp file on the SSD
# (the boot disk is small and fills up when swap grows).
SSD_DEV="/Volumes/SSD_1TB/DEV"
export CARGO_HOME="$SSD_DEV/.toolchains/cargo"
export RUSTUP_HOME="$SSD_DEV/.toolchains/rustup"
export TMPDIR="$SSD_DEV/.tmp"
export HF_HOME="$SSD_DEV/.cache/huggingface"
export PARDA_HOME="$SSD_DEV/pii/.parda-dev"
# Keep peak RAM (and therefore swap on the boot disk) down while compiling.
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}"
export PATH="$CARGO_HOME/bin:$HOME/.cargo/bin:$PATH"
mkdir -p "$CARGO_HOME" "$RUSTUP_HOME" "$TMPDIR" "$HF_HOME" "$PARDA_HOME"
