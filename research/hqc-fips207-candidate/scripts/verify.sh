#!/usr/bin/env bash
set -euo pipefail

workspace_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${workspace_dir}"

for tool in cargo rustup cargo-audit; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "ERROR: required verification tool is unavailable: ${tool}" >&2
    exit 1
  fi
done

export RUSTFLAGS="-D warnings"
export RUSTDOCFLAGS="-D warnings"

echo "[gate] cargo fmt --package q-periapt-hqc-fips207-candidate -- --check"
cargo fmt --package q-periapt-hqc-fips207-candidate -- --check

echo "[gate] cargo clippy --locked --all-targets --all-features -- -D warnings"
cargo clippy --locked --all-targets --all-features -- -D warnings

echo "[gate] cargo test --locked --all-features"
cargo test --locked --all-features

echo "[gate] cargo test --locked --release --all-features"
cargo test --locked --release --all-features

echo "[gate] cargo doc --locked --no-deps --all-features"
cargo doc --locked --no-deps --all-features

echo "[gate] cargo audit --deny warnings"
cargo audit --deny warnings

echo "[gate] cargo build --locked --lib"
cargo build --locked --lib

if rustup toolchain list | grep -Eq '^1\.85(-|\s)'; then
  echo "[gate] cargo +1.85 check --locked --lib"
  cargo +1.85 check --locked --lib
else
  echo "[not-run] MSRV toolchain 1.85 is not installed"
fi

targets=(
  aarch64-apple-darwin
  aarch64-apple-ios
  aarch64-apple-ios-sim
  aarch64-linux-android
  aarch64-unknown-linux-gnu
  armv7-linux-androideabi
  thumbv7em-none-eabihf
  wasm32-unknown-unknown
  x86_64-apple-darwin
  x86_64-apple-ios
  x86_64-linux-android
  x86_64-pc-windows-gnu
  x86_64-pc-windows-msvc
  x86_64-unknown-linux-gnu
)

installed_targets="$(rustup target list --installed)"
missing_targets=()
for target in "${targets[@]}"; do
  if grep -Fxq "${target}" <<<"${installed_targets}"; then
    echo "[gate] cargo build --locked --lib --target ${target}"
    cargo build --locked --lib --target "${target}"
  else
    missing_targets+=("${target}")
  fi
done

if ((${#missing_targets[@]} > 0)); then
  echo "[not-run] targets not installed: ${missing_targets[*]}"
else
  echo "[gate] all declared cross targets were installed and built"
fi

echo "[result] all runnable HQC candidate gates passed"
