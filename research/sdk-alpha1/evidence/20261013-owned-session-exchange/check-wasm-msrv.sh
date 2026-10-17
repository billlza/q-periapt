#!/bin/sh
set -eu
qperiapt_msrv_root=/Users/bill/Documents/Codex/sdk-020-lifecycle-ci-20261006/target/continuity-browser-connection/msrv-tools/rustup/toolchains/1.90.0-aarch64-apple-darwin
export RUSTC="$qperiapt_msrv_root/bin/rustc"
export RUSTDOC="$qperiapt_msrv_root/bin/rustdoc"
export CARGO_HOME=/Users/bill/Documents/Codex/sdk-020-recovery-20260929-160244/apple-cargo-home-ff4a153e
export CARGO_TARGET_DIR=/Users/bill/Documents/Codex/sdk-020-lifecycle-ci-20261006/target/continuity-browser-connection/msrv-target
export CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang
export RUSTFLAGS='-D warnings'
"$RUSTC" -Vv
"$qperiapt_msrv_root/bin/cargo" -V
"$qperiapt_msrv_root/bin/cargo" check --locked --offline --target wasm32-unknown-unknown -p q-periapt-sdk-wasm --features browser-continuity -j2
