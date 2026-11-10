#!/bin/sh
set -eu
export RUSTUP_HOME=/Users/bill/Documents/Codex/sdk-020-recovery-20260929-160244/rustup
export RUSTUP_TOOLCHAIN=1.98.1-aarch64-apple-darwin
export CARGO_HOME=/Users/bill/Documents/Codex/sdk-020-recovery-20260929-160244/apple-cargo-home-ff4a153e
export CARGO_TARGET_DIR=/Users/bill/Documents/Codex/sdk-020-lifecycle-ci-20261006/target/continuity-browser-creation/rust-target
export CC_wasm32_unknown_unknown=/opt/homebrew/opt/llvm/bin/clang
export RUSTFLAGS='-D warnings'
exec cargo "$@"
