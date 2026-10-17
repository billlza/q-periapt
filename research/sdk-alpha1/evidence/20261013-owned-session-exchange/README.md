# Owned session exchange component checkpoint

The new portable adapter composes the original enrolled owner, encrypted journals,
archive index and traffic engine. `QPCXCH01` requires an epoch-zero session MAC
before reporting establishment; it does not reuse TLS-bound `QPCNET01` READY
semantics. The protocol and recovery boundaries are in
[`SESSION_EXCHANGE_V1.md`](../../../continuity-identity-candidate/SESSION_EXCHANGE_V1.md).

Seven new core tests pass with real signatures/KEMs and native encrypted storage.
They cover bidirectional delivery and reopen, duplicate effects, forged READY,
lost READY, cancellation before dispatch, application-effect uncertainty, lost
message acknowledgements, valid old-prefix replay, wrong owner, closed policy and
carrier grammar/bounds. The carrier and host effects in these new tests are
in-process test implementations. They do not establish browser network or durable
host-application qualification.

The shared receive-delivery path now supports async WASM storage while preserving
the synchronous native signature. The existing TLS regression suite passed 11
tests, including two child-process helper entrypoints. Its real network/process
cuts, archive boundaries and acknowledgement checks qualify that retained native
path, not a deployed QPCXCH01 carrier. Strict native Clippy with `connection-tls`,
strict WASM Clippy, formatting, native Rust 1.90 checking and 44 exact source
inventory tests passed. The tracked Rust inventory is 603 files.

The product WASM entry also passed Rust 1.90 `cargo check --locked --offline`
with `browser-continuity` and `-D warnings`. Its task-local toolchain was installed
with an isolated Rustup/Cargo home; the live native qualifier's shared toolchains
were not modified. This checks the minimum compiler, not minimum browser runtime.

Commands (from the repository root, using the pinned driver/environment retained
as `BUILD_DRIVER.sh` and `check-wasm-msrv.sh`):

```sh
cargo test --manifest-path research/continuity-identity-candidate/Cargo.toml --locked -j2 session_exchange::tests -- --nocapture
cargo clippy --manifest-path research/continuity-identity-candidate/Cargo.toml --locked --lib --tests --features connection-tls -j2 -- -D warnings
cargo clippy --manifest-path research/continuity-identity-candidate/Cargo.toml --target wasm32-unknown-unknown --lib --locked -j2 -- -D warnings
cargo test --manifest-path research/continuity-identity-candidate/Cargo.toml --locked --features connection-tls -j2 connection_tls -- --nocapture
cargo +1.90.0-aarch64-apple-darwin check --manifest-path research/continuity-identity-candidate/Cargo.toml --locked --features connection-tls --lib -j2
```

Initial compile errors and the rejected fixture are retained. The fixture had
incorrectly assumed manifest leaf ordering matched publication-plan ordering;
the complete manifest verifier rejected it with `Scope`. The fixture now verifies
each member and selects its authenticated role. No production admission rule was
weakened. The final seven-test log is `native-tests-04.log`.

Browser ownership bindings, bounded carrier integration, actual installed browser
communication and broader lifecycle/rekey/release qualification remain open.
This component checkpoint is not a whole-protocol proof, independent implementation
or 0.2.0 release claim. A reopened session describes original local state; it is
not a new remote-liveness receipt or a substitute for retrying failed establishment.
