# Q-Periapt host policy store

Unpublished Rust host persistence for the owned SDK. `PolicyStore` verifies and
durably stores an exact signed policy/state before exposing its runtime, holds
an exclusive lifetime file lock, and closes retained runtime aliases on failure
or disposal. Its private filesystem implementation is shared with the existing
policy agent. The reviewed host boundary is macOS/Linux.

See [the API sequence, storage assumptions and actual validation](../../docs/SDK_HOST_STORE.md).
This is neither a cross-process authorization service nor a hardware rollback
counter. Additive C ABI 2 functions and Swift's `QPeriaptPersistentRuntime` now
share this implementation. Installed packages and Linux runtime qualification
remain release gates.
