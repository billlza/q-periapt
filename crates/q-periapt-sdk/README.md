# Q-Periapt owned SDK (0.2.0 development)

Create `Runtime::from_signed_policy(policy, signature, pinned_root,
last_trusted_state, Limits::default())`, atomically persist its `trusted_state()`,
then use `generate_key()`, `encapsulate(public_key, context)` and
`key.decapsulate(ciphertext, context)`. Keys carry their paired public key and
verified runtime; there is no raw decision constructor or default private-key
getter. Check `is_enabled()` before starting protocol work: a valid revocation
policy retains its trusted state while denying cryptographic operations.

The returned `SharedSecret` is a non-cloneable owner. `export_for_protocol()` is
an explicit copy into a zeroizing Rust buffer for a separately reviewed
protocol. `derive_key` implements the specified [purpose-key schedule](../../docs/SDK_KEY_DERIVATION.md)
without exporting the combined secret. Authentication, confirmation and a
long-lived session protocol still belong to the integrating protocol.

Professional plaintext key transfer is isolated in [`expert`](../../docs/SDK_KEY_TRANSFER.md).
The optional `sealed-operations` feature adds
[exact KEM operation recovery](../../docs/SDK_SEALED_OPERATIONS.md). Platform-generated
coins are sealed to the policy, operation ID and complete inputs; a trusted durable
service can replay the same operation after a crash. It is not a journal or permission
to reuse ephemeral material for another connection. Default generation remains fresh.
[`prepare_policy_update`](../../docs/SDK_POLICY_UPDATES.md) verifies a future policy;
the host atomically persists its state pair before activating it. Activation
revokes old owners and returns an independent, possibly disabled runtime.

`close()` revokes new runtime operations; admitted synchronous calls can finish.
Key storage is erased on key close/drop. Close of a key takes `&mut self`, which
cannot coexist with an active shared borrow in safe Rust. Closing/dropping a
runtime revokes every bound key but does not immediately erase retained key
objects. Retain the runtime for as long as its keys should remain usable.
Preparing storage does not authorize reuse of a protocol's ephemeral key across
connections. Freshness, key confirmation and allowed lifetime remain explicit
requirements of the integrating protocol.

The host pins roots and persists monotonic state. Handles do not isolate hostile
same-process code. Quotas bound live keys and in-flight KEM work, not process OOM,
number of runtimes, host inputs or externally retained results. Policy parsing
and initial owner allocations still use Rust's ordinary allocator.

This crate is part of the 0.2.0 Rust package cohort. Its source and package
qualification precede the release transaction. See [current readiness](../../docs/SDK_0_2_RELEASE_READINESS.md).
