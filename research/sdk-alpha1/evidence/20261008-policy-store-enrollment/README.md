# Explicit enrollment of an existing policy store

An existing v1 store can now acquire independently configured recovery authority
without replacing its file or resetting its signed policy/version floor. This
requires an explicit host-authorized operation, the original exact policy state,
independent trust configuration and recovery-key possession proof. Ordinary
open/provision functions still refuse implicit enrollment or replacement.

Rust `PolicyStore::enroll_recovery`, C
`q_periapt_sdk_runtime_enroll_recovery_store` and Swift `enrollRecovery` share
the same transaction. Close the previous owner first. C/Swift authenticate the
caller-retained original signed policy to derive the expected state. A complete
comparison inside the write transaction precedes the five-to-nine-field schema
change; the original root, policy bytes, signature and floor are retained.

Exact retries accept the identical initial v2 configuration without another
write. Success means that configuration is present, not that this call freshly
committed it. Original retries reject later policy/root transitions or conflicting
trust/proofs. They cannot clear recovery history. After cancellation, Swift
disposes undelivered ownership and leaves the durable enrollment available for
reconciliation. This is new explicit capability; no red/green claim is made for
a previously nonexistent API. The existing non-enrollment entry's refusal is
retained as a negative control.

The implementation is `194124cb`; package-count corrections are `0ffd7c2b` and
`9e192da6`. Final Apple source is `5b3cbfa0`. The only later Rust source changes
are two documentation lines. ABI major 2, the previous 50 declarations/layouts
and 26 JNI registrations remain unchanged; exactly one new C function brings
the unpublished SDK contract to **51 exports**.

Observed validation:

- Rust 1.98.1: 47 host-store tests in Debug and Release, 49 FFI tests, strict
  all-target Clippy. Minimum Rust 1.90: 47 host-store and 49 FFI tests plus the
  same strict Clippy checks.
- Native cases cover active leases, stale/equivocal states, wrong roots/proofs,
  missing/corrupt files, enabled and disabled `u32::MAX`, subsequent independent
  root recovery, actual pre/post-commit process exits, post-commit unwind/result
  loss and a real-file backend sync failure. All preserve the original floor.
- Swift Debug and Release each pass 14 SDK, two compatibility and four probe
  tests, including cancellation after the actual enrollment commit.
- C Debug/Release consumers pass with the frozen old header, owned SDK and
  public enrollment/recovery vectors. The complete C archive from `0ffd7c2b`
  also passes shared/static pkg-config, CMake and frozen-header consumers. An
  additional outside-checkout shared/static C consumer exercises enrollment and
  subsequent root recovery from that exact archive.
- A clean ordinary checkout passes 190 package/source-contract tests and full
  formatting. The `5b3cbfa0` source gate checks 254 current and 249 historical
  inputs without claiming release readiness.
- The full Apple package builds all four targets and validates all three slices
  at 51 exports. Actual installed Swift consumers outside the checkout pass all
  **six** cases, including legacy enrollment and subsequent authority recovery.
  macOS 13/iOS 16 deployment-floor linkage passes. Compiler and source identities
  remain unchanged throughout the successful build.

`QUALIFICATION.json` identifies sources, exact artifacts, checks and limitations.
`CAPTURES.zip` retains all raw success/failure records, logs and the independent
C driver; its member hashes and uncompressed stream hashes are in that record.
Failed attempts are retained: an incorrect new-test error expectation, a checked
slice lint correction, an outdated closed export count, the linked-worktree
provenance refusal, and a diagnostic harness's incorrect installed dylib name.

The first full Apple attempt rejected the public comment `policy/root/floor`
because its `/root/` substring matched the conservative path-hygiene filter.
The prose was clarified without weakening that filter. The complete rerun
passes, and all three native archives are byte-identical across the prose fix.

This is policy-image v1-to-v2 enrollment inside a currently readable redb file.
It is **not** redb file-format 2-to-3 migration, Continuity account-root migration,
physical power-loss qualification or post-compromise message recovery. iOS
evidence here is linkage, not durable iOS storage or physical/minimum-OS runtime
execution. Current-head hosted CI and the full 0.2.0 lifecycle, platform,
performance and security requirements remain separate gates. Intel macOS is
outside the support matrix.
