# Explicit policy-store format migration

The `policy-store-migration` CLI feature adds an offline maintenance command
for the original five-field host policy image. Implementation is at `22d01d71`,
with the Linux legacy-lock correction at `de965d6e`. This closes the missing
command path for that schema; it does not complete all 0.2.0 storage upgrades.
Usage and recovery instructions are in the
[CLI guide](../../../../crates/q-periapt-cli/README.md#offline-host-policy-store-upgrade).

The caller supplies an independently retained ML-DSA-65 root and exact 36-byte
trusted state. The command admits the existing private inode, verifies complete
slot checksums before selecting a provider, authenticates the policy, converts
the storage format while retaining its lease, and verifies the identical image
through the current backend. It checks errors from the complete database close
before emitting `verified-format-3`. It never creates a missing store, replaces
the inode, changes the policy/floor/root, or returns a host runtime. A matching
already-current retry is an observation of configuration, not a new commit receipt.

The legacy parser stays in this explicitly enabled maintenance executable.
Default CLI and SDK FFI dependency-tree captures contain neither redb 2.6.4 nor
twox-hash; enabling migration adds both. The SDK library still uses redb 4.3.0.
No SDK/FFI ABI, cryptographic primitive or policy wire format changed.

## Qualification

The final macOS ARM64 source passes:

- Rust 1.98.1 Debug and Release, and Rust 1.90 Debug: 28 tests per run. The
  migration module includes two child-worker entry tests; its substantive cases
  exercise actual legacy files, both enabled/disabled policies at `u32::MAX`,
  independent root/state and signature rejection, schema rejection, missing and
  insecure paths, hard links, symlinks and corrupt current-format headers.
- In each complete migration test run, 232 typed I/O errors around 116 observed
  boundaries, 126 process exits around 63 write/resize/sync/close boundaries,
  and 37 actual partial writes. Every injected error remains an error with its
  original typed cause. Full-operation cuts recover the same signed state.
  Partial-write tests assert truthful failure and retention of the same inode;
  they do not claim automatic repair of arbitrary torn pages or slots.
- Forty-eight independently launched old/current lock competitors are refused
  while conversion and final close still own the file. The current SDK can open
  the verified image after release.
- Strict Clippy on Rust 1.98.1 and 1.90, plus 18 default-feature CLI tests.
- A release `cargo install` into a new private directory outside the checkout.
  Its real executable runs from another external directory and converts the
  retained redb-2.6.3 database. Seven calls cover conversion, current-format
  retry, invalid state length, missing storage, both corrupt-slot controls and
  a final successful re-read. The binary's SHA-256 is
  `de2fe95a22570f675d3577dbdf03804051de2c459142577676b0fb0b093e92e2`.
- Clean-checkout format and source-readiness checks. A 190-test packaging and
  analysis run had 189 successes and one stale documentation-count failure;
  `19baab2e` corrected the guide from 423 to 425 and that exact regression passed.
  The inventory gate still requires every tracked Rust source, without exclusions.

`QUALIFICATION.json` indexes the exact commands, sources and outputs. Detailed
member hashes stay inside `CAPTURES.zip` to keep this review entry small. The
installed consumer is now a reproducible CI step, and feature-enabled tests
are wired into Linux, the product minimum compiler and Apple Silicon CI.

## Failures that changed the implementation

The first typed-error test incorrectly searched only `Error::source()`;
`io::Error::get_ref()` exposes its stored leaf error. After correcting that
inspection, the next boundary demonstrated a real issue: some legacy database
error wrappers do not expose the original I/O source. The attempt now retains
the original backend error and returns it together with the independently
reported operation context. This also catches errors discarded by destructors.
The original failing captures remain; no assertion or warning was suppressed.

The source review found a separate Linux issue before Linux qualification:
the selected 4.3 backend's whole-storage path uses OFD range locks, while 2.6.4
uses `flock`. Their namespaces are normally independent on Linux; see the
[platform specification](https://man7.org/linux/man-pages/man2/flock.2.html).
The command now acquires both on the same open file description before content
reads and retains them across provider handoff. Both unlock results are checked.
A Linux-only test holds an old producer's lock and requires untouched refusal,
then verifies that migration can proceed after that owner closes.

The macOS results do not qualify that Linux-specific branch. Its actual
hosted execution remains required. Also open: formal prebuilt maintenance-tool
distribution, minimum-OS physical execution, hardware power-loss behavior,
general malformed-database robustness, application-schema evolution and
Continuity journal/witness/root migration. Slot checksums are not authentication,
and a parser panic is command failure, never a success receipt or an SDK fallback.

At the preceding source `aa0cc949`, both Windows SDK producer/consumer jobs pass:
[Windows](https://github.com/billlza/q-periapt/actions/runs/37747438351/job/113212170818)
and [Windows 2022](https://github.com/billlza/q-periapt/actions/runs/37747438351/job/113212170909).
Those close the earlier 50-versus-51 import-library guard failure; they do not
provide Windows policy-store persistence or qualify this new maintenance command.
