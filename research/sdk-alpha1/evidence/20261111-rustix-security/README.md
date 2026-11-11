# rustix security update, 11 November 2026

The canonical paper branch policy-agent pin and root dependency lock move from rustix 1.1.4 to 1.1.6, preserving its separate dependency graph.

## Cause and source identity

The published SDK audit jobs rejected RUSTSEC-2026-0486. The fixed upstream [RustSec record](https://github.com/rustsec/advisory-db/blob/31cf5a8673e10d3a4d7d829ad5095f47ed419049/crates/rustix/RUSTSEC-2026-0486.md) identifies incorrect initialization accounting for zero-length xattr output buffers in rustix versions from 1.0.0 through versions before 1.1.6. Version 1.1.6 supplies the upstream repair. `UPSTREAM.json` records the advisory commit and blob, the repair commit, and the authenticated crate and audit-tool identities.

The 426,484-byte rustix 1.1.6 crate SHA-256 is `e5e76742e5294153d4dde1207dbec5bdd81eef6fabdc0d2118babadabfd858aa`. An independent download matched the official sparse-index checksum and all five updated locks across the SDK and canonical branches. The index marks the release as not yanked. Its Rust 1.65 minimum remains below both project minimums.

## Exact change and audit result

Cargo generated each change with `update -p rustix@<original-version> --precise 1.1.6`. The independent review compares every parsed package record: only rustix version and checksum change, its dependency lists remain identical, and the manifest feature selections remain identical. Original package counts and each before/after SHA-256 appear in `INDEPENDENT_REVIEW.json`.

All 2 selected locks in this branch pass the actual cargo-audit 0.22.2 invocation with `--deny warnings`, the complete fixed advisory database at `31cf5a8673e10d3a4d7d829ad5095f47ed419049`, and no ignored advisory. Exact commands and output are retained. The audit uses `--no-yanked` for the advisory phase, as the production entrypoint does; registry checksum and yanked-state evidence for the only changed crate is recorded separately.

The production audit gate remains unchanged. Its local SDK invocation stopped at the isolated sparse-index worker because direct DNS is unavailable in this executor. The retained entrypoint log distinguishes that environment result from the completed advisory scans.

## Runtime validation

The canonical policy-agent passed 252 tests on its selected Rust 1.96.1 toolchain; one pre-existing ignored test remains ignored.

Both branch runs compile with warnings denied. Nine policy-agent cases need AF_UNIX sockets and encounter errno 1 (`Operation not permitted`) at socket setup. A separate Python standard-library control, loading neither Rust nor rustix, encounters the same error when creating an AF_UNIX socket. These cases retain their original failures in `runtime-tests.log`; the receipt records the specific environment condition and exact case names. Hosted CI supplies the normal socket-capable execution environment.

## Preserved comparison and evidence inputs

The paper subtree and retained evidence lockfiles remain byte-identical. The separate SPQR reference keeps its original upstream-matching lock, as required by `artifact/spqr_reference.py:check_lock`. Its rustix 1.0.5 remains in the advisory range and is explicitly outside these updated SDK and application graphs; the reference is not recorded as repaired. No archive, reference identity, or audit admission rule changes.
