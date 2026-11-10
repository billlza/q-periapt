# Staging maintenance protocol experiment — incomplete

This is an isolated experiment for the **already open exclusive staging-maintenance
requirement**. It changes no product code and introduces no automatic cleanup.
The extended experiment fails on a valid zero-byte payload; that failure remains
part of this checkpoint. The narrower successful runs are not an aggregate pass.

## What the existing implementation establishes

The current `StagedFile` pins its original descriptor and parent, but ordinary byte
publication has no publication/maintenance lease. Database publication acquires a
nonblocking `LockedFileBackend` lock after staging creation; it does not cover
ordinary files or directories. `OwnedPrivateDirectory` pins a directory, but does
not exclude a concurrent publisher. An old `staging_name()` remains diagnostic
correlation data, never cleanup authority.

The relevant sources are
[`publication.rs`](../../../../crates/q-periapt-host-store/src/filesystem/publication.rs),
[`directory_publication.rs`](../../../../crates/q-periapt-host-store/src/filesystem/directory_publication.rs),
[`publication_ops.rs`](../../../../crates/q-periapt-host-store/src/filesystem/publication_ops.rs)
and the existing [file admission and lock boundary](../../../../crates/q-periapt-host-store/src/filesystem.rs).
No cleanup path currently exists in these publication helpers.

The experiment uses copies of the genuinely installed consumer's existing SDK
and candidate sources outside the checkout. All **1,037** copied package files
are unchanged before/after; all **22** installed host-store Rust source files
match current checkout `c64a0248`. Adding direct access to the already locked
`rustix 1.1.5` changes only the experimental consumer's root dependency list;
its 118 external package identities, versions, origins and checksums are unchanged.
The probe itself is new research code, not an installed product maintenance API.

## Observed results

| Experiment | Actual outcome | Scope |
| --- | --- | --- |
| Fixed-directory-descriptor negative control | After the real installed SDK publishes the directory, deletion through its old descriptor removes a child from the formal directory | Shows why pinning the inode alone cannot authorize a future cleaner; this is deliberately unsafe experiment code, not an existing SDK defect |
| Versioned record plus continuous separate control lease | Four file/directory pre-publication and post-publication scenarios pass | The actual `LockedFileBackend` refuses cleanup while another process owns the lease; after SIGKILL, cleanup removes an unpublished payload or reports `NoPayload` without touching the formal value |
| Corrupt/substituted inputs | Six controls refuse partial metadata, changed parent, changed payload, symlink, hardlink and an extra control entry | Original payload bytes remain |
| Crash before complete metadata | Refused; empty payload and incomplete attempt remain | No application bytes are written before the metadata barrier; prefix/name does not authorize deletion |
| Extended crash after metadata, before application bytes | **Failed**, exit 1, `PrivateFileError`; original bound zero-byte payload remains | Existing operational file admission correctly refuses an empty existing file; it cannot be reused unchanged for this maintenance role |
| Separate active-lease replacement control | Passed | Moving the still-locked original lease away and creating a new unlocked file of the same name does not authorize cleanup: the record's original lease identity differs |

The first run has **12 recorded cases**, including **11 distinct owner PIDs**
terminated by real SIGKILL. A later single-case run validates active-lease
replacement. The failed extended aggregate stops at its first zero-byte case;
no later case in that aggregate is counted as executed or passed.

The prototype deliberately uses a closed one-file directory fixture, a fixed
experimental target, and a private record binding parent, control, lease and
payload inode metadata. Its `QPSTG001` tag is experimental, not a frozen product
format. Device/inode pairs are local correlation values, not permanent identity
or authorization on their own. The private namespace, correctly constructed
record and continuously held lease are separate assumptions. The experiment does
not establish isolation from hostile same-UID code or arbitrary filesystem changes.

`NoPayload` means only that the original payload leaf is absent from the control
directory. It does not prove publication, recover a missing formal destination,
or mean that the same cleanup previously committed. The prototype retains its
control record and lease. It does not remove/recreate lock files to retry, recover
an unpublished attempt as live state, or follow the recorded target to delete it.

## Required implementation decisions now supported by evidence

A product implementation needs a control directory that remains outside the
published payload, a versioned bounded record, and one continuous lease shared
by **all** participating publisher and cleaner paths. Take the lease before
initialization and hold it across rename, original-target checks and both source
and target directory synchronization. Cleanup must reopen the existing lease,
recheck its original identity after locking, and admit only the original payload
still inside that control directory. The present publisher paths do not implement
this protocol, so this probe must not be pointed at their old residues.

The failed extended case identifies a concrete next change: maintenance needs an
internal disposable-payload admission that can validate an empty regular inode
under the original record/lease while retaining ownership, mode/ACL, link,
parent and identity checks. **Do not relax `open_private_file(..., false)`** or
add a create-on-missing recovery path. Its empty operational-store rejection is
correct and remains unchanged.

Further product work remains: per-attempt identity and format integration;
bounded general tree preflight and cleanup; crash-safe control-record retention
or retirement and exact unknown-result reporting; explicit bounds for residues
created before metadata completion; Windows handle/rename behavior and other
platform execution; actual installation/foreign-consumer validation; and resource
measurement. Unknown legacy residues remain retained, with no retroactive cleanup
authority inferred from their names. These are obligations of the existing
maintenance requirement, not new requirements for unrelated automatic compaction
or end-to-end operating-system proofs.

## Validation, retained failures and evidence

Rust 1.98.1 Release builds and strict Clippy (`-D warnings`) pass for the tested
probe revisions on Apple M4 Max, macOS 26.7.2 / Darwin 25.6.0. Unsafe Rust is
forbidden by the experimental consumer manifest. No global toolchain or host
security setting is changed.

The first preparation build failed because the probe called the existing
three-argument provisioning helper as a one-argument function. It also exposed
an external selected-toolchain `rust-objcopy` loader failure for `libLLVM.dylib`.
The next build corrected the call shape but failed on ambiguous error conversion.
Both original sources and diagnostics remain. Explicit error typing fixes the
source error. A child-process-only loader search for that same toolchain's
existing library fixes the tool problem; warnings are denied, not suppressed.
The source and binary for every executed revision are retained. The extended
runtime failure remains separate from these preparation failures.

`review.py` verifies the exact basic census, selected control, captured fixture
bytes/inodes and the nonzero failed aggregate. It explicitly reports
`extended_aggregate_passed: false` and `product_maintenance_implemented: false`.
The archive is reread member by member and that review is rerun over the archive.
The fixtures contain only synthetic experiment bytes; no original user key,
account, credential or device store is touched or copied. Captured inode metadata
is observation evidence, not portable restore or deletion authority.

At **15:27:43 UTC**, the twelve current-head CI runs contain **275 successful,
47 queued, one running, seven failed and two skipped jobs**. The seven failures
are the same previously classified jobs. PR #117/#118 remain at
`475cd239`/`6084f3bf`; no push, rerun or new CI wave was started. Protocol/product
freeze, safe maintenance implementation, platform qualification, external review
and the overall release remain incomplete.
