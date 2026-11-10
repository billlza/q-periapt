# Leased publication maintenance and installed native command

Implementation: `f560d803c43a24fff222daa5e5e5bd623bfdf874`.
Documentation/package builder: `7429f655bd48c1fb3997fc866d6ef048d7e758cf`.
Host: Apple M4 Max, Mac16,5, 48 GiB, macOS 26.7.2 / Darwin 25.6.0.
This is a local implementation and installed Apple-Silicon checkpoint, not a
release decision, complete candidate regression result or Windows runtime result.

The [v2 contract](../../../../docs/PRIVATE_PUBLICATION_MAINTENANCE.md) adds a
separate continuous attempt lease before exposing an unpublished payload. File,
database and directory publication retain it through NOREPLACE publication and
both parent syncs. Explicit maintenance admits the original private scope and
whole remaining payload, obtains file leases before removal, and retains an
original cleanup intent and receipt. It handles an empty disposable file without
relaxing the normal operational opener. It never follows the formal destination.
Old prefix-only, incomplete and substituted controls are refused.

## Actual execution

| Boundary | Observed result |
| --- | --- |
| Host-store library, Debug and Release | 73 libtest cases in each profile pass, including harness dispatchers. Four actual cleanup process cuts per profile verify original-result recovery; publication/database cuts remain enabled. |
| Candidate installation, provisioning and two Witness import cut groups | 79 + 7 + 1 + 1 = 88 cases pass. These focused groups do not replace the full aggregate. |
| Host-store, candidate and CLI Clippy | Selected Rust 1.98.1, `--all-targets`, `-D warnings`, locked/offline dependency resolution pass. Candidate uses all three TLS features. CLI default-feature build also passes. |
| Python quality checks | 48 CodeQL-gate, 17 Rust-package and 2 maintenance-package tests pass. Actual tracked Rust inventory is 1,171; this is not a CodeQL scan result. |
| Fresh SDK cohort | 12 Cargo archives from an independent clean checkout of `f560d803`; nine exact archive-derived packages are consumed outside the checkout. All four public API consumer tests pass, including original orphan reclamation without changing a later formal publication. This is not a public-registry upload. |
| Extracted native maintenance package | Actual `qperiapt` executable passes seven existing policy-format migration invocations and the new publication-maintenance integration case (five real command invocations). Package/source/tool identities are checked after execution. |
| Separate original-byte capture | Another archive-derived application invokes the same extracted binary five times. Active owner, insufficient budget and a formal path refuse; successful cleanup and retry return identical JSON bytes. Original control, lease, intent, receipt and all command streams are retained. |
| Windows source boundary | Real Windows GNU std and native portable C build: `cargo check --lib` and Clippy `-D warnings` pass. All 29 host-store source/example/manifest files match the implementation. This is neither MSVC nor Windows/NTFS execution. |

The actual captured attempt is
`.private-attempt-v2-53cdfda23681320bb3c425a2354db88f`.
Its repeated result is **2 entries / 26 bytes**. The archive contains the raw
record, intent and receipt, not only their hashes. An independent reader checks
their checksums, nonce/name, original parent/control/lease filesystem identities,
destination digest, counts and exact retry output. The formal fixture still
contains its original 26 bytes. These are public test bytes, not user storage.

The SDK cohort uses advisory database
`965bf9ad083b58e6340d65829d85217b18be9290`; workspace, fuzz and consumed-package
audits share that identity. The consumer audit reports zero vulnerabilities and
zero warnings at that snapshot. This is not a permanent dependency-safety claim.

Native package identity:

- Archive SHA-256: `46010c2cc29eeee237fb7ced18717443bfc02ccd4c60e1ab5e8660ce36c76e0c`.
- Executable SHA-256: `805920c70fd7d4ecd2603cb71a1b2634f4698bd39bcf71529e3abb6a8ea42133`.
- Manifest SHA-256: `f0b4822b018f63ccf3cdbd7dc34893b3b4d8c28461d07f2980d6fd7222631c17`.
- The declaration of macOS 13 deployment metadata does not establish execution
  on macOS 13. Ninety package-license entries are verified by the existing gate.

## Failures retained and their scope

The earlier [isolated experiment](../20261104-staging-maintenance-protocol/README.md)
remains unchanged and failed in its extended empty-payload aggregate. It did not
demonstrate an existing SDK cleaner deleting formal state: no product cleaner
existed. The new mechanism incorporates its separate-lease requirement.

During implementation, a depth-one budget incorrectly admitted second-level
files; its pre-fix test returned `Reclaimed { entries: 3, bytes: 72 }`. A completion
prefix without a committed intent was also accepted. Both counterexamples are
retained, followed by passing tests requiring refusal before payload removal.
The latter group also rejects duplicate and out-of-order completion records.

Parallel quiescent-owner fixtures produced `Busy`. A controlled inherited-open-
description case proves that a parent close does not release a child-retained
owner. The original parallel failures did not identify their particular holder
PID, so they are not claimed to be fully traced to that holder. Quiescent fixtures
now create their descriptors only after an isolated exec; production still returns
`Busy`, with no timed retry or weaker assertion. The bounded reproduction's first
three successes and fourth failure remain retained.

**The complete candidate suite is not passed.** Three 600-second observations
remain failures: the combined Debug run, the combined Release run, and one
runtime-only Release diagnostic using the identical 1,456-case binary. Release
compilation took 230 seconds, but runtime alone also exceeded 600 seconds; compile
time alone cannot explain the deadline. No timeout was raised. The first driver's
missing streaming sinks lost its partial per-test output; its exception and exact
driver are retained and that missing output is not reconstructed. The two Release
streams are retained. Focused successes are not relabeled as aggregate success.

Other preparation failures remain visible: initial syntax/visibility/Clippy
errors; missing locked dependency-cache entries; a CLI fixture created without
the required private mode; and two package-launcher admission failures (adjacent
Python bytecode, then missing explicit CPython selection). The corrected fixture
creates its own 0700 directory; the operational private admission is unchanged.

The first native package build was correctly rejected for `rust-objcopy` warnings.
The original tool loads with an explicit dynamic-library search path, while the
system shell removes that variable. A task-private copy of the exact 1.98.1
toolchain supplies the missing relative `libLLVM.dylib` link. Its Cargo, rustc,
rustdoc, objcopy and LLVM bytes match the original; the global toolchain is
unchanged. The final build retains `-D warnings -C strip=debuginfo` and the Apple
deployment wrapper, and passes the unchanged warning gate.

The MSVC cross-check still stops in real C compilation at missing `string.h`,
before host-store modules are compiled. The separate GNU checks preserve this
failure and do not substitute for a Windows host. Registry dependency warnings
visible in verbose GNU diagnostics are recorded separately from the clean
host-store Clippy result; their unchanged sources do not become new product fixes.

## Remaining work and provenance

The final snapshot covers all 332 jobs in the existing 12 runs: **280 success,
41 queued, 2 in progress, 7 failure, 2 skipped**. PR #117 remains `475cd239`; #118
remains `6084f3bf`. The same four installed count-check failures, two classified
Android infrastructure failures and one pre-validation artifact-fetch failure
remain. No remote ref, workflow rerun or publication was performed.

The full candidate aggregate, new Continuity installed-peer lifecycle with this
SDK cohort, real Windows/NTFS and other supported platform execution, legacy or
incomplete-control disposition, final contract/ABI admission, remaining proof and
resource obligations, external security review and final release authorization
remain separate. Process termination is not a power-loss or physical-erasure test.

`EVIDENCE.zip` retains 565 members / 8,813,595 uncompressed bytes. SHA-256:
`ad7ff0991b46ead8c33e0c8dbb1ea30c9b681ab82d0d3d8675f5b441af7fe123`.
`FILES.json` binds every member's exact bytes and size; `RESULT.json` gives the
scope ledger. A final repeat of both 73-case host-store profiles and all-target
Clippy rechecks the complete library source against the committed implementation
before and after execution; its full commands and streams are retained separately
in `FINAL_SOURCE_VALIDATION.json`, whose digest is pinned by `RESULT.json`.
`runs/`, `sdk-cohort/`, `maintenance-package/`,
`maintenance-package-original-warning/`, `installed-original/`, `windows/` and
`source/` distinguish the boundaries. Large reproducible compiler/SDK downloads,
the exact built packages and surviving owned fixtures remain in the raw private
locations recorded by those receipts, not duplicated into this archive.
