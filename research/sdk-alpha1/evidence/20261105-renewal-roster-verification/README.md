# Reuse authenticated rosters within credential renewal verification

Implementation commit: 1bdb29a20d1d9c68496648f3be91efad710e4b0c.

The original hosted macOS composition timeout and Linux Rust 1.90 roster-capacity
timeout remain retained as failures. Local sampling and bounded input counting
identified avoidable repeated signature work in the historical renewal path.
This checkpoint repairs and validates that work; it does not retrospectively
prove the precise hosted delay or mark either remote failure resolved.

## Change and preserved checks

Previously, decoding one retained credential renewal verified the predecessor
and successor rosters repeatedly while finding historical validity instants and
then validating the devices. The new path authenticates those two immutable
rosters once for that verification and reuses the resulting objects.

The reusable device path checks the exact account, root, family and checkpoint,
then checks time and membership. The renewal path also requires the exact
original roster bytes. Credential, renewal-statement, policy and Witness
signature verification still execute. There is no persistent or global
verification cache, change to wire/storage formats, new public API, capacity
change or deadline extension.

New negative cases cover substituted roster signature bytes even with the same
body/checkpoint, a different pin/root/family/checkpoint, expiry, revocation and
corrupt credentials. The retained-journal path additionally rejects corruption
of each of the six signed fields, truncation and appended bytes. Existing valid
outputs and recovery cases remain required. Authentication is performed earlier
for some inputs, so a container with several independently invalid components
can expose a different existing error first; it is still rejected.

## Measured verification work

Two fresh random 32-member witnessed fixtures ran with the same Rust 1.98.1
instrumentation and unchanged 30-second native/worker bounds. Each completed
91 worker operations and 15 actual process cuts. The input digests differ
between these random fixtures; their distinct-input counts and workload match.

| Signature purpose | Before attempts | After attempts | Distinct inputs per run |
| --- | ---: | ---: | ---: |
| Credential | 7,548 | 7,548 | 96 |
| Roster | 12,648 | 5,223 | 4 |
| Manifest | 1 | 1 | 1 |
| Witness request / reply | 17 / 17 | 17 / 17 | 17 / 17 |
| Enrollment request | 62 | 62 | 1 |
| Credential renewal | 2,475 | 2,475 | 32 |
| Policy renewal | 226 | 226 | 2 |
| Total | 22,994 | 15,569 | 170 |

The reduction is exactly three repeated roster verifications for each of 2,475
historical grant decodes: 7,425 attempts. Each roster fingerprint was separately
matched to its real public root and signed wire. Roster 2 changes from 7,425 to
2,475 attempts; roster 3 changes from 4,999 to 2,524. Rosters 1 and 4 retain 126
and 98 attempts.

The target exchanges took 10.731 and 7.650 seconds in these two observations.
Instrumentation, different random fixtures and uncontrolled host conditions
make this a diagnostic timing pair, not a tail-latency result, a formal resource
budget, or attribution of the hosted timeout. The production change contains
none of the counting instrumentation. Its separate diagnostic commits are
3c3617019f2265f6f42b8d8f599b48584fa79d05 and
4ac872a09afc82f98f9a2b2a7055726206edff1a; their source, patches and actual binaries
are retained in COUNTING.zip.

## Actual current-source validation

| Check | Observed result |
| --- | --- |
| Full Rust 1.98.1 Release library suite | 1,461 passed; 0 failed, ignored or filtered; 2,774.097 seconds |
| Focused identity/renewal tests | 12 passed in Debug and Release on Rust 1.98.1; 12 passed in Debug on Rust 1.90.0 |
| Strict Clippy and formatting | All-target Clippy with warnings denied and formatting check passed |
| Original Debug roster-capacity case | Passed with all 32 original installations on Rust 1.98.1 (493.281 seconds) and Rust 1.90.0 (553.062 seconds) |
| Uninstrumented native composition | All four 3/32-member local/witnessed profiles, two workers, completed in 281.209 seconds |
| Deliberate total-deadline cancellation | Two active owners cleaned and two queued profiles prevented from starting native processes; 2.230 seconds; workload correctly remains failed |

The uninstrumented run used native binary SHA-256
60febe5463f71ba35820c75eb60edb99d24c2d35f46720594627c01a6c4f4c4f.
Its public readback checks all 818 native command records, 634 Witness attempts,
344 worker operations and 60 actual process cuts. The longest observed exchange
was 8.643 seconds. All four owned native processes were reaped by the existing
fixture cleanup. The per-exchange limit remains 30 seconds and the total
acceptance budget remains 900 seconds. Cancellation is cooperative at existing
bounded operation boundaries; it is not a generic detached-process-tree claim
or a hard 900-second kill of an intermediate supervisor.

The capacity test retains its original three-second Witness attempt limit.
Full Release and the selected capacity checks use the existing CI job's
90-minute budget. These are Apple Silicon host results. They do not substitute
for Linux Rust 1.90, device execution, or final package/platform qualification.

The first full-suite inventory reader failed despite test-process exit 0:
libtest appends a should-panic annotation to two declared negative oracle tests.
The original failed RESULT.json and complete output remain unchanged. A separate
reader checks both exact source declarations and their actual expected panic
messages, then requires the complete unique 1,461-case inventory and zero
failures/ignores/filtering. It rejects eleven missing/duplicate/unknown/failed/
ignored/incorrect-panic/incorrect-summary controls. No runtime case was dropped
or rerun to repair this bookkeeping failure.

Other retained diagnostic failures are the initial cross-checkout Python-wrapper
refusal before compilation and the build.json / BUILD.json collision on the
case-insensitive filesystem after the three build/check commands succeeded.
The baseline executable was copied and hash checked before Cargo reused its
original output path.

## Source and package boundary

Run-time source hashes match the committed three-file implementation, including
checks started before the commit was created. SOURCE_IMPACT.json reconstructs
the parent input inventories and compares the actual package source selectors.
Its JSON digests use sorted keys and compact comma/colon separators.

The SDK workspace root remains
c064df108a07da40099f9c2fe8115577d54f421fea918a0fefb1810d76a42c4d.
The private candidate's C/JNI and WASM input maps both change in the three
implementation/test files. Their old package reports cannot qualify this source.
The older ff072 SDK report already differs from this workspace root because of
the preceding Windows correction; a matching new SDK producer is still needed
before updating the dependent Android pin. No remote wave, push or rerun was
triggered by this checkpoint.

This is implementation and local validation evidence. Hosted failures, final
CI, package identity, platform gates, complete computational/product contracts,
external review and explicitly authorized release remain separate.

## Retained artifacts

COUNTING.zip has 4,481 members / 26,651,752 bytes, SHA-256
7156784b674561283ac22c50510134cfbd8f9b1d6773dd6a8eb072e528af9a56.

VALIDATION.zip has 5,362 members / 65,944,802 bytes, SHA-256
9c6e0a574fe197d88f4e3b2ba6299948c28d2a490e444e919e7ba970580e3a34.

The corresponding JSON manifests bind every member's bytes and SHA-256. Both
archives passed CRC and complete byte readback. They retain original failures,
raw command outputs, original and corrected readers, complete selected public
transcripts, source snapshots and actual runtime binaries. Generated private
fixture state and key files are excluded; private-path identifiers are not
followed. Public test vectors remain part of the ordinary test source/binaries.

