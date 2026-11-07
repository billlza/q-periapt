# Hosted Kotlin pair: installed packages and retained lifecycle evidence

The Debug and Release Kotlin partitions in run `42008993544` completed at source
`232ace17915407596d66f3a5fd7c7765251a38cc`. Their actual installed package bytes,
unit reports and selected public lifecycle records have now been independently
reread with that source's unchanged readers. This is historical macOS arm64
qualification, distinct from the later local candidate and Android ART.

| Profile | Job | Original interval on 2026-11-05 (UTC) | Artifact |
| --- | --- | --- | --- |
| Debug | `127187927198` | 18:55:28–22:19:37 | `13459070135` |
| Release | `127187927234` | 19:12:11–22:44:57 | `13458493800` |

Both original ZIPs match GitHub's exact sizes and SHA-256 values and pass a full
member/CRC reread: Debug is 135,864,731 bytes; Release is 134,853,414 bytes; each
contains 39,116 members. Their six-partition source/SDK identity is independently
joined in the [coverage record](../20261105-hosted-profile-coverage/README.md).
Each original partition retains `partition_completed=true`, `completed=false`
and `release_claim_eligible=false`.

The two installed Kotlin packages each have 281 members. The original archive,
Maven, source-JAR, module metadata and license validators pass. Maven coordinates
remain `dev.qperiapt:q-periapt-continuity-kotlin:0.0.0`, with 241 classes and JVM
version 25. The actual arm64 native dylib bytes match each C engine's fingerprint;
its Mach-O header identifies a dylib. Packaged consumer sources and C header match
the original source. Both Rust/C Cargo graphs resolve nine SDK crates and one
candidate outside the source checkout. All 1,393 source inputs and the 766-member
candidate archive were also reread.

The original runtime is Temurin OpenJDK 25.0.5+8 with Gradle 9.8.0 on macOS 15.8.2
arm64. The SDK's declared Kotlin dependency is 2.4.20; the Gradle banner's embedded
Kotlin 2.4.10 describes a different component. The exact 79-test, fifteen-suite
reader passes for both Maven-publication and installed-native lanes in each job.
Those are repeated executions of the same test catalog, not 316 distinct tests.
Java module and public-configuration probe markers also match.

For each build profile, 21 original public-reader groups reproduce their
recorded results: client, server, closure recovery, original-session restoration,
opening restoration, in-flight GC and parent-account lifetime under Serial/G1,
four root routes under each collector, and four Witness routes including explicit
controller interruption. The root readers preserve the original approvals,
rekey/traffic, cleanup and observed Cleaner revocation of the still-live successor.
They explicitly reject a claim that JVM stack size was measured.

Prepared-owner GC receipts retain sixteen rounds and 1,024 forgotten, strongly
live and stale owner checks under each collector. In-flight checks preserve eight
callbacks, seven returned-slot checks and the deliberately absent return after a
process cut. Each profile's 26 original HotSpot compilation logs pass the exact
reader: thirteen invocations per collector, original invocation paths and flags,
the expected workload counts, and required C2 frames. These are bounded
observations under the selected JVM/collectors; they do not qualify every JVM,
automatic cancellation or physical power loss.

Fifteen retained negative-control commands per profile have nonzero exits and
the original expected diagnostics: six loader/native-access refusals and nine
Java visibility refusals. The original summary lists only eleven labels; the
additional retired-owner, account-authority, configuration and configuration-key
commands are present in its raw receipts. [RETENTION.json](RETENTION.json)
records the actual fifteen-command reread rather than treating that summary as
the complete executed inventory.

The current local qualifier now includes those four already-executed controls
in its report inventory. [INVENTORY_READBACK.json](INVENTORY_READBACK.json)
checks the corrected labels against both actual fifteen-command receipt sets,
and an AST comparison confirms that only this inventory expression changes.
All eleven existing Kotlin qualifier tests pass via
`sh artifact/python-run.sh -m unittest discover -s artifact -p test_continuity_kotlin_consumer.py`.
The captured test streams and source fingerprints are listed in
[INVENTORY_FILES.json](INVENTORY_FILES.json). This changes qualification-report
inputs, with no JVM/native behavior or safety check changed. A full package
execution of this later source has not been claimed; historical reports remain
unchanged.

The actual SDK JAR and native library are exported. The installed consumer JAR,
Kotlin stdlib JAR and annotations JAR are absent from the original artifact and
installed package member inventories. Their hashes and original resolution/
execution records remain receipts. The original live-path runtime-closure
checker was not rerun against nonexistent hosted paths. No new JVM/native
workload was executed during this readback.

Both artifacts also omit `kotlin-publication-public`. Each Serial/G1 publication
record names 85 public readbacks; forty required content digests per collector
and profile are absent from all outer artifact, installed Kotlin package and
candidate crate members. Common or empty matching digests cannot reconstruct the
missing directory. This is the same historical upload omission already corrected
by local commit `d2c951f03`; it remains pending complete exports and reader replay
in the next permitted wave. It is not evidence of a new publication runtime
failure. Other exported scenarios remain in the full original ZIPs and are not
claimed to have been independently replayed by this selected reader.

[DEBUG_READBACK.json](DEBUG_READBACK.json) and
[RELEASE_READBACK.json](RELEASE_READBACK.json) record the exact packages, tests,
GC/JIT observations, source-reader identities and limits. [CAPTURE.json](CAPTURE.json)
identifies three byte-verified capsules: [DEBUG.zip](DEBUG.zip),
[RELEASE.zip](RELEASE.zip) and [READERS.zip](READERS.zip). Their file manifests
record every captured member. The full source byte dependency remains the
[Swift INPUTS.zip](../20261105-hosted-swift-pair/INPUTS.zip). Full original Kotlin
workflow ZIPs remain retained locally for the other scenario evidence.
