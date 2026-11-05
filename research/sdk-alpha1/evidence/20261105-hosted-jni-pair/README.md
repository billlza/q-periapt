# Hosted Android adapter JNI: Debug and Release readback

The original [Debug job](https://github.com/billlza/q-periapt/actions/runs/42008993544/job/127187927191)
and [Release job](https://github.com/billlza/q-periapt/actions/runs/42008993544/job/127187927184)
both completed successfully at source
`232ace17915407596d66f3a5fd7c7765251a38cc`. They ran the Android adapter on
**macOS arm64 host JNI**, using packaged Java classes and the installed C engine.
This record completes the original pair's public-trace and source/package
readback. It does not execute a new native workload, qualify ART/AAR or a
physical device, establish an independent protocol implementation, or qualify
the later local source.

| Original partition | Job execution UTC, 2026-11-05 | Local public readback |
| --- | --- | --- |
| Debug | 14:36:50–18:19:13 | 20 public result groups checked; 4.871 seconds |
| Release | 15:00:12–18:49:32 | 20 public result groups checked; 5.974 seconds |

## Executed behavior and readback scope

The original readers recompute lifecycle/account outcomes, required-witness
registration, credential and policy expiry/renewal, roster changes, cancellation
and process-loss recovery, original pending-write continuation, retirement,
account-root replacement, joint renewal and two-generation renewal cycles.
Recovery also replays the retained native semantic oracles and the recorded
Java/C dispatch roles. It does not relabel C registration as Java registration.
The exact report comparisons and per-field results are retained.

Each JNI test binary lists 70 entries. Thirty-six recorded native commands
execute all 67 JNI-specific cases once, with no extra or repeated case. The
other three entries come from the imported `owned_connection.rs` fixture; the
separate installed Rust consumer executes those three with zero failures,
ignored cases or filtered cases. The source import and Cargo target paths bind
that correspondence. This is not a claim of one unfiltered 70-case invocation
of the JNI executable.

The six joint-cycle cases passed in each profile, retaining local/signed/TLS
carriers and fixed/recoverable trust. Their recorded native durations were
548.41 and 548.14 seconds, with 64 other JNI catalog entries filtered from that
particular command. These timings describe these executions, not a product
latency budget or a comparison with the newer roster-verification repair.

Each public replay loads 69 unchanged modules from source `232ace17`; the
99-module static reader closure is retained. The initial Debug replay stopped
because the new mapping driver incorrectly appended `.public` to stdout/stderr
filenames for the twelve basic process steps. The original exporter retains those
streams without that suffix. Only this mapping was corrected. The failed
driver, traceback, command receipt and partial readback remain in the capture;
the original validation functions and assertions were not changed. Release
uses the same mapping with explicit profile and input-directory arguments.

The original OpenSSL client/server/rejection readers also reproduce their
results for both profiles. The server trace and negotiation records retain
exactly **146 witness exchanges**; the client retains its own two-exchange
contract. This supports the observed installed TLS-peer path, with the native
witness engine and same-host scope preserved.

## Identity and limits

Both partitions have identical source inputs, SDK producer report, Rust compiler
identity and Rust tool fingerprints. The SDK report SHA-256 is
`56ae2a2ab6c4f661d8cc0b3c3c8e499ce31c9aee2a3737456424adf7602fb0cf`;
its workspace root is
`75bbe6e71aadf3d3315c5708047684cbf55f782e6c1e1decf77a59e387d39f51`.
The audit checks 1,393 source inputs against the commit, the unchanged before/after
inventories, 146 JNI source files, 720 packaged candidate source/test files,
the 383-file SDK workspace, its 20 additional source bindings and all twelve
SDK crate archives. The Rust and C consumer graphs in each profile resolve nine
SDK packages plus one candidate, with 171 external package identities retained.

The actual retained JAR contains 131 class files at Java class version 55
(`--release 11`) and has the same SHA-256 in both profiles:
`4d4c77e63975a693155e3693e6c76349e8df54c930af3a807b31529800126d0a`.
The retained candidate archive also matches its declared bytes and source.
Seven native program/library fingerprints per profile are **receipt-only**:
their binary bytes are absent from the original artifact. The complete artifact
hash scan confirms that absence. The C/JNI linkage in the reports is checked,
but these fingerprints are not represented as downloaded binary verification.

At local source `0a80941978b83cf16c82aa9013fff9d71d81847d`, the package's
explicit source inventory has 1,401 files: 46 pinned inputs changed and eight
were added. The current SDK workspace root is
`c064df108a07da40099f9c2fe8115577d54f421fea918a0fefb1810d76a42c4d`.
The full differences are retained. This historical pair does not qualify that
changed source, nor supersede the separate
[failed local aggregate](../20261105-android-parent-timeout/README.md) or its
[component-only follow-up](../20261105-android-release-cycle-followup/README.md).

The original reports deliberately retain `partition_completed=true` and
`completed=false`. `PAIR.json` records the same-source Android pair without
changing them. The original complete foreign-consumer gate requires all six
Swift/Kotlin/Android Debug/Release partitions; that gate is not claimed here.

## Capture

Three original GitHub artifacts are retained: Debug `13441811850` (82,412,095
bytes), Release `13443652836` (82,536,838 bytes), and SDK producer `13405394674`
(5,939,469 bytes). Their lengths, full ZIP CRCs and GitHub SHA-256 values were
checked. They contain 66,741 members in total. All capture-capsule members were
then reread and checked against `FILES.json`.

| Capsule | Bytes | Members | SHA-256 |
| --- | ---: | ---: | --- |
| `INPUTS.zip` | 6,514,675 | 115 | `11381e923f865af1fcec5075a43cd60a48626c4d60b0ac6d6cb47b1ab4b72024` |
| `DEBUG.zip` | 72,554,868 | 24 | `8528be4e195d5e7c6e8f6e8bbbe880a076e2c1a98e777c370334b0eafe8dbe52` |
| `RELEASE.zip` | 72,540,080 | 18 | `13d92a28cf8db4a624598fc9ef1a63bd5f4a78b3fefe1f318e06ddfb5685301c` |

`INPUTS.zip` includes the original SDK producer, pinned readers and capture/replay
drivers. The profile capsules retain original artifacts, job logs/API identities,
readback results/commands, source audits and test inventories. Debug's initial
`STATUS.json` is intentionally preserved as a pre-readback observation; final
readback results and `PAIR.json` carry the later conclusions. No CI rerun,
timeout change, product-source edit, support change or publication occurred.
