# Hosted six-partition receipt coverage

Run `42008993544` completed its six installed foreign-consumer partitions and
coverage job `127583678438` at source
`232ace17915407596d66f3a5fd7c7765251a38cc`. The original coverage checker has been
replayed on the six actual, unmodified `CONTINUITY_PACKAGE.json` reports. Its
result matches the hosted result exactly as structured data. This closes the
historical Debug/Release receipt-union observation; it does not qualify the
later local candidate, all platforms, or a release.

| Consumer | Debug job / artifact | Release job / artifact |
| --- | --- | --- |
| Swift | `127187927379` / `13457675209` | `127187927229` / `13429478114` |
| Kotlin | `127187927198` / `13459070135` | `127187927234` / `13458493800` |
| Host Android JNI | `127187927191` / `13441811850` | `127187927184` / `13443652836` |

The authoritative job IDs and intervals are also retained in [JOBS.json](JOBS.json).
All reports bind the same 1,393 source input files, Rust compiler identity and
SDK report `56ae2a2ab6c4f661d8cc0b3c3c8e499ce31c9aee2a3737456424adf7602fb0cf`.
The SDK workspace identity is
`75bbe6e71aadf3d3315c5708047684cbf55f782e6c1e1decf77a59e387d39f51`.
Every source file was reread against the pinned Git extraction. The original
fourteen loaded checker modules and isolated Python dispatcher are retained.

All six artifact ZIP sizes and SHA-256 values match GitHub metadata. The newly
downloaded Kotlin pair also passes full ZIP CRC validation. The actual report
bytes are preserved, rather than reconstructed from selected fields. The
coverage artifact `13460680435` is 1,002 bytes with SHA-256
`e1a4915a5691483c5ae72dfea14ec9001c9cb36d1c4ae36a8a0a487ce6c62bb6`;
its contained JSON is 2,116 bytes with SHA-256
`1402734b8810a286aa06458965dad849a4efd9254f4285fd5777e3d3d8a28606`.

The unchanged checker requires exactly Swift, Kotlin and Android JNI in both
profiles; matching complete source inputs and SDK report; completed requested
Rust/C/foreign profile partitions; Swift Apple packaging and minimum-Rust
execution; and Kotlin publication tests using their requested profile. It
retains each full report's digest. Each individual partition still has
`completed=false`, `partition_completed=true` and `release_claim_eligible=false`.

This checker joins producer receipts. It does not rerun native workloads or
read each public protocol transcript. In particular, its success cannot repair
the [Swift publication export omission](../20261105-hosted-swift-pair/README.md).
The Kotlin public scenarios have not been independently replayed by this
observation; a [separate subsequent Kotlin reread](../20261105-hosted-kotlin-pair/README.md)
checks the actual packages and 21 selected public groups per profile. macOS host
JNI remains distinct from an AAR installation, Android
ART, emulator or physical-device execution. Shared-engine receipts do not become
independent protocol-engine evidence. The main run still has its two previously
recorded failures; a passed coverage job does not make the run successful.

[READBACK.json](READBACK.json) records the independent result and exact input
identities. [COVERAGE.json](COVERAGE.json) preserves the hosted output.
[CAPTURE.zip](CAPTURE.zip) contains the six report bytes, original checker
modules, dispatcher, replay harness, metadata, coverage job log and readback
streams. [FILES.json](FILES.json) lists every captured member, all of which were
reread after capture. The full original source byte dependency is the previously
verified [Swift INPUTS.zip](../20261105-hosted-swift-pair/INPUTS.zip), with digest
recorded in [CAPTURE.json](CAPTURE.json). Full original workflow ZIPs remain
retained locally for their separately scoped scenario evidence.
