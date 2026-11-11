# Hosted Swift pair: packages, selected public replay and retention gap

Both Swift profile jobs in run `42008993544` completed successfully at source
`232ace17915407596d66f3a5fd7c7765251a38cc`. The actual downloaded packages,
dependency graphs and selected retained public records have now been checked
independently. The historical artifacts omit the publication public directory;
that scenario cannot be independently replayed from these exports. These results
do not qualify the later `5678d101` candidate or the complete foreign matrix.

| Profile | Job | Original interval (UTC) | Artifact |
| --- | --- | --- | --- |
| Debug | `127187927379` | 2026-11-05 19:21:29–21:50:02 | `13457675209` |
| Release | `127187927229` | 2026-11-05 13:05:39–15:40:50 | `13429478114` |

Both original reports have `partition_completed=true`, `completed=false` and
`release_claim_eligible=false`. Their source and SDK inputs match each other.
The producer report digest is
`56ae2a2ab6c4f661d8cc0b3c3c8e499ce31c9aee2a3737456424adf7602fb0cf`,
with SDK workspace identity
`75bbe6e71aadf3d3315c5708047684cbf55f782e6c1e1decf77a59e387d39f51`.
The twelve actual SDK archives, candidate archive, 1,393 source inputs and both
installed Cargo graphs were checked. The candidate has 766 members; ordinary
Swift packages have 294 members. Both Rust and C graphs use nine SDK packages
and one candidate from the outside-checkout installation. Forty-six source
inputs change and eight are added between this cohort and the current recorded
`5678d101` inputs; older artifacts are not relabeled as that candidate.

## Checked Swift and Apple boundaries

The original Swift compiler is Apple Swift 6.1.2, targeting arm64 macOS 15.
Each ordinary profile's original unit-test streams pass the unchanged exact
78-name reader. Each job also rebuilds the same installed C engine with actual
Rust/Cargo 1.90.0 in Debug and runs those 78 Swift tests again, plus seven named
native root-controller tests. Those seven are a focused filtered native lane,
not a full minimum-Rust library run. Repetition across profiles and compiler
lanes does not create additional distinct test names.

The ordinary and minimum Swift archives were re-extracted through the original
archive validator. Actual packaged native dylib bytes match the report hashes
and the C engine identity. The ordinary dylibs have arm64 Mach-O dylib headers;
the shipped Swift sources and header bind to the pinned source and manifests.
The supplementary [interface reread](INTERFACE_READBACK.json) compares all 73
Swift fixture source files and the C header in each of the four ordinary/minimum
packages directly with `INPUTS.zip`; its source-only reader is retained beside
the result.

Each job separately builds the Apple binary package's three **Release** static
libraries: arm64 macOS, arm64 iOS device and arm64 iOS simulator. Both actual
Apple archives were re-extracted and checked with the original package,
XCFramework, header, module-map and license validators. The local `llvm-nm`
executable has exactly the original tool's SHA-256. Running it on all six
retained static archives confirms each target's exact 158 owner exports.
The profile named Debug does not imply that these Apple static libraries were
built in Debug.

The original macOS binary-consumer execution has the exact expected owner-probe
marker and empty stderr. iOS and simulator consumer builds and arm64 selection
receipts are retained and checked. `physical_device_execution=false` and
`simulator_execution=false` remain explicit: these are build/link observations,
not device or simulator execution. The retained iOS x86_64 simulator packaging
requirement is not covered by these three arm64 slices.

Standalone Swift clients, Apple consumer executables and root harness/peer
executables are absent from both the top-level artifact and retained nested
packages. Their original execution fingerprints remain receipts. Actual native
engine dylibs and the three Apple static libraries are present and byte-verified;
absence of the standalone executable bytes is not hidden by that distinction.

## Independent public reread

For each profile, the original readers reproduce 17 result groups exactly:
Swift client, server, closure recovery, original-session restoration, opening
restoration, complete-account owner, opening/signed-TCP/mutual-TLS Witness
paths, four ordinary root routes and four minimum-Rust Swift root routes.
Root replay preserves actual worker-stack observations, final ARC revocation,
original approvals, cleanup and bidirectional traffic after rekey.

The original OpenSSL server, client and rejection readers also match each C
profile's retained records. Server traces retain exactly 146 exchanges; the
independent TLS client retains its separate two-exchange meaning. These are
independent TLS peers with the shared native Witness engine, on one host.

All rereads run through the pinned source's isolated Python dispatcher; 48
loaded reader modules are recorded. No native Swift or protocol workload is
rerun. The other exported lifecycle/fault groups retain their original job
reports and bytes in the full downloaded artifacts; they are not represented
here as independently replayed by this new reader.

## Historical publication retention omission

Both original publication execution reports say completed and name 85 public
readbacks. Neither artifact contains `swift-publication-public`. Forty expected
file digests in each profile are absent even after scanning all exported members
and the nested ordinary Swift, minimum Swift, Apple and candidate crate packages.
The other matching digests include common/empty files and do not restore the
missing publication directory. See [PUBLICATION_RETENTION_GAP.json](PUBLICATION_RETENTION_GAP.json).

The original `232ace` workflow omitted C, Swift and Kotlin publication upload
patterns. Existing commit `d2c951f03` adds them to the actual six-partition
foreign matrix and the relevant Rust/C job. This fix is in the current local
branch, awaiting the next permitted CI wave. This is an evidence-retention gap
under P1 and the installed-lifecycle contract, not an observed publication
runtime failure or an added platform requirement. Closing it requires applicable
complete public exports and their original reader; hashes alone do not replace
missing bytes. The historical artifacts are not rewritten.

## Retained evidence

The original ZIPs match GitHub's exact sizes and SHA-256 values and pass full
CRC checks: Debug 156,178,389 bytes/36,843 members; Release 155,304,653 bytes/37,219
members. Their complete local files remain preserved at the paths recorded in
[CAPTURE.json](CAPTURE.json), including groups outside this selected reread.

Decoded-log retrieval through the connector failed twice with `Transport closed`.
The CLI's first attempt refused ANSI control sequences. Its documented per-call
output option then saved complete raw logs directly to files, without rendering
those control sequences or changing a global setting. Both refusals and raw
logs are retained; neither was a retry or change to the CI job.

| Capsule | Members | Bytes | SHA-256 |
| --- | ---: | ---: | --- |
| `INPUTS.zip` | 1,417 | 10,568,952 | `9a46fb9d761588cb6da670168d140838a94a17a222608a05aac54447c8e119cd` |
| `DEBUG.zip` | 16,471 | 94,535,304 | `c65971c8741a5bb1255e22786d62f203164ab5a39abea537af6fe93fb08e0198` |
| `RELEASE.zip` | 16,831 | 93,622,102 | `30ad349788ad0f4de652bddd62afb6a9f56d8f4467ea1c40d24a8b965d54229e` |

Every captured member was reread against its corresponding `*_FILES.json`.
The capsules retain actual packages, the selected public directories, complete
job logs, source and checker inputs, SDK producer and independent results.
They do not export private runtime state or substitute for current-source,
cross-host, device, main-proof, external-review or release acceptance.
