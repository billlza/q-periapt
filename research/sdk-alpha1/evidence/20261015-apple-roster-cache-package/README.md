# Current Apple package and startup boundary

Source: `9d396755c3f872d3a59932c6fe106b2b5e1b2e59`.
The roster-decoding optimization is now in a newly built and extracted Apple
candidate package. Package qualification passed; physical SDK recovery on this
delta has not passed. The preceding device results retain their original source
scope. No Intel macOS target is introduced.

## Package validation

`QPeriaptContinuity-Apple-candidate.zip` is 22,041,710 bytes, SHA-256
`5cbaba4b10e5c779a362f3bf20f09d687ed31fabce78579e95ff8ea32c4315e7`.
The producer built macOS arm64, iOS arm64 and iOS-simulator arm64 from a fresh,
outside-checkout consumer. The current candidate crate was packaged and compiled;
the nine unchanged SDK archives and all ten path-package resolutions were
verified against their retained identities and the current source. Rust 1.98.1,
locked/offline resolution, strict warnings, license inventories, architecture and
all 157 candidate owner exports were checked. This candidate export table is
separate from the product ABI 2 contract.

After extraction, the macOS consumer ran its actual native-owner probe. iOS and
simulator consumers built and their link maps selected the exact corresponding
static libraries. The iOS archive hash is
`a2b313e80919c6179492131ddc5ebe55acc64589a1f2ddda1057fe950ec0bea8`.
The simulator result is a build/link check, not simulator execution.

## Physical observations

A fresh signed app was installed on the offered iPad Pro 11-inch (M4), iPadOS
27.0.1. The first launch emitted `didFinish protected=true` and `sceneConnect`,
but no `sceneActive` or host-startup-admission marker. The existing 80-second
transport deadline stopped it; the outer case failed after 84.09 seconds.
Zero SDK operations completed and no relay exchange occurred. Owned-app removal
was verified, and this failed cohort is sealed. The lock query reported
`passcodeRequired=false` and `unlockedSinceBoot=true`; those fields do not prove
that a usable foreground scene existed. The cause remains unresolved.

A separate fresh app on the offered network-connected iPhone 16 Pro used the
same source files and exact iOS library (only the project/bundle changed).
Its cold-start control reached `sceneActive`, completed host admission, wrote a
receipt independently copied from the app container, and exited with code 0.
The owned app was removed. This control returns before any SDK protocol call
and performs no USB relay exchange; it is not session/recovery acceptance.
The iPad foreground-state request remains pending before a fresh recovery run.

## CI diagnostic observation

The [frozen-database evaluator comparison](https://github.com/billlza/q-periapt/actions/runs/38692135312)
kept all 39 exact queries and compiled plans, memory allocations and the
900-second bound; four versus one evaluator threads were compared. Both timed
out with unambiguous child cleanup. The baseline logged 38 completed results,
single-thread 35; neither finished the full `SummaryStats` query. Whole-run
logs contain 2,856 and 844 memory-eviction pauses respectively. This does not
establish the sole cause or a fix. Its retained database is older than this
source, so it is not current-source security acceptance. No query, source
inventory, security gate or timeout was weakened.

The [current-source CodeQL run](https://github.com/billlza/q-periapt/actions/runs/38692152632)
and [push CI](https://github.com/billlza/q-periapt/actions/runs/38692135318) are
separate ongoing qualifications. No new push was made while those checks ran.

## Retained evidence and limits

[CAPTURE.json](CAPTURE.json) binds all 282 public archive members to
`CAPTURE.zip` SHA-256
`5fb72a631568450da2bba971ed6bfd6b9d3422a8f9dec18de33c27670fc39dbf`.
[READBACK.json](READBACK.json) records hash, package, failed-startup and iPhone
console/container-receipt readback. The capture includes command receipts,
consumer sources, the failing iPad boundary, the successful startup control,
and evaluator summaries with raw artifact IDs/digests. The raw evaluator ZIPs
remain local; they are not embedded in this archive.

The initial evaluator reader assumed a console file existed on timeout and
failed. A fresh bounded reader instead processed the retained evaluator logs;
its final count excludes loaded-query markers. The first package-evidence
collector selected command JSON twice and stopped before creating an archive;
the corrected collector uses disjoint receipt inventories. Both failed recipes
are retained. No private journal, private key, provisioning profile or previous
runtime state was reopened or included.

This checkpoint changes no product code. Full SDK device recovery, remaining
platform/protocol qualification and the overall 0.2.0 release remain open.
The accepted single Android phone remains sufficient; its old IP plus the newly
provided port 35397 was unreachable during this attempt. A second phone or an
API 36 device is not an added requirement.
