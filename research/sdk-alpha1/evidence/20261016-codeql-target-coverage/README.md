# Rust target coverage qualification

Implementation: `5358c90db5abda29f97f71b624a6c536f2a0c3d1`.
The compiler-source collector, macro census and target validator are implemented
and tested. The production CodeQL workflow and its strict gate are unchanged;
this capture does not qualify a complete query suite or a release.

The new census preserves every macro entity, including entities sharing a source
location. The collector reads depfiles selected by the artifacts in each
successful Cargo JSON result, using that command's workspace directory. It does
not inventory stale files in a shared target directory. Source hashes must agree
across compilation and analysis profiles. A successful peer profile cannot hide
an unresolved executable macro in a source file compiled by the current profile.

All 67 existing and new checker regression tests passed in a standalone checkout.
The first attempt retained two provenance errors because the editing checkout
was a linked worktree. Those assertions were unchanged. An initial QL query used
an internal type not exported by the public library; the corrected query uses
the public path API and passed with QL warnings treated as errors.

Four actual Rust 1.98.1 compiler runs supplied source dependencies: the native
workspace, native Continuity engine with every target and feature, product browser
entry, and legacy WASM test targets. The databases use CodeQL 2.27.2 and contain
the same 693 tracked Rust sources at `6c13c486e9aa3a1ac852f2127fc4cbb30c5e63d5`.
The subsequent implementation changes do not alter those Rust files.

The native census has 27,996 macro entities and 16 unexpanded calls in browser
sources. The WASM census has 21,631 entities and 9,223 unexpanded calls: 9,210 are
covered by the compiled native profile, 11 are compiler-only export-name
attributes, and two belong to a Linux-only migration test. The validator rejects
the combined macOS/WASM repository result because the Linux-only sites still
lack the relevant profile. No source or query is removed to change that result.

A separate valid control builds both a native library and a WASM module with a
`concat!` export-name attribute. Both binaries contain the expected exported
symbol, and both CodeQL databases retain parameter-to-return taint flow. CodeQL
leaves the attribute macro unexpanded. This is a counterexample to requiring
every raw macro expansion count to be zero. The validator reports this metadata
separately. A negative control changes an executable macro to unresolved while
its peer stays expanded; the validator rejects it.

`CAPTURE.json` binds every retained member. `READBACK.json` records full CRC and
SHA-256 readback of the archive, including the real compiler control binaries.
Raw queries, compiler output, failed attempts, implementation files and test
results are included. The complete repository databases and toolchain archives
are not embedded; their identities and prerequisite receipts are retained.

Remaining work is production integration with actual Linux and WASM profiles,
followed by all pinned security-extended queries, including full SummaryStats.
The old hosted SummaryStats timeout has not been shown to be fixed by this work.
