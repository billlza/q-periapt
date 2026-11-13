# Scanner filesystem boundary — 2026-10-17

The migration scanner checked path metadata before reopening the same path.
A concurrent writer could replace an admitted regular file or directory with a
symbolic link, causing the scanner to read outside the selected tree despite
its no-follow contract. Controlled interleavings reproduced both failures on
Apple Silicon. The file reader was copied byte-for-byte from source
`7434448a5f3707959c27ddc8402f2639a75cbf68`; the directory case reproduced its
metadata, enumeration and reader sequence. Both no-follow assertions failed
with exit 101 and read only a synthetic outside marker. This is a boundary
reproduction, not a timing-dependent exploit through the public command.

The fix retains directory handles and opens each child relative to its retained
parent, refusing links at open time. An opened directory remains the selected
directory after its path is renamed. A file replaced with a FIFO is opened
nonblocking and rejected as nonregular before reading. Actual content reads
remain bounded to 2 MiB and invalid UTF-8 remains an incomplete scan. Explicit
root selection is ambient authority; this is not an atomic snapshot of changing
contents or membership. The matching rules and public `scan` interface remain.

Filesystem traversal now lives in a 179-line module with separate boundary
tests. The existing library falls from 984 to 744 lines. This separation follows
the I/O boundary and does not claim a runtime speedup. `cap-std` and `cap-fs-ext`
4.0.3 provide the portable safe interface; the CLI still forbids unsafe code.
The lockfile adds twelve packages and changes no existing external version.

## Observed checks

- Rust 1.98.1: all 11 scanner tests and all 23 default CLI package tests pass,
  with zero ignored tests. The FIFO case also passes under a separate 10-second
  process limit. The replacement tests call the actual implementation at its
  metadata/use boundary; no duplicated replacement reader is tested as the fix.
- Strict all-target/all-feature Clippy, package formatting, and the library
  check on minimum Rust 1.90 pass without diagnostic allowances.
- A task-local release `cargo install --locked --offline` executes seven scan
  cases: clean, legacy finding, exact byte limit, oversized, invalid UTF-8,
  child symlink and a symlink root with a trailing separator. Exit codes
  0/2/1 and the JSON findings/errors/completeness are checked. Installed SBOM
  output exactly matches all 290 locked package identities.
- A clean standalone review checkout passes 224 tests across the six affected
  artifact/packaging modules and the actual SDK source gate. Current inventory
  is 695 Rust files and 256 proof inputs. The 190-key initial baseline and the
  249-key historical publication record retain their original shape and bytes.
- Offline dependency resolution and license copying/readback pass for Apple
  Silicon, Linux x86_64 and Windows x86_64. The Windows closure includes `winx`.
  These license checks do not constitute Windows or Linux runtime execution.

[observations.json](observations.json) records source hashes, commands, terminal
results, the review snapshot and installed executable hash. Adjacent logs retain
the successful package/lint/minimum-compiler checks and both original failures.
The earlier failed preparation and contract checks remain explicitly listed;
their complete local receipts are under
`target/continuity-codeql-9c65-terminal-20261016/` (347 and 349–357).

Native Linux/Windows checks for this implementation delta and full current-source
CI remain open. Existing protocol analysis, resource/performance, maintenance
and external-review requirements remain separate. This checkpoint neither
qualifies the entire SDK for release nor replaces the accepted physical-device
cohorts. No Intel Mac target is added.
