# Frozen X25519 table experiment

`manifest.json` hashes the retained text and raw samples; `summary.json` records
all block-level quantiles. `block-*.stdout` contains every measured nanosecond.
No block or failed setup attempt is removed. The archived `*.txt` files are
literal build inputs and the machine-specific controller used for this capture;
they are evidence snapshots, not an additional maintained workspace crate.

To reconstruct the probe, create a directory outside the product checkout,
restore `Cargo.toml.txt` and `Cargo.lock.txt` without their `.txt` suffix, put
`probe.rs.txt` at `src/main.rs`, and copy `fixtures/`. Obtain the seven baseline
Cargo archives identified by name and SHA-256 in `summary.json`, verify each
hash, and extract each under `packages/` with its original versioned directory.
The source commit by itself does not substitute for those artifact identities.

Use Rust 1.98.1 and the recorded lockfile. Build with
`cargo build --release --locked`, copy the executable aside, then build with
`cargo build --release --locked --features precomputed` and save that executable
separately. Record both feature graphs and executable hashes. After all builds
finish, run each executable with the single argument `1000` in five fresh
process blocks, alternating baseline/candidate and candidate/baseline order.
The probe performs its own warmups and functional checks. Verify the nine JSON
lines per process, the fixed seven-cell order, all sample counts and completion
records before computing nearest-rank quantiles as in the frozen controller.

The capture used exact archive-derived local patches rather than a registry
publication. Host load/power were uncontrolled. These files establish a bounded
local comparison, not all-platform performance, controlled tails, energy,
constant time or release readiness. The `context_rejections` field in raw output
means a changed context produced a different secret, not an API error.
