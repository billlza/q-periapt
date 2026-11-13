# redb policy-store upgrade investigation

This is an isolated macOS ARM64 experiment at product source `2b596975`, not a
product migration API or release approval. Normal `PolicyStore::open` continues
to refuse format 2 without resetting the file. No legacy database dependency
was added to the workspace, SDK packages or public ABI.

The fixture writer uses the historical redb 2.6.3; the converter uses its 2.6.4
maintenance successor; the actual host-store reader uses the selected 4.3.0.
All database images contain only the repository's public policy-recovery test
fixture. The converter authenticates the independent fixture root/signature
and compares all five stored fields, including the exact 36-byte trusted state.
It cannot migrate arbitrary deployment state. Dependency checksums, source,
commands and raw captures are indexed by `QUALIFICATION.json` and retained in
`CAPTURES.zip`.

## Results and counterexamples

1. The current SDK refuses the original format-2 file with
   `Storage(UpgradeRequired(2))`, without changing its bytes. The legacy
   converter upgrades it and the actual current SDK opens the same signed
   policy and exact trusted state.
2. Calling the legacy converter again after the current reader has used the
   file panics. In 2.6.4, `AllocatorStateKey::from_bytes` accepts tags 0, 1 and 2;
   4.3.0 writes tags 3, 4 and 5 and treats the earlier tags as deprecated.
   File-format version 3 therefore does not imply backward readability by 2.x.
3. The successful conversion executes 39 observed write, resize and sync
   boundaries, including database destruction. Injecting an I/O error or a
   process exit on each side produces 156 cases. All 78 I/O errors were observed;
   all 78 process cuts exited with the designated code 72. Ninety interrupted
   files opened directly with the current SDK; 66 required legacy conversion
   first. All recovered the exact authenticated fixture state. All current
   `UpgradeRequired(2)` refusals left file bytes unchanged.
4. Twenty cases left mixed format slots `[2,3]`. They recovered in this
   experiment. Looking only at the primary slot or assuming a completed
   `upgrade()` call is necessary would mishandle reachable partial outcomes.
5. In 38 typed-error cases the error occurred during legacy destruction after
   `upgrade()` had returned `Ok(true)`. The instrumented probe reported failure
   because it observed the backend error; that return value alone cannot serve
   as a complete migration receipt.
6. A separate handoff prototype retains one admitted descriptor and exclusive
   whole-file lock. Its legacy adapter does not instantiate a second file
   backend or release the outer lease; after all legacy owners drop, it moves
   the same backend into the current database. The final run recovers the 156
   interrupted files and the earlier panic file: **157/157**, with **1,206/1,206**
   independently launched legacy/current lock competitors refused. Already
   current files do not enter the legacy provider. The actual `PolicyStore`
   also verifies the image after the final owner closes.
7. That successful handoff matrix did **not** establish a safe format dispatcher.
   Changing either version byte in a current file from 3 to 2 made the current
   reader return `UpgradeRequired(2)`, then made the original handoff prototype
   panic in the old bitmap or allocator parser. Both corrupt files stayed
   byte-identical, but neither was a valid old-format migration input.
8. The revised prototype verifies both complete commit-slot checksums before
   interpreting their versions. On paired identical inputs, the old prototype
   exits 101; the revised one exits 1 with `slot checksum mismatch before
   provider dispatch`, without changing the file. The 157-case matrix still
   passes. These checksums detect corruption; they do **not** authenticate
   provenance or stop an attacker who can recompute them.

The slot layout and checksum coverage were checked against the
[pinned upstream header implementation](https://github.com/cberner/redb/blob/v2.6.4/src/tree_store/page_store/header.rs).
The checksum probe uses twox-hash 2.1.4's XXH3-128 with seed zero; matching all
legacy/current database-generated slots is independent of its own encoder.

## Reproduction and retained failures

Unpack `CAPTURES.zip` into a fresh `target/storage-format-upgrade-current` under
the recorded product checkout. The three isolated Cargo manifests are separate
workspaces and refer to that checkout's SDK crates. Use the pinned Rust 1.98.1
compiler, a private Cargo home and `RUSTFLAGS='-D warnings'`; build each manifest
with `--locked`, placing output in the experiment's `build` directory. The
original format-2 and current-format public fixture files are included.

`run_matrix.py NEW_OUTPUT` enumerates the recorded 39 baseline events and uses
fresh private copies for every cut. `run_lease_matrix.py NEW_OUTPUT` replays
those retained interrupted files through the handoff prototype. Reconstruct
the old bridge from `bridge-before-checksum.zip` in a separate checkout to
build `policy-store-lease-probe-without-checksum`; retain its executable mode.
`run_corrupt_dispatch.py NEW_OUTPUT` then runs the paired old/new counterexample.
Never run these fixture-only programs against deployment storage.

The initial path-dependency build failed on unmodified upstream lifetime
syntax warnings. Subsequent probes used separate pinned registry dependencies;
no upstream source or lint allowance was patched. The first extracted probe
also failed on an owned unused helper, corrected by recording its image digest.
`control-01` terminated on its unexpected legacy retry panic; its raw streams
remain. `build-bridge-02` accidentally re-resolved several transitive patches;
its results are retained as a separate closure. `build-bridge-03` restored the
original bridge lock and added only twox-hash. A comparison with the product
lock then identified libc 0.2.190 in that bridge's original closure; the final
`build-bridge-04` pins it back to the product's 0.2.189. `lease-matrix-04` and
`corrupt-dispatch-05` verify that final closure. The archived failing bridge
retains its original libc 0.2.190; its parser counterexample and the new early
checksum refusal are not a performance comparison between matched binaries.
The first paired-control harness
could not execute a copied binary because its mode was not preserved; it
failed before that subprocess ran, and the corrected attempt uses a new output.

## Product work still required

- General independently supplied trust/floor admission, complete schema
  validation, original typed I/O error retention, and bounded current-backend
  operations. The prototype's exact public-fixture comparison is not that API.
- Fault coverage for the complete owner handoff, including initial legacy open,
  read/partial-write errors, current-provider open and close, cancellation and
  result loss. The 156 cuts instrument the legacy conversion/destruction path;
  the later lease matrix replays those files rather than injecting new faults.
- A reviewed policy for corrupt slots and newer format-3 internal metadata.
  Checksum validity alone cannot guarantee an old parser accepts arbitrary
  input; malformed or adversarial database handling remains open.
- Independent Linux execution and minimum-toolchain qualification; no Intel
  Mac. No physical power-loss, hardware-flush or torn-sector claim is made.
- Continuity schemas, journal secrets, witness reconciliation, retained backups,
  rollback policy and cross-platform migration. Converting this five-field
  policy image establishes none of those properties.

The next product step should reuse the existing private-file owner and the
normal authenticated policy admission, retain the lease across provider
handoff, and expose success only after the required durable boundary. Neither
catching a parser panic nor returning success after a swallowed close error
would satisfy that contract.
