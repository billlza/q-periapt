# Artifact evaluation guide

This artifact backs the paper's claims in three layers, ordered by cost and dependency weight. A
reviewer with only Rust installed can run **Tier 1** in ~10 minutes; **Tier 2** reproduces the CI
gates in ~1 hour given a few extra toolchains; **Tier 3** reproduces the hardware-dependent
measurements (network shaping, binary constant-time) and needs specific hosts.

All commands run from the repository root. `cargo` ≥ 1.85 is the only hard prerequisite for Tier 1.

---

## Tier 1 — 10-minute smoke test (Rust only)

Verifies the core composition logic, the six-method conformance matrix (host side), and the
no-admit proof gate. No C toolchain, Docker, or network required.

```sh
cargo test --workspace            # ~93 tests: KATs, ACVP, differential, proptests, FFI/WASM host vectors
cargo fmt --all --check           # formatting gate
! grep -rnE 'admit|sorry' --include='*.ec' formal/easycrypt/   # no proof holes (always-on hard gate)
```

Expected: all tests pass; the grep finds nothing (exit 0 via the `!`). This establishes byte-identical
KATs, NIST ACVP conformance, the independent-crate differential checks, and that the committed
EasyCrypt proof has no `admit`/`sorry`.

## Tier 2 — ~1 hour, reproduce the CI gates

Adds the optional backends, the **hermetic EasyCrypt machine-check**, the language bindings, and the
cross-target builds. Extra prerequisites in parentheses.

```sh
RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets         # lint gate
cargo test -p q-periapt-backends --features slh-dsa,hqc                # SLH-DSA + HQC (needs a C toolchain)

# Hermetic binding proof (needs Docker). Builds a pinned EasyCrypt r2026.06 image and re-checks the
# proof + the deleted-hypothesis necessity controls as a HARD gate:
docker build -f formal/Dockerfile -t q-periapt-ec .
docker run --rm -v "$PWD/formal/easycrypt:/src:ro" q-periapt-ec \
    opam exec -- sh -c 'mkdir -p /tmp/ec && cp -r /src/. /tmp/ec && cd /tmp/ec && rm -f *.eco \
        && easycrypt BindingViaCR.ec && sh negative-controls.sh'

sh bindings/c/build-and-run.sh                                         # C-ABI link smoke (needs cc)
cargo build -p q-periapt-wasm --target wasm32-unknown-unknown          # wasm32 (needs the target)
cargo build -p q-periapt-core --target thumbv7em-none-eabihf           # no_std embedded (needs the target)
```

Optional binding faces (each needs its own toolchain): `swift test --package-path bindings/swift`
(Swift); the Kotlin/Panama FFM tests (JDK ≥ 22 + gradle); `wasm-pack test --node crates/q-periapt-wasm`
(wasm-pack + Node). The full GitHub Actions workflow in `.github/workflows/ci.yml` is the canonical
list; `formal-hermetic` is the proof hard gate.

## Tier 3 — hardware-dependent measurements

These produce the paper's primary network table and the binary constant-time discriminator. They
need specific hosts and privileges, and are **not** required to validate the security claims.

- **Bare-metal time-to-session (Table VI).** A quiesced bare-metal **Linux x86-64** host, root (for
  `tc netem` + CPU pinning), and Rust. `sudo sh camera-ready-bare-metal.sh 2>&1 | tee out.txt`
  (~20 min). Output format matches `paper/camera-ready-results.txt`. On a virtualized host the
  RTT-0 medians are noisier (the paper labels that run supporting, not primary).
- **Source→binary constant-time discriminator (§V-A).** Valgrind/Memcheck on **x86-64 or aarch64
  Linux** (native or a Linux container; not under nested emulation). `sh ctstats/scripts/ct-gap-probe.sh`
  via Docker, or build `ct_decaps_gap`/`ct_hqc_gap` with `--features valgrind` and run under
  `valgrind`. Expect ML-KEM `probe=0` vs HQC `>0` (the discrimination is the signal; raw counts are
  ISA-dependent).
- **Symbolic provers.** `make` under `formal/tamarin/` and `formal/proverif/` (Tamarin 1.10 + maude;
  ProVerif 2.05 via opam). CI presence-gates the lemmas/queries; full `make prove` is best-effort.
- **Footprint (platform-dependent).** `sh paper/footprint.sh` writes `paper/footprint.csv` for the
  host it runs on (cdylib + WASM module sizes).
