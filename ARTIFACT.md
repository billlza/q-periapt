# Artifact evaluation guide

This artifact backs the paper's claims in three layers, ordered by cost and dependency weight. A
reviewer with only Rust installed can run **Tier 1** in ~10 minutes; **Tier 2** reproduces the CI
gates in ~1 hour given a few extra toolchains; **Tier 3** reproduces the hardware-dependent
measurements (network shaping, binary constant-time) and needs specific hosts.

This artifact evaluates the implemented hybrid-KEM, policy, bindings, four-flight
demo handshake, and evidence chain. It does **not** evaluate a Q-Periapt Continuity
protocol: there is no account/device directory, prekey service, wire protocol,
persistent ratchet, multi-device manager, recovery adapter, or stateful protocol
implementation in this repository. A separate `publish = false` lifecycle model has
31 lifecycle integration tests, 12 canonical-context tests, eight strict canonical
prekey-selection tests, and one private receipt-atomicity regression. It retains trusted pairwise session/current-context
admission across reconstruction, exact version+digest state advances, and a candidate
structured `LifecycleContextV1` plus a strict non-production `PrekeySelectionV1`
record; operation and storage payloads remain opaque. The
model is not part of the paper artifact tiers and contains no real crypto or deployed
session bytes. Its trusted genesis is not credential authentication, and it has no
context-advance API.
Its provider completions, repository/anchor outcomes, receipts, and durability
boundary are abstract trusted-adapter contracts; it does not prove provider-policy
authorization, downgrade resistance, or host fsync-before-effect ordering. The research plan and
model boundary are in
[`docs/CONTINUITY_RESEARCH.md`](docs/CONTINUITY_RESEARCH.md); no existing pass marker
may be interpreted as a PQ3/Signal-parity claim.

All commands run from the repository root. `cargo` ≥ 1.85 is the only hard prerequisite for the
host smoke; proof/release Python gates additionally require CPython ≥ 3.11. The hardened launcher
uses fixed platform paths or an explicit absolute `QPERIAPT_PYTHON`, never a PATH fallback.

## Quick start — one command

```sh
sh artifact/smoke.sh
sh artifact/proof-to-byte.sh
QPERIAPT_SKIP_SMOKE=1 QPERIAPT_RUN_CONTINUITY_DIAGNOSTIC=1 sh artifact/proof-to-byte.sh
```

The third command is an explicitly scoped, non-release Continuity diagnostic. It
checks the test-only Rust model, independent Python Lifecycle and strict Prekey
encoders/decoders plus full-byte vectors, isolation rules, and both separate EasyCrypt
projection/omission developments. Its pass marker does not
enter the ABI 2 release-attestation state machine.

Runs the minimal closed loop (core tests, shared/reference vectors, the C-ABI face + a real C
link-and-run, the WASM face's shared vector on the host, a real loopback TLS 1.3 handshake over the
hybrid group, and the EasyCrypt no-`admit` gate) and prints `ALL PASS` (exit 0). Needs a Rust
toolchain and a C compiler — no Docker, wasm-pack, Node, or device hardware.
`proof-to-byte.sh` additionally validates the selected hashes in
[`artifact/results.json`](artifact/results.json), verifies the claim ledger and canonical
source-input digest, then runs the same host smoke unless `QPERIAPT_SKIP_SMOKE=1` is set. That
digest covers tracked plus ignored and visible untracked canonical source inputs under a fixed,
verifier-owned ephemeral-output policy, except the two named generated evidence files,
`artifact/results.json` and `paper/camera-ready-results.txt`. Worktree `.gitignore`,
`.git/info/exclude`, and `core.excludesFile` cannot remove an input; any untracked `.gitignore`
outside a fixed ephemeral-output prefix fails closed. The transcript is
bound by its exact named hash in the manifest. When Apple-device, Apple-matrix, or performance
evidence is required, the verifier also requires the actually selected proof path and SHA-256 to
equal the corresponding `artifact/results.json` fields; an environment override cannot silently
select another same-source proof. `artifact/evidence_io.py` strict-loads one bounded regular-file
snapshot, and the Apple/performance verifier uses those same bytes for the manifest SHA-256 check
and semantic validation. Duplicate keys, non-finite JSON, symlinks, oversized files, and ordinary
read-time mutation fail closed; one startup results-manifest digest is pinned across subprocess
gates. Apple verification snapshots its logs, profile, entitlements, linkage report, executable,
and static library once each before using the same bytes for semantics and SHA-256. Clean-state
classification uses a fixed `/usr/bin/git`, an explicit repository, and a minimal environment;
it rejects `assume-unchanged`/`skip-worktree`, compares HEAD with the index and actual tracked
bytes/executable modes, and detects untracked inputs without trusting Git's stat cache or exclude
configuration. Every live-worktree proof/package/device entrypoint also dispatches Python through
`artifact/python-env.sh` and `artifact/python_bootstrap.py`: isolated/no-site startup, a fresh
private bytecode-cache prefix, no writes, cleared `PYTHON*` state, standard-library-first import
order, and repository-only script execution. Repository `.pyc`/`.pyo` files fail provenance even
when ignored. This blocks adjacent forged bytecode and user-site/`.pth` startup injection; it does
not attest the interpreter, standard library, dynamic libraries, OS, or privileged host. The
camera-ready lane is separate: it uses fixed `/usr/bin/python3 -I -S` from its root-owned,
read-only Git archive. The canonical digest is a source-input commitment after fixed generated
prefixes are removed, not a hermetic proof that no build ever reads those prefixes; release-grade
source-to-binary closure still requires an isolated checkout and fresh per-lane output roots. The
manifest root itself is intentionally outside the
non-self-referential digest and **must** be bound by clean committed/signed release provenance
before attestation. A clean proof may be captured at parent commit `P` and selected by a clean
successor `H` only when `P` is an ancestor, `P..H` changes exclusively the two named generated
evidence roots, and the canonical source digest remains equal; this breaks the manifest/proof
self-reference without weakening source binding. The finalizer enforces that
`provenance.snapshot_commit` names `P` (or the exact current commit when there is no successor),
and strictly derives the three `footprint_bytes` entries from the canonical
`paper/footprint.csv`; both checks are repeated around domain verification. A dirty diagnostic has
consistency evidence, not an immutable root.
Manifest-only validation requires any promotional local-current status to carry a canonical
selected-proof path, SHA-256, expected schema, matching canonical source digest, generation time,
and pass summary. It deliberately does not claim the locally referenced target/device file is
portable or present in a fresh checkout; only the required Apple/performance domain verifier loads
that proof and its auxiliary artifacts, checks freshness, and may emit the scoped domain marker.
The legacy JSON field `proof_source_tree_sha256`, transcript label `source-tree-sha256`, and
`CLAIM_LEDGER_AND_SOURCE_TREE_PASS` marker are retained for schema/tool compatibility; each denotes
this exclusions-aware canonical **source-input** digest, not an unfiltered Git tree hash or a
hermetic build-input closure.
The Apple manifest keys named `current_dirty_*` and the
`current_dirty_diagnostic_pass` status are also legacy field names. The selected proof's
`source_tree_dirty` value is authoritative; clean-tree single-device evidence may occupy those
fields until a deliberate manifest-schema migration renames them atomically.

The proof wrapper deliberately has no generic `PROOF_TO_BYTE_PASS` marker. It emits separate
markers for manifest/source validation, Tier-1 host execution, formal machine-checking, Apple
single-device or matrix evidence, Android runtime evidence, matched-backend host performance, and
an optional producer-origin camera-ready capture bundle.
Only a clean-tree run that requires host smoke + all formal tools + the iPad/iPhone matrix + a
fresh controlled-host performance budget + a warning-denied dependency audit may emit the
explicitly local Apple/core-scoped `PROOF_TO_BYTE_APPLE_LOCAL_CANDIDATE_PASS`; otherwise the final line is a
scoped `PROOF_TO_BYTE_RUN_FINISHED ...` summary (or `PROOF_TO_BYTE_RELEASE_NOT_ATTESTED` for a dirty
diagnostic run). Android runtime remains an independently gated proof until its physical-vs-emulator
release policy is decided; no distribution, notarization, or generic all-platform release marker
exists. The local-candidate marker does not accept an Apple Development profile as distribution
provenance. Neither a package build nor historical device evidence is promoted to current release
proof.
The wrapper freezes the exact starting commit, canonical source digest, manifest digest, and dirty
state before any domain gate. Its finalizer rechecks those values in one fail-closed Python boundary
and includes the three identifiers in the final marker. A persistent commit or source transition
observed by the final recheck fails; a later merely clean `git status` observation cannot promote
it. This does not make the working tree immutable: a same-UID replace-and-restore between samples
remains outside detection and requires an isolated read-only checkout or a signed or
transparency-backed source root.
The final marker is only a terminal summary inside a successfully completed
`artifact/proof-to-byte.sh` transcript whose exit status and preceding gate output are retained. It
is not signed or independently verifiable, and a detached or copied marker line is not evidence.

The Tamarin and ProVerif gates cover the current four-flight server-authenticated
handshake only. They do not cover PQXDH, SPQR/Triple Ratchet, ML-KEM Braid, Sesame,
crash consistency, or recovery. Likewise, proof-to-byte binds claims and execution
evidence but is not a formal spec-to-Rust refinement; Signal's public SPQR baseline
reports separate hax/F* implementation checks that this artifact does not yet match.

Set `QPERIAPT_REQUIRE_DEPENDENCY_AUDIT=1` together with the other release requirements to execute
`cargo audit --deny warnings`. Omitting that flag leaves the run scoped and cannot emit the release
marker. The research-alpha release graph now uses the portable-only `q-periapt-mlkem-native-sys`
boundary over vendored `mlkem-native` v1.2.0, plus pinned `fips204` 0.4.6 and
`sha3` 0.10.9. This removes both the `fips203` path that failed the project binary-CT
gate and the earlier `libcrux`/hax/`proc-macro-error2` advisory path. The current
lockfile passes `cargo audit --deny warnings` with no advisory ignore. RustSec covers
the resolved Rust package graph only; it does not inspect vendored C, compiler output,
side channels, license correctness, or provenance. This closes only the Rust
dependency-advisory gate, not a third-party cryptographic, C/FFI, side-channel,
implementation, or ABI audit.
The vendored trust anchors are upstream commit
`0ba906cb14b1c241476134d7403a811b382ca498` and the immutable GitHub commit
archive SHA-256
`f1975616b99c86819fb959803b090370d206d2b5fc9639146b79ce846864d677`.
The supplemental canonical `git archive --format=tar HEAD mlkem` SHA-256 is
`77603845ef1bc00cfed17635d4d6844bbf2019b656a3baea8ab18041daa74396`.
The upstream tag/commit is not a signed provenance statement, and neither upstream
mlkem-native nor this Rust/C integration has completed an independent audit.

ABI 2 / `0.1.0-alpha.1` is a release-ready research-alpha source line intended
for coordinated Rust-crate publication, with a frozen exact-nine dynamic `q_periapt_*` export
contract. The static archive constrains that reserved public namespace but retains
unsupported hidden `qpn_mlkem_bridge_*` link symbols; hidden visibility is not
access control, and a same-process static consumer can deliberately call them. It removes
raw/deterministic public product exports, uses OS randomness, major-isolates the
binary/package identities, and rejects ABI1's four-byte state. This publication does
not include or attest current C archives, XCFrameworks, AARs, or device binaries. A
proof-to-byte pass does not by itself authorize production promotion or platform-binary
distribution: every claimed platform package/index, dependency audit, clean signed or
transparency-backed provenance, and fresh same-source device/performance proof must
still pass. ABI1 needs explicit authorized
re-enrollment/reset; a version alone cannot be converted into an exact-policy digest.
The noncanonical Continuity research snapshot shape is unrelated and never a release substitute.
The backend/source migration changed the canonical source-input digest. Consequently,
the later clean-tree Apple schema-3 matrix, controlled-host matched-backend proof,
package artifacts, and `libcrux` binary-CT captures are all historical even if they
passed on their recorded source. Each release-scoped package/device/performance/CT lane
must be rebuilt or re-collected against the new digest. Time-varying currentness is
authoritative only through `artifact/results.json` plus the required live domain
verifiers; source prose cannot promote an old proof after a source change. Even fresh
local product-execution and single-host results will not substitute for independent
signed release provenance, device-energy evidence, or cross-implementation performance parity.

The expected per-step counts, toolchain, current-source local footprint sizes, and data-file pointers are pinned in
[`artifact/results.json`](artifact/results.json) (every value measured, so drift is visible). A
frozen historical capture is in [`artifact/ci-snapshot.log`](artifact/ci-snapshot.log); it is useful
for provenance, but the current clean gate is the live command output, not that historical log.

---

## Tier 1 — 10-minute host smoke (Rust + C compiler)

Verifies the core composition logic, host-side conformance checks, the real C link smoke, and the
no-admit proof gate. No Docker, symbolic prover, Node, or device hardware is required.

```sh
cargo test --workspace            # KATs, ACVP, differential, proptests, FFI/WASM host vectors
cargo fmt --all --check           # formatting gate
! grep -rnEw 'admit|sorry' --include='*.ec' formal/easycrypt/  # complete EasyCrypt tokens only
```

Expected: all tests pass; the grep finds nothing (exit 0 via the `!`). This establishes byte-identical
KATs, NIST ACVP conformance, the independent-crate differential checks, and that the committed
EasyCrypt proof has no `admit`/`sorry`.

The dk-format separation (Theorem 1, item 5) is witnessed by a runnable example — both the
expanded-`dk` break and its seed-`dk` negative control, against the release-graph portable
`mlkem-native` backend:

```sh
cargo run -p q-periapt-backends --example binding_dk_format_witness
```

It prints, for two distinct ML-KEM public keys: over expanded-`dk` the lean (X-Wing-shaped)
combiner collides on K-PK while `ContextBound` does not; over seed-`dk` (z re-derived from a 32-byte
seed, as deployed X-Wing mandates) the attack vector is closed. The same two checks run as the
`binding_keyformat_separation` integration test under Tier 1's `cargo test`.

## Tier 2 — ~1 hour, reproduce the CI gates

Adds the optional SLH-DSA backend, the isolated HQC draft-candidate shadow gate, the
the **pinned-source EasyCrypt container check**, the language bindings, and the cross-target builds.
Extra prerequisites are in parentheses.

```sh
cargo clippy --workspace --all-targets -- -D warnings                  # lint gate
cargo test -p q-periapt-backends --features slh-dsa                    # optional SLH-DSA backend
bash research/hqc-fips207-candidate/scripts/verify.sh                  # independent publish=false HQC-v5/FIPS-207-draft gate
cargo audit --deny warnings                                            # no advisory warning or ignore is release-safe

# Pinned-source binding proof (needs Docker). Builds the exact-base/exact-EasyCrypt image and re-checks
# the proof + seven proof-dependency regression controls as a HARD gate. These controls show that
# the current scripts use named facts; they are not semantic necessity proofs. The checked
# `kctx_without_nonbottom_broken` lemma is the explicit probability-one countermodel for omitting
# `K != bottom` from the explicit-rejection context-binding game:
docker build -f formal/Dockerfile -t q-periapt-ec .
docker run --rm -v "$PWD/formal/easycrypt:/src:ro" q-periapt-ec \
    opam exec -- sh -c 'mkdir -p /tmp/ec && cp -r /src/. /tmp/ec && cd /tmp/ec && rm -f *.eco \
        && easycrypt BindingViaCR.ec && sh negative-controls.sh'

sh bindings/c/build-and-run.sh                                         # C-ABI link smoke (needs cc)
CC_wasm32_unknown_unknown=/absolute/path/to/llvm-clang \
  cargo build -p q-periapt-wasm --target wasm32-unknown-unknown        # wasm32 (needs the target)
cargo build -p q-periapt-core --target thumbv7em-none-eabihf           # no_std embedded (needs the target)
```

The WASM compiler path must be absolute and name upstream LLVM Clang with a
`wasm32` backend (`clang --print-targets` must list it); Apple Clang is rejected.
Use `$(brew --prefix llvm)/bin/clang` on macOS or `/usr/bin/clang-18` on Linux.
Pass the same environment variable to `wasm-pack test --node crates/q-periapt-wasm`.

Optional binding faces (each needs its own toolchain): `swift test --package-path bindings/swift`
(Swift); `sh artifact/android-aar.sh` (Android AAR/JNI package proof, Android SDK/NDK + Rust Android
targets); the Kotlin/Panama FFM tests (JDK ≥ 22 + gradle); `wasm-pack test --node
crates/q-periapt-wasm` (wasm-pack + Node). The full GitHub Actions workflow in
`.github/workflows/ci.yml` is the canonical list; `formal-easycrypt` is the proof hard gate. Its
base image and EasyCrypt source are immutable, but apt/opam transitive resolution is not a hermetic
or bit-reproducible closure.

### Consumer embedding readiness gate

For downstream consumers that want the current "download/build/use" contract rather than only the
paper smoke, run:

```sh
sh artifact/embedding-readiness.sh
```

This is fail-closed and warning-clean: it checks locked Cargo metadata, `cargo fmt`, warning-denied
clippy, workspace tests, optional SLH-DSA backend tests, release C-ABI build, generated-header
freshness (`cbindgen` output must match both the C and Swift vendored headers), the C link-and-run
smoke with runtime ABI/suite metadata, host C release archive proof (`artifact/c-package.sh`) through
extracted dynamic/static pkg-config and CMake consumers plus archive license/CBOM/SBOM validation,
Swift XCTest count, Swift XCFramework/binaryTarget pre-publication proof
(`artifact/swift-xcframework.sh`) through an isolated binary consumer, Android AAR/JNI packaging
proof (`artifact/android-aar.sh`) with four ABI slices, native/JNI symbol audits, dex conversion, and
an isolated Java consumer compile, Kotlin/Panama tests with explicit native library loading, WASM
Node tests, and `proof-to-byte.sh`. The Rust crate release
surface has a separate publication-contract gate,
`sh artifact/rust-publish-dry-run.sh`, which requires a clean tree by default, validates the
ten-crate publish allow/deny list, checks package file lists, applies every downstream local patch,
and runs patched `cargo publish --dry-run` for each publishable crate. It then creates fresh
isolated sys/backend archives. The sys `.crate` is inspected independently for links/special or
forbidden paths, the fixed 124-entry upstream inventory, the exact packaged 118-code-file hash
subset (excluding six upstream README files), the pinned upstream license and v1.2.0 provenance,
and a portable-only build surface. Cargo's normalized backend graph is generated
with the sys crate patched in and audited separately, so Cargo versions that discard dry-run
archives cannot skip the provider, retired-HQC/PQCrypto, inventory, license, or normalized-graph
checks. The coordinated registry order is sys, core, KEM/signature traits, backends, policy, then
the FFI/WASM/rustls leaves; the dependency-free CLI is part of the same version set. The Swift XCFramework gate also requires a clean tree by default; set
`QPERIAPT_ALLOW_DIRTY_SWIFT_XCFRAMEWORK=1` only for local diagnostics. Set
`QPERIAPT_EMBED_REQUIRE_DEVICE_MATRIX=1` plus `QPERIAPT_DEVICE_RESULT_DIR=<matrix-run-dir>` to also
require a fresh iPad+iPhone matrix proof. Set `QPERIAPT_EMBED_REQUIRE_ANDROID_RUNTIME=1` after
running `artifact/android-device-smoke.sh` to require a fresh emulator or physical-Android runtime
proof too. Passing this gate proves that the current source tree can be embedded through the
existing faces and that the host C archive is consumable after extraction. After those package gates
have produced artifacts, `sh artifact/local-release-index.sh` creates a local hash-bound index under
`target/qperiapt-local-release/<version>/<commit>/` over the C archive, Swift XCFramework zip, and
Android AAR. Release mode requires a clean tree. Set `QPERIAPT_ALLOW_DIRTY_RELEASE_INDEX=1` only for
diagnostic indexes; optional Apple/Android runtime evidence is included as sanitized proof summaries,
never as copied raw device logs or profiles. The release-ready research alpha is not a
full multi-platform binary or production release claim: Swift still needs an actual public XCFramework
URL/checksum/provenance and fresh device-matrix proof for the same source state, Android still needs
clean-tree release provenance plus CI/physical-device policy before a product-ready runtime claim,
the planned registry crates still need independently verifiable signed or transparency-backed
provenance before production promotion, and the C archive still needs multi-target publishing plus
Windows archive shape and full third-party dependency license inventory beyond the current
Cargo.lock-derived SBOM.

## Tier 3 — hardware-dependent measurements

These produce the paper's primary network table and the binary constant-time discriminator. They
  need specific hosts and privileges, and are **not** required to validate the security claims.

- **Bare-metal time-to-session (Table VI).** A quiesced bare-metal **Linux x86-64** host with
  Linux kernel 5.14+ and util-linux 2.39+ (`cgroup.kill` and recursive read-only mounts are mandatory),
  unified cgroup v2 plus `cgroup.kill`, Python 3.11+, native Valgrind, and a root-owned/non-writable Rust
  toolchain (default lookup under `/opt/qperiapt-rust/bin`, `/usr/local/bin`, then `/usr/bin`).
  Provision a locked `qperiapt-camera` system account whose primary group is not shared and whose
  shell is `nologin`/`false`; the account must own no process before capture. Also pre-populate a
  root-owned, recursively non-writable, symlink-free Cargo seed at
  `/opt/qperiapt-cargo-home` (or set `QPERIAPT_CARGO_SEED_HOME`). The seed may contain only
  `registry/cache/.../*.crate` and `registry/index/...` files: no pre-extracted `registry/src`, Git
  source, Cargo config, credential, executable, or special file is accepted. Before either build,
  the harness requires an exact one-to-one closure with every crates.io package in `Cargo.lock` and
  verifies each cached `.crate` against the lockfile checksum. Each build gets a fresh writable copy
  of that verified seed and a fresh target directory. Cargo runs `--frozen` and build scripts run in
  a separate network namespace with no host network; measured binaries run in a distinct persistent
  namespace whose only enabled interface is loopback, where the root supervisor applies and verifies
  netem. Use a pipe whose status cannot hide a script failure:

  ```sh
  mkdir -p target/camera-ready
  bash -o pipefail -c \
    'sudo env QPERIAPT_BARE_METAL_CONFIRMED=1 sh camera-ready-bare-metal.sh 2>&1 | \
       /usr/bin/tee target/camera-ready/transcript.txt'
  ```

  (~20 min). Before any untrusted build code can run, the bootstrap copies itself to a root-owned
  launcher and later proves those launcher bytes equal the clean Git archive. The root process is
  only the host-state/build supervisor. Cargo/build.rs, benchmarks, and Valgrind run under the
  dedicated locked account with groups/capabilities cleared, `no_new_privs`, a fixed tool
  environment, and a fresh cgroup v2 per command. Every cgroup has finite process, memory, and swap
  limits; any surviving descendant fails the command and is killed. The supervisor work root is the
  root-owned on-disk `/var/lib/qperiapt-camera-ready-work`, while all runner-owned Cargo homes and
  targets live on a separate 8-GiB/524,288-inode tmpfs. Each untrusted command also receives private
  mount and IPC namespaces plus bounded private `/tmp`, `/var/tmp`, `/dev/shm`, and `/run` mounts.
  The inherited host mount tree is recursively read-only; only the current protected work tree and
  those bounded private mounts are writable. This is not a host-confidentiality boundary: the
  disposable measurement host must contain no unrelated readable secrets.
  Build outputs are copied only after that cgroup is empty into root-owned non-writable measurement
  paths. Valgrind receives a separate root-owned empty HOME and working directory, so build code
  cannot inject `.valgrindrc`. The harness freezes and rechecks the commit, canonical
  canonical source archive, trusted-tool and measured-binary hashes; validates the exact netem
  delay and rejects additional loss/jitter/rate/reorder/corruption; checks tuning before and after
  every measured command; and restores host state before its sole success marker. Measurement rows
  remain compatible with `paper/camera-ready-results.txt`, while the hardened harness adds
  provenance and bundle fields absent from that historical capture. A
  virtualized or emulated host is rejected; such measurements cannot be promoted to primary data.
  This containment limits host escape and resource exhaustion from faulty dependency/build code; it
  is **not** a proof against an actively malicious Cargo dependency modifying sibling extracted
  sources or target artifacts during the same-UID Cargo invocation. The camera lane therefore
  assumes the checksum-pinned dependency closure and compiler are trusted experiment inputs. A
  hostile-dependency source-to-binary claim would require per-action sandboxing or an independent
  reproducible builder and is outside this bundle's stated boundary.
  A successful run prints `bundle-location:` and atomically publishes a root-owned run-id directory
  at `/var/lib/qperiapt-camera-ready/<run-id>/`: the clean source archive, three measured binaries,
  120-row TSV plus canonical summary JSON, build logs, all five raw Memcheck logs, tool identities,
  the lock-closed Cargo-seed manifest, baseline/10ms/25ms/final qdisc snapshots, and canonical
  before/active/after capture metadata. Reverify a fresh capture against the referenced capture
  commit and current canonical source-input tree by explicitly using that emitted run-id directory:

  ```sh
  sh artifact/python-run.sh artifact/camera_ready_proof.py verify \
    --root . \
    --transcript target/camera-ready/transcript.txt \
    --bundle /var/lib/qperiapt-camera-ready/<run-id> \
    --max-age-seconds 86400
  ```

  The verifier permits a successor commit only when its changes are confined to the two named
  generated-evidence exclusions and the canonical source-input digest is unchanged. The resulting
  `CAMERA_READY_BUNDLE_INTEGRITY_PASS` is integrity-checked producer-origin evidence, **not** an
  independent runtime attestation: hashes alone do not prevent the producer from fabricating or
  replaying an entire bundle. A TPM/signing trust anchor plus an external nonce would be required
  for that stronger claim. The committed `paper/camera-ready-results.txt` predates this hardened
  schema and is historical data, not a passing current-tree camera proof. Set
  `QPERIAPT_REQUIRE_CAMERA_READY=1` on `artifact/proof-to-byte.sh` and explicitly set
  `QPERIAPT_CAMERA_READY_BUNDLE=/var/lib/qperiapt-camera-ready/<run-id>`; the transcript continues to
  default to `target/camera-ready/transcript.txt` and may be overridden with
  `QPERIAPT_CAMERA_READY_TRANSCRIPT`. Requiring an explicit bundle path prevents an unbound
  transcript location from silently selecting a different run.
- **Source→binary constant-time discriminator (§V-A).** Valgrind/Memcheck on **x86-64 or aarch64
  Linux** (native or a Linux container; not under nested emulation). `sh ctstats/scripts/ct-gap-probe.sh`
  via Docker, or build `ct_decaps_gap` with `--features valgrind` and run under `valgrind`.
  The current harness requires the genuine-secret ŝ+z probe for every shipped
  ML-KEM-512/768/1024 wrapper to report exact zero and its synthetic planted
  secret-indexed control to report positive, so zero cannot pass vacuously. The superseded
  `fips203` 0.4.3 provider is historical failure evidence, not a pass: [CI run
  29230650107](https://github.com/billlza/q-periapt/actions/runs/29230650107) reported
  34,306 errors / 100 contexts on x86_64 and 30,464 / 70 on aarch64. Earlier `libcrux`
  captures are historical too. A fresh x86-64+aarch64 zero/zero pass for portable
  `mlkem-native`, bound to the release source digest, is required before promotion. The committed
  PQClean-HQC counts (193 on aarch64 and 22,849 on x86-64) came from the retired backend and are
  historical older-source evidence only; `ct_hqc_gap` is no longer a current release gate.
- **Symbolic provers.** `make` under `formal/tamarin/` and `formal/proverif/` (Tamarin 1.12.0 +
  Maude 3.5.1; ProVerif 2.05 via opam). The current inventories are five Tamarin lemmas and six
  exact ProVerif queries, including authenticated context agreement. CI gates their presence and
  full `make prove`; Tamarin is invoked with `--quit-on-warning`, and the ProVerif Makefile matches
  each expected result independently.
- **Apple device binding smoke.** `sh artifact/apple-device-smoke.sh` runs the macOS native Swift
  binding tests, builds the Rust `aarch64-apple-ios` staticlib, builds a host-app runner for a
  physical iPhone/iPad, installs it, and accepts only an on-device
  `QPERIAPT_DEVICE_PASS run-id=<32 hex chars>` marker plus the matching run-bound
  result file copied from the app data container and a structured single-device
  proof JSON. Proof schema v2 freezes the git commit and the claim-ledger canonical
  source-input digest before any build, then rechecks both after the device run
  and immediately before proof emission. The verifier recomputes that digest; dirty mode never
  relaxes content or commit binding. The proof also binds the run id, readable named source hashes
  including the signed-policy vector and named Rust workspace source files, worktree dirty status,
  app/staticlib hashes, Xcode build log hash,
  copied marker hash, provisioning profile
  validity, codesign entitlements, static Rust FFI linkage, and the weak AppIntents link used for
  Xcode 27 warning-clean app builds. The verifier recomputes `device_id_sha256` from the child
  `device_id`; matrix distinctness cannot be supplied as an unbound self-declared hash. Verification rejects proof inputs outside
  `artifact/device-runs` and app/staticlib paths outside `target`.
  `QPERIAPT_DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer` pins the Xcode 27 beta
  lane without changing global `xcode-select`. This lane requires local signing. Set
  `DEVELOPMENT_TEAM`, set `QPERIAPT_IOS_DEVICE_ID` when more than one physical device is connected,
  and set `QPERIAPT_ALLOW_PROVISIONING_UPDATES=1` only when automatic profile changes are intended;
  otherwise the lane fails closed rather than falling back to a simulator. By default,
  `artifact/proof-to-byte.sh` does not require local signing hardware; set
  `QPERIAPT_REQUIRE_APPLE_DEVICE=1` on `artifact/proof-to-byte.sh` to require and re-verify the
  single-device proof; stale evidence is rejected after `QPERIAPT_DEVICE_PROOF_MAX_AGE_SECONDS`
  (default: 86400). Release verification fixes this value to 86400 seconds and requires the
  proof's profile policy to demand at least 30 valid days; wider thresholds are diagnostic-only.
  The capture freezes the app executable and Rust static-library hashes before installation,
  strictly verifies the app signature, and rechecks both hashes after the run-bound marker returns
  from the app-private container and again during proof emission. This binds persistent local
  artifacts to the installation window; it is not on-device binary attestation. Raw local evidence
  uses a private umask and is never part of a publishable package or release index.
  For iPhone+iPad family coverage, use the matrix lane:
  `QPERIAPT_IOS_DEVICE_MATRIX='ipad:<ipad-udid>,iphone:<iphone-udid>' sh artifact/apple-device-matrix.sh`.
  The matrix lane writes one proof per device plus `apple-device-matrix-proof.json`, and
  `QPERIAPT_REQUIRE_APPLE_DEVICE_MATRIX=1 sh artifact/proof-to-byte.sh` verifies that both physical
  families are present, fresh, source-bound, and artifact-bound. Matrix schema v3 requires exactly
  canonical `ipad`/iPad and `iphone`/iPhone entries, distinct device commitments, run ids, and child
  proofs; the former device-type override has been removed. For beta/GM readiness, prefer
  `artifact/apple-device-xcode27-gate.sh`: with `QPERIAPT_IOS_DEVICE_ID` it captures and directly
  verifies the single-device proof; with `QPERIAPT_IOS_DEVICE_MATRIX` it does the same for the
  iPhone+iPad matrix. The capture deliberately stops with `promotion=pending`: select its path and
  SHA-256 in `artifact/results.json`, then run the matching required domain in
  `artifact/proof-to-byte.sh` for manifest-bound promotion.
  By default, Apple device proof requires a clean tree. Use
  `QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE=1` only to generate local diagnostic proof, and
  `QPERIAPT_ALLOW_DIRTY_APPLE_DEVICE_PROOF=1` only to reverify that diagnostic proof.
- **Android runtime binding smoke.** `sh artifact/android-device-smoke.sh` first rebuilds and audits
  the Android AAR, then creates a temporary debuggable APK that consumes the AAR on ART, installs it
  on an adb device or emulator, and accepts only a run-bound
  `QPERIAPT_ANDROID_DEVICE_PASS run-id=<32 hex chars>` marker copied from the app-private
  files directory. The ABI2 runtime checks cover metadata, exact signed-policy decision/digest,
  OS-random atomic key generation and encapsulation, context-bound roundtrip, ABI1
  legacy-state/rollback/tamper rejection, secret wipe, and boundary fail-closed behavior;
  raw combine/X-Wing/deterministic paths are forbidden exports. Proof schema v2 records hashed
  adb serial and build fingerprint only, hashes the AAR/APK/result/logcat/named inputs, and freezes
  the claim-ledger canonical source-input digest before the build. It recomputes
  that digest before proof emission, so a source change during the run fails instead of binding old
  binaries to new source. The proof is
  reverified with `QPERIAPT_REQUIRE_ANDROID_RUNTIME=1 sh artifact/proof-to-byte.sh`. By default this
  lane requires a clean tree; use `QPERIAPT_ALLOW_DIRTY_ANDROID_DEVICE=1` and
  `QPERIAPT_ALLOW_DIRTY_ANDROID_RUNTIME_PROOF=1` only for local diagnostics. To boot a local AVD,
  set `QPERIAPT_ANDROID_BOOT_AVD=1 QPERIAPT_ANDROID_AVD=<avd-name>`.
- **Matched-backend performance gate.** Collect a paired host proof with:

  ```sh
  sh artifact/python-run.sh artifact/performance_gate.py collect --root . \
    --raw target/performance/paired-profile.jsonl \
    --proof target/performance/paired-profile-proof.json
  ```

  Both profiles use the same ML-KEM-768 seed-dk +
  X25519 backend and deterministic corpus; the harness uses 5 s warm-up, 20,480 samples per
  operation/profile, and ABBA/BAAB order. Raw schema v2 records unrounded batch totals plus a strict
  per-operation iteration map: combine/encapsulate/decapsulate use 256/1/2 calls per timed sample
  for both profiles. Analysis divides total time by the authenticated iteration count. Paired
  primary percentile/bootstrap estimates use consecutive 1,024-pair blocks; nearest-rank p99
  therefore has 11 tail observations in each estimate block rather than three. Budget schema v4
  pins a minimum of 10 and also recomputes the former 256-pair estimator as a regression guard;
  every published ratio/delta limit must pass at both block scales. Separately parameterized
  stability windows use 64/256/256 pairs for
  combine/encapsulate/decapsulate. Every statistical block contains whole
  ABBA cycles and a balanced multiple of the 64-case corpus. The 5% block-median CV threshold is
  unchanged. The nine budgeted upper bounds are per-metric one-sided 95% bootstrap bounds, not a
  joint 95% family guarantee; span-5 coverage under autocorrelation has not been independently
  calibrated. The verifier
  rejects malformed/missing pairs, iteration or schema drift, invalid totals, unstable block
  medians, source/binary/budget drift, stale evidence, any uncontrolled pre-build/pre-run/post-run/
  post-analysis thermal or power observation, or any
  published ratio/absolute-delta budget failure. The verifier fixes policy to
  `artifact/performance-budgets.json`; alternate paths fail even when their bytes happen to match.
  That policy also fixes the Cargo and Rustc executable hashes, versions, and host target.
  Collection selects one same-directory matching pair before executing it, rejects repository/
  ancestor/user Cargo configuration, clears caller compiler/wrapper/loader controls, fixes system
  tool lookup, builds offline in a fresh private target, and rechecks those executables. The
  user-writable Cargo registry cache, Rust sysroot/driver, OS tools/libraries, and same-UID
  replace-and-restore races remain trusted. The verifier also trusts the local collector to have
  built the content-addressed binary it records; it does not independently rebuild it. Therefore
  this is a strengthened single-host diagnostic, not hermetic or hostile-builder attestation.
  Proof schema v4, raw schema v2, and budget schema v4 are required; older files
  fail closed and must be recollected. Shared CI runs only a short schema exercise; numeric
  decisions require controlled hardware. Reverify with
  `QPERIAPT_REQUIRE_PERFORMANCE=1 sh artifact/proof-to-byte.sh`. Dirty diagnostic collection and
  verification require the explicit `--allow-dirty` and
  `QPERIAPT_ALLOW_DIRTY_PERFORMANCE_PROOF=1` opt-ins and never qualify for release attestation.
  Process-level CPU and compositor energy are outside the authenticated performance schema. Before
  collection, observe the host without changing repository inputs; if WindowServer, MenuBarAgent,
  or another persistent process is continuously busy, defer the run. Do not kill WindowServer,
  lower budgets, or automate restart-and-retry loops until a favorable sample appears. A future
  device/host energy claim requires a separate calibrated energy lane with explicit hardware,
  duration, power, thermal, and selection-bias controls.
- **Footprint (platform-dependent).** `sh paper/footprint.sh` writes `paper/footprint.csv` for the
  host it runs on (cdylib + WASM module sizes). The committed rows are a current-source
  Darwin 27.0.0 arm64 local capture with Rust 1.96.0, `wasm-pack` 0.15.0, and
  Homebrew LLVM Clang 22.1.8: 667.8 KiB stripped C ABI, 97.7 KiB lean WASM, and
  332.6 KiB signed-policy WASM. They are platform/toolchain-specific diagnostics,
  not signed provenance or a cross-platform binary-size claim.
