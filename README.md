# Q-Periapt — PQ/T Hybrid Cryptographic Suite

[![CI](https://github.com/billlza/q-periapt/actions/workflows/ci.yml/badge.svg)](https://github.com/billlza/q-periapt/actions/workflows/ci.yml)

**Q-Periapt 0.2.0 was released on 17 November 2026.** Install the
[Rust SDK](https://crates.io/crates/q-periapt-sdk/0.2.0) in an existing Cargo project, or install the
[CLI](https://crates.io/crates/q-periapt-cli/0.2.0) to get the `qperiapt` executable.

```sh
cargo add 'q-periapt-sdk@=0.2.0'
cargo install --locked --version 0.2.0 q-periapt-cli
```

Choose a [language and installation command](https://github.com/billlza/q-periapt/blob/main/docs/SDK_GETTING_STARTED.md). The twelve Rust SDK
crates are on crates.io. Download the [Apple SDK](https://github.com/billlza/q-periapt/releases/download/v0.2.0/QPeriapt-Swift-SDK-0.2.0.zip) and [Apple Continuity 0.2.0 r1](https://github.com/billlza/q-periapt/releases/download/continuity-apple-v0.2.0-r1/QPeriaptContinuity-Apple-0.2.0-r1.zip) for Swift, or the
[platform SDKs and Continuity distributions](https://github.com/billlza/q-periapt/releases/tag/abi2-platforms-v0.2.0) for Android, JVM,
JavaScript/WASM, native libraries and persistent sessions. The
[verified release record](https://github.com/billlza/q-periapt/tree/v0.2.0-verified-cohort/release/0.2.0) identifies the published bytes and evidence.
SDK ABI 2 exposes 51 C functions. Continuity has its own `qpc-owner/1` interface.

## Release status and public evidence

Start with the [public evidence index](https://github.com/billlza/q-periapt/blob/main/docs/EVIDENCE_INDEX.md)
for direct links to released packages, installed execution, proofs, performance
results and reproduction instructions. The [changelog](https://github.com/billlza/q-periapt/blob/main/CHANGELOG.md)
records product releases and distribution revisions separately.

| Question | Public entry point |
| --- | --- |
| Which packages were published? | [Verified 0.2.0 publication](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/publication/VERIFIED_COHORT.json) and [installation guide](https://github.com/billlza/q-periapt/blob/main/docs/SDK_GETTING_STARTED.md) |
| Where are the API docs? | [SDK](https://docs.rs/q-periapt-sdk/0.2.0/q_periapt_sdk/), [core](https://docs.rs/q-periapt-core/0.2.0/q_periapt_core/), [host store](https://docs.rs/q-periapt-host-store/0.2.0/q_periapt_host_store/) and [rustls integration](https://docs.rs/q-periapt-rustls/0.2.0/q_periapt_rustls/) |
| Which native and installed paths ran? | [Selected CI](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/qualification/ci.json), [installed-language coverage](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/qualification/installed_coverage.json) and [host-store guide](https://github.com/billlza/q-periapt/blob/main/docs/SDK_HOST_STORE.md) |
| Which security statements have evidence? | [Combiner binding](https://github.com/billlza/q-periapt/blob/main/docs/BINDING_SECURITY.md), [Continuity adoption](https://github.com/billlza/q-periapt/blob/main/docs/continuity/ADOPTION_0_2.md) and [recovery manuscript/artifacts](https://github.com/billlza/q-periapt/blob/main/paper/continuity/README.md) |
| Where are the measurements? | [SDK archive comparison](https://github.com/billlza/q-periapt/blob/main/docs/SDK_X25519_TABLES.md) and [Continuity workload observations and budgets](https://github.com/billlza/q-periapt/blob/main/docs/continuity/SUPPORTED_WORKLOAD_BUDGETS_0_2.md) |

The release records bind the qualified source and exact published bytes. Some
README text inside the immutable 0.2.0 crate archives predates publication and
retains development status or repository-relative links. This maintained index
supplies the current status and working evidence routes; documentation corrections
in the source tree do not rewrite those archives or their verification receipts.

## SDK and protocol scope

The **current 0.2.0 source** selects `mlkem-native` **2.0.0**, `sha3` **0.12.0**,
`shake` **0.1.0**, and `x25519-dalek` **3.0.0** with fixed-base precomputed tables.
The tables reduce observed key-generation and encapsulation latency in the
[installed-archive Rust SDK comparison](docs/SDK_X25519_TABLES.md), with a measured
binary-size cost. This is a local observation, not a cross-platform performance
or constant-time guarantee. The [dependency policy](docs/SDK_DEPENDENCY_POLICY.md)
records the current pins; historical 0.1.5 timing and binary-CT receipts do not
qualify this dependency graph.

For JavaScript and TypeScript, install the [product npm tarball](https://github.com/billlza/q-periapt/releases/download/abi2-platforms-v0.2.0/q-periapt-sdk-wasm-0.2.0.tgz)
from GitHub Releases. The [WASM quickstart](https://github.com/billlza/q-periapt/blob/main/crates/q-periapt-sdk-wasm/PackageREADME.md)
covers Node CJS/ESM and browser ESM. The [Rust package guide](https://github.com/billlza/q-periapt/blob/main/docs/SDK_RUST_PACKAGE.md)
lists the registry packages and the command for each.

The opt-in [standard TLS entry point](docs/SDK_STANDARD_TLS.md) uses the maintained
RFC 10024 group with mutual certificate authentication. It has local independent
OpenSSL interoperability evidence. The separate [SDK connection](docs/SDK_CONNECTION.md)
adds explicit peer pins, bound application-policy confirmation and a cancellable
Swift TCP adapter. The [host policy store](docs/SDK_HOST_STORE.md) supplies
durable policy reconciliation through Rust and the supported native bindings.
[Installed SDK connection tests](docs/SDK_INSTALLED_CONNECTION.md) cover macOS
and native Linux with separate persistent stores, while the verified release
records identify the selected native package consumers. The retained cross-OS
checkpoint uses one physical Mac and its native Linux VM; independent physical-host
deployment has its own qualification scope. This standard TLS path remains
separate from the private ContextBound provider.

The [security policy](https://github.com/billlza/q-periapt/blob/main/SECURITY.md) and
[embedding guide](https://github.com/billlza/q-periapt/blob/main/docs/EMBEDDING_READINESS.md) describe the
scope of the evidence. HQC remains a separate research implementation.

**Q-Periapt** — *Q for Quantum; a periapt is an amulet worn to ward off danger* —
is a portable, `no_std` post-quantum / traditional (PQ/T) hybrid cryptographic
suite, **built side-channel-aware from the start** (with the caveats below: the
failure-path indistinguishability check is a hard CI gate; empirical timing is a
local diagnostic and is not run or gated on noisy shared CI). The name is the design: a periapt
shields its bearer from a fatal blow (in the spirit of the Chinese 玉佩, a jade
pendant said to shatter to protect its wearer). The hybrid design targets secrecy
when at least one component assumption holds; the symbolic protocol models verify
that property under their stated abstractions. Separately, EasyCrypt machine-checks
the standard K-CT/K-PK combiner claims and a self-defined context-parameterized
K-CTX syntactic extension under its collision-resistance model. K-CTX is not a node
in the published CDM lattice, and hashing context bytes does not authenticate their
protocol meaning. Binding and hybrid IND-CCA/robustness are distinct claims; neither is used as
a shortcut proof of the other. The suite is built around one dependency-free Rust core
(crate namespace `q-periapt-*`) that third-party primitive backends are injected into
through traits, and that is reused unchanged across C, WASM, Swift and Kotlin. The
scope is narrow and deliberate: this project makes no ML-KEM/ML-DSA speed claim and
no MLKEM768-X25519 combiner-cycle advantage claim —
adding more transcript binding than X-Wing means strictly *more* hashing, i.e. a
*slower* combiner, never a faster one. Its intended contributions are safe
*composition*, a
side-channel CI pipeline that re-checks the property the compiler can break,
policy-driven crypto-agility with assumption diversity (a structural capability
X-Wing's single fixed construction does not have), audit transparency, and P99
*transport* measurement done on the constraint that actually binds (bytes and
packets, not encap/decap cycles).

## Honest positioning

ML-KEM-768 is the **same standardized primitive family** used by X-Wing and the
RFC 10024 TLS `X25519MLKEM768` group. Apple PQ3 is a protocol-level baseline, not the same
construction: it uses Kyber-1024 for initial establishment and Kyber-768 for its
ongoing PQ ratchet. Signal's current public baseline is likewise no longer PQXDH
alone: its 2025 Double Ratchet revision adds SPQR/ML-KEM Braid and a Triple Ratchet
for ongoing hybrid FS/PCS. Sesame is the separate generic multi-device manager model;
composition with the newer components is an integration claim, not one published stack spec.
Q-Periapt Continuity 0.2.0 implements its separately specified accountable
bootstrap, full-hybrid epoch rekey and persistent lifecycle. Its
[adopted contract](docs/continuity/ADOPTION_0_2.md) and
[recovery analysis](paper/continuity/README.md) identify the implemented protocol
and its security statements. PQXDH/SPQR references retain their separate comparison
scope; Continuity does not claim wire compatibility with those protocols. The
primitive families alone do not establish a performance or security advantage.

The current IRTF hybrid-KEM draft-12 already specifies a `UniversalCombiner` over
both secrets, ciphertexts, public keys, and a label, so that field list is not our
novelty. Its Section 6.4.2 explicitly presents informal LEAK-BIND sketches, defers
rigorous proofs, and does not prove the potential common-seed MAL strengthening. The
narrow defensible research delta is Q-Periapt's machine-checked, field-resolved standard
MAL-BIND-K-CT/K-PK reductions, a separately scoped local K-CTX wrapper reduction,
executable countermodels, and realization evidence—not “hash everything.”
Because of that, the suite ships **two combiner profiles**
selected by policy, and is explicit about the trade between them:

| Profile | What it binds | Cost | When |
|---|---|---|---|
| **`CompatXWing`** | `ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ label` (the MLKEM768-X25519 construction now specified in CFRG `concrete-hybrid-kems-04`, identical to X-Wing) | the same one-block combiner shape; historical draft-10 bytes and the current draft's official Appendix B.2 vector (stored as the repository vector-0 fixture) are KAT-checked | Construction-compatible control profile; only admitted for a backend whose exposed key format is X-Wing-safe (today: the ML-KEM-768 seed-dk backend). Because the construction has no suite/version/context inputs, q-periapt requires their canonical absence (`[]`, `0`, `[]`) and rejects supplied values instead of silently discarding them. The CFRG document is still an Internet-Draft, not an RFC, and external endpoint/HPKE interoperability is not yet an artifact claim. |
| **`ContextBound`** | domain tag + length-prefixed *every* shared secret, ciphertext, public key, **and** an external context (transcript / suite / policy version) | strictly **slower** (more SHA3 input → more Keccak blocks); a deliberate robustness trade, **not** a speed win | default profile; expanded/imported keys, backends without a mapped C2PRI/API proof, or when maximal binding / downgrade resistance is required |

The library core keeps both profiles for comparison and KAT research. The retained
0.1.5 ABI 2 contract has nine C functions and exposes `ContextBound` operations
under a signed-policy decision, with operating-system randomness. The 0.2.0 SDK
extends that compatible contract to **51 C exports**, including owned runtime,
connection and persistent-policy operations. Its public header and retained
compatibility contract are described in the [C SDK guide](bindings/c/README.md).
Raw deterministic seed/coins, X-Wing and combiner entry points remain outside the
native product API. Continuity uses the separately versioned `qpc-owner/1` interface.

Dynamic export validation and static-link visibility have different scopes.
Unsupported implementation symbols in a static archive do not provide an access
control boundary against deliberately hostile code in the same address space;
static embedding retains the trusted-consumer assumption.

ML-KEM implementation selection is a fixed compile-time target contract. Exactly
`aarch64-apple-darwin`, `aarch64-apple-ios`, `aarch64-apple-ios-sim`,
`aarch64-unknown-linux-gnu`, and `aarch64-linux-android`, all little-endian, use
upstream AArch64 native arithmetic plus a fixed per-target FIPS 202 assembly
profile: `aarch64-apple-darwin` and `aarch64-apple-ios-sim`, whose entire
install base is FEAT_SHA3-capable Apple Silicon, pin the upstream Armv8.4-A
SHA3 x1/x2 Keccak assembly under `-march=armv8.4-a+sha3`, while the iOS device
slice, Android, and generic Linux pin the Armv8-A scalar x1 and scalar/Neon x4
paths under `-march=armv8-a+nosha3`. Every other target remains on portable C,
including x86, Windows/MSVC, Wasm, and freestanding builds. Each native cell's
profile is fixed at build time and deliberately has no runtime dispatch. This
internal backend selection does not change ABI 2, ML-KEM key/ciphertext
encodings, or the combiner wire bytes.

The `CompatXWing` profile can omit the ML-KEM ciphertext **only** because
ML-KEM-768 is C2PRI (ciphertext-second-preimage-resistant via the FO transform and
implicit rejection) **and** because X-Wing's seed-derived key format preserves that
self-binding precondition. Primitive C2PRI is necessary but not sufficient: an
expanded/imported-key backend can be C2PRI while still unsafe for the lean
X-Wing-shaped API, so `CompatXWing` requires both `Kem::C2PRI` and
`Kem::COMPAT_XWING_SAFE`. Raw expanded ML-KEM must use `ContextBound`; X25519 is
valid in X-Wing's absorbed traditional slot but is rejected
if placed in the omitted first slot. `ContextBound` hashes all fields directly. The
hashing delta between the two profiles is real and directional. Historical local
measurements found it to be a small fraction of their total encap/decap path, but no
fresh source-bound proof is selected for the current tree. The historical
Criterion harness remains useful for primitive scale, while
[`paired_profile_perf.rs`](crates/q-periapt-backends/examples/paired_profile_perf.rs)
now records two independent estimands in one process. `profile_non_regression`
gives both profiles the same ML-KEM-768 seed-dk backend, X25519 backend, keys,
coins, ciphertext corpus, and ABBA/BAAB order. Raw schema v5 records the canonical
inputs separately for each profile: `ContextBound` uses the fixed suite, policy
version, and application context, while `CompatXWing` uses their required canonical
absence (`[]`, `0`, `[]`). `implementation_improvement` measures only the ContextBound
`hybrid_core` encapsulation and decapsulation surface with the fixed ContextBound
inputs and an `expanded_fips203_2400` ML-KEM key, comparing the target-selected
native implementation against a private symbol-renamed portable C reference in
native/portable order. Both C implementations use the same
O3/PIC/macOS-11/function-and-data-section contract with per-implementation
`-march` pins (native `armv8.4-a+sha3`, portable reference `armv8-a`), and the
Rust harness is likewise O3 with thin LTO and one codegen unit under the stable
Rust/Cargo 1.96.1 producer. Before timing, the harness generates one expanded keypair, feeds the same
expanded key bytes, coins, and corpus to both implementations, and requires byte-identical
encapsulation/decapsulation outputs for all 64 deterministic corpus cases. Portable
key generation is neither invoked nor compared. It does not time the C ABI, policy
parsing, FFI copying, or OS randomness.
The portable reference
has no Cargo feature, runtime override, shipping backend, or public API. The
fail-closed [`performance_gate.py`](artifact/performance_gate.py) requires 20,480
paired samples per variant/operation, fixed 256/1/2-call timing batches, balanced
time blocks, a stable host, and the published
[`performance-budgets.json`](artifact/performance-budgets.json). Controlled
collection takes the exact sample count and warm-up only from that schema-10 budget;
the CLI cannot override either policy value.
Apple-Silicon runs are judged against one-sided 95% upper budgets: p50/p95/p99 ratios
of 1.10/1.15/1.20 and a 15 µs p95 absolute delta for encapsulation/decapsulation,
plus a 10 µs combiner p95 delta. The independently preregistered implementation gate
requires the one-sided 95% upper native/portable ratio to be at most 0.95 for primary
p50 and p95 and at most 1.0 for p99, for both registered hybrid-core operations; threshold drift or
failure blocks the proof. A run counts as current only when its bound canonical
source digest equals the verifier's live digest; source drift and uncontrolled power
or thermal state fail closed. Release verification always loads the exact repository
`artifact/performance-budgets.json`; a proof cannot select an alternate policy path.
Raw schema v5, proof schema v8, and budget schema v10 preserve the profile statistical
contract and add the separate implementation estimand. They use 1,024-pair primary
percentile-estimate blocks, so nearest-rank p99 is supported by 11 tail observations
per block instead of only three. The gate also recomputes the former 256-pair estimator
as a regression guard and applies every
published numeric limit to both block scales; changing the primary estimator therefore
cannot turn a former-scale failure green. Separately parameterized 64/256/256-pair
stability windows retain the same 5% CV limit.
The proof binds the final dual-implementation binary, portable archive and source,
raw records, fixed budget, source tree, and toolchain identity. The machine-verifiable
gate is implemented; the claim is live exactly while `artifact/results.json` selects
a fresh clean-source, controlled-host exact-sample proof for this tree, and
historical and dirty diagnostics remain non-claim evidence. Exact quantitative
results require a fresh controlled proof-schema-v8 run under budget schema v10
selected by that manifest. Even a passing implementation estimand would establish only the
registered expanded-key hybrid-core native/portable result, not complete ABI, rustls,
device, or competitor performance.
The target-selection/source migration changes the canonical source digest, so every
portable-derived device, package, performance, and binary-CT result recorded before
this migration is historical only and must be rebuilt or re-collected per selected
target before release; the verifier will not promote it.
The same policy pins the exact rustup toolchain name and target plus the Cargo,
Rustc, Xcode Clang, and Xcode `ar` executable paths and hashes, plus the canonical
macOS SDK path, version, and settings digest (and version output where the tool exposes
it). Collection selects those fixed tools, rejects
repository/ancestor/user Cargo configuration, clears caller compiler/wrapper/loader controls,
fixes system-tool lookup, and builds offline in a
fresh private target before rechecking the four executables. The user-writable Cargo registry cache,
Rust sysroot/driver, OS tools/libraries, and same-UID replace-and-restore races remain trusted; this
is a strengthened local diagnostic, not a hermetic or hostile-builder attestation.
Within `combine`, the SHA3 staging backend marks the two component shared-secret bodies and the
conservatively sensitive caller-context body for volatile erasure, while preserving the exact
X-Wing/ContextBound byte stream. It erases both inline and heap copies, safely wipes
secret-bearing old allocations before replacement, and falls back to a whole-buffer wipe for
legacy/unclassified input or invalid range metadata. Allocation/invariant failure wipes live
staging before termination. This removes the large public ciphertext/key transcript from the
erase path without weakening the previous conservative contract; it is not a new cryptographic
or full-memory-erasure claim. TLS key confirmation independently labels its own secret inputs.
Exact run values and the current freshness state live
in the proof and
[`artifact/results.json`](artifact/results.json), rather than being copied into this
source file. A passing result is a matched-backend single-host
non-regression result, not cross-device, energy, rustls end-to-end, or optimized
production-X-Wing parity. We never claim a combiner speed win.

### Scoped contributions and evidence

- **Crypto-agility + assumption diversity** — the single most defensible claim.
  A strictly parsed signed policy is authenticated, checked against persisted
  `(version, digest)` state, and resolved into one closed `ResolvedSuite`
  (suite + profile + key format + non-zero policy version). The **library**
  instantiates ML-KEM-768/1024 + X25519. Wire/suite code `3`, formerly assigned to
  the retired PQClean-HQC experiment, is a permanent fail-closed tombstone and is
  not reassigned. The HQC-v5/FIPS-207-draft shadow lane has no runtime suite or ABI identity.
  Runtime faces remain deliberately narrower: **rustls** accepts only its exact
  ML-KEM-768 + X25519/version-1 group, while the fixed **C ABI 2** product path
  accepts only a compatible ContextBound decision and rejects an L5 policy rather
  than binding false agility metadata. Raw/deterministic conformance remains private
  Rust test code and is absent from the product export allowlist. The 40-byte decision
  is still a trusted-local descriptor, not an unforgeable capability: the host must
  pin the policy verification key and isolate untrusted native code.
- **One auditable codebase across platforms** — a single Rust core means one
  shared target for CT verification, fuzzing, and differential testing under C / WASM /
  Swift / Kotlin, reducing audit and implementation-bug surface. (Note: ML-KEM and
  X25519 are deterministic standardized primitives, so *any* conformant
  implementation interops across platforms — the contribution here is a reduced audit
  surface, **not** a unique cross-platform interop capability.)
- **Side-channel CI as an assurance feature** — the failure-path indistinguishability
  / implicit-rejection check **is a hard merge gate today**
  ([`ctstats/`](ctstats/README.md): an invalid ML-KEM-768 ciphertext decapsulates
  to a deterministic, success-shaped secret, with no error-code oracle). The
  empirical dudect-style Welch t-test is a **local diagnostic**, not a shared-CI
  step (shared runners are too noisy for a stable threshold), and
  binary-level constant-time re-verification (Valgrind/Memcheck-TIMECOP) — needed
  because source-level CT does not survive the compiler (clangover, KyberSlash) — is
  now a **hard CI gate** (`constant-time` job) over the suite's own CT composition
  code (`ct_eq`/`ct_select32`/the combiner). The same x86_64+aarch64 job also runs a
  self-validating shipped-provider ML-KEM-512/768/1024 decapsulation probes that
  mark only each expanded key's ŝ + z fields and require exact zero reports. The
  superseded `fips203` 0.4.3 probe is retained as historical **failure** evidence:
  [CI run 29230650107](https://github.com/billlza/q-periapt/actions/runs/29230650107)
  reported 34,306 errors / 100 contexts on x86_64 and 30,464 / 70 on aarch64.
  Those counts do not describe the current provider. Earlier portable-`mlkem-native`
  captures also predate target selection: fresh x86_64 portable and aarch64 native
  zero/zero runs are required for the release source digest. The stable platform tag
  transaction admits only fixed, successful `Binary CT [x86_64-portable]` and
  `Binary CT [aarch64-native]` jobs from the deterministically selected exact-R
  `main`/`push` CI run, together with all six successful CodeQL language jobs. It also
  requires `refs/heads/main` to remain exactly R, selects the latest exact-R Code
  Scanning analysis for each fixed language category, requires every analysis to have
  adjudicated results, a positive rule count, and no error/warning, and requires the main-ref
  open-alert response to be empty. Bounded run/job/analysis IDs, R/S identity, relative
  workflow paths, and workflow-source digests are stored in an attested private receipt
  that is structurally
  retained by pending and verified publication receipts, but is not a public product
  asset. The completed [0.2.0 CI qualification](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/qualification/ci.json)
  records the selected source and job identities; the release contract above does
  not replace those execution records. Earlier `libcrux` logs
  are historical too. Other
  primitive paths and riscv64/wasm32 binary-CT remain **TODO**. See
  [`ctstats/README.md`](ctstats/README.md) for the honest per-cell scope.
- **Audit transparency** — a machine-checked combiner binding model is **done**
  ([`formal/easycrypt/BindingViaCR.ec`](formal/easycrypt/BindingViaCR.ec),
  CI-gated against admits). CBOM (CycloneDX crypto-bill-of-materials) + SBOM +
  migration-inventory tooling are scaffolded (see status).
- **P99 transport measured on the deployment constraint** — the scoped methodology is
  *methodology* (P99 handshake completion on emulated lossy / high-RTT links,
  where pure encap/decap microbenchmarks mis-rank designs), not the transport
  techniques themselves (IW10 budgeting, cert compression, resumption are standard
  TLS/QUIC engineering that mainstream stacks already do).

### Explicit non-claims

- **Combiner CPU speed** — more binding is strictly more hashing. `CompatXWing`
  targets byte compatibility; historical combiner-only measurements are not a
  current production parity claim. `ContextBound` is intentionally slower.
- **Primitive performance** — it wires target-selected `mlkem-native` v1.2.0 (ML-KEM), `fips204` (ML-DSA),
  RustCrypto `sha3`,
  x25519-dalek, and fips205 (SLH-DSA). The isolated RustCrypto HQC candidate is a
  shadow comparison, not a product-graph primitive. There is
  no evidence of superiority over optimized AVX2 ML-KEM or FIPS-validated AWS-LC;
  those remain required baselines. This is a composition / safety layer, not a
  demonstrated faster primitive.
- **FIPS 140-3 validation out of the box** — the pure-Rust `no_std` core is **not**
  FIPS-validated. The trait-injected backend design leaves room for a FIPS path
  (e.g. an aws-lc-rs / AWS-LC backend) later, but no such backend is wired today
  and the project makes no validation claim of its own.
- **Wire-format / standards novelty** — the construction historically specified by
  `draft-connolly-cfrg-xwing-kem-10` is now the identical MLKEM768-X25519 instance in
  CFRG `draft-irtf-cfrg-concrete-hybrid-kems-04`. The latter is still an
  Internet-Draft, not an RFC,
  while the local rustls groups remain private-use `0xFE01`/`0xFE02`. The IANA
  RFC 10024 `X25519MLKEM768` group (`0x11EC`, Recommended=Y) is only an optional
  rustls/aws-lc standard baseline, not the local wire group. RFC 10024 uses the
  RFC 9954 64-byte concatenated secret in the RFC 9846 TLS key schedule; the private
  Q-Periapt groups instead return a 32-byte custom-combiner secret and cannot be
  presented as standards-compatible endpoints.
  The separate HQC shadow tracks HQC v5 and a prospective, not-yet-public FIPS 207 draft.
  The project tracks standards; it does not set them, and an `-rc.0` implementation is
  not promoted into ABI 2.
- **Compiled-binary side-channel safety from source verification alone** —
  source-level backend verification and binary CT checks have separate scopes.
  The CBOM, CT-CI results and formal models retain their source, build and
  assumption boundaries.

### Released Continuity protocol and retained research models

[Q-Periapt Continuity 0.2.0](docs/continuity/README.md#start-an-integration)
ships a persistent session engine with its own Cargo source archive, native and
language bindings, browser distribution and reference services. The
[adopted 0.2.0 contract](docs/continuity/ADOPTION_0_2.md) selects accountable hybrid
identity signatures, the confirmed three-flight bootstrap, four-flight full-hybrid
rekeys, signed application-send allowances, exact-operation crash recovery,
required-Witness protection and complete-roster fanout under one sender store.
The [selected release qualification](https://github.com/billlza/q-periapt/tree/v0.2.0-verified-cohort/release/0.2.0/qualification)
binds installed executions and packages to their actual sources.

The [recovery manuscript and reproduction entry](paper/continuity/README.md)
connect original randomness reservations and record acquisition to the declared
message-security experiments. Its computational arguments, mechanized multi-epoch
model and native disclosure experiments retain their individual assumptions and
source identities. The [public evidence index](docs/EVIDENCE_INDEX.md) separates
these results from the combiner proof and the older four-flight demo models.

The earlier [Continuity research plan](docs/CONTINUITY_RESEARCH.md),
[non-normative lifecycle model](models/q-periapt-continuity-model/README.md) and
[encoding diagnostics](formal/easycrypt/continuity/README.md) preserve their
original component/reference questions. Their historical candidate status is not
the publication or qualification status of the released Continuity engine.

### Authenticated migration is another separate research lane

The `publish = false` [`q-periapt-migration`](models/q-periapt-migration/README.md)
model begins a layer **above** frozen ABI 2. Phase 1 remains a frozen 315-byte,
role-normalized `MigrationContextV1` application body. The V2 reference candidate now
adds typed authenticated transitions, a monotonic state/repository model, and a
role-ordered two-Finished exchange: I, responder state/witness recheck and acceptance,
durable reservation/key/cache retention before R is exposed, then initiator
verification/acceptance. Protocol role, not KEM direction, fixes that order. IPC is a
hard V2 cut with no V1 fallback; exact response retry requires a new nonce and works
only in the same process while the retained key is live. Crash/restart does not recover
that key or R. Outcome-bearing floor checks, independent vectors, and bounded
EasyCrypt/Tamarin evidence remain research evidence; the Rust ordering matches the
Tamarin target but is not a formal refinement. The `q-periapt-policy-agent` is a
separate reference service. ABI 2 remains byte-for-byte unchanged and no publishable
product crate depends on V2.

This is still research, not a deployed migration protocol. Its rollback claim assumes a
separately protected external witness; the Unix service needs real permission and pinned-
credential deployment evidence; there is no device interoperability, hostile-kernel or
same-process isolation proof, unbounded state-machine proof, or formal-to-Rust refinement.
The exact status and non-claims are in
[`docs/MIGRATION_CONTRACT_RESEARCH.md`](docs/MIGRATION_CONTRACT_RESEARCH.md), while the
frozen phase-1 bytes remain in
[`docs/migration/MIGRATION_CONTEXT_V1.md`](docs/migration/MIGRATION_CONTEXT_V1.md).

## Released 0.2.0 capability and evidence map

| Surface | Released capability | Evidence and scope |
| --- | --- | --- |
| Rust SDK | Twelve registry crates, including owned SDK and host policy store | [Package guide](docs/SDK_RUST_PACKAGE.md) and [frozen registry verification](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/publication/registry/REGISTRY_ARCHIVE_DOWNLOADS.json) |
| Native and language SDKs | SDK C ABI 2 with 51 exports; Apple, Android/JVM, JavaScript/WASM and native distributions | [Installation guide](docs/SDK_GETTING_STARTED.md); target and consumer coverage are recorded per package |
| Host policy persistence | Persist-before-activate, exclusive ownership, configured-policy reconciliation and independent online-root recovery | [Storage contract and qualification](docs/SDK_HOST_STORE.md); supported API/platform combinations are explicit |
| TLS | Standard mutual-TLS entry and separate private ContextBound research groups | [Standard TLS](docs/SDK_STANDARD_TLS.md), [SDK connection](docs/SDK_CONNECTION.md) and [installed connection evidence](docs/SDK_INSTALLED_CONNECTION.md) |
| Continuity | Confirmed bootstrap, accountable epoch rekeys, persistent recovery, Witness and account/device lifecycle | [Adoption](docs/continuity/ADOPTION_0_2.md), [packages](docs/continuity/README.md) and [installed qualification](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/qualification/installed_coverage.json) |
| Formal and computational security | Combiner binding reductions; separately scoped symbolic handshake and Continuity recovery results | [Evidence index](docs/EVIDENCE_INDEX.md) maps each statement to its proof, model and reproduction entry |
| Native conformance and side channels | KAT/differential checks and selected binary-CT CI jobs | [Selected 0.2.0 CI record](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/release/0.2.0/evidence/ci/FINAL_HOSTED_RUN.json); covered probes and targets do not imply whole-program CT |
| Performance and resources | Source-bound SDK measurements and completed Continuity reference workloads | [SDK comparison](docs/SDK_X25519_TABLES.md) and [workload budgets](docs/continuity/SUPPORTED_WORKLOAD_BUDGETS_0_2.md); hardware, denominator and sample scope are retained |

The [retained 0.1.5 overview](https://github.com/billlza/q-periapt/blob/v0.1.5-verified-cohort/README.md)
records that release's nine-function ABI, dependency versions and qualification
stages. It is historical evidence rather than the current feature matrix.

## Stable release targets and published history (ABI 2)

The current SDK and Continuity downloads are listed in the
[0.2.0 release record](https://github.com/billlza/q-periapt/tree/v0.2.0-verified-cohort/release/0.2.0). Both official GitHub release pages carry
checksums, and the Rust packages have independent crates.io checksums.

The 0.1.0 through 0.1.2 stable tags were never published.
The `v0.1.3` and `abi2-platforms-v0.1.3` releases then
published for real — the first fully published stable line, including the ten
`0.1.3` crates on crates.io — and `v0.1.4` and `abi2-platforms-v0.1.4` published in
turn on 2026-08-30, together with the ten `0.1.4` crates. Version 0.1.5 completed its GitHub and crates.io publication on 2026-09-06. Both distributions and
all ten registry packages are covered by the complete
[`v0.1.5-verified-cohort`](https://github.com/billlza/q-periapt/tree/v0.1.5-verified-cohort)
record.
The later Android/Linux maintenance distribution
[`abi2-platforms-v0.1.5-r4`](https://github.com/billlza/q-periapt/releases/tag/abi2-platforms-v0.1.5-r4)
was published on 2026-09-08. Its independent record is
[`abi2-platforms-v0.1.5-r4-verified`](https://github.com/billlza/q-periapt/tree/abi2-platforms-v0.1.5-r4-verified).
It retains library version 0.1.5 and does not replace the base Apple or registry packages.
`0.1.5` is 0.1.4's successor, not a correction
(see the 0.1.0 through 0.1.4 history in
[`artifact/stable-release-notes.md`](artifact/stable-release-notes.md)).

The 0.1.4 verified cohort is recorded at the annotated `v0.1.4-verified-cohort` tag,
not on `main`. Reopening the source line for the next version returns
`artifact/results.json` to its initial baseline, which drops the pending 0.1.4
leaves, and the receipt finalizer's release proof requires a results-only descendant
of the 0.1.4 release commit, which `main`'s tip is not. Consequently `main`'s trusted
results record no 0.1.4 publication and still carry `apple_v0_1_3` as the active
Apple selector. The published GitHub and crates.io records are immutable and
completely unaffected by this; it is a statement about where the evidence lives, not
about whether 0.1.4 shipped.

| Tag | Scope | Toolchain | Status |
|---|---|---|---|
| [`v0.2.0`](https://github.com/billlza/q-periapt/releases/tag/v0.2.0) | Signed XCFramework and complete Swift SDK | Rust 1.98.1 | Published 2026-11-17 |
| [`abi2-platforms-v0.2.0`](https://github.com/billlza/q-periapt/releases/tag/abi2-platforms-v0.2.0) | SDKs and Continuity distributions | Rust 1.98.1 | Published 2026-11-17 alongside the twelve crates.io packages |
| [`abi2-platforms-v0.1.5-r4`](https://github.com/billlza/q-periapt/releases/tag/abi2-platforms-v0.1.5-r4) | Maintained Android AAR, canonical runtime and full/minimal AGP consumer evidence, GNU/Linux x86_64+aarch64 SDK tars; library SemVer 0.1.5 | Rust 1.96.1 | Published immutable on 2026-09-08; independent record at `abi2-platforms-v0.1.5-r4-verified`; preferred 0.1.5 Android/Linux distribution |
| [`abi2-platforms-v0.1.5`](https://github.com/billlza/q-periapt/releases/tag/abi2-platforms-v0.1.5) | Android AAR (arm64-v8a/armeabi-v7a/x86/x86_64, 16 KiB pages, API 35 emulator runtime evidence), GNU/Linux x86_64+aarch64 SDK tars | Rust 1.96.1 | Published immutable on 2026-09-05; cohort verified on 2026-09-06 |
| [`v0.1.5`](https://github.com/billlza/q-periapt/releases/tag/v0.1.5) | Apple Developer ID-signed static XCFramework ZIP | Rust 1.96.1 | Published immutable on 2026-09-05; remote consumer and complete cohort verified |
| [`abi2-platforms-v0.1.4`](https://github.com/billlza/q-periapt/releases/tag/abi2-platforms-v0.1.4) | Published 2026-08-30: Android AAR (arm64-v8a/armeabi-v7a/x86/x86_64, 16 KiB pages, API 35 emulator runtime evidence), GNU/Linux x86_64+aarch64 SDK tars | Rust 1.96.1 | Published immutable stable predecessor; its verified receipt is recorded at the annotated `v0.1.4-verified-cohort` tag, not on `main` |
| [`v0.1.4`](https://github.com/billlza/q-periapt/releases/tag/v0.1.4) | Published 2026-08-30: Apple Developer ID-signed static XCFramework ZIP; the ten `0.1.4` crates are also published on crates.io | Rust 1.96.1 | Published immutable stable predecessor; its verified receipt is recorded at the annotated `v0.1.4-verified-cohort` tag, not on `main`, so `main`'s trusted results record no 0.1.4 publication |
| [`abi2-platforms-v0.1.3`](https://github.com/billlza/q-periapt/releases/tag/abi2-platforms-v0.1.3) | Published 2026-08-25 at results successor `69e64078`: Android AAR (arm64-v8a/armeabi-v7a/x86/x86_64, 16 KiB pages, API 35 emulator runtime evidence), GNU/Linux x86_64+aarch64 SDK tars | Rust 1.96.1 | Published immutable stable release, superseded by `abi2-platforms-v0.1.4`; its frozen verified receipt nevertheless remains the platform selection recorded in `main`'s trusted results |
| [`v0.1.3`](https://github.com/billlza/q-periapt/releases/tag/v0.1.3) | Published 2026-08-25 at results successor `69e64078`: Apple Developer ID-signed static XCFramework ZIP; the ten `0.1.3` crates are also published on crates.io | Rust 1.96.1 | Published immutable stable release, superseded by `v0.1.4`; its frozen verified receipt nevertheless remains the Apple selection recorded in `main`'s trusted results |
| [`abi2-platforms-v0.1.2`](https://github.com/billlza/q-periapt/tree/abi2-platforms-v0.1.2) | Tagged 2026-08-23 at results successor `533a6d63`; the tag-triggered stable platform release run built a candidate that verified successfully and produced the platform assembly plus both pending receipts, but the first end-to-end coordinated GitHub-release publication run against real GitHub could not finalize because of several first-real-publish defects in the stable release publication and observation paths, so no release was published (defects since fixed on this source line) | Rust 1.96.1 | Historical: tagged, unpublished, superseded by `abi2-platforms-v0.1.3` |
| [`v0.1.2`](https://github.com/billlza/q-periapt/tree/v0.1.2) | Tagged 2026-08-23; the 0.1.2 Apple and source publications were never finalized (no GitHub release, crates.io publication, or signed Apple distribution) | Rust 1.96.1 | Historical: tagged, unpublished, superseded by `v0.1.3` |
| [`abi2-platforms-v0.1.1`](https://github.com/billlza/q-periapt/tree/abi2-platforms-v0.1.1) | Tagged 2026-08-22 at results successor `dc3fa303`; the tag-triggered stable platform release run 32572800739 built a candidate that verified successfully and produced the platform assembly plus both pending receipts, but the coordinated GitHub-release publication could not finalize because a latent argument bug in the publication receipt IO staging helper aborted the prepare step, so no release was published (defect since fixed on this source line) | Rust 1.96.1 | Historical: tagged, unpublished, superseded by `abi2-platforms-v0.1.2` |
| [`v0.1.1`](https://github.com/billlza/q-periapt/tree/v0.1.1) | Tagged 2026-08-22; the 0.1.1 Apple and source publications were never finalized (no GitHub release, crates.io publication, or signed Apple distribution) | Rust 1.96.1 | Historical: tagged, unpublished, superseded by `v0.1.2` |
| [`abi2-platforms-v0.1.0`](https://github.com/billlza/q-periapt/tree/abi2-platforms-v0.1.0) | Tagged 2026-08-21 at results successor `c4907760`; the tag-triggered candidate build was sound, but the frozen candidate verifier pinned two Sigstore certificate-summary fields to the wrong values, so no release was published | Rust 1.96.1 | Historical: tagged, unpublished, superseded by `abi2-platforms-v0.1.1` |
| [`v0.1.0`](https://github.com/billlza/q-periapt/tree/v0.1.0) | Tagged 2026-08-21; the 0.1.0 Apple and source publications were never finalized (no GitHub release, crates.io publication, or signed Apple distribution) | Rust 1.96.1 | Historical: tagged, unpublished, superseded by `v0.1.1` |
| [`abi2-platforms-v0.1.0-alpha.2-r2`](https://github.com/billlza/q-periapt/releases/tag/abi2-platforms-v0.1.0-alpha.2-r2) | Prior Android/Linux/Windows ABI 2 distribution | Rust 1.96.1 / 1.97.0 | Published immutable predecessor |
| [`v0.1.0-alpha.2-r1`](https://github.com/billlza/q-periapt/releases/tag/v0.1.0-alpha.2-r1) | Prior Apple Developer ID-signed static XCFramework ZIP | Rust 1.96.1 | Published immutable predecessor |
| [`v0.1.0-alpha.2`](https://github.com/billlza/q-periapt/releases/tag/v0.1.0-alpha.2) | Apple XCFramework | Rust 1.96.0 | Superseded by `-r1` (historical attested evidence only) |
| [`v0.1.0-alpha.1`](https://github.com/billlza/q-periapt/releases/tag/v0.1.0-alpha.1) | Apple XCFramework research alpha | — | Historical |

For the original 0.1.5 transaction, see the
[historical release notes](artifact/stable-release-notes.md). For 0.2.0 use
the [verified tag and package manifests](https://github.com/billlza/q-periapt/tree/v0.2.0-verified-cohort/release/0.2.0) and the checksums on the
two release pages above.

## Quickstart

For an installed package, follow the [0.2.0 installation guide](https://github.com/billlza/q-periapt/blob/main/docs/SDK_GETTING_STARTED.md).
To build the matching source, use the toolchain selected by the checkout.

```sh
git clone --branch v0.2.0 https://github.com/billlza/q-periapt.git q-periapt
cd q-periapt

cargo build --workspace          # build the implemented crates
cargo test  --workspace          # unit tests + real-backend round-trips + X-Wing KAT
cargo clippy --workspace --all-targets

# Prove the security-critical core is dependency-free and builds bare-metal no_std:
rustup target add thumbv7em-none-eabihf
cargo build -p q-periapt-core --target thumbv7em-none-eabihf

# Cross-platform behavioural consistency (same code, every ISA):
rustup target add aarch64-unknown-linux-gnu riscv64gc-unknown-linux-gnu wasm32-unknown-unknown
cargo build -p q-periapt-core -p q-periapt-kem --target wasm32-unknown-unknown
```

Building `q-periapt-wasm` itself also compiles the portable C ML-KEM provider. Set
`CC_wasm32_unknown_unknown` to an **absolute path** to an upstream LLVM `clang`
whose `--print-targets` output includes `wasm32`; Apple Clang is not supported for
this target. For example, use `$(brew --prefix llvm)/bin/clang` from Homebrew LLVM
on macOS or `/usr/bin/clang-18` on Linux, then run:

```sh
CC_wasm32_unknown_unknown="$(brew --prefix llvm)/bin/clang" \
  cargo build --locked -p q-periapt-wasm --target wasm32-unknown-unknown
```

The build fails closed if the variable is missing, relative, not a regular compiler
file, identifies Apple Clang, or lacks the `wasm32` backend.

For downstream embedding readiness across the current Rust/C/Swift/Android/Kotlin/WASM faces, run
`sh artifact/embedding-readiness.sh`. It is stricter than the quickstart: it checks locked
dependencies, warning-denied clippy, generated C-header freshness, C link smoke, Swift XCTest count,
Swift XCFramework/binaryTarget pre-publication packaging through an isolated consumer, host C archive
extraction through dynamic/static pkg-config and CMake consumers, archive license texts plus
CycloneDX CBOM/SBOM, Android AAR/JNI packaging through four ABI slices and an isolated Java
consumer compile, Kotlin/Panama, WASM Node, and the proof-to-byte manifest. The
[Rust SDK package gate](docs/SDK_RUST_PACKAGE.md) exercises the twelve published
Rust packages with an external consumer. The [verified 0.2.0 release record](https://github.com/billlza/q-periapt/tree/v0.2.0-verified-cohort/release/0.2.0)
identifies the independent registry and platform checks for the distributed bytes.

The `artifact/rust-publish-contract.sh` job produces a pre-publication package-ready
report by rebuilding archives without uploading them. Uploading involves separate
checks for upload-API acceptance, crate-name ownership, publishing credentials and
server-side policy acceptance. The [verified 0.2.0 cohort](https://github.com/billlza/q-periapt/tree/v0.2.0-verified-cohort/release/0.2.0) contains
the registry receipt for all twelve public packages.

### Crate tree

```
q-periapt/
├── crates/
│   ├── q-periapt-core      # ✅ dependency-free no_std core: combiner + transcript binding + primitive traits
│   ├── q-periapt-kem       # ✅ generic hybrid-KEM composition; CompatXWing-safe backend guard
│   ├── q-periapt-sig       # ✅ signature trait surface: ML-DSA-65/87, SLH-DSA (roots/firmware/long-term)
│   ├── q-periapt-mlkem-native-sys # ✅ publishable target-selected safe boundary over pinned mlkem-native C/assembly
│   ├── q-periapt-backends  # ✅ publishable backends (mlkem-native/fips204/sha3, x25519-dalek, optional fips205)
│   ├── q-periapt-policy    # ✅ crypto-agility policy engine: TOML + signed-policy verification, no hardcoded algorithms
│   ├── q-periapt-ffi       # 🟡 ABI 2 crate; stable Apple and Android/Linux publication receipts are separately gated
│   ├── q-periapt-wasm      # 🟡 caller-randomness conformance surface; portable C ML-KEM builds for wasm32
│   ├── q-periapt-rustls    # 🟡 rustls CryptoProvider/private-use hybrid groups
│   ├── q-periapt-tls-demo  # 🟡 loopback PQ/T hybrid handshake + P99 harness
│   └── q-periapt-cli       # 🟡 migration inventory + CBOM/SBOM generator
├── models/
│   ├── q-periapt-continuity-model # 🧪 publish=false non-normative lifecycle research model
│   └── q-periapt-migration # 🧪 publish=false V1/V2 migration domain and state model
├── services/
│   └── q-periapt-policy-agent # 🧪 publish=false process-isolated migration/ABI 2 reference service
├── research/
│   └── hqc-fips207-candidate # 🧪 publish=false RustCrypto RC shadow; no ABI/suite code
├── ctstats/          # ✅ indistinguishability hard gate + binary-CT probes; dudect local diagnostic
├── docs/             # BINDING_SECURITY.md, COMBINER_SPEC.md, ARCHITECTURE.md, ...; policy/default.policy.toml
├── formal/           # ✅ EasyCrypt binding proof (pinned-source container re-check + proof-dependency controls and explicit countermodels) + Tamarin & ProVerif symbolic proofs
├── tests/            # kat/ + differential/ (X-Wing KAT currently lives in q-periapt-backends)
├── bench/  fuzz/  sbom/   # harness scaffolds (combiner bench lives in q-periapt-backends/benches/)
└── bindings/         # c/ + swift/ + kotlin/ (exercised in CI against a shared test vector)
```

All crates under `crates/`, `models/`, and `services/`, plus `ctstats`, are Cargo
workspace `members` (see `Cargo.toml`); the `research/` candidate is explicitly excluded.

### Architecture in one line

`q-periapt-core` is **dependency-free and `no_std`** (zero crypto crates) and contains
only the security-critical *composition* logic — the combiner and its binding.
Primitives (for example ML-KEM, X25519, and SHA3/SHAKE) are injected through the `Kem`,
`Xof256` (and forthcoming `Dh` / `Hash` / `Sig`) traits, so the security review surface
stays tiny and reviewable in isolation. Because primitives live in swappable
backends, the constant-time guarantee is **per-(backend, arch)**: backend
selection changes the CT posture, and each backend must carry its own independent
CT attestation. The differential testing (the whole KEM chain — ML-KEM-768, X25519,
and the full hybrid — vs independent implementations) proves *output equality*, never
CT equality.

## Integration and assurance scope

The [embedding guide](docs/EMBEDDING_READINESS.md) identifies the released
interfaces, selected platform execution and host obligations. The
[security policy](SECURITY.md) records supported publications and reporting.
The [evidence index](docs/EVIDENCE_INDEX.md) keeps protocol assumptions, model
coverage, physical-device observations, package readback and benchmark conditions
attached to the claims they support. Historical 0.1.5 observations remain at the
[verified historical source](https://github.com/billlza/q-periapt/blob/v0.1.5-verified-cohort/README.md).

## Docs

Current navigation and versioned research documents:

- [`docs/BINDING_SECURITY.md`](docs/BINDING_SECURITY.md) — **binding/committing security** (authoritative): target notion (`MAL-BIND-K-CT`/`K-PK`), construction, the machine-checked EasyCrypt reduction, honest claim vs X-Wing ✅
- [`docs/COMBINER_SPEC.md`](docs/COMBINER_SPEC.md) — combiner definition + test-vector plan ✅
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — core/backend split, trait surface ✅
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — assets, adversary, mitigations ✅
- [`docs/COMPETITIVE_ANALYSIS.md`](docs/COMPETITIVE_ANALYSIS.md) — primary-source capability/evidence boundaries for MLKEM768-X25519, PQ3, and the current Signal stack; no aggregate ranking ✅
- [`docs/EVIDENCE_INDEX.md`](docs/EVIDENCE_INDEX.md) — public release, package, proof, runtime and performance evidence with exact scope
- [`CHANGELOG.md`](CHANGELOG.md) — released changes and packaging revisions
- [`docs/continuity/ADOPTION_0_2.md`](docs/continuity/ADOPTION_0_2.md) — adopted Continuity 0.2.0 contract
- [`docs/CONTINUITY_RESEARCH.md`](docs/CONTINUITY_RESEARCH.md) — retained early component/reference research plan; the adopted contract and released engine have their own evidence
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — milestones M0–M5 and exit criteria ✅
- [`formal/easycrypt/README.md`](formal/easycrypt/README.md) — the mechanized binding proof: `BindingViaCR.ec`, scope, and how to reproduce `make check` ✅
- [`docs/policy/default.policy.toml`](docs/policy/default.policy.toml) — example agility policy ✅
- [`artifact/abi2-platform-release-notes.md`](artifact/abi2-platform-release-notes.md) — the published `abi2-platforms-v0.1.0-alpha.2-r2` scope, hardening evidence, verification commands, and explicit non-goals ✅
- [`artifact/stable-release-notes.md`](artifact/stable-release-notes.md) — the ABI 2 `0.1.5` Apple/platform transaction, hardening scope, verification commands, and explicit non-goals ✅
- [`SECURITY.md`](SECURITY.md) — supported publications and vulnerability-reporting policy ✅

## License

Apache-2.0 OR MIT, at your option. See [`LICENSE`](LICENSE), [`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt), and [`LICENSES/MIT.txt`](LICENSES/MIT.txt).
