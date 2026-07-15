# Threat Model — Q-Periapt PQ/T Hybrid Suite

> **Status: release-ready ABI 2 research alpha, pre-1.0, NOT for production deployment.**
> The intended publication surface is source plus a planned coordinated set of Rust crates and a
> separately evidenced Apple-only XCFramework research prerelease, not an attested multi-platform
> binary bundle.
> No third-party audit. The portable-only `q-periapt-mlkem-native-sys` integration
> over vendored `mlkem-native` v1.2.0, pinned `fips204` 0.4.6,
> `sha3` 0.10.9, x25519-dalek, and optional fips205 integrations are unaudited
> as this suite and ABI. This document is the
> authoritative statement of *what the design defends against and — equally
> important — what it does not.* Every guarantee below is tagged as **ENFORCED**
> (a CI gate or a compile-time/type-level invariant fails the build on regression),
> **PROVED** (machine-checked in EasyCrypt at the abstract-spec level), or
> **REPORT-ONLY / TODO** (measured or aspirational, not gated). Read the
> [§5 Out-of-scope](#5-out-of-scope--honest-caveats) section before relying on
> anything here.
>
> This is the threat model for the **implemented KEM/handshake artifact**, not for a
> future asynchronous messaging protocol. Identity directories, one-time prekey
> generation/serving/consumption, persistent ratchets, multi-device state, recovery,
> and key transparency are absent. A strict test-only prekey-selection commitment
> record does not change that product boundary.
> Their research requirements live in
> [`CONTINUITY_RESEARCH.md`](CONTINUITY_RESEARCH.md) and must not be inferred here.

Cross-references:
[`docs/BINDING_SECURITY.md`](BINDING_SECURITY.md) (the authoritative binding proof and
its honest scope),
[`formal/easycrypt/BindingViaCR.ec`](../formal/easycrypt/BindingViaCR.ec) +
[`formal/easycrypt/README.md`](../formal/easycrypt/README.md) (the mechanized proof),
[`ctstats/README.md`](../ctstats/README.md) (side-channel CI scope),
[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) (which checks gate vs report).

---

## 1. Assets

What an adversary wants and what the suite is built to protect:

| Asset | Description | Where it lives |
|-------|-------------|----------------|
| **A1 — Combined hybrid shared secret `K`** | The 32-byte output of the combiner ([`q_periapt_core::Secret`](../crates/q-periapt-core/src/lib.rs)). Compromise breaks the session that uses it as keying material. | Derived in [`q_periapt_core::combine`](../crates/q-periapt-core/src/lib.rs); transient. |
| **A2 — Long-term secret keys** | ML-KEM-768 decapsulation key, X25519 static secret, and the signing keys (ML-DSA / SLH-DSA). | Backend types in `q-periapt-backends`; held by the application. The standalone HQC shadow is not a product-key lifecycle. |
| **A3 — Component shared secrets `ss_pq`, `ss_trad`** | The per-component KEM outputs that feed the combiner. Transient, but leakage of either degrades the hybrid toward its surviving half. | Caller-provided buffers passed to [`HybridKem::encapsulate`/`decapsulate`](../crates/q-periapt-kem/src/lib.rs). |
| **A4 — Policy authenticity / integrity** | The active algorithm policy (`min_nist_level`, allowed KEMs/sigs, combiner profile). A forged or tampered policy can silently weaken the whole suite. | [`q_periapt_policy::Policy`](../crates/q-periapt-policy/src/lib.rs), loaded from `*.policy.toml`. |
| **A5 — Binding integrity of the transcript** | The guarantee that one derived `K` is reachable from exactly one tuple of `(suite_id, policy_version, every ct/pk, context)`. Compromise enables key-reuse / re-encapsulation / cross-context confusion attacks. | Established by the combiner encoding; see [§4.1](#binding-proof). |

The combiner core deliberately contains **no primitive implementations** and **no
secret-dependent error information** — its entire job is to compose A3 into A1 with
binding A5, in a way small enough to audit in isolation.

---

## 2. Adversary capabilities

We model four adversaries. They may be combined; each row states the assumed power.

| ID | Adversary | Assumed capability |
|----|-----------|--------------------|
| **ADV-MAL** | Malicious-key / binding adversary | Supplies adversarially chosen public keys **and** decapsulation keys (the **MAL** class of Cremers–Dax–Medinger). Tries to produce two encapsulation transcripts that collide on `K` while disagreeing on some `ct`, `pk`, or `context` (re-encapsulation / UKS / cross-context confusion). This is the load-bearing adversary — its venues (PQ-KEM-in-HPKE, Signal/MLS-style handshakes, PQXDH) accept attacker-supplied key material. |
| **ADV-CCA** | Chosen-ciphertext adversary | Submits arbitrary (including malformed or maliciously mutated) ciphertexts to `decapsulate` and observes any distinguishable reaction — a return code, a derived-secret relationship, or an error string. Seeks a Bleichenbacher/Manger-class **decapsulation oracle**. |
| **ADV-TIME** | Passive timing / microarchitectural side-channel | Measures wall-clock latency (and, on a quiet host, finer signals) of `decapsulate` over many calls to distinguish valid from invalid ciphertexts or to recover secret-dependent control flow. Cannot read memory directly. |
| **ADV-POLICY** | Policy-tampering / downgrade adversary | Modifies the policy file in transit or at rest, or stands in as a downgrading peer during negotiation, to push the suite below its intended NIST floor or onto a weaker combiner profile. |

**Adversary boundary (assumed honest / out of model):** the host running the code,
its RNG, the compiler/toolchain, the OS, and physical access (fault injection,
power/EM, cold-boot). See [§5](#5-out-of-scope--honest-caveats).

---

## 3. Trust base

Every in-scope guarantee rests on these assumptions; if one fails, the
corresponding guarantee fails:

- **Collision-resistance (and, for the KDF, PRF/ROM behaviour) of SHA3-256 /
  SHAKE-256.** This is the single primitive assumption under the binding proof.
- **Each selected release-graph backend correctly implements its primitive, and any
  constant-time claim is limited to the backend/ISA evidence actually checked.**
  The vendored portable `mlkem-native` ML-KEM, `fips204` ML-DSA, RustCrypto SHA3, x25519-dalek, and
  fips205 SLH-DSA integrations are
  third-party implementations and remain **unaudited for this use**. The known-leaky,
  unmaintained `pqcrypto-hqc` adapter was removed from the publishable/runtime graph.
  The standalone RustCrypto HQC-v5/FIPS-207-draft RC shadow has only its explicitly tested
  research correctness/format boundary and no constant-time or production-suitability claim.
- **The Rust/C ML-KEM boundary preserves its documented FFI preconditions.** The
  sys facade's fixed local arrays must remain initialized, correctly sized, mutually
  non-aliasing, and alive for each call; C return codes must be mapped explicitly and
  temporary output must not reach callers on failure. The portable C compiler, build
  script/configuration, value barriers, private unsafe declarations and zeroization are
  part of the TCB. Upstream CBMC/HOL-Light and dynamic CT evidence does not prove this
  wrapper or arbitrary downstream compiler output.
- **The host OS CSPRNG is sound.** The dependency-free core remains deterministic
  for KATs, while native ABI2 key generation and encapsulation call the OS CSPRNG
  internally and return explicit `ERR_ENTROPY` on failure. WASM remains a separately
  scoped caller-randomness conformance surface.
- **The policy verification key is a genuine trust anchor** (out-of-band
  provisioned), and the intended SLH-DSA root signer is honest.

---

## 4. In-scope guarantees

<a id="binding-proof"></a>
### 4.1 Provable binding to collision-resistance of SHA3 — **PROVED (abstract spec)**

Defends against: **ADV-MAL**.

The `ContextBound` combiner profile
([`Profile::ContextBound`](../crates/q-periapt-core/src/lib.rs)) hashes the **full**
component tuple under an injective, fixed-width-length-prefixed, domain-separated
encoding:

```
K = SHA3-256( Encode( DOMAIN, suite_id, policy_version,
                      ss_pq, ss_trad, ct_pq, pk_pq, ct_trad, pk_trad, context ) )
```

where `DOMAIN = b"Q-PERIAPT-HYBRID-KEM/v1"` and every field is emitted as an
8-byte big-endian length prefix followed by the field bytes
([`absorb_lp`](../crates/q-periapt-core/src/lib.rs)). Because **every** ciphertext
and public key is absorbed, binding reduces to collision-resistance of SHA3 **with
no binding assumption on ML-KEM or X25519**.

- **Machine-checked.** `bind_le_cr` in
  [`BindingViaCR.ec`](../formal/easycrypt/BindingViaCR.ec) proves a generic
  transcript-projection collision bound. Its CT/PK projections instantiate the standard
  `MAL-BIND-K-CT` and `MAL-BIND-K-PK` notions; its context projection is a self-defined,
  context-parameterized `MAL-BIND-K-CTX` syntactic extension, with **0 admits**.
  K-CTX is outside the published CDM lattice and does not inherit CDM monotonicity.
  `encode_inj` (the
  injectivity of the encoding) is now a **proved lemma**, reducing only to two
  elementary `be8` facts (8-byte fixed width + injectivity) plus CR of SHA3 — it is
  no longer an axiom.
- **CI enforcement.** A `formal-proof` job
  ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml)) hard-gates on
  `! grep -rnEw 'admit|sorry' formal/easycrypt/` (catches complete proof-hole tokens);
  `formal-easycrypt` rebuilds the pinned-base, pinned-EasyCrypt image and re-checks
  `BindingViaCR.ec` plus seven proof-dependency regression controls. Those controls
  detect changes to the current tactic dependencies; they do not prove logical
  necessity. The explicit probability-one `kctx_without_nonbottom_broken`
  countermodel is the semantic evidence that `K != bottom` is load-bearing in the
  explicit-rejection K-CTX game. Apt/opam transitive inputs are not snapshot-pinned, so this
  hard gate is not a hermetic or bit-reproducible toolchain proof.
- **Implementation mirror.** The injective encoding is exercised by a negative KAT
  in [`q-periapt-core`](../crates/q-periapt-core/src/lib.rs)
  (`injective_encoding_prevents_boundary_collision`): two tuples that would collide
  under naive concatenation are kept distinct by length prefixing. A mandatory
  non-empty `context` is enforced (`Error::InvalidLength` otherwise) as a profile-level
  guard that forces an explicit protocol/application label. Empty fields remain
  injectively encoded, so this guard is not a premise of the syntactic CR theorem.

**Honest ceiling (do not overstate):** `ContextBound` is **not** "stronger binding
than X-Wing." A correctly-implemented seed-format X-Wing attains the same
`MAL-BIND-K-CT` / `MAL-BIND-K-PK` ceiling; the X-BIND lattice has no point above
that pair on the CT/PK axes. The real edge is **assumption-minimality and proof
coverage** (binding from CR alone, in one self-contained machine-checked proof,
instead of relying on ML-KEM's FO self-binding), plus a separately scoped syntactic
commitment to exact context bytes. That wrapper is not a CDM axis and does not
authenticate context semantics. `X-BIND-CT-*` notions (a *ciphertext* binding the key) are **structurally
impossible** for an implicitly-rejecting ML-KEM-based hybrid and are **not claimed**.
See [`docs/BINDING_SECURITY.md`](BINDING_SECURITY.md) §5–§6 for the full, careful
claim. The proof is **abstract-spec level only**: H's collision-resistance is a
modeling assumption, IND-CCA2 robustness is argued on paper (not mechanized), and
there is **no spec↔implementation linkage proof**.

### 4.2 No decapsulation oracle — implicit rejection — **ENFORCED (hard CI gate)**

Defends against: **ADV-CCA**, and the return-code half of **ADV-TIME**.

The [`Kem`](../crates/q-periapt-core/src/lib.rs) trait contract requires
`decapsulate` to use **implicit rejection**: an invalid ciphertext yields a
deterministic pseudorandom secret rather than an error. The failure path is
designed to be indistinguishable from success.

- **No error oracle.** `decapsulate` does **not** return `Error` to signal an
  invalid correct-length ciphertext. Public input conditions — buffer-length
  mismatches, invalid peer key shares, and policy denials — are classifiable.
  Local decapsulation-key/provider/internal failures are reported only as the
  opaque `Backend` class.
  `q_periapt_core::Error` is non-exhaustive and currently includes
  `InvalidLength`, `Backend`, `InvalidKeyShare`, and `PolicyDenied`. By
  construction none encodes whether or why an FO-KEM ciphertext was invalid.
- **Public invalid input is distinguishable; local failure detail is not.** This is
  the deliberate boundary of the coarse `Error` type
  ([`q-periapt-core`](../crates/q-periapt-core/src/lib.rs) "Security notes").
  `InvalidKeyShare` may identify a noncanonical ML-KEM peer encapsulation key or a
  low-order/non-contributory X25519 peer share. In contrast, malformed local
  expanded decapsulation-key material and provider failures propagate as opaque
  `Backend`; native FFI maps that to `ERR_INTERNAL`, and rustls treats it as a
  generic local TLS failure rather than blaming the peer.
- **CI hard gate.** `cargo test -p q-periapt-ctstats` is a **merge-blocking** gate.
  `mlkem_implicit_rejection_no_error_oracle` asserts that decapsulating a corrupted
  ML-KEM-768 ciphertext (a) returns `Ok` (no oracle), (b) yields a secret different
  from the valid one, and (c) is deterministic across repeats.
  `hybrid_decaps_no_error_on_invalid_ct` asserts the same for the full hybrid
  decapsulation. See [`ctstats/src/lib.rs`](../ctstats/src/lib.rs) and the
  `sidechannel` job in CI.
- **Constant-time selection primitive.**
  [`ct_select32`](../crates/q-periapt-core/src/lib.rs) is the branch-free
  primitive intended for implicit rejection: always compute both the real and the
  rejection derivation, then select with a mask so the failure path is
  instruction-indistinguishable. [`ct_eq`](../crates/q-periapt-core/src/lib.rs)
  is constant-time over equal-length inputs (lengths are treated as public). These
  helpers are best-effort in portable Rust — see the timing caveat in §4.2's
  local-diagnostic counterpart, [§5.1](#51-empirical-timing-is-a-local-diagnostic-not-gated).

### 4.3 Downgrade protection — NIST floor + signed policy, fail-closed — **ENFORCED (type/logic + unit-gated)**

Defends against: **ADV-POLICY**.

Three linked mechanisms, all fail-closed at the signed-policy execution boundary:

- **Validated floor and closed suites.** `Policy::try_new` / `from_toml` reject zero
  versions, invalid NIST floors, unknown/duplicate identifiers, unknown TOML fields,
  and unsatisfiable documents. `meets_floor`, `kem_allowed`, and `sig_allowed` reject
  below-floor or deprecated algorithms. `resolve_suite` then intersects the policy
  with concrete locally implemented [`HybridSuite`](../crates/q-periapt-policy/src/lib.rs)
  variants and returns one private-field `ResolvedSuite` containing suite, profile,
  key format, and policy version. If no complete local suite satisfies the document,
  resolution fails; an L5 document is never mapped onto the fixed L3 runtime. Retired
  suite code `3` is a permanent tombstone (`HybridSuite::from_u8(3) == None`) and
  cannot alias the standalone HQC-v5/FIPS-207-draft candidate or any future suite.
- **Signed policy, authenticated exact bytes.**
  [`Policy::load_signed`](../crates/q-periapt-policy/src/lib.rs) verifies a detached
  signature over the domain-separated, length-prefixed message
  `Q-PERIAPT-SIGNED-POLICY/v1 || u64_be(len) || exact_toml_bytes` through an injected
  [`q_periapt_sig::Verifier`](../crates/q-periapt-sig/src/lib.rs) before parsing or
  trusting the policy. Signature, parsing, signer-strength, or resolution failure is
  returned as an error. There is no fallback-success API.
- **Monotonic exact-document identity.** `Policy::load_signed_monotonic` takes an
  optional persisted `TrustedPolicyState = (non-zero version, SHA3-256(exact TOML))`.
  A lower version is rollback; different bytes reusing the same version are
  equivocation; exact re-application is idempotent. Callers must persist the returned
  state atomically after acceptance. Tests cover tampering, wrong keys, invalid schema,
  zero version, weak signer, rollback, and same-version equivocation.
- **Profile/backend coupling (compile-time guard).** The fast `CompatXWing`
  profile omits the PQ ciphertext and public key from the KDF. Primitive C2PRI is
  necessary but not sufficient: the exposed backend/key format must also preserve
  X-Wing's seed-derived self-binding precondition. [`HybridKem::new`](../crates/q-periapt-kem/src/lib.rs)
  rejects the omitted first-slot backend unless both `Kem::C2PRI` and
  `Kem::COMPAT_XWING_SAFE` are true (`Error::PolicyDenied`). This confines
  expanded/imported ML-KEM to `ContextBound`; X25519 remains valid in the absorbed
  traditional slot but is rejected in the omitted
  first slot. Both associated constants default to false, and a contradictory
  `COMPAT_XWING_SAFE=true, C2PRI=false` third-party backend fails closed. The default
  policy selects `ContextBound`; the X-Wing construction-compatible control uses the
  seed-dk backend. Independent endpoint/HPKE interoperability is not established here.

**Trusted-caller boundary.** The C/WASM policy-decision bytes are not a MAC or an
authorization token: same-process native/JS code can forge them. Native ABI2 removes
the raw/deterministic bypass exports, so Swift/Kotlin/Android decision types and the
exact-nine dynamic `q_periapt_*` surface prevent accidental field mixing under a
trusted host; they do not stop hostile code already executing in that address space.
Static archives constrain only that reserved public namespace: unsupported hidden
`qpn_*` bridge symbols remain deliberately linkable, because hidden visibility is
not static-link access control. WASM still exposes a
separately scoped conformance surface. The verification key must be pinned outside the
policy channel; otherwise an attacker can self-sign a replacement policy. These are
trusted-caller values, not authorization capabilities.
Untrusted local callers require a service/process that owns the pinned verification key
and monotonic state; an opaque handle in the same hostile address space is insufficient.

**State and output atomicity.** ABI1's four-byte version cannot authenticate the exact
policy digest required by ABI2 and is rejected; automatic conversion is impossible
without the exact previously accepted bytes. Empty state is permitted only for explicit
first enrollment or an authorized reset—storage read failure/deletion must not silently
become first use. Once output extents are valid, native ABI2 clears them before further
validation, computes into local temporaries, and commits only on success; invalid policy,
entropy failure, panic, or a low-order X25519 share leaves no partial key/ciphertext/secret.

**Resource bounds.** Signed policy documents and policy-bound application contexts are
each capped at 64 KiB. Rust checks precede its signature-message, parser, and derived-context
allocation; Java, Kotlin, and JNI facades also reject before their own explicit native copy.
Swift/wasm-bindgen/runtime marshalling may already have copied a caller-owned input before
Rust receives it, so this is not a whole-runtime memory quota. Oversized input is an explicit
error, never truncation or fallback. Network-facing services still need request/body limits.

### 4.4 Core-local secure zeroization — **ENFORCED for owned Rust storage**

Defends against: residual exposure of **A1** after use (in cooperation with the
host memory model).

[`q_periapt_core::Secret`](../crates/q-periapt-core/src/lib.rs) wraps the 32-byte
combined key and is wiped on `Drop` with **volatile zero writes** (which the
optimizer may not elide) followed by a `compiler_fence(SeqCst)` — the audited
`zeroize` crate's technique, inlined to keep the core dependency-free. `Secret` is
deliberately **not** `Clone`/`Copy`, preventing implicit owner duplication. Its
`as_bytes` borrow can still be read repeatedly or copied explicitly; callers own
those copies. The core is `#![deny(unsafe_code)]` with **one** documented
`#[allow(unsafe_code)]` block — the wipe — and nothing else.

**Honest limit:** this protects only storage owned by the Rust type being dropped.
Component secrets (`ss_pq`, `ss_trad`) in caller-provided buffers and raw arrays returned
through C/Swift/Kotlin/JavaScript are caller-managed. Swift copy-on-write, JVM/JS copies,
garbage collection, FFI marshalling, and OS paging can create copies the core cannot erase.
Upstream primitive containers may also retain transient private-key/shared-secret storage
without a zeroizing `Drop`; the core-owned guarantee must not be projected onto those internals.
The concrete `Sha3_256Xof` staging owner marks component shared-secret bodies and the
caller-context body separately from public transcript bytes and volatile-wipes every tracked
inline/heap copy on `Drop`; ordinary
unclassified `absorb`, range exhaustion, or inconsistent metadata falls back to wiping the whole
live staging buffer. This reduces needless public-byte wiping without weakening the prior default.
It does not prove erasure of `mlkem-native`/`fips204`/`sha3` state temporaries,
compiler/register copies, freed
storage outside the controlled migration path, crash/hibernate images, or secrets misclassified
as public by an external caller. Allocation/invariant failures synchronously wipe live staging
before terminating because abort does not run Drop. The formal models do not model memory erasure.
Swift/Kotlin expose explicit best-effort wipe operations; Android result objects are
`AutoCloseable` and wipe their retained internal secret, while caller clones must be wiped
separately. These lifecycle APIs reduce residue but do not establish full-stack zeroization.

### 4.5 Cross-platform implementation consistency — **PARTIAL / split evidence**

Defends against: silent divergence between language bindings that could produce
inconsistent (and therefore exploitable) keys.

The same dependency-free core runs across C ABI / WASM / Swift / Kotlin / Android-JNI. Deterministic
shared-vector, combiner and X-Wing byte equality remains Rust/WASM conformance evidence;
native ABI2 intentionally does not export the raw seed/coins surface needed to replay it.
C/Swift/Kotlin/Android product evidence instead checks the same signed-policy/OS-random
workflow and fail-closed semantics. The backend/source migration invalidated the previous macOS C,
Swift XCFramework, Android AAR, and device proofs; each lane requires fresh same-source evidence.
A Developer ID-signed, exact-static-only XCFramework, when selected by `artifact/results.json`,
covers only the hash-bound Apple SDK ZIP. The SDK contains no standalone executable or notarizable
bundle and is explicitly not reported as notarized. It does not attest an iOS app, physical-device runtime behavior,
Linux/Windows binaries, Android ART, or the source tag itself.
The X-Wing byte-exact KAT
(`q-periapt-backends`) **reproduces the `draft-connolly-cfrg-xwing-kem` reference
output on its 3 happy-path vectors**, and the NIST ACVP sets (ML-KEM-512/768/1024,
ML-DSA-44/65/87 external/pure, context, hedged, and SHAKE-128 pre-hash modes, plus
SLH-DSA) and the `ContextBound` reference vectors pass too —
this is conformance to the published vectors, not certification (see
[§5.5](#55-acvp-conformance-not-cmvp-certification)).

---

## 5. Out-of-scope / honest caveats

This is the part to read before trusting anything above. These are **not** defended,
or are only partially defended.

### 5.1 Empirical timing is a local diagnostic, not gated

The dudect Welch-t timing test (`dudect_decaps`,
[`ctstats/src/lib.rs`](../ctstats/src/lib.rs)) is intentionally not run in shared CI.
Shared cloud runners have too much scheduling/frequency noise for a stable
`|t| < 4.5` threshold, and converting a noisy failure into default success would
hide evidence. Run it locally on dedicated, quiesced hardware and retain its exit
status. A real timing gate needs such hardware
([`ctstats/README.md`](../ctstats/README.md)). **Do not read "side-channel-first" as
"timing is gated."** What *is* gated is failure-path *indistinguishability* (§4.2),
not wall-clock *equality*.

### 5.2 Binary-level constant-time: composition + ML-KEM decapsulation gated on two ISAs

A **dataflow constant-time check** is configured in CI (`constant-time` job) as an
**x86_64 + aarch64 matrix**: the `ct_verify` harness marks secrets "undefined" and
Valgrind/Memcheck (TIMECOP) flags any branch or index that depends on them, over the
suite's **own** constant-time composition code — `ct_eq`, `ct_select32`, and the combiner
over secret shared secrets. A compiler-introduced secret-dependent branch *there* would fail
the build on either arch (the emitted assembly differs per target, so each is an independent
check), catching exactly the source→assembly gap that best-effort source-level CT cannot.
The `constant-time` CI job is configured to run the dataflow gate on x86_64 and
aarch64 (matrix `[ubuntu-latest, ubuntu-24.04-arm]`); the local container harness
([`ctstats/scripts/ct-in-container.sh`](../ctstats/scripts/ct-in-container.sh)) includes
a planted-secret-branch negative control so a zero result cannot pass vacuously.
The same job now targets the release-graph portable `mlkem-native` ML-KEM-512/768/1024
decapsulation wrappers. Each secret probe marks only that parameter set's ŝ + z;
its planted secret-indexed control must report positive, while embedded-public-key
and whole-dk runs are diagnostic only because an expanded FIPS 203 dk contains public
`ek` and `H(ek)` fields.

The earlier 0-report `libcrux` captures and their hax/source-level argument are
**historical predecessor evidence only**. The intervening `fips203` 0.4.3 provider
failed the corrected gate in [CI run 29230650107](https://github.com/billlza/q-periapt/actions/runs/29230650107):
34,306 errors / 100 contexts on x86_64 and 30,464 / 70 on aarch64. Those are
historical `fips203` failure counts; they do not transfer to `mlkem-native`. The
backend/source migration changed the canonical digest. A fresh x86_64+aarch64 capture
must pass for the release source before the ML-KEM binary-CT cell can be promoted.
There is currently no inherited source-CT attestation for the new backend. Other
primitive backends remain outside this hard gate.
Also TODO: promoting a quiesced-hardware **timing** check to a gate (the statistical dudect
test is currently a local diagnostic). Binary-CT tooling is configured on
**x86_64-linux and aarch64-linux**; **riscv64 / wasm32** remain unverified at the
binary level and have no inherited source-CT claim.
CT posture is **per-backend**, not universal — swapping a backend changes the
guarantee. Known carve-out: **ML-DSA signing uses rejection sampling, so its
iteration count is secret-dependent by design** — an auditable, documented exception,
not a covert leak.

### 5.3 No third-party audit

Nobody outside this project has reviewed the design or the code. The mechanized
proof is a strong internal artifact, not an external attestation.

### 5.4 Pre-1.0 / unaudited backends

The cryptographic primitives come from external pre-1.0 sources and remain unaudited
for this integration. The research-alpha release path uses portable `mlkem-native` v1.2.0,
`fips204` 0.4.6, and `sha3` 0.10.9, removing both the failed `fips203` path and the
earlier `libcrux`/hax/`proc-macro-error2` advisory edge. The vendored ML-KEM trust
anchors are commit `0ba906cb14b1c241476134d7403a811b382ca498` and immutable GitHub
commit archive SHA-256 `f1975616b99c86819fb959803b090370d206d2b5fc9639146b79ce846864d677`.
`cargo audit --deny warnings` passes while `.cargo/audit.toml` retains `ignore = []`.
RustSec does not inspect vendored C, its compiler output, provenance, licenses or side
channels. This is a warning-clean Rust dependency scan, not an independent
cryptographic, C/FFI, side-channel, implementation, or ABI audit.

### 5.5 ACVP conformance, not CMVP certification

The backends pass the NIST ACVP conformance sets for ML-KEM-512/768/1024 and
ML-DSA-44/65/87 (keyGen + external/pure, hedged-context, and SHAKE-128 pre-hash
signature modes), plus SLH-DSA-SHA2-{128,192,256}s — reproducing the
authoritative vectors byte-for-byte (`q-periapt-backends/src/acvp.rs`,
`acvp_slhdsa.rs`). Vendored internal-interface vectors remain explicit, unwired
reference data and are not a backend pass. **Passing ACVP vectors is conformance evidence, not a FIPS
validation.** There is no CMVP/CAVP certification, no validated cryptographic-module
boundary, and no operational-environment accreditation. Do not read "passes the ACVP
vectors" as "FIPS-validated."

### 5.6 No spec↔implementation linkage proof

The EasyCrypt binding theorem is at the **abstract-spec level**. There is no
mechanized proof that the Rust in [`q_periapt_core::combine`](../crates/q-periapt-core/src/lib.rs)
refines the EasyCrypt model. The link between proof and code is **human review plus
a mirrored negative KAT**, nothing stronger. Equally, the proof models SHA3 as
collision-resistant (and as a PRF/RO for the KDF); the guarantee is only as strong
as that idealization.

### 5.7 Adversary-boundary exclusions

Explicitly **out of model**: host/OS compromise; a broken or backdoored RNG;
compiler/toolchain compromise; physical-access attacks (fault injection, power/EM,
cold-boot/paging); the simultaneous cryptanalytic break of **both** the PQ and the
traditional component (the hybrid degrades gracefully to its surviving half, but is
not magic if both fall); the retired PQClean-HQC historical leak and the isolated
HQC-v5/FIPS-207-draft candidate's implementation/standardization posture (neither is part of
the current product CT claim); and the application's own use of `K` after the suite returns it.

### 5.8 No speed advantage is claimed (and none should be inferred)

This suite ships the **same** NIST primitive family as its baselines through third-party
backends, with **no demonstrated** primitive/speed edge. `CompatXWing` is byte-exact against the
draft vectors. A paired matched-backend gate measures identical seed-dk/X25519 inputs
against a published single-Mac non-regression budget. A proof counts as current only
when its source digest matches the live canonical tree and the host satisfies the
controlled-environment contract; `artifact/results.json` carries a path/hash/schema/source/pass
summary, while the required performance verifier checks the selected proof and artifacts. The
backend/source migration changed that digest, so every recorded package, device,
performance, and binary-CT proof is historical regardless of whether its older-source
run passed. A fresh controlled-host proof and physical-device matrix must be collected
against the release source. Currentness is determined only by `artifact/results.json`
plus live verification against the canonical tree. The
schema-v4 producer fixes Cargo/Rustc executable hashes, versions, and target; rejects repository/
ancestor/user Cargo configuration and caller compiler/wrapper/loader controls; fixes system-tool
lookup; and builds offline in a fresh private target. It still trusts the user-writable Cargo
registry, Rust sysroot/driver, OS tools/libraries, same-UID host, and collector source-to-binary
honesty; standalone verification does not independently rebuild the binary. Even
a passing result remains diagnostic host evidence, not cross-device energy, rustls
end-to-end, or optimized production parity.
`ContextBound` is **slower on the extra-hashing axis, not stronger** there. The value of Q-Periapt
is **auditability, crypto-agility, side-channel CI, cross-platform byte-identical
consistency, and the machine-checked binding proof** — never speed.

### 5.9 Camera-ready capture is not a hostile-builder refinement proof

The Linux camera harness constrains runner code with a dedicated locked UID, cleared
groups/capabilities, `no_new_privs`, per-command cgroup limits, bounded runner/tmp
filesystems, private mount/IPC namespaces, no-network build namespaces, and a
loopback-only measurement namespace. These controls protect the host and make accidental
resource/output failure fail closed. The root-owned seed is closed exactly against
`Cargo.lock` `.crate` checksums, and each build lane starts from a fresh copy.

Cargo still executes every dependency build script and compiler action under one UID with
one writable lane target. An actively malicious pinned dependency could therefore tamper
with sibling extracted sources or intermediate outputs during that same invocation. The
bundle does not claim to rule this out, nor does it establish compiler correctness or a
formal source-to-binary refinement. Its experiment-integrity boundary trusts the
checksum-pinned dependency closure and toolchain; a hostile-builder claim needs per-action
sandboxing plus an independent reproducible builder or equivalent attestation.

Authoritative JSON now uses one bounded regular-file snapshot for strict parsing and
SHA-256, rejecting duplicate keys, non-finite values (including finite-syntax exponent
overflow), caller-controlled ancestor/final symlinks, and ordinary mutation during a read.
Selected Apple/performance proof paths and hashes are checked before the same bytes enter
semantic verification; Apple auxiliary logs/plists/linkage/binaries also use one snapshot
per semantic/hash decision. Matrix membership, device-ID commitment recomputation, and the performance budget are
verifier policy. This closes selected-proof and Apple-auxiliary A/B hash-versus-semantics mixing and policy
self-selection. Clean provenance additionally ignores caller Git environment, rejects
assume-unchanged/skip-worktree, compares HEAD/index to actual tracked bytes and modes, and
enumerates ignored plus visible untracked inputs under a fixed verifier-owned non-input policy
rather than Git exclude files. That policy excludes only exact untracked regular `.DS_Store`
files and explicitly enumerated generated-output locations; lookalikes and special files remain
inputs. Untracked `.gitignore` files outside fixed ephemeral outputs fail closed. This is a
canonical source-input inventory after explicit non-input exclusions, not a hermetic build-input
closure: tracked code can still read generated-output locations. Release-grade
closure requires an isolated checkout, unique fresh lane outputs, and hashes for every generated
artifact later consumed.
Proof/package/device Python entrypoints
use isolated/no-site CPython 3.11+, a fresh private cache prefix, no bytecode writes, cleared
`PYTHON*` state, and a source-only repository bootstrap; repository `.pyc`/`.pyo` files are
rejected even when ignored. This closes forged adjacent pyc, user-site/`.pth`,
`PYTHONPATH`/`PYTHONHOME`, and local Git-exclude verifier bypasses. It does not authenticate the
selected interpreter, standard library, dynamic libraries, or kernel.
It does not atomically snapshot the complete writable worktree or resist
a privileged local writer that can replace and restore every input between processes.
That adversary still requires an immutable clean checkout plus signed, transparent, or
independently attested release provenance.

### 5.10 No asynchronous identity, prekey, ratchet, or recovery guarantee

The current four-flight symbolic model is a server-authenticated hybrid handshake
with a pinned server verification key. It does not model or implement:

- account identity or a mapping from a human identifier to device keys;
- a malicious/split-view key directory or key transparency;
- signed, one-time, or last-resort prekey generation/service and atomic consumption;
- replay-safe offline first messages;
- symmetric, DH, sparse-PQ, or Triple Ratchet state;
- skipped-message keys, bounded out-of-order delivery, or healing under loss;
- multi-device session convergence, revocation, retries, or stale devices;
- crash-consistent persistence, rollback/fork detection, or backup recovery.

The `publish = false` model under `models/q-periapt-continuity-model` changes none of
those product absences. It contains opaque operation/storage commitments plus a
candidate structured `LifecycleContextV1` over externally asserted identity,
directory, prekey, transcript, policy and ratchet-epoch commitments. Its nested
`PrekeySelectionV1` strictly encodes suite, responder identity scope, bundle epoch,
directory checkpoint, manifest, and independent classical/PQ modes and IDs. Bootstrap
B21-B23 are derived atomically and reject outer-scope grafts, so an in-model caller can
no longer attach an arbitrary digest to a claimed quality. It cannot verify any of
those assertions or prove that the selected key was leased once. The model exercises
the proposed ordering `reserve -> execute ->
result pin -> anchor reservation -> anchor -> final commit -> idempotent release ->
release ack`. Every abstract pending write survives
model reconstruction and is queried before replay. A security failure first
reconciles any pending write and then installs an append-only suspension intent. Its
first cause cannot be overwritten, fence loss and repository conflict use distinct
evidence types, and `Volatile` results are scrubbed at every durable cut.
Reconstruction only re-emits the same quarantine. The model can reject an effect
before durable reservation, a full-binding/result-shape mismatch, a stale or newly
lost fence, a provider terminal outcome contradicting an accepted success, an unknown
non-repeatable outcome, and premature release in finite traces.
It cannot model real secrets, wire parsing, credential verification, directory
consistency, manifest signature/membership/expiry, prekey authenticity/lease/
consumption, cryptographic authentication, fsync, WAL, hardware
providers, or remote anchor authenticity; its snapshot and
suspension journal are desired abstract contracts, not storage evidence. Receipts are
trusted adapter oracles; provider completions and repository/anchor outcomes are
trusted too. Provider profile/epoch echo equality is not policy authorization or
downgrade resistance. Host-side `durable journal ack -> external effect`
ordering remains an unclosed integration P0 until a real adapter and kill/failpoint
harness exist.

Signal's current public baseline includes published PQXDH and SPQR/Triple-Ratchet
components with ML-KEM Braid plus a separately specified Sesame-compatible manager
integration; Apple PQ3 also includes asynchronous establishment, per-device
identity infrastructure, and ongoing PQ rekeying. Q-Periapt is therefore behind both
on protocol lifecycle. K-CTX cannot fill this gap: it commits exact caller-supplied
bytes but does not authenticate account semantics, make a prekey one-time, prevent a
server split view, advance a ratchet, or establish PCS.

The future Continuity threat model must add malicious directories, prekey draining,
KCI/UKS, mode substitution, stale bundle/manifest, exact/conflicting replay,
malicious double lease, directory split view, device compromise/revocation, state rollback/fork, concurrent operations,
unbounded skipped-key/queue DoS, RNG/keystore failure, metadata leakage, and
compromise-timed FS/PCS. It must also distinguish provider, repository, and anchor
outcomes as applied, exact-absent, conflict, or unknown; timeout is never ordinary
failure. Its minimum fail-closed invariants and evidence gates are specified in
[`CONTINUITY_RESEARCH.md`](CONTINUITY_RESEARCH.md), with the current lifecycle slice
in [`continuity/G1_EFFECT_LIFECYCLE.md`](continuity/G1_EFFECT_LIFECYCLE.md). Until the
full model and implementation exist, there is no session-protocol security claim.

---

## 6. Summary table

| # | Guarantee | Adversary | Mechanism | Enforcement |
|---|-----------|-----------|-----------|-------------|
| 4.1 | Binding to CR(SHA3); no KEM binding assumption | ADV-MAL | `ContextBound` injective hash-everything encoding | **PROVED** (`bind_le_cr`, 0 admits) + no-admits CI gate + mirror KAT |
| 4.2 | No decapsulation oracle; correct-length ciphertext failure-path indistinguishable; public input classifiable and local failure opaque | ADV-CCA | Implicit rejection; coarse `Error`; `ct_select32` | **ENFORCED** (ctstats hard gate) |
| 4.3 | Downgrade/equivocation protection and policy/execution coupling | ADV-POLICY | strict signed document; `(version,digest)` state; closed `ResolvedSuite`; `C2PRI && COMPAT_XWING_SAFE` guard | **ENFORCED on decision APIs** (logic/type + four-quadrant unit gate); native ABI2 raw bypass removed, forgeable decision descriptor and separate WASM conformance surface explicit |
| 4.4 | Core-owned combined-key storage zeroization | post-use exposure | volatile wipe + fence; core `Secret` is not `Clone` | **ENFORCED only for owned Rust storage**; binding/OS copies are caller-managed best effort |
| 4.5 | Byte-identical output in reported deterministic host/ISA cells; semantic parity in native product cells | binding divergence / adapter drift | shared-vector conformance plus policy/round-trip/context/failure-atomicity product tests | **ENFORCED only in explicitly reported cells**; product randomness is not replay evidence, and neither result alone is a clean release attestation |
| 5.1 | Empirical timing equality | ADV-TIME | dudect Welch-t | **LOCAL DIAGNOSTIC** (not run in shared CI; not gated) |
| 5.2 | Binary-level CT — our composition (`ct_eq`/`ct_select32`/combiner) | ADV-TIME | Memcheck/TIMECOP `ct_verify` | CI matrix x86_64+aarch64 (job `constant-time`); fresh release-source capture required |
| 5.2 | Binary-level CT — portable `mlkem-native` ML-KEM-512/768/1024 decapsulation | ADV-TIME | parameter-specific ŝ+z Memcheck probes + planted-leak and embedded-public-key diagnostics | **CONFIGURED HARD GATE on x86_64+aarch64**; `fips203` failed historically and a fresh current-provider release-source pass is pending |
| 5.2 | Binary-level CT — riscv64 / wasm32 + timing-as-gate | ADV-TIME | — | TODO |
| 5.5 | NIST ACVP conformance (wired FIPS modes) | — | X-Wing KAT + wired ACVP sets (`acvp.rs`) | **CONFORMANCE DONE for the stated modes**; internal-interface vectors are reference-only; not CMVP-certified |
| 5.6 | Spec↔impl refinement | — | human review + mirror KAT | **NOT PROVED** |
| 5.10 | Async identity/prekeys/ratchet/multi-device/recovery | directory, replay, compromise, rollback, DoS | Test-only model checks canonical role-ordered context admission, a strict four-quadrant prekey-selection record with atomic B21-B23 derivation, exact version+digest CAS, no-op-anchor rejection and abstract reconstruction; independent Python/Rust full-byte vectors and structural EasyCrypt diagnostics agree, but fields still enter through trusted genesis and there is no manifest verifier, lease/tombstone state, context-advance API, credential/prekey/directory authentication, ratchet, manager, or production protocol mechanism | **OUT OF SCOPE / G1 PARTIAL** |
