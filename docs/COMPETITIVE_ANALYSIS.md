# Competitive analysis — where Q-Periapt can lead, and where it cannot yet compete

> **External comparison baseline: 2026-07-11; local model status: 2026-07-12.**
> Q-Periapt is a pre-1.0, unaudited research
> artifact. This document separates construction-level security, protocol scope,
> implementation assurance, performance, standardization, and deployment. A win on
> one axis is never reported as a win on all axes. Machine-readable claim status is
> in [`../artifact/claim-ledger.json`](../artifact/claim-ledger.json).

## Executive answer

An honest “all-dimensional crush” is **not currently possible**. X-Wing has a
published construction, vectors, analyses, and multiple implementations; the IRTF hybrid-KEM draft now
specifies a proposed general hash-everything `UniversalCombiner`; a Standards Track TLS
Internet-Draft defines the `X25519MLKEM768` group; PQ3 has deployment, ratcheting,
external review, and protocol-level formal analysis. Signal's current baseline is not
PQXDH alone: the 2025 public stack adds SPQR/ML-KEM Braid and Triple Ratchet, and
Signal reports ProVerif design analysis plus hax/F* checks of core Rust invariants and
panic freedom in CI. Q-Periapt cannot beat those facts with more local tests.

A narrower but valuable lead **is feasible**: become the reference artifact for the
conjunction of:

1. field-resolved standard K-CT/K-PK reasoning plus a separately scoped local
   context-wrapper game and explicit countermodels;
2. authenticated context and exact-policy commitment;
3. typed, fail-closed suite resolution rather than caller-assembled metadata;
4. one implementation across native/WASM/Apple/JVM faces;
5. a formal-source/conformance ledger with named binary/device evidence boundaries;
6. matched performance with a published non-regression budget.

Among the explicitly compared public baselines, none demonstrates that entire conjunction in one
open artifact. That is the defensible “multi-layer assurance” position, not an exhaustive priority
claim; a systematic novelty review remains pending. It is not stronger
cryptographic primitives, a higher binding ceiling than correct seed-`dk` X-Wing, or
production superiority.

## 1. Current baselines

| Baseline | Actual scope | What it already does well | Boundary relevant to Q-Periapt |
|---|---|---|---|
| [NIST FIPS 203 ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) | Standardized PQ KEM primitive | Stable parameter sets, conformance target, broad ecosystem | A primitive standard does not specify hybrid composition, negotiation, authenticated context, deployment migration, or proof-to-binary evidence. |
| [TLS `X25519MLKEM768` draft-05](https://datatracker.ietf.org/doc/html/draft-ietf-tls-ecdhe-mlkem-05) | Standards Track Internet-Draft defining a TLS 1.3 group | Simple ecosystem path; transcript is bound by the TLS key schedule | Concatenates component secrets at the group layer; its goal is TLS interoperability, not a reusable committing hybrid-KEM API. |
| [X-Wing draft-10](https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-10) | Individual, intended-Informational ML-KEM-768 + X25519 KEM | Lean fixed construction, seed-`dk` format, peer-reviewed analysis, implementations | Not an IETF Standards Track or CFRG WG item. No external context or policy input. Draft-10 itself warns that transmitting expanded `dk` loses MAL-BIND K-PK/K-CT guarantees. |
| [IRTF hybrid KEMs draft-12](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hybrid-kems/) | General hybrid-KEM constructions; CFRG RG Last Call as of 2026-07-11 | `UniversalCombiner` binds secrets, ciphertexts, public keys, and a label; C2PRI route captures the X-Wing shape | This eliminates any claim that “hash every field” is unique. Section 6.4.2 labels its LEAK-BIND analyses informal sketches and defers rigorous proofs; it also does not prove the possible MAL strengthening of common-seed keys. Q-Periapt's narrower possible lead is machine-checked, field-resolved standard MAL-BIND-K-CT/K-PK reductions, a separately scoped local K-CTX wrapper reduction, countermodels, and implementation evidence—not the field list. |
| [NIST CSWP 39upd1](https://csrc.nist.gov/pubs/cswp/39/upd1/considerations-for-achieving-crypto-agility/final) | Crypto-agility strategies and operational continuity, updated 2026-06-29 | Treats replacement/migration across protocols, software, hardware, and infrastructure as an operational discipline | “Crypto agility” is established practice, not novelty. Q-Periapt must justify its closed decision, semantic security floor, migration order, and exact execution evidence as a scoped realization. |
| [Signal PQXDH](https://signal.org/docs/specifications/pqxdh/) | Asynchronous initial key agreement | Identity, signed/one-time classical and PQ prekeys, offline first ciphertext, replay and server-trust analysis; its published analyses include conditional KCI resistance | Authentication is classical in the current revision; one-time-key exhaustion, last-resort keys, replay, and directory trust remain protocol concerns. Any modified hybrid/PQ identity mode must re-prove KCI for its own assumptions and compromise schedules. PQXDH is only the bootstrap component. |
| [Signal SPQR / Triple Ratchet](https://signal.org/docs/specifications/doubleratchet/) + [ML-KEM Braid](https://signal.org/docs/specifications/mlkembraid/) | Ongoing hybrid FS/PCS | Sparse PQ continuous key agreement, bounded epoch/skipped-key state, dropped-message analysis, heterogeneous migration, public specifications | This removes the old comparison claim that Signal has only initial PQ protection. Q-Periapt has no comparable state machine or implementation-level proof. |
| [Signal Sesame](https://signal.org/docs/specifications/sesame/) | Asynchronous multi-device session management | Per-device active/inactive sessions, convergence, retries, stale devices, bounded storage/error handling | Q-Periapt has no user/device/session graph, queue, retry, revocation, or recovery implementation. |
| [Apple PQ3](https://security.apple.com/blog/imessage-pq3/) | Deployed messaging protocol with asynchronous establishment and ongoing PQ ratcheting | Pairwise per-device sessions, Contact Key Verification, hardware-backed classical device authentication, periodic PQ healing, protocol analysis, external review, huge deployment | Authentication remains classical against an active quantum attacker; cadence and platform infrastructure are product trade-offs. Q-Periapt still has no comparable ratchet, transparency service, audit, telemetry, or scale. |
| [Apple CryptoKit / Secure Enclave PQ APIs](https://developer.apple.com/documentation/cryptokit/secureenclave) | Platform provider surface on supported current Apple systems | X-Wing and ML-KEM APIs plus Secure Enclave ML-KEM-768/1024 and ML-DSA-65/87 private-key operations | A valuable provider/security/performance baseline, not a Q-Periapt invention. Current software `mlkem-native`/`fips204` keys do not automatically gain hardware isolation; OS/device availability, background/lock behavior, error semantics, and speed/energy must be measured on physical devices. |
| Q-Periapt `CompatXWing` | Byte-exact X-Wing comparison profile | Three official-vector KATs; seed-`dk` guard | Intentionally ignores suite/version/context; native X-Wing has no context parameter, so the local K-CTX wrapper property is inapplicable. |
| Q-Periapt `ContextBound` | Non-standard committing hybrid profile | Binds suite/version/all ct/pk/context; machine-checked reductions and countermodels | Research profile; no standards adoption, external audit, or formal spec-to-Rust refinement. |

For operational KEM guidance, NIST’s [SP 800-227](https://csrc.nist.gov/pubs/sp/800/227/final)
and the IETF’s [RFC 9958](https://www.rfc-editor.org/rfc/rfc9958.html) reinforce the
same lesson: selecting a sound primitive is necessary but does not close protocol,
key-management, or migration risk.

## 2. The field’s recurring hard problems

### 2.1 Primitive security does not imply realization security

The recurring failure mode is a sound KEM embedded under the wrong serialization,
combiner, context, state machine, or key lifecycle. FIPS conformance alone cannot show:

- which `dk` representation an API accepts;
- whether a component ciphertext/public key is committed;
- whether negotiation and policy are authenticated;
- whether two implementations encode the same tuple;
- whether the proven source is the binary that ran.

Q-Periapt can lead here only by keeping these links explicit. It must never translate
“ACVP/KAT passed” into “hybrid protocol is secure.”

### 2.2 Lean combiners inherit hidden component and key-format assumptions

X-Wing’s lean shape is excellent when its mandated seed-derived key format and ML-KEM
properties hold. It is not a universal drop-in formula for arbitrary imported/expanded
keys or arbitrary KEMs. Q-Periapt’s useful contribution is not “X-Wing is broken”; it is:

- a byte-exact safe X-Wing lane;
- a mechanically enforced rejection of expanded-key `CompatXWing` misuse;
- an explicit probability-one expanded-`dk` witness;
- a ContextBound lane that commits every field without relying on component binding.

That is a realization-hardening edge at the **same MAL K-CT/K-PK ceiling** as correctly
deployed seed-`dk` X-Wing.

### 2.3 “Hash everything” is no longer a unique construction claim

The CFRG hybrid-KEM work’s `UniversalCombiner` includes both component secrets,
ciphertexts, public keys, and a label. Q-Periapt therefore must not market the field list
alone as novelty. Its differentiators must be the parts the generic construction does
not by itself deliver:

- field-deletion countermodels and exact assumption ledger;
- authenticated application-context agreement;
- signed-policy identity in the context;
- type-level suite/profile/key-format coupling;
- cross-language and physical-device evidence tied to the same claims.

### 2.4 K-CTX is weak unless the surrounding protocol authenticates the context

“Different context bytes hash to different keys” is nearly tautological under collision
resistance. The hard property is that both authenticated peers agree on the intended
context and cannot be downgraded to another suite/policy/transcript.

Current Q-Periapt status:

- Tamarin and ProVerif record context in completion events and prove authenticated
  context agreement in their symbolic model.
- The signed-policy native ABI 2 and WASM paths use the shared canonical encoding
  `LP(domain) || LP(SHA3-256(exact signed policy)) || LP(application context)`.
- Swift/Kotlin/Android expose a read-only atomic decision and exercise the same
  authenticated semantics. Their OS-random product paths do not claim deterministic
  byte replay.
- The rustls `SupportedKxGroup` API still sees only a fixed protocol-domain label; TLS
  binds its transcript in the TLS key schedule, but the Q-Periapt KEM layer on that path
  must **not** be claimed as per-session K-CTX. Its `provider_with_policy` entry point
  consumes an already parsed, unauthenticated `Policy` and supports either resolved
  profile; it does not consume the signed-policy decision or policy digest.

### 2.5 Crypto agility can become a downgrade API

An allow-list and a profile byte are not sufficient. Before this hardening, an L5 signed
policy could select `ContextBound` while the fixed runtime still executed ML-KEM-768.
That was a real policy/execution split.

The corrected path now:

- rejects unknown TOML fields, zero versions, duplicate/unknown algorithms, and
  unsatisfiable policies;
- domain-separates signatures over length-prefixed exact policy bytes;
- persists `(version, policy digest)` and rejects rollback plus same-version equivocation;
- resolves a closed `HybridSuite` enum into one private-field `ResolvedSuite` containing
  suite, profile, key format, and version;
- rejects an L5 policy at the fixed L3 native/WASM/rustls boundary rather than silently mapping it;
- carries the exact policy digest into the ContextBound execution context on the
  signed-policy native/WASM paths. The rustls provider is a separate
  parsed-policy selection path and is excluded from that authenticity claim.

Remaining boundary: C memory is writable by the local caller. Typed Swift/Kotlin/Java
objects prevent accidental field mixing, and ABI 2 removes raw/deterministic crypto
exports, but hostile code in the same process can still forge the decision descriptor or
invoke exported product operations. That threat needs process isolation or a service
boundary, not another public struct.

### 2.6 Protocol lifecycle can dominate the KEM

PQXDH addresses asynchronous initial agreement. Apple PQ3 and Signal's current
SPQR/Triple Ratchet both add ongoing PQ healing; Sesame covers Signal-style
multi-device session management. Q-Periapt is primarily a composition/assurance
artifact. It does not currently match either deployed stack on identity, prekeys,
ratcheting, metadata handling, recovery, multi-device state, or operational rollout.

That gap is now a separate research program rather than an optional bullet. The
authoritative plan is [`CONTINUITY_RESEARCH.md`](CONTINUITY_RESEARCH.md): first build a
published-spec reference lane, then compare a distinct Continuity research lane. The
KEM core and current paper must not absorb server/database/session responsibilities.

### 2.7 Side channels are backend-and-architecture properties

Q-Periapt configures ML-KEM-768 decapsulation binary-level constant-time gates on x86_64 and
aarch64, and implicit-rejection behavior is tested. The production migration to portable
`mlkem-native` invalidated all former-provider captures; a fresh two-ISA pass for the release
source is required, and no predecessor source-CT/hax claim transfers. In particular,
`fips203` 0.4.3's historical probe failed on both ISAs in
[CI run 29230650107](https://github.com/billlza/q-periapt/actions/runs/29230650107);
those counts do not transfer to the current provider. This cannot be generalized to every
primitive, feature, or ISA. The old HQC/PQClean backend was pre-standard, unaudited,
known timing-leaky, and unmaintained; it has now been removed from the publishable and
runtime-suite graph rather than carried as a hedge. Its 193/22,849 Memcheck counts are
historical older-source evidence, not the current CT gate. The live gate uses a synthetic
planted secret-indexed leak as its non-vacuity control. The standalone `publish = false`
RustCrypto `hqc-kem 0.1.0-rc.0` HQC-v5/FIPS-207-draft shadow is useful for format/performance/
correctness research only and owns no suite code or ABI. NIST’s
[HQC selection announcement](https://csrc.nist.gov/News/2025/hqc-announced-as-a-4th-round-selection)
does not turn an RC into a production implementation. The crate says it tracks an IPD,
but as of 2026-07-12 the official FIPS 207 IPD is unavailable and NIST says it is coming soon.

### 2.8 Evidence islands create false green claims

Unit tests, formal proofs, a package hash, and an old device run can each be green while
the aggregate claim is false. Q-Periapt now separates:

- manifest/canonical source-input validation after fixed generated-prefix exclusions;
- Tier-1 host execution;
- full EasyCrypt/Tamarin/ProVerif execution;
- package evidence;
- same-source physical-device evidence;
- performance evidence;
- optional bare-metal producer-origin bundle integrity, explicitly separated from
  independent hardware attestation.

Only the required clean-tree Apple/core combination may emit the explicitly scoped local marker
`PROOF_TO_BYTE_APPLE_LOCAL_CANDIDATE_PASS`. It is not distribution signing, notarization, or public
attestation. Android runtime remains a separate proof until an emulator-vs-physical release policy
is selected; there is no generic all-platform release marker.
[`claim-ledger.json`](../artifact/claim-ledger.json) deliberately leaves formal
spec-to-implementation refinement and end-to-end performance parity as `pending`. Apple matrix
and matched-host proof currentness are time-varying states selected by `artifact/results.json` and
checked by their live domain verifiers.

### 2.9 Implementation linkage is now a competitive baseline

Signal's [SPQR engineering report](https://signal.org/blog/spqr/) says its protocol
candidates were modeled in ProVerif and that its Rust implementation is translated by
hax into F* on every CI run to prove core pre/postconditions and panic freedom. This is
not a complete end-to-end compiler proof, but it directly exceeds Q-Periapt's present
link from abstract EasyCrypt/Tamarin/ProVerif models to Rust, which is human review plus
mirrored tests and provenance hashes.

Therefore `proof-to-byte` remains valuable public evidence, but it is not a formal
refinement advantage. Any stateful Continuity crate needs implementation-level
refinement or translation validation as a P0 gate, not a distant nice-to-have. The
new strict evidence snapshots, Git-exclude-independent input inventory, and isolated source-only
Python verifier startup close duplicate-key, proof hash/semantics A/B, hidden-input, forged-pyc,
and user-site startup mixing, but they strengthen provenance consistency rather than
model-to-code refinement.

### 2.10 Identity, prekeys, recovery, and performance form one trade space

The field's remaining hard problems are coupled:

- classical identity is fast and hardware-backed on Apple but not active-PQ secure;
- ordinary PQ signatures can provide accountable PQ authentication but are large,
  transferable, and can undermine Signal-style deniability;
- one-time prekeys improve initial forward secrecy but can be withheld or exhausted;
- sparse PQ chunks reduce average wire cost but dropped or one-way traffic can delay
  healing;
- backing up live ratchet state improves convenience but risks rollback, nonce/key
  reuse, and cloned device state;
- key transparency can make directory equivocation detectable only under its signed-
  log consistency and witness/gossip/user-anchor assumptions; it does not stop
  censorship, metadata collection, or prekey draining.

The research target is a measured and proved Pareto improvement, not a blanket claim
that one setting is simultaneously more secure, faster, and more available.

### 2.11 Session handling and security-aware ratcheting are prior art

The research gap is narrower than “formalize the manager.” Cremers, Jacomme, and
Naska's [USENIX Security 2023 session-handling analysis](https://www.usenix.org/conference/usenixsecurity23/presentation/cremers-session-handling)
already models Sesame at the conversation layer, demonstrates clone-attacker PCS
failures, and proposes two provably stronger mechanisms. Durak, Caforio, and
Vaudenay's [security-aware on-demand ratcheting](https://www.microsoft.com/en-us/research/publication/beyond-security-and-efficiency-on-demand-ratcheting-with-security-awareness/)
already studies which messages remain unsafe under leakage patterns and hybrid
light/heavy ratcheting.

Consequently, session convergence, clone detection, a “healing status,” or on-demand
heavy ratcheting alone are not Q-Periapt inventions. A defensible delta must reproduce
those attacks and then add something jointly stronger and evidenced: exact
effect-reservation ordering, commit-unknown reconciliation, authenticated
per-transition rollback anchors, proof-to-state-to-byte linkage, or a measured
wire/energy/security frontier. The current `publish = false` lifecycle model covers
only the first finite-state slice. It now exercises trusted canonical role-ordered
context admission, exact version+digest repository advances, typed persist/evidence
subjects, exact unknown-write reconstruction, no-op-anchor rejection, volatile-result
scrubbing, first-cause retention and durable quarantine/release ordering. Its strict
`PrekeySelectionV1` also prevents independently chosen quality, manifest, and opaque
selection-digest values: suite, responder scope, bundle epoch, checkpoint, manifest,
and both legs' modes/IDs form one 492-byte record, with all four exhaustion states
preserved. Rust and independent Python encoders/decoders agree on frozen full bytes.
Separate EasyCrypt diagnostics prove modeled LP8 injectivity and policy/direction plus
named prekey-field omission collisions but not
semantic completeness, authentication, or Rust refinement. Trusted
credential/prekey/directory authenticity, legal context advancement,
canonical storage bytes, authenticated adapters, and fsync-before-effect remain
external obligations. Provider profile/epoch echo equality is not policy authorization,
downgrade resistance, or epoch attestation.
It has no context-advance API and makes no identity, session-security, or production
crash-safety claim.

### 2.12 Exact prekey semantics are necessary but not sufficient

PQXDH already represents the optional classical one-time prekey independently from
the PQ one-time or signed last-resort key and binds actual public keys into its
authenticated/KDF inputs. A single aggregate `one_time/last_resort` bit would therefore
be a regression, not an innovation. The new Continuity diagnostic preserves all four
availability quadrants and cross-binds the selection to responder identity, suite, and
checkpoint before Lifecycle B21-B23 can exist.

The plausible research delta is the next composition, not the codec alone: an atomic
signed manifest/leaf format plus durable local acceptance/tombstone, exact-versus-
conflicting replay handling, privacy-aware double-lease evidence, directory-fork
detection, and rollback-conditional proof, all linked to exact bytes and device runs.
PQXDH itself documents replay and one-time-key exhaustion/withholding concerns; key
transparency systems address directory consistency under their own witness/gossip
assumptions. Until those stateful pieces and their privacy cost are proved and
measured, Q-Periapt has only removed an internal semantic-laundering bug class.

### 2.13 The defensible stateful direction is proof-to-state-to-byte

A plausible research delta is to bind one canonical prekey/lifecycle decision, exact
`(version,digest)` state, crash/rollback ordering, authenticated receipts, model traces,
Rust transitions, wire bytes, binaries, and physical-device evidence into one
independently replayable chain. Most work proves a primitive or protocol model; the
candidate contribution would be the cross-layer refinement and evidence contract.
That chain is **not implemented today**: the repository has candidate codecs and a
non-production lifecycle model, but no authenticated prekey service, durable WAL,
receipt protocol, ratchet implementation, model-to-Rust refinement, or end-to-end trace.

## 3. Scorecard after this hardening

Legend: **lead** = defensible current advantage; **parity** = same ceiling/capability;
**behind** = baseline has material evidence Q-Periapt lacks; **pending** = no current claim.

| Dimension | X-Wing / CFRG / TLS | PQ3 / current Signal stack | Q-Periapt status |
|---|---|---|---|
| Standardized primitives | mature baseline | mature baseline | **parity**: same ML-KEM/X25519 primitives |
| Seed-`dk` X-Wing bytes | reference | n/a | **parity**: byte-exact CompatXWing KAT |
| MAL K-CT/K-PK ceiling | seed-`dk` X-Wing reaches MAL | protocol-specific | **parity**, not stronger |
| Field-resolved combiner reductions | CFRG general construction + evolving binding analysis | protocol-specific KDF/proof models | potential artifact delta in executable standard MAL-BIND-K-CT/K-PK reductions plus a separately scoped local K-CTX wrapper reduction; still no refinement or exhaustive novelty proof |
| Authenticated external context | no X-Wing context; TLS binds transcript elsewhere | both protocols authenticate extensive transcript/state data | potential reusable-API delta only; not a current protocol lead, and the rustls KEM-layer path is partial |
| Signed policy/execution coupling | fixed suites or stack-specific config | versioned product protocols | potential open-artifact delta among the explicitly compared baselines: atomic decision + digest state + fail-closed fixed-suite boundary; systematic novelty review pending |
| Source/claim/binary/device ledger | implementation-specific | Signal reports CI implementation proofs; product evidence is otherwise partly internal | potential **public reproducibility** delta: strict single-byte proof/auxiliary snapshots, environment-independent HEAD/index/actual-byte Git checks, ignore-independent untracked-input inventory, isolated source-only Python startup, manifest path/hash binding, and fixed release policy; not refinement superiority. A clean schema-3 physical iPad+iPhone matrix exists, but its currentness is established only by the live verifier. |
| Asynchronous identity/prekeys | outside KEM scope | both have deployed device/key-directory paths; Signal specifies independent classical/PQ one-time/fallback semantics | **behind**: no protocol/service; only a strict model-level 16-field selection codec and outer-scope graft controls |
| Ongoing hybrid PQ ratchet | outside KEM scope | PQ3 and Signal Triple Ratchet **lead** | **behind / absent** |
| Multi-device/recovery | outside KEM scope | major deployed capability | **behind / absent** |
| Crash/effect refinement | transport stack specific | deployed systems plus published protocol/implementation analyses; storage internals are not a public interoperability profile | **pending potential delta**: diagnostic model now includes canonical trusted-context/prekey admission, exact version+digest CAS and effect ordering, but no prekey tombstone/lease state, authenticated context advancement or real WAL/adapter/refinement evidence |
| Spec-to-implementation refinement | implementation-specific | Signal reports hax/F* checks for its Rust ratchet crate | **behind / pending** |
| Standards/interoperability | X-Wing/CFRG/TLS **lead** | deployed proprietary protocols | **behind** for ContextBound |
| Third-party audit/deployment | major **lead** | major **lead** | **behind**: none |
| Constant-time/FIPS backend maturity | production implementations vary, best are strong | production-hardened | **behind/partial**; per-backend/ISA only |
| Matched-backend core performance | optimized baseline | implementation-specific | raw schema v2/proof schema v4/budget schema v5 gate fixes the exact rustup toolchain plus Cargo/Rustc executable identity, rejects Cargo/wrapper configuration, uses an offline fresh target, and records controlled pre-build/pre-run/post-run/post-analysis observations; mutable registry/sysroot/OS and collector honesty remain trusted |
| End-to-end/device performance | optimized baseline | optimized deployed code | **pending**; rustls/backend, energy, and device gaps remain |

## 4. Performance: the only acceptable claim after fresh capture

The paired harness removes the earlier backend comparison confound: both profiles use
`MlKem768XWingSeed + X25519`, the same keys/coins/ciphertexts, a 64-case deterministic
corpus, 5 s warm-up, 20,480 paired samples per operation/profile, and ABBA/BAAB ordering.
Raw schema v2 times fixed 256/1/2-call batches for combine/encapsulation/decapsulation in both
profiles and records the unrounded total. Verification normalizes by a strict, budget-bound
iteration map. Consecutive 1,024-pair blocks define the primary paired percentile ratio/delta
estimand and its moving-block-bootstrap upper bound. Under the nearest-rank rule, each block's p99
is supported by 11 tail observations; budget schema v5 preserves the v4 estimator and requires at
least 10 instead of allowing the three tail observations produced by the previous 256-pair primary
blocks. Because that changes the estimand rather than monotonically shrinking its acceptance set,
schema v5 continues to recompute the
former 256-pair estimator as a regression guard and requires the same published limits at both
block scales. Separately parameterized 64/256/256-pair stability windows prevent
environment CV from sharing that statistical role. Every block preserves complete ABBA cycles and
the 64-case corpus balance. The 5% stability threshold and published ratio/delta limits remain
unchanged. The nine budgeted bounds are **per-metric** one-sided 95% bootstrap bounds, not a
simultaneous 95% family guarantee. The span-5 bootstrap is deterministic and threshold-conservative,
but its coverage under autocorrelation has not been independently calibrated; this is another reason
the result remains a diagnostic non-regression gate rather than a population-level performance claim.

Schema v5 additionally binds the exact rustup toolchain name so byte-identical mutable aliases
cannot make tool selection ambiguous. An earlier 256-pair-primary attempt failed the decapsulation
p99 bootstrap upper bound: its block
ratios ranged from 0.24 to 4.28 while the global ContextBound p99 was below CompatXWing and both
order halves had the same approximately 1.063 median ratio. Later schema-v4 collections moved the
primary tail estimator to 1,024-pair blocks while retaining 256-pair blocks as a regression guard.
A 20,480-pair run then missed the unchanged encapsulation p99 limit, and a 40,960-pair follow-up
missed it by 0.000220. An older complete 81,920-pair-per-profile collection belonged to digest
`80c418b2...`; all 491,520 raw records passed schema validation, but combine block-median CV was
0.121067 against the fixed 0.050000 environment limit, so no proof was emitted and numeric budgets
were not evaluated. A later clean-tree collection at the same preregistered sample count passed the
unchanged stability and non-regression budgets. The selected path/hash/source status is recorded in
`artifact/results.json` and must pass the live verifier; neither the failed raw nor this prose can
establish a current-source or performance-lead claim.

This redesign invalidates the earlier single-call controlled-Mac diagnostic: its 334/375 ns
CompatXWing combine block medians were timer-quantization levels, so their mixture could cross the
5% CV line without establishing host instability. Raw-schema-v2/proof-schema-v4 controlled runs
are accepted only when the proof's canonical source digest equals the live verifier digest and the
host satisfies the power/thermal contract. The verifier, rather than the proof, fixes
`artifact/performance-budgets.json` as the release policy. The machine-readable manifest carries the current proof
summary and selected path/hash so updating this source document cannot self-promote a stale run;
the required domain verifier, not manifest prose alone, checks the actual proof, artifacts, and
freshness. The backend/source migration invalidated all recorded performance proofs,
including the later matched-backend capture; a fresh same-source controlled-host run
is required. The old single-call proof also remains invalid and must not be cited.
The fixed budget-schema-v5 policy pins the exact rustup toolchain name plus Cargo/Rustc executable
hashes, versions, and target. Collection selects that named same-directory pair, rejects
repository/ancestor/user Cargo configuration, clears
caller compiler/wrapper/loader controls, fixes system-tool lookup, builds offline in a fresh private
target, and rechecks the two executables. The user-writable Cargo registry, Rust sysroot/driver, OS
tools/libraries, same-UID host, and local collector's source-to-binary honesty remain trusted; this is
not a hermetic producer attestation.
The current rustls path still has a backend-related gap versus the optimized IANA group,
and there is no paired iPad/iPhone energy/thermal evidence, allocations/RSS budget, stable
multi-run clean baseline, or direct optimized production-X-Wing comparison. Shared CI
runners verify the harness/schema, not noisy microseconds.

This section is strictly a KEM/core diagnostic. It says nothing about asynchronous
bootstrap, ordinary-message cost, PQ-healing latency, multi-device fanout, storage,
energy, or vulnerable-message exposure. The future Continuity lane has separate
end-to-end budgets for cold/cached bootstrap, average and peak wire bytes, mobile
energy/thermal state, bounded storage, crash recovery, and healing under bidirectional,
one-way, offline, lossy, and reordered traces.

The performance research may not save cycles by deleting authenticated fields or
lowering the PQ cadence. Candidate optimizations are byte-preserving cloning of an
already-absorbed **public-only** SHA3 prefix, bounded background batches of independent
prekeys with fail-closed storage/expiry, and authenticated fixed-budget chunking or
erasure-code experiments whose epoch-completion rule and healing-debt bound remain
unchanged. Each needs byte-equality KATs, cache-capacity and erasure rules, adversarial
loss/reassembly tests, and physical-device latency/energy evidence before it becomes a
claim. `CompatXWing` remains the fast, byte-exact comparison profile—not evidence that
`ContextBound` can match its combiner cycles by weakening its transcript.

## 5. What would make a multi-layer lead publishable

Priority order:

1. **Close refinement:** prove or translation-validate the canonical encoder and decision
   context from EasyCrypt specification to Rust bytes; keep Decaps/FIPS linkage explicit.
2. **Fresh physical proof:** run clean same-commit Mac + iPad + iPhone evidence on the new
   policy-bound path, with exact named test inventory.
3. **Performance budget:** keep the matched Mac proof canonical-source-input and controlled-host fresh,
   establish clean baseline history, and extend the same
   relative/absolute thresholds to iPad/iPhone energy and public APIs.
4. **Portable CT:** extend binary/dataflow evidence to every shipping primitive/backend/ISA;
   remove unmaintained experimental dependencies from product claims.
5. **External review:** obtain cryptographic, formal-methods, FFI, and side-channel audits.
6. **Standards strategy:** submit the authenticated-policy/context and proof-ledger ideas as
   composable extensions/evidence, not as a claim that a private-use wire should replace X-Wing.
7. **Continuity reference lane:** implement component-conformant PQXDH bootstrap and
   Triple Ratchet/SPQR plus a separately specified Sesame-compatible manager; prove
   the integration rather than relabeling a modified KDF as compatible. The public
   source revisions/reproducible content hashes are recorded in
   `continuity/REFERENCE_BASELINE.md`; only versioned archives and a pinned Git commit
   are immutable, and the integration profile remains pending.
8. **Continuity research lane:** test the R1–R8 hypotheses in
   [`CONTINUITY_RESEARCH.md`](CONTINUITY_RESEARCH.md), including authenticated
   policy-context continuity, prekey accountability, identity semantics, measurable
   healing debt, crash/rollback refinement, native Apple PQ provider measurements,
   metadata privacy, and workload-matched performance.
9. **Stateful implementation proof:** match the current competitive baseline with
   model-to-Rust refinement/panic-freedom evidence before any production comparison.
10. **Prekey state, not just bytes:** freeze signed manifest/leaf membership and prove
    local at-most-once acceptance, replay/tombstone, double-lease blame, directory-fork,
    rollback, parser/DoS, and receipt-linkability behavior before calling the model an
    asynchronous bootstrap.

If items 1–5 land while performance stays within a published budget, Q-Periapt can
credibly claim a strong **open assurance stack** among compared hybrid-KEM research
artifacts. “Strongest” still requires a systematic comparison, especially because
Signal now reports implementation-level verification. Without items 5–9, it cannot
honestly claim protocol or production superiority.

## 6. Claim discipline

Allowed:

- “ContextBound has a machine-checked, field-resolved binding argument under the stated model.”
- “The signed-policy execution path binds exact policy identity and application context and
  rejects an incompatible fixed suite.”
- “CompatXWing is byte-exact against the official X-Wing vectors and remains the
  construction/control profile.” Independent endpoint or HPKE interoperability is a
  separate, currently unclosed claim.
- “The artifact exposes proof, implementation, package, and device boundaries separately.”
- “The non-normative model rejects session/device/current-context grafts before
  reservation and preserves that trusted authority across abstract reconstruction.”
  This is a test-model invariant, not context advancement, authentication, or protocol parity.

Forbidden:

- “Q-Periapt is stronger than correctly deployed X-Wing on the shared MAL K-CT/K-PK axes.”
- “X-Wing is Standards Track” or “Q-Periapt replaces CFRG UniversalCombiner.”
- “The rustls group provides per-session K-CTX.”
- “HQC is a production-ready hedge in this build,” or that the HQC-v5/FIPS-207-draft shadow
  is part of ABI 2 / assigned the permanently tombstoned suite code `3`.
- “Proof-to-byte is a formal source-to-binary refinement.”
- “Current HEAD has clean iPad+iPhone proof” without the selected matrix passing the live verifier.
- “Performance parity” until the pending ledger claim is closed.
- “Signal only provides initial PQ protection” or “Signal has no ongoing PQ ratchet.”
- “Proof-to-byte is stronger than Signal's reported hax/F* implementation checks.”
- “Continuity protocol/security is implemented” from the test-only lifecycle model;
  it has no real crypto, wire, identity, prekey, ratchet, persistence adapter, FS/PCS,
  or interoperability evidence.
