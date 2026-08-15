# Comparative evidence analysis — capabilities, boundaries, and unclosed claims

> **External comparison baseline: 2026-08-16; local model status: 2026-08-16.**
> Q-Periapt is a pre-1.0, unaudited research
> artifact. This document separates construction-level security, protocol scope,
> implementation assurance, performance, standardization, and deployment. A win on
> one axis is never reported as a win on all axes. Machine-readable claim status is
> in [`../artifact/claim-ledger.json`](../artifact/claim-ledger.json).
> External rows are scoped to the linked standard, specification, vendor documentation,
> or project repository—the primary source for what that baseline publicly claims.
> They are not independent audits, an exhaustive market survey, or an aggregate ranking.

## Executive answer

No aggregate ranking is supported by these unlike-for-like artifacts. The
MLKEM768-X25519/X-Wing construction has published vectors and analyses; the IRTF hybrid-KEM draft now
specifies a proposed general hash-everything `UniversalCombiner`; RFC 10024 defines the
Standards Track `X25519MLKEM768` TLS 1.3 group under the RFC 9954 framework; PQ3 has deployment, ratcheting,
external review, and protocol-level formal analysis. Signal's current baseline is not
PQXDH alone: the 2025 public stack adds SPQR/ML-KEM Braid and Triple Ratchet, and
Signal reports ProVerif design analysis plus hax/F* checks of core Rust invariants and
panic freedom in CI. Local tests do not substitute for those different forms of evidence.

A narrower artifact contribution is feasible around the conjunction of:

1. field-resolved standard K-CT/K-PK reasoning plus a separately scoped local
   context-wrapper game and explicit countermodels;
2. authenticated context and exact-policy commitment;
3. typed, fail-closed suite resolution rather than caller-assembled metadata;
4. one implementation across native/WASM/Apple/JVM faces;
5. a formal-source/conformance ledger with named binary/device evidence boundaries;
6. a matched-performance diagnostic contract with a published non-regression budget.

This table does not establish whether every other public or private artifact demonstrates
that entire conjunction. The defensible position is a scoped “multi-layer assurance”
artifact claim subject to systematic novelty review, not priority or rank. It is not stronger
cryptographic primitives, a higher binding ceiling than correct seed-`dk` X-Wing, or
production superiority.

## 1. Current baselines

| Baseline | Actual scope | What it already does well | Boundary relevant to Q-Periapt |
|---|---|---|---|
| [NIST FIPS 203 ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) | Standardized PQ KEM primitive | Stable parameter sets, conformance target, broad ecosystem | A primitive standard does not specify hybrid composition, negotiation, authenticated context, deployment migration, or proof-to-binary evidence. NIST's 2025-11-17 planning note also identifies a future publication update, so release claims must pin the reviewed revision and track the official errata rather than treating one ACVP run as timeless. |
| [RFC 10024 `X25519MLKEM768`](https://www.rfc-editor.org/rfc/rfc10024.html) under [RFC 9954](https://www.rfc-editor.org/rfc/rfc9954.html) | Proposed Standard TLS 1.3 group (`0x11EC`, Recommended=Y) using the RFC 9954 hybrid framework | Widely deployed ecosystem path; fixed 1216/1120-byte shares and a 64-byte ML-KEM/X25519 secret enter the RFC 9846 TLS key schedule | Concatenates component secrets at the group layer; its goal is TLS interoperability, not a reusable committing hybrid-KEM API. Q-Periapt's private-use groups are different protocols. |
| [OpenSSL 3.5 LTS](https://openssl-library.org/post/2025-04-08-openssl-35-final-release/) | General-purpose provider and TLS stack with native ML-KEM, ML-DSA, SLH-DSA, multiple key shares, and support through 2030 | A maintained ecosystem baseline with a stable provider surface and a long security-support horizon | Q-Periapt does not gain OpenSSL's lifecycle, audit, or deployment assurance by using the same primitives. A standards claim needs an independent OpenSSL 3.5 wire-interoperability lane, not another same-backend round trip. |
| [AWS-LC PQ integrations](https://github.com/aws/aws-lc/blob/main/crypto/fipsmodule/PQREADME.md) and [AWS PQ readiness](https://aws.amazon.com/security/post-quantum-cryptography/aws-pq-readiness-confidentiality/) | FIPS-oriented primitive implementation plus large-service hybrid-PQ TLS rollout | Supports the standardized `0x11EC` group, publishes primitive benchmarks, and exposes negotiated key-exchange evidence in service/access logs where available | A downstream build is not automatically covered by AWS-LC's validation. The transferable lesson is explicit rollout policy plus evidence of the group actually negotiated, not merely a configured algorithm list. |
| [Cloudflare hybrid-PQ deployment](https://blog.cloudflare.com/post-quantum-ipsec/) | Internet-scale TLS deployment and cross-vendor hybrid-ML-KEM IPsec interoperability | Reports hybrid protection for more than two-thirds of human-generated TLS traffic and tests an emerging IPsec profile against independent Cisco, Fortinet, and strongSwan implementations | Early private ciphersuites created real interoperability gaps. Q-Periapt must keep private research groups out of its standards lane and add independent wire, HRR, and network-middlebox evidence before claiming production interoperability. |
| [CFRG concrete hybrid KEMs draft-04](https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-04.html), with historical [X-Wing draft-10](https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-10) | CFRG/IRTF intended-Informational MLKEM768-X25519 construction; the current draft states it is identical to X-Wing | Lean fixed construction, 32-byte seed-`dk` format, analyses, and official vectors | The current document is an Internet-Draft, not an RFC or Standards-Track standard. It has no external context or policy input. The expanded-`dk` binding boundary remains a key-format concern rather than a claim that the specified seed-`dk` construction is broken. |
| [IRTF hybrid KEMs draft-12](https://datatracker.ietf.org/doc/draft-irtf-cfrg-hybrid-kems/) | General hybrid-KEM constructions; CFRG RG Last Call as of 2026-07-11 | `UniversalCombiner` binds secrets, ciphertexts, public keys, and a label; C2PRI route captures the X-Wing shape | This eliminates any claim that “hash every field” is unique. Section 6.4.2 labels its LEAK-BIND analyses informal sketches and defers rigorous proofs; it also does not prove the possible MAL strengthening of common-seed keys. Q-Periapt's distinct scoped evidence is machine-checked, field-resolved standard MAL-BIND-K-CT/K-PK reductions, a separately scoped local K-CTX wrapper reduction, countermodels, and implementation evidence—not the field list. |
| [NIST CSWP 39upd1](https://csrc.nist.gov/pubs/cswp/39/upd1/considerations-for-achieving-crypto-agility/final) | Crypto-agility strategies and operational continuity, updated 2026-06-29 | Treats replacement/migration across protocols, software, hardware, and infrastructure as an operational discipline | “Crypto agility” is established practice, not novelty. Q-Periapt must justify its closed decision, semantic security floor, migration order, and exact execution evidence as a scoped realization. |
| [Signal PQXDH](https://signal.org/docs/specifications/pqxdh/) | Asynchronous initial key agreement | Identity, signed/one-time classical and PQ prekeys, offline first ciphertext, replay and server-trust analysis; its published analyses include conditional KCI resistance | Authentication is classical in the current revision; one-time-key exhaustion, last-resort keys, replay, and directory trust remain protocol concerns. Any modified hybrid/PQ identity mode must re-prove KCI for its own assumptions and compromise schedules. PQXDH is only the bootstrap component. |
| [Signal SPQR / Triple Ratchet](https://signal.org/docs/specifications/doubleratchet/) + [ML-KEM Braid](https://signal.org/docs/specifications/mlkembraid/) | Ongoing hybrid FS/PCS | Sparse PQ continuous key agreement, bounded epoch/skipped-key state, dropped-message analysis, heterogeneous migration, public specifications | This removes the old comparison claim that Signal has only initial PQ protection. Q-Periapt has no comparable state machine or implementation-level proof. |
| [Signal Sesame](https://signal.org/docs/specifications/sesame/) | Asynchronous multi-device session management | Per-device active/inactive sessions, convergence, retries, stale devices, bounded storage/error handling | Q-Periapt has no user/device/session graph, queue, retry, revocation, or recovery implementation. |
| [Apple PQ3](https://security.apple.com/blog/imessage-pq3/) | Deployed messaging protocol with asynchronous establishment and ongoing PQ ratcheting | Pairwise per-device sessions, Contact Key Verification, hardware-backed classical device authentication, periodic PQ healing, protocol analysis, external review, huge deployment | Authentication remains classical against an active quantum attacker; cadence and platform infrastructure are product trade-offs. Q-Periapt still has no comparable ratchet, transparency service, audit, telemetry, or scale. |
| [Apple CryptoKit / Secure Enclave PQ APIs](https://developer.apple.com/documentation/cryptokit/secureenclave) | Platform provider surface on supported current Apple systems | X-Wing and ML-KEM APIs plus Secure Enclave ML-KEM-768/1024 and ML-DSA-65/87 private-key operations | A valuable provider/security/performance baseline, not a Q-Periapt invention. Current software `mlkem-native`/`fips204` keys do not automatically gain hardware isolation; OS/device availability, background/lock behavior, error semantics, and speed/energy must be measured on physical devices. |
| Q-Periapt `CompatXWing` | Byte-exact MLKEM768-X25519 construction/control profile | Three retained X-Wing draft-10 vectors plus the official `concrete-hybrid-kems-04` Appendix B.2 vector (stored as the repository vector-0 fixture); seed-`dk` guard; noncanonical metadata rejection | The construction has no suite/version/context inputs, so the local K-CTX wrapper property is inapplicable. Q-Periapt requires canonical absence (`[]`, `0`, `[]`) and rejects supplied values instead of implying that they are bound. KAT equality is not independent endpoint interoperability or RFC status. |
| Q-Periapt `ContextBound` | Non-standard committing hybrid profile | Binds suite/version/all ct/pk/context; machine-checked reductions and countermodels | Research profile; no standards adoption, external audit, or formal spec-to-Rust refinement. |

For operational KEM guidance, NIST’s [SP 800-227](https://csrc.nist.gov/pubs/sp/800/227/final)
and the IETF’s [RFC 9958](https://www.rfc-editor.org/rfc/rfc9958.html) reinforce the
same lesson: selecting a sound primitive is necessary but does not close protocol,
key-management, or migration risk.

The release consequence is concrete. ABI 2 may ship its private ContextBound lane as
a clearly named research interface, but a standard-TLS claim additionally requires
the RFC 10024 lane, an independent implementation at the wire boundary, captured
negotiation/HRR evidence, and failure semantics that distinguish peer input from local
provider failure. Fleet-scale rollout telemetry and a stateful PQ ratchet remain
separate product programs; neither is implied by a successful KEM or TLS handshake.

## 2. The field’s recurring hard problems

### 2.1 Primitive security does not imply realization security

The recurring failure mode is a sound KEM embedded under the wrong serialization,
combiner, context, state machine, or key lifecycle. FIPS conformance alone cannot show:

- which `dk` representation an API accepts;
- whether a component ciphertext/public key is committed;
- whether negotiation and policy are authenticated;
- whether two implementations encode the same tuple;
- whether the proven source is the binary that ran.

Q-Periapt contributes here only by keeping these links explicit. It must never translate
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
aarch64, and implicit-rejection behavior is tested. The earlier provider migration to
portable `mlkem-native` invalidated former-provider captures. The current source then
selected upstream native arithmetic plus fixed Armv8-A x1/x4 FIPS 202 assembly on
exactly the little-endian targets `aarch64-apple-darwin`, `aarch64-apple-ios`,
`aarch64-apple-ios-sim`, `aarch64-unknown-linux-gnu`, and
`aarch64-linux-android`, while retaining portable C everywhere else, including
Wasm. It has no runtime dispatch or Armv8.4-A SHA3 path.
That source change also makes the pre-selection portable captures historical; fresh
x86_64-portable and aarch64-native passes are required, and no predecessor
source-CT/hax claim transfers. In particular,
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

The native selection is an implementation optimization, not formal-assurance evidence.
Upstream HOL-Light evidence is limited to selected upstream assembly source/object
routines under its stated preconditions; it does not prove downstream reassembly,
the Rust/C wrapper, the full ABI, or a released package. This integration has no
independent audit.

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

## 3. Capability and evidence matrix

This is a scope matrix, not a score or rank. “Same primitive/ceiling” means only
that narrow property; “absent” and “pending” identify an unimplemented capability
or unclosed evidence claim without assigning an overall position.

| Dimension | X-Wing / CFRG / TLS | PQ3 / current Signal stack | Q-Periapt status |
|---|---|---|---|
| Standardized primitives | mature baseline | mature baseline | same ML-KEM/X25519 primitive family; no additional primitive claim |
| Seed-`dk` MLKEM768-X25519 bytes | current CFRG draft plus historical X-Wing vectors | n/a | construction-byte KATs cover the current Appendix B.2 vector (stored as the repository vector-0 fixture) and retained draft-10 vectors; no endpoint claim |
| MAL K-CT/K-PK ceiling | seed-`dk` X-Wing reaches MAL | protocol-specific | same stated ceiling, not stronger |
| Field-resolved combiner reductions | CFRG general construction + evolving binding analysis | protocol-specific KDF/proof models | potential artifact delta in executable standard MAL-BIND-K-CT/K-PK reductions plus a separately scoped local K-CTX wrapper reduction; still no refinement or exhaustive novelty proof |
| Authenticated external context | no construction-level X-Wing context; TLS binds transcript elsewhere | both protocols authenticate extensive transcript/state data | potential reusable-API distinction only; not a current protocol result, and the rustls KEM-layer path is partial |
| Signed policy/execution coupling | fixed suites or stack-specific config | versioned product protocols | potential open-artifact delta among the explicitly compared baselines: atomic decision + digest state + fail-closed fixed-suite boundary; systematic novelty review pending |
| Source/claim/binary/device ledger | implementation-specific | Signal reports CI implementation proofs; product evidence is otherwise partly internal | potential **public reproducibility** delta: strict single-byte proof/auxiliary snapshots, environment-independent HEAD/index/actual-byte Git checks, ignore-independent untracked-input inventory, isolated source-only Python startup, manifest path/hash binding, and fixed release policy; not refinement superiority. The recorded schema-3 physical iPad+iPhone matrix is historical after target selection; fresh target-specific evidence is required. |
| Asynchronous identity/prekeys | outside KEM scope | both have deployed device/key-directory paths; Signal specifies independent classical/PQ one-time/fallback semantics | absent as a protocol/service; only a strict model-level 16-field selection codec and outer-scope graft controls exist |
| Ongoing hybrid PQ ratchet | outside KEM scope | PQ3 and Signal publish ongoing-ratchet designs | absent |
| Multi-device/recovery | outside KEM scope | deployed capability | absent |
| Crash/effect refinement | transport stack specific | deployed systems plus published protocol/implementation analyses; storage internals are not a public interoperability profile | pending research: the diagnostic model includes canonical trusted-context/prekey admission, exact version+digest CAS and effect ordering, but no prekey tombstone/lease state, authenticated context advancement or real WAL/adapter/refinement evidence |
| Spec-to-implementation refinement | implementation-specific | Signal reports hax/F* checks for its Rust ratchet crate | pending / not established |
| Standards/interoperability | current CFRG draft and standardized TLS groups | deployed proprietary protocols | ContextBound is non-standard; independent endpoint interoperability is absent |
| Third-party audit/deployment | available for named implementations | available for named products | none claimed |
| Constant-time/FIPS backend maturity | implementation-specific | product-specific | partial and per-backend/ISA only |
| Matched-core performance | implementation-specific | implementation-specific | raw schema v5/proof schema v8/budget schema v10 preserves the seed-dk profile estimand and separately compares O3/codegen-matched native/portable ContextBound `hybrid_core` encap/decap using one generated `expanded_fips203_2400` keypair and identical key bytes/coins/corpus. It excludes FFI and OS RNG, binds stable Rust/Cargo 1.96.1 plus the SDK/toolchain, final binary, portable archive/source, and canonical source, and remains pending without a fresh selected proof. |
| End-to-end/device performance | optimized baseline | optimized deployed code | **pending**; rustls/backend, energy, and device gaps remain |

## 4. Performance: scoped evidence only after fresh capture

Raw schema v5 carries two separately named estimands in one same-process harness.
For profile non-regression, ContextBound and CompatXWing use the same native
`MlKem768XWingSeed + X25519` backend, keys/coins/ciphertexts, and 64-case
deterministic corpus under the same ABBA/BAAB schedule. Strict nested
`profile_inputs` fixes ContextBound's suite/version/application context and
CompatXWing's canonical absence of those inputs (`[]`, `0`, `[]`). For implementation
improvement, native and evidence-only portable ML-KEM-768 execute only the
ContextBound `hybrid_core` encapsulation and decapsulation surface over one generated
`expanded_fips203_2400` keypair. The same expanded key bytes, coins, and corpus enter
both implementations, and every encapsulation/decapsulation output is compared before
timing; portable key generation is not invoked. FFI, policy handling, OS RNG, rustls,
and full ABI overhead are excluded. Both C paths use the same
O3/PIC/Armv8-A/macOS-11/section-codegen contract, while the O3 Rust harness uses thin
LTO and one codegen unit. Each estimand/operation receives its own 5 s warm-up
immediately before collection, as bound by raw and budget metadata, followed by
20,480 paired samples per applicable operation and variant and ABBA/BAAB ordering.
Fixed 256/1/2-call batches cover
combine/encapsulation/decapsulation and record unrounded totals; verification
normalizes only after the strict budget-bound iteration-map check.

Consecutive 1,024-pair blocks define the primary paired percentile ratio/delta
estimand and moving-block-bootstrap upper bound. Under the nearest-rank rule, each
block's p99 has 11 tail observations. Budget schema v10 preserves the v6 profile
contract, including its former 256-pair regression guard, and requires the published
profile limits at both block scales. Separately parameterized 64/256/256-pair
stability windows retain the 5% CV limit. The profile's nine bounds remain
per-metric one-sided 95% bounds. The implementation estimand adds six: for both
ContextBound hybrid-core operations, native/portable p50 and p95 upper ratios must be at
most 0.95 and p99 at most 1.0. These are not a simultaneous 95% family guarantee;
span-5 coverage under autocorrelation has not been independently calibrated. A
passing current proof therefore supports only the registered expanded-key hybrid-core
native-over-portable implementation result, not a population, complete ABI, device,
rustls, or ContextBound-over-X-Wing speed
claim.

A local dirty native/portable diagnostic motivated a native/portable expanded-key
hybrid-core performance hypothesis on that host only. It has no checked-in
canonical-source/toolchain-bound raw and analysis
bundle and is not formal release evidence, an optimized X-Wing comparison, or a
protocol/device result. Exact quantitative results require a fresh
raw-schema-v5/proof-schema-v8 run under budget schema v10.

Historical proof schema v5 additionally bound the exact rustup toolchain name so byte-identical mutable aliases
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
establish a current-source or performance claim.

This redesign invalidates the earlier single-call controlled-Mac diagnostic: its 334/375 ns
CompatXWing combine block medians were timer-quantization levels, so their mixture could cross the
5% CV line without establishing host instability. Those historical
raw-schema-v2/proof-schema-v5 controlled runs were accepted only when the proof's
canonical source digest equalled the live verifier digest and the host satisfied the
power/thermal contract. The current verifier, rather than the proof, fixes
`artifact/performance-budgets.json` as the release policy. The machine-readable manifest carries the current proof
summary and selected path/hash so updating this source document cannot self-promote a stale run;
the required domain verifier, not manifest prose alone, checks the actual proof, artifacts, and
freshness. The target-selection/source migration invalidated all recorded portable-derived performance proofs,
including the later matched-backend capture; a fresh same-source controlled-host run
is required. The old single-call proof also remains invalid and must not be cited.
The fixed budget-schema-v10 policy additionally pins the macOS SDK path, version,
and settings digest, together with the stable Rust/Cargo 1.96.1 rustup toolchain and target plus Cargo,
Rustc, Xcode Clang, and Xcode `ar` executable paths and hashes (and version output
where available). Proof schema v8 also binds the final harness binary and the
evidence-only portable reference source/archive. Collection selects those fixed tools, rejects
repository/ancestor/user Cargo configuration, clears
caller compiler/wrapper/loader controls, fixes system-tool lookup, builds offline in a fresh private
target, and rechecks the four executables. The user-writable Cargo registry, Rust sysroot/driver, OS
tools/libraries, same-UID host, and local collector's source-to-binary honesty remain trusted; this is
not a hermetic producer attestation.
The Compat rustls path now expands its stable 32-byte seed once per in-flight client
handshake and reuses one zeroizing 2,400-byte prepared owner at completion, rather
than repeating key generation. This process-local change has no global secret-key
cache or C-ABI surface. There is still no current paired IANA-group comparison,
iPad/iPhone energy/thermal evidence, allocations/RSS budget, stable multi-run clean
baseline, or direct optimized production MLKEM768-X25519 comparison. Shared CI
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

## 5. What would make a multi-layer assurance claim publishable

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
credibly claim the specifically enumerated **open assurance stack** for this artifact.
That would still not establish an aggregate rank or exhaustive novelty result.
Without items 5–9, protocol or production superiority remains unsupported.

## 6. Claim discipline

Allowed:

- “ContextBound has a machine-checked, field-resolved binding argument under the stated model.”
- “The signed-policy execution path binds exact policy identity and application context and
  rejects an incompatible fixed suite.”
- “CompatXWing retains byte equality for three historical X-Wing draft-10 vectors
  and the current CFRG `concrete-hybrid-kems-04` Appendix B.2 vector (stored as the
  repository vector-0 fixture), and remains the
  construction/control profile.” Independent endpoint or HPKE interoperability and
  RFC status are separate, currently unclosed claims.
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
