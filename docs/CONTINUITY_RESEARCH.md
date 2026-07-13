# Q-Periapt Continuity — protocol research direction

> **Status: G0 is complete and G1 is partially started. Only a non-normative,
> public-commitment effect/journal lifecycle model plus a strict non-production
> prekey-selection record is implemented; no Continuity protocol, wire format,
> identity/prekey service, ratchet, production session crate,
> or security claim exists. Evidence date: 2026-07-12.**
> The implemented artifact remains the hybrid-KEM, signed-policy, bindings,
> formal-handshake, and proof-to-byte work described in the repository claim ledger.
> Continuity is scoped to two-party, pairwise, per-device sessions and their
> multi-device manager. Group/MLS messaging, calls/media, attachments, contact
> discovery, spam/abuse controls, push infrastructure, and cloud backup are separate
> product systems and are not included in a “PQ3/Signal parity” claim.

This document is the authoritative plan for deciding whether Q-Periapt should grow
from a hybrid-KEM assurance artifact into an asynchronous, long-lived, multi-device
session protocol. It separates three things that must not be conflated:

1. **parity work** required merely to enter the same protocol class as Apple and
   Signal;
2. **research hypotheses** that might yield publishable security, performance, or
   assurance improvements; and
3. **evidence gates** required before any improvement may be claimed.

## 1. Decision

The protocol work is strategically justified, but it must be a new layer named
**Q-Periapt Continuity**, not feature growth inside `q-periapt-core` and not a
retroactive expansion of the current paper's claims.

- If Q-Periapt remains only a committing hybrid KEM, adding identity directories,
  prekeys, ratchets, persistence, and recovery would dilute the contribution and
  enlarge the trusted code base without improving the KEM theorem.
- If Q-Periapt intends to compete with deployed secure-messaging or long-lived
  control-channel protocols, asynchronous bootstrap, ongoing PQ healing,
  multi-device state, recovery, and operational migration are mandatory. A stronger
  combiner alone is not a substitute.

The work therefore proceeds in **two non-interchangeable session lanes**:

| Lane | Purpose | Rule |
|---|---|---|
| **Reference lane** | Implement component-conformant PQXDH bootstrap and Triple Ratchet (SPQR with ML-KEM Braid), wrapped by a separately specified Sesame-compatible multi-device manager, as a comparison oracle | Freeze the exact specification revisions and integration profile. Preserve each component's algorithms, KDF inputs, state transitions, and limits. Sesame rev. 2 names X3DH + Double Ratchet, so composition with PQXDH/Triple Ratchet requires its own trace corpus and cannot be assumed interoperable. Do not insert `ContextBound` and still call the result Signal-compatible. |
| **Continuity research lane** | Evaluate Q-Periapt-specific identity, context-policy, prekey-accountability, recovery, and proof-to-byte ideas | Use a distinct protocol identifier and wire version. Every delta is compared against the same-device reference lane and justified by a proof, attack, or measured Pareto improvement. |

`CompatXWing` remains the byte-exact construction/control lane for hybrid-KEM work.
It is not a runtime-selectable session profile because it intentionally ignores
external context. `ContextBound` remains available to the research lane, but it may
only bind canonical bytes whose protocol meaning is independently authenticated.

## 2. The 2026 comparison baseline

The relevant Signal baseline is no longer PQXDH alone. Signal published the
[Sparse Post-Quantum Ratchet and Triple Ratchet](https://signal.org/docs/specifications/doubleratchet/)
in revision 4 of the Double Ratchet specification, uses the
[ML-KEM Braid](https://signal.org/docs/specifications/mlkembraid/) as its recommended
sparse continuous key agreement, and announced a heterogeneous rollout in 2025; the
public announcement does not establish that every historical session has migrated.
PQXDH supplies asynchronous initial establishment; Triple Ratchet supplies ongoing
hybrid FS/PCS. [Sesame](https://signal.org/docs/specifications/sesame/) supplies a
generic multi-device session-management model around per-device sessions, not a
published end-to-end integration specification for the newer components.
The selected public-source revisions, immutable identifiers where available, and
versioned reproducible content hashes for mutable publisher pages are in
[`continuity/REFERENCE_BASELINE.md`](continuity/REFERENCE_BASELINE.md); component
conformance, the separately specified manager composition, and interoperability are
still three different claims.

| Capability | Apple PQ3 | Signal public stack | Q-Periapt today | Continuity entry gate |
|---|---|---|---|---|
| Offline first message | Registered per-device PQ + classical keys | PQXDH signed and one-time prekeys | No protocol; model-only selection bytes | Signed, expiring, one-time-capable prekey bundle and initial ciphertext |
| Ongoing per-message FS | Symmetric ratchet | Double/Triple Ratchet chains | No | One-use message keys with deletion and bounded out-of-order support |
| Classical PCS | P-256 ratchet | X25519/448 Double Ratchet | No | Published-reference behavior first |
| PQ PCS | Periodic Kyber/ML-KEM ratchet | SPQR + ML-KEM Braid | No | Measured sparse PQ epochs under loss/offline traffic |
| Multi-device | Pairwise per-device sessions | Sesame-style device/session records | No | Independent device sessions, monotonic roster, revocation and convergence |
| Identity directory | IDS + Contact Key Verification | Identity keys, safety-number verification, service directory | Pinned demo server key only | Account/device certificates plus transparent or explicitly TOFU directory semantics |
| Implementation-level proof | External game/symbolic analyses and review | ProVerif design plus hax/F* implementation checks reported in CI | Abstract EasyCrypt plus separate symbolic handshake; no refinement | State-machine proof and spec-to-Rust refinement or translation validation |
| Deployment evidence | Global production | Large deployment/rollout | Research artifact | Pilot telemetry and independent audit; local tests cannot substitute |

Apple's public PQ3 description says the initial exchange uses Kyber-1024 plus
P-256, while ongoing PQ rekeys use Kyber-768 and were initially scheduled at about
50 messages with a seven-day maximum, assisted by encrypted receipts. Signal's
ML-KEM Braid instead spreads public-key material through erasure-coded chunks; with
32-byte chunks its specification lists 3, 30, 36, and 5 messages for the major
pieces of one exchange. These are existing performance/security trade-offs, not
Q-Periapt inventions.

## 3. Architecture boundary

The current dependency direction stays intact, but the reference oracle and product
research protocol do not share a session implementation:

```text
dependency arrow: caller --> dependency

reference-manager/test-harness --> reference-session-model --> crypto contracts
continuity-session-service      --> q-periapt-continuity-core --> crypto contracts

existing/provider adapters --> crypto contracts
directory/repository/network/platform adapters --> service-owned ports
Swift/Kotlin/C/WASM application faces --> continuity-session-service
```

The future production research core owns distinct `wire`, `identity`, `prekey`,
`handshake`, `ratchet`, `state`, `kdf`, and context-state types. Its effect protocol
is pure in the systems sense, but provider execution is not exposed until its
reservation is durable:

```text
prepare(state, input, entropy_reservation, trusted_time)
  -> TransitionPlan | PendingDraft
SessionRepository::install_pending(PendingDraft, fence)
  -> DurablePending
DurablePending::command()
  -> CryptoCommand
resume(DurablePending, CryptoCompletion)
  -> TransitionPlan | DurablePending | SuspensionPlan
```

It performs no database, network, clock, keychain, Secure Enclave, or retry I/O. A
`CryptoCommand` carries a distinct transition ID and command ordinal plus a one-use
operation ID. Before the canonical operation-ID encoder is frozen, the exact
structured binding is authoritative: protocol/version, session and both device IDs,
prior/reserved state version and digest, transition ID, ordinal, purpose, closed
policy, provider profile and instance epoch, typed context, writer fence, and a
commitment to the complete command intent. `resume` compares that full pending
command, not only a caller-supplied ID. This allows non-exportable hardware
signing/decapsulation and lock-state failures to remain explicit effects without
making the state machine impure or allowing an old result to be replayed into a new
state. The diagnostic model no longer treats the pairwise session and current context as
caller-authoritative: `TransitionModel` and abstract snapshot schema 3 retain the
trusted `SessionIdentity` and current `AuthenticatedContext`, and `prepare` rejects a
different session/device pair or context before reservation. The context is derived
from candidate canonical `LifecycleContextV1` bytes plus one signed-policy digest and
an explicit fallible digest adapter; this is structural binding to trusted genesis,
not authentication of the encoded claims.

`ProviderBinding` remains caller-selected draft data. The model proves exact
profile/epoch echo equality only after admission; it does not prove that the policy
authorized that provider, that the epoch is current, or that algorithm downgrade is
closed. Provider completion, repository/anchor outcomes, and receipts are trusted
authenticated-adapter-oracle inputs rather than attacker-validated bytes.

The diagnostic model derives retry semantics and expected result shape from a closed
`ModeledOperation` variant rather than accepting an independent retry flag. It does
not advance the trusted context: role/direction, accountable-versus-deniable policy,
local zero-RTT state names, confirmation evidence, and privilege rules must be frozen
before a legal transition API exists. The production operation set, confirmation
protocol, privilege taxonomy, and canonical encoder are not yet frozen. Production callers
will not inject raw entropy: an approved CSPRNG creates a purpose/algorithm/transition-
bound, one-use sealed entropy reservation before execution; only test/KAT code may
inject deterministic bytes. A deterministic command retries byte-identically. A
stable-handle command queries the same provider epoch/profile/handle. An uncertain
non-repeatable operation suspends rather than re-executing. The model exercises durable
cancellation/supersession points and late-result rejection, but numeric tombstone
retention, durable quarantine, and orphan hardware-key/handle cleanup are still open.

`SessionRepository::transact` is one aggregate transaction for session state,
one-time-prekey acceptance/tombstones, deduplication, inbox, and immutable outbox.
Using unrelated `SessionStore` and `Outbox` commits would permit nonce reuse or
plaintext release after a torn update. Receiving uses a state version/CAS; if commit
loses a race, candidate plaintext and keys are destroyed and the transition is
recomputed from the winning state. The dispatcher sends only committed outbox bytes.
Every write has a durable transition ID and a linearizable exact-operation outcome
query. A timeout after the database may have committed is `CommitOutcomeUnknown`, not
failure: no provider re-execution, plaintext release, dispatch, or new transition is
allowed until the exact committed/absent/conflict outcome is reconciled. Only a CAS
loss proven before reservation may prepare a new transition.

Database atomicity cannot cover a hardware counter, keychain deletion, transparency
log, or remote witness. If an external non-rollback anchor protects more than device
enrollment, the state machine uses an idempotent two-phase journal:

1. atomically persist `PendingAnchor(op_id, prior_anchor, next_state_digest)` plus the
   complete encrypted/sealed staged next state and effects, immutable outbox bytes, or
   an encrypted operation-bound inbox delivery record;
2. advance the authenticated external anchor for that exact operation and digest;
3. atomically install the final state and one exact idempotent release/delivery record
   after verifying the anchor response;
4. replay that exact release/delivery ID until its acknowledgement is durable.

Plaintext is never journaled unencrypted. Candidate plaintext remains volatile until
finalization or is stored only as an authenticated sealed-delivery record under a
separate hardware-bound queue key with an explicit retention bound. Recovery
reconciles every pending record through an authenticated
`compare_and_advance(anchor_id, exact_prior, exact_next, transition_id, fence)`: an
exact applied result finalizes; an authenticated exact-prior result retries the same
operation; unknown is queried; ahead, conflict, equivocation, or an unauthenticated
response suspends. Provider key deletion
is post-commit hygiene unless the provider offers an attestable one-time primitive;
the proof never treats best-effort deletion as an atomic database fact. A profile that
anchors only the device epoch must explicitly admit that same-epoch full-snapshot
rollback is out of scope.

The future `continuity-session-service` must contain two explicit roles. A per-device
session engine will drive one pairwise state machine. The account-level
`SessionManager` must verify a fresh
roster snapshot, applies a bounded eligibility policy, and fans one application
message out to independent sessions. It prepares all required ciphertexts, then one
all-or-none account transaction CAS-commits the roster version and eligibility digest;
every required session's expected version and complete next ratchet/bootstrap state;
every prekey tombstone, deduplication effect, or new-session record; and all immutable
per-device outbox items. Any CAS/fencing failure commits none of them and destroys all
candidate material; a required-device failure does not silently produce application
success.

If those sessions require external anchors, the transaction first records one
`PendingFanout` containing all sealed candidate states/effects and anchor intents. An
account-level anchor over the fanout digest is preferred; otherwise every required
anchor must confirm before one final transaction makes any session/outbox dispatchable.
A partially advanced set of external anchors remains unavailable but not partially
delivered, and recovery must complete the exact fanout or suspend/rekey it as a unit.
Post-commit network delivery may be partial and retries each immutable item
independently. Account serialization or a fixed account-then-sorted-session lock order
prevents deadlock. Explicit policy may quarantine a stale/incompatible device, but it
must expose that recipient exclusion to the caller.

Non-negotiable boundaries:

- `q-periapt-core` remains dependency-free and contains no account, server,
  database, clock, retry, or ratchet logic.
- `q-periapt-tls-demo` remains a synchronous authenticated-handshake experiment; it
  does not become the messaging implementation.
- The reference package is research/test-only and is not linked into the default
  product. The two lanes share only primitive providers: no KDF, codec, state enum,
  transition, migration logic, protocol/session ID, or persistence keyspace is shared.
  An upgrade creates a new session; ratchet state is never converted in place.
- `ReferenceProfile` freezes specification revisions, algorithms, encodings, limits,
  and the PQXDH/Triple-Ratchet/Sesame-manager integration choices. Component
  conformance, the composition, and external interoperability are separate claims.
- A session policy is one closed value: primitives, identity mode, prekey mode,
  ratchet construction, wire version, limits, cadence floor, and exact digest.
- The active state machine never receives a loose bag of algorithm names or caller-
  assembled context fields.
- The reference lane uses its fixed profile, not runtime policy resolution. The
  research lane receives a validated, indivisible `ResolvedSessionPolicy`; the
  current KEM-level `ResolvedSuite` cannot be reused as that type.
- `ContextBound` is used only when a Q-Periapt two-leg KEM combination actually
  occurs. Ordinary DH, symmetric, and sparse-PQ root transitions use distinct,
  domain-separated `SessionKdf` functions. A fixed-length canonical context digest,
  typed by its current authentication stage, may be KDF input; the combiner is never
  a transcript authenticator, ratchet KDF, identity verifier, or policy engine.
- A future narrow `q-periapt-session-crypto-contracts` layer must own the exact deterministic
  DH/KEM/KDF/AEAD/signature command/result semantics; it does not enlarge
  `q-periapt-core`. Reference commands preserve published DH/KEM ordering exactly and
  cannot substitute `HybridKem` or X25519-as-KEM for a specified operation.
- Bootstrap's peer-agreed authentication stages are `PrekeyAuthenticated ->
  PeerConfirmed -> MutuallyConfirmed`. `ZeroRttSent` is a separate local outbox/
  dispatcher state, because sending does not prove peer agreement. The test-only
  lifecycle model rejects a session/device/current-context graft before reservation,
  but deliberately does not implement those stage transitions. A pre-signed offline
  bundle is not a fresh sender-specific
  responder proof. Application privileges requiring mutual confirmation fail before
  the final stage. The corresponding context types prevent calling all bootstrap
  context “already authenticated,” which would be circular. This still trusts the
  initial model context and does not authenticate credentials, roles, freshness, or
  the digest encoding.
- Client directory/prekey/transparency ports do not substitute for an adversarial
  service model. A separate server model/harness owns lease, split-view, consistency,
  witness, delay, replay, quota, and receipt-linkability tests for R2.

## 4. Parity requirements — what competitors already do

These are P0 requirements, not novelty claims.

### 4.1 Identity, devices, and directory

- One account has a monotonic roster of independent devices.
- Every device has independent identity, prekey, and session keys; devices never
  share one ratchet root.
- A device certificate binds account, device ID, device epoch, capabilities,
  validity, public keys, and a stable policy authority/family/floor. An exact mutable
  policy digest belongs in the session transcript, not the long-lived certificate.
- Key changes, device additions, and revocations have explicit user-visible or
  transparency-backed semantics. A directory response or Merkle root alone is not
  proof of human identity or global consistency. Clients verify signed tree heads,
  inclusion and consistency, plus a stated gossip/witness/quorum or user-verified
  anchor; first-use, stale-checkpoint, and witness-unavailable behavior is explicit.
- The server may delay, drop, replay, equivocate, withhold one-time prekeys, or
  present split views. Availability and metadata attacks remain possible even when
  key substitution is detectable.

### 4.2 Asynchronous prekeys

- Signed medium-term classical and PQ prekeys, one-time pools, unambiguous key IDs,
  expiry, and an explicit last-resort mode.
- An honest service leases/removes atomically, but a malicious service can double-
  lease. The receiver locally permits at most one successful acceptance for a prekey
  ID and keeps a bounded tombstone; the accountability design must make service
  double-leasing detectable rather than pretending to provide a distributed atomic
  transaction. Server deletion is never the only one-time guarantee.
- One-time exhaustion never silently changes the security level. A signed policy
  either rejects or explicitly admits a last-resort key and binds that fact into the
  initial transcript.
- Exact initial-message retransmission is idempotent. The same key/nonce is never
  used to encrypt different bytes after a crash or retry.

### 4.3 Ratchet and bounded state

- A symmetric chain advances for every application message.
- A classical DH ratchet supplies rapid PCS when peers exchange messages.
- A sparse PQ mechanism supplies PQ FS/PCS without adding a full ML-KEM key and
  ciphertext to every message.
- Skipped keys, previous epochs, pending offers, retries, and input sizes are bounded
  before allocation or expensive cryptography.
- The implementation exposes the last confirmed PQ epoch and protocol progress, not
  an omniscient `pq_healed` truth value. A proof or simulator may call a trace healed
  only relative to an explicit compromise schedule and the selected construction's
  recovery rule. For ML-KEM Braid Triple Ratchet, the current specification requires
  two SCKA output keys to be mixed for its Module-LWE PCS statement. Time elapsed or
  an offer being sent is insufficient.

### 4.4 Transactional persistence and recovery

Sending uses a transactional outbox: advance the chain, encrypt, persist the new
state and immutable ciphertext, then send after commit. Receiving verifies and
decrypts on a candidate state, atomically commits the new state, local prekey
acceptance/tombstone, deduplication marker, consumed skipped key, and any
reply/receipt, then releases plaintext after commit.

Active prekey and ratchet state is not restored from an ordinary backup. A restore or
reinstall creates a new device epoch and fresh sessions. Detecting rollback moves the
session to an explicit suspended/rekey-required state; resetting counters and
continuing is forbidden. A fully rolled-back local store cannot detect its own fork:
the design therefore requires an explicit non-rollback hardware counter, transparency
checkpoint, or external witness. The selected anchor and its availability/privacy
trade-offs are part of the threat model, not an implicit platform promise.

### 4.5 Metadata and traffic-analysis parity

- Pad payloads under a published leakage/overhead rule; report padding separately
  from cryptographic overhead. [Apple PQ3](https://security.apple.com/blog/imessage-pq3/)
  publicly uses Padmé with at most 12 percent padding overhead.
- Define what the delivery service sees about sender, recipient, device fanout,
  roster/prekey lookups, receipts, push tokens, lengths, timing, and IP addresses.
  [Signal's sealed-sender design](https://signal.org/blog/sealed-sender/) reduces
  sender-envelope exposure while explicitly leaving timing/IP correlation as an open
  problem.
- Make prekey-consumption receipts and transparency lookups unlinkable or quantify
  the new linkage they introduce. Security accountability cannot silently worsen the
  social graph.
- Keep parser limits, errors, retries, and deletion policies uniform enough to avoid
  implementation fingerprinting. Proof and telemetry artifacts use synthetic or
  explicitly de-identified traces.

## 5. Research hypotheses — where a real lead might exist

None of the following is a novelty claim yet. Each is a hypothesis with known nearby
work and a required falsification test.

| ID | Hypothesis | Why it may matter | Known nearby work / reason not to overclaim | Required evidence |
|---|---|---|---|---|
| **R1 — authenticated policy-context continuity** | Commit one canonical `SessionContext` covering roles, account/device epochs, identity digests, prekey mode/IDs, directory checkpoint, protocol suite, policy digest, transcript, ratchet epochs, and direction at bootstrap and every root transition | Makes downgrade, cross-device mixup, last-resort use, and policy migration machine-visible instead of caller convention | PQ3 and Signal already bind extensive protocol data; hashing fields is not novel. The candidate contribution is one canonical closed typed decision in an open artifact plus a cross-layer agreement/refinement proof | Concrete attack or ambiguity prevented; symbolic authenticated agreement; exact cross-language vectors; spec-to-code mapping |
| **R2 — verifiable prekey accountability** | Commit batches of one-time hybrid prekeys under a signed Merkle manifest and explore privacy-preserving lease/consumption receipts | Amortizes large PQ signatures and makes one-time versus last-resort service behavior auditable | Merkle authentication of ephemeral keys and key-transparency systems already exist. Novelty, if any, is the privacy-preserving consumption/accountability composition, not the tree | Literature review; malicious-server model; unlinkability analysis; at-most-one successful local acceptance plus detection/audit of service double-lease or equivocation; bandwidth benchmark |
| **R3 — explicit active-PQ identity mode** | Bind a hardware-backed classical device credential and a PQ account/device credential to both roles and the bootstrap transcript, with stage-appropriate fresh PQ proof of possession while keeping PQ signatures off the ordinary hot path when the selected accountability semantics permit it | Apple PQ3 and the current PQXDH design authenticate classically; a mutually confirmed PQ control-plane proof could resist an active quantum attacker under its stated trust model | A receiver cannot provide a sender-specific fresh proof while offline, so zero-RTT starts only prekey-authenticated and becomes mutually confirmed after an online response. A static PQ certificate or one-sided PQ signature is insufficient. Post-quantum asynchronous deniable AKE using designated-verifier signatures is prior work. Ordinary ML-DSA signatures are transferable, large, and can weaken deniability. Apple now exposes Secure Enclave ML-DSA on supported systems, so hardware availability is an empirical matrix | Choose accountable-bootstrap, per-message origin accountability, or deniable semantics first; prove each stage's permissions, mutual authentication after confirmation, freshness, proof of possession, and KCI; measure cached/cold and per-message costs; document the hardware/OS boundary |
| **R4 — measurable PQ-healing debt** | Expose bounded last-confirmed PQ epoch/progress and derive `healing_debt` or vulnerable-message bounds only relative to an explicit compromise schedule in the model | Gives applications and policy honest observable progress without pretending the implementation knows when compromise occurred | Signal already analyzes vulnerable-message sets; Apple already bounds periodic rekey policy; Durak–Caforio–Vaudenay already study security-aware/on-demand ratcheting. The possible delta is an open runtime contract tied to policy, persistence and proof artifacts, not an absolute “healed” boolean | Define observables and schedule-relative metric formally; simulate realistic traffic/loss; show it bounds vulnerable-message exposure; prevent network-controlled downgrade/fingerprinting |
| **R5 — crash- and rollback-refined ratchet** | Prove that the transactional state machine never reuses a message key/nonce and that rollback/recovery cannot silently fork a device epoch when checked against an explicit non-rollback anchor or external witness | Real implementations fail at persistence boundaries that symbolic crypto models often abstract away | Transactional outboxes and monotonic counters are established systems techniques. Cremers–Jacomme–Naska already formally expose Sesame session-handling clone attacks and propose stronger mechanisms, so clone/session convergence is not new. A wholly rolled-back local store cannot detect its own rollback. The possible contribution is the joint protocol/storage/effect/anchor refinement and exact crash evidence | Crash injection at every boundary; concurrent-send/receive model; reproduce the published clone attack and mitigations; rollback/fork traces; anchor-loss and equivocation tests; machine-checked state invariants |
| **R6 — proof-to-state-to-byte** | Extend the evidence ledger from one handshake to the exact state transition, wire bytes, policy, binary, device run, and performance budget that implement each protocol claim | Could make a complex stateful protocol independently reproducible instead of presenting disconnected proof/test islands | Signal already reports ProVerif plus hax/F* implementation checking; current Q-Periapt proof-to-byte is not refinement. Public provenance alone is not stronger | Implementation-level refinement or translation validation; trace corpus generated from the model; external reproducibility and audit |
| **R7 — workload-matched sparse-ratchet frontier** | Compare whole-KEM periodic rekeys, ML-KEM Braid chunk sizes, receipts, and deterministic policy floors on bytes, energy, tail latency, loss tolerance, and vulnerable-message set | The best construction depends on traffic directionality and loss, not KEM cycles alone | PQ3 and Signal already amortize PQ material. Merely changing cadence is not novel | Same-device implementations, pre-registered workloads, Pareto analysis, and a security floor that an attacker cannot tune downward |
| **R8 — native PQ hardware/provider frontier** | Add an Apple platform adapter for current CryptoKit X-Wing/ML-KEM and [Secure Enclave ML-KEM/ML-DSA](https://developer.apple.com/documentation/cryptokit/secureenclave), then differentially compare it with the existing portable `mlkem-native`/`fips204` software provider | Non-exportable PQ keys may improve compromise containment, while platform-native code may change latency, energy, background availability, and footprint | Apple already supplies these APIs; using them is not novel and support is OS/device dependent. Apple's X-Wing documentation currently names draft-06, while local `CompatXWing` is pinned to draft-10, so CryptoKit is not assumed to be a draft-10 oracle. Current Q-Periapt keys do not automatically live in Secure Enclave, and no speed advantage is assumed | Freeze both provider/spec versions; official-vector and cross-encap/decap differential tests before comparison; physical iPad/iPhone/Mac support matrix; cold/warm latency, energy, lock/background behavior, access-control, export/restore, error, and downgrade tests |

The first narrow R1 diagnostic is now concrete: `PrekeySelectionV1` canonically binds
suite, responder account/device/epoch/credential, bundle epoch, directory checkpoint,
manifest, and independent classical/PQ mode and selected IDs. Lifecycle B21-B23 are
derived atomically, so a caller cannot relabel an arbitrary digest as a one-time
selection or hide one-leg exhaustion behind a lossy aggregate. Rust/Python exact-byte
vectors and EasyCrypt projection/omission checks cover that structure. This is an
assurance improvement over the repository's previous opaque tuple, not evidence that
PQ3 or Signal omit equivalent authenticated transcript binding and not a protocol
security result. R2's stateful accountability, unique lease, local tombstone,
double-lease evidence, split-view detection, and privacy analysis remain entirely open.

The R4/R5 prior-art boundary includes
[security-aware on-demand ratcheting](https://www.microsoft.com/en-us/research/publication/beyond-security-and-efficiency-on-demand-ratcheting-with-security-awareness/)
and the USENIX Security 2023
[formal analysis of Sesame session handling and clone attacks](https://www.usenix.org/conference/usenixsecurity23/presentation/cremers-session-handling).
The latter is especially important: a new manager model must reproduce those attacks
and proposed mitigations before claiming stronger conversation-level PCS.

The strongest plausible thesis is therefore not “another ratchet.” It is:

> a stateful hybrid session protocol whose identity, policy, prekey quality, healing
> progress, persistence state, exact wire bytes, formal model, implementation, and
> device evidence are bound into one auditable contract, while remaining within a
> published bandwidth/latency/energy budget.

That conjunction is a research target. It is not yet known to be novel, and the
novelty review must include current IETF work, Signal's 2025 papers/specifications,
PQ3 analyses, post-quantum asynchronous deniable AKE, key-transparency deployments,
and Merkle-authenticated ephemeral-key literature.

### 5.1 Research priority and stop conditions

The program should optimize for a defensible conjunction, not the largest feature
count. Work is ordered by how much it can improve security/assurance while preserving
a credible non-inferiority path:

| Priority | Combined track | Plausible delta beyond the public baseline | Parity prerequisite | Stop or redirect condition |
|---|---|---|---|---|
| **A** | R5 + R6: crash/rollback refinement plus proof-to-state-to-byte | Publicly bind the exact effect reservation, terminal outcome, state transition, record/wire bytes, implementation, device run and budget; neither provenance alone nor a transactional outbox alone is novel | Match Signal's implementation-level checking floor and the reference session behavior; implement real authenticated WAL/receipt/anchor adapters | Stop the “lead” claim if the source-to-state/byte link remains review-only, or if kill/rollback traces expose key/nonce reuse or false release |
| **A** | R1 + R3: typed policy/context continuity plus explicit active-PQ identity | A stage-typed, mutually confirmed accountable mode could close the classical-authentication boundary while keeping transferable PQ signatures off the ordinary hot path | Match offline bootstrap, KCI analysis, device identity, revocation, and confirmation semantics; maintain a separate deniable profile | Redirect if fresh PQ confirmation requires an extra blocking round trip, breaks the chosen deniability goal, or misses cached/cold mobile budgets |
| **B** | R7 + R8: workload-matched sparse ratchet plus native provider frontier | A signed, attacker-non-tunable security floor combined with measured software/Secure-Enclave provider choices may yield a better wire/energy/healing frontier on supported devices | Reproduce whole-KEM and ML-KEM-Braid reference traces byte/state accurately on the same hardware | Reject adaptive scheduling if network behavior can lower the floor or create stable fingerprints; reject a provider path that lacks version compatibility or non-inferiority |
| **B** | R2: privacy-preserving prekey accountability | Jointly detect double lease/equivocation while limiting receipt and lookup linkability | Match one-time/last-resort semantics, exhaustion behavior, replay handling and directory verification | Stop if accountability creates a larger social-graph oracle, unbounded proof traffic, or requires online recipient participation |
| **C** | R4: measurable healing debt | Honest, schedule-relative runtime observability tied to policy and evidence may improve operations | Reproduce the baseline vulnerable-message analyses and cadence behavior | Treat as instrumentation, not novelty, if it does not tighten a proved bound or enable a safe policy decision |

No track may trade away the parity floor to win a microbenchmark. A candidate advances
only if it is non-inferior on the frozen reference workload's security semantics and
meets its pre-registered wire, latency, energy, state, availability, privacy, and
healing limits. A Pareto win on selected cells is publishable; “faster, safer and more
stable everywhere” is not an admissible claim without an exhaustive matched matrix.

## 6. Performance strategy

Performance cannot be obtained by weakening the transcript or silently reducing PQ
frequency. It comes from keeping expensive operations off the hot path and measuring
the actual bottlenecks.

### 6.1 Candidate techniques

- Clone/precompute a SHA3 state only after absorbing a frozen, public-only prefix whose
  exact bytes are independently KAT-checked against the one-shot path. Never cache a
  state after secret, caller-private, or freshness-dependent input; bound entries/bytes,
  key cache identity by every public prefix field, and wipe on eviction. This is a
  byte-preserving optimization, not permission to omit a field.
- Cache validated device certificates and signed prekey manifests; transmit hashes
  or compact inclusion proofs on the initial path instead of repeating ML-DSA material.
  A cache miss or expiry fetches and authenticates the full object or fails; a hash is
  not a credential.
- Batch verification of one signed prekey-manifest root and reuse a validated directory
  checkpoint across bounded multi-device fanout instead of verifying one large PQ
  signature per device/message. Cache keys include account, roster epoch, policy and
  expiry; partial or stale cache hits fail rather than falling back.
- For bootstrap-peer accountability, sign enrollment, prekey roots, upgrades, and
  recovery events rather than every ordinary message. Ratcheted AEAD proves creation
  by a holder of the session key but not third-party-attributable origin. Apple-style
  per-message device accountability is a distinct profile and cost target; a deniable
  profile requires its own proof and cannot reuse either claim.
- Precompute a bounded pool of independently generated one-time keys while
  idle/charging and destroy each private key immediately after consumption. Do not
  retain a master derivation seed that can recreate deleted prekeys; any compact
  forward-secure generator is a separate construction requiring a proof and
  compromise analysis. RNG or secure-storage failure aborts generation.
- Precompute only sealed, operation-bound provider commands whose exact bytes and
  entropy reservations are durably installed before use. This can move key generation
  off the latency-critical path without permitting “crash then generate a new key” or
  an unbounded pool. Capacity, expiry, memory/keystore footprint and cleanup are gated.
- Piggyback PQ ratchet material and encrypted receipts; add no protocol-only online
  round trip.
- Stream and incrementally authenticate bounded sparse-PQ chunks to cap peak allocation
  and copy cost, but do not expose a new root key until the construction's complete
  epoch condition is satisfied. Parser work saved must be measured against loss-driven
  reassembly/state cost.
- Evaluate fixed-budget erasure coding only around authenticated chunk transport, never
  by treating reconstructed partial KEM material as an accepted epoch. Freeze the code,
  redundancy, byte overhead, maximum work/state, duplicate/conflict behavior, and the
  same healing-debt floor before the run; adversarial loss/reordering must not select a
  weaker cadence or create a parser/CPU oracle.
- Use a compact, canonical, length-bounded binary wire format with borrowed parsing
  where safe, a single transcript pass, and fixed-size stack/scratch storage for common
  headers. Parsing and state limits run before signature verification or decapsulation;
  zero-copy views never outlive their authenticated input buffer.
- Keep the common message path symmetric; isolate public-key transitions and measure
  their peak cost separately from amortized cost.
- Compare 32-byte and 64-byte Braid chunks and whole-KEM periodic rekeys under the
  same traces. Do not pick a cadence from a microbenchmark.
- Resolve software, CryptoKit and Secure Enclave providers at a typed session/epoch
  boundary from authenticated local capability and policy, never per message from
  peer input. Measure cold/warm setup, lock/background failures, copies across FFI,
  energy and code size; native hardware is selected only when it is secure and
  non-inferior for the declared cell.
- Allow charging/idle hints to move work earlier but never later than a signed maximum
  healing-debt/cadence bound. Network loss, receipts, thermal state or the server cannot
  silently lower the PQ security floor.

### 6.2 Acceptance budgets

These are design gates, not current measurements:

| Metric | Initial target |
|---|---:|
| Recipient participation rounds before first ciphertext | **0**; directory/cache work may block the sender and is measured end to end |
| Additional blocking protocol round trips for ordinary or PQ-ratchet messages | **0**; receipts remain measured protocol traffic |
| Cached initial-envelope protocol bytes | **≤ 6.5 KiB**, plus full cold/cached total bytes including credentials, transparency data, padding, and cache misses |
| Ordinary-message protocol header and tag | **≤ 128 B** |
| Average PQ-ratchet wire cost | **≤ 64 B/message** for the declared workload; peak bytes reported separately |
| Pure ordinary transition + serialization + AEAD p95 | **≤ 0.5 ms** on each supported physical mobile device |
| Durable send/receive p95 | Report and gate transition + repository transaction/fsync separately |
| Initial sender / receiver crypto p95 | **≤ 20 / 25 ms** on each supported physical mobile device |
| Scheduled PQ transition p95 | **≤ 10 ms** on each supported physical mobile device |
| Pre-registered workload amortized CPU delta vs matched classical reference | **< 10% target**, plus a separately pre-registered non-inferiority margin against the frozen session reference |
| State growth | Bounded by policy: finite devices, sessions, epochs, skipped keys, retries, and bytes |

This table is not yet G1-frozen. Before G1 closes, pilot measurements must set numeric,
device-class-specific thresholds for full cold bootstrap, durable send/receive
including fsync and anchor work, construction-specific whole-PQ-epoch completion,
energy/thermal non-inferiority, per-session/per-account/global state quotas, crash
recovery, and convergence under a stated fair-delivery schedule. “Report and gate” or
“bounded” without a number is not an acceptance criterion and cannot authorize an
implementation-performance claim.

The targets must be measured on physical iPad, iPhone, macOS, and Android hardware
under the same fixed payload corpus, credential-cache states, serialization/AEAD
boundary, power/thermal conditions, directionality, fanout, loss, reordering,
retransmission, receipts, and offline patterns. Workload denominators, sample sizes,
one-sided confidence bounds, non-inferiority margins, and stability gates are
pre-registered. A single-host KEM diagnostic cannot close a session-level performance
claim.

Performance reporting must include all of the following, because any one number can
mis-rank designs:

- cold and cached bootstrap bytes and p50/p95/p99 latency;
- ordinary-message and PQ-transition CPU, allocation, RSS, energy, and thermal state;
- average and peak wire overhead;
- healing time and vulnerable-message set for bidirectional chat, sender bursts,
  offline linked devices, delayed receipts, and controlled loss/reordering;
- state size and recovery time after crashes and reconnects.
- fault-path stability: every persistence failpoint, bounded-state exhaustion,
  duplicate delivery, convergence under stated fairness, and no wrong plaintext or
  key/nonce reuse.

## 7. Security invariants

The research lane fails closed unless all invariants hold:

1. The complete capability offer and selected protocol are authenticated; timeout or
   error never invokes a legacy fallback.
2. A peer/device that has authenticated a higher version cannot accept a lower one
   without an authenticated, monotonic recovery action.
   Version monotonicity is not security monotonicity: a code/hardware-pinned semantic
   floor and allowed migration partial order reject a newer but weaker identity mode,
   cadence, last-resort rule, or resource limit. Policy-signer rotation and compromise
   recovery are explicit.
3. A local one-time prekey ID permits at most one successful acceptance and leaves a
   bounded tombstone. Unknown, expired, reused, or wrong-mode IDs fail before
   application delivery; malicious-server double-lease is detected/audited, not
   declared impossible.
4. Epochs, counters, device generations, roster versions, and policy versions are
   bounded and monotonic; overflow and same-version/different-digest equivocation fail.
   Expiry and cadence floors use a stated trusted monotonic-time source; wall-clock
   rollback or attacker-controlled connectivity cannot postpone the security floor.
5. Confirmation/AEAD, signature, or storage failure commits no partial state and
   releases no plaintext. ML-KEM implicit rejection is not exposed as a distinct
   remote oracle; it closes through the uniform confirmation/AEAD failure path.
6. Send state and immutable outbox bytes commit before network release; retries resend
   identical bytes. Concurrent writers require a single-writer lease/fencing token in
   addition to the repository transaction.
7. Skipped keys are indexed by session, sender device, direction, epoch, and counter,
   used once, capped, expired deterministically, and zeroized best-effort.
8. After a sender observes and verifies a sufficiently fresh, consistent roster that
   revokes a device, it creates no new encryption for that device. Directory delay,
   offline cache staleness, queued ciphertext, and the freshness budget remain explicit.
   Restore/reinstall creates a new device epoch rather than reviving old ratchet state.
9. The runtime reports last-confirmed PQ epoch/progress, not an absolute compromise-
   recovery fact. In a trace with an explicit compromise schedule, a healed verdict
   requires the construction-specific recovery condition after the compromise (two
   mixed SCKA outputs for the cited ML-KEM Braid Triple Ratchet statement); offline
   peers, dropped chunks, or an outstanding offer remain incomplete.
10. RNG, hardware-keystore, database-integrity, or transparency-proof failure is an
    explicit error. An approved OS CSPRNG is valid; there is no weaker/unapproved RNG,
    old-state, or classical-only fallback.
11. Canonical lengths, chunk uniqueness, epoch windows, and per-session, per-account,
    and global inbox/outbox/skipped-key/PQ-work quotas are checked before allocation or
    expensive verification/decapsulation. Local errors remain typed and observable;
    remote failure classes are response- and timing-uniform enough not to enumerate
    prekey state or create a cryptographic oracle.
12. Release evidence consumes strict, bounded regular-file snapshots: duplicate keys,
    non-finite JSON, caller-controlled symlinks, ordinary read-time mutation, proof-selected device
    subsets, and proof-selected performance budgets fail closed. Hash comparison and
    semantic validation use the same bytes. Clean provenance also rejects hostile Git
    environment selection, hidden index flags, HEAD/index/actual-byte disagreement,
    local Git-exclude hiding, and repository Python bytecode caches. Covered Python
    entrypoints use isolated/no-site source dispatch with a fresh private cache prefix and
    cleared `PYTHON*` state.
    This is consistency evidence, not a
    replacement for a clean signed or transparency-backed manifest root.
13. Every modeled operation is admitted against a trusted durable pairwise session and
    exact current context commitment. A draft cannot select another device pair,
    self-assign a higher stage, or change the digest. Candidate role-ordered
    `LifecycleContextV1` body/policy/digest-preimage bytes, an independent Python
    encoder, and frozen SHA3 vectors now exist. The model still has no legal
    context-advance API; genesis/migration authenticity, role/profile-specific local
    stages, transition evidence, signed manifest/leaf semantics, strict outer and
    production decoders, and canonical operation/snapshot/record codecs remain explicit G1
    obligations.

## 8. Formal and implementation assurance gates

Signal's current public baseline includes ProVerif state-machine modeling and reports
hax-to-F* checks of core Rust preconditions, postconditions, and panic freedom on every
CI run. Q-Periapt cannot call its present source/hash/device ledger stronger than that;
the claim ledger correctly leaves spec-to-implementation refinement pending.

Continuity therefore requires:

1. **Executable reference model:** deterministic wire/state vectors and positive
   traces before networking code.
2. **Symbolic protocol model:** mutual device authentication, context agreement,
   replay/UKS/KCI, malicious directory, prekey consumption, revocation, downgrade,
   classical/PQ compromise schedules, FS, and PCS.
3. **State and storage model:** crash points, duplicate/reordered/lost messages,
   concurrent operations, bounded skipped keys, outbox idempotence, rollback, fork,
   counter overflow, and the exact non-rollback hardware/transparency/witness
   assumption used to detect a wholly restored local snapshot. The model and fault
   harness also cover secret/message-key remnants in WALs, old database pages,
   snapshots, system backups, crash reports, and diagnostic telemetry; compaction,
   retention, encryption-at-rest, exclusion, and deletion claims are provider-specific.
4. **Implementation linkage:** hax/F*, Verus, Creusot, translation validation, or an
   equivalently explicit method that proves the Rust transition functions refine the
   model and are panic-free. Tool choice follows a prototype; the property is mandatory.
   The production backend migration removed the `libcrux`/hax
   `proc-macro-error2` advisory edge, and the current lockfile passes
   `cargo audit --deny warnings` with no ignore. That dependency result does not
   satisfy the separate model-to-Rust refinement or independent audit requirement.
5. **Differential/reference lane:** exact state and wire comparisons against the
   published reference algorithms, plus negative controls for every security premise.
6. **Cross-language vectors:** Swift/Kotlin/C/WASM must reproduce canonical parsing,
   context bytes, state-transition outputs, and errors without reimplementing crypto.
7. **Proof-to-state-to-byte:** the final ledger binds claim, model, source, wire corpus,
   binary, device, and performance evidence while preserving each proof boundary.

## 9. Delivery gates

| Gate | Required outcome | Claims allowed afterward |
|---|---|---|
| **G0 — baseline correction** | All documentation names the published PQXDH and Triple Ratchet components plus the separately specified Sesame-compatible manager integration, and preserves current-vs-future boundaries | Accurate research comparison only |
| **G1 — specification** | Threat model, wire grammar, state/effect machine, identity and recovery semantics, complete service-visible metadata surface, padding/linkability/fingerprinting goals, secret-retention rules, and budgets frozen; accountable vs deniable goal chosen | Protocol proposal, no security claim. **Partial:** selected source revisions/reproducible content hashes, the candidate effect lifecycle, exact version+digest CAS, no-op-anchor rejection, role-ordered lifecycle context bytes, the strict 16-field prekey-selection record, independent encoders/decoders, frozen vectors, and structural EasyCrypt diagnostics are recorded. The model fixes durable pairwise session/current-context admission authority and atomic B21-B23 derivation but does not advance context. Mutable pages are not byte-archived; trusted genesis, manifest/identity/prekey/directory semantics, outer production codecs, lease/consumption state, ratchet, persistence adapters, metadata goals and numeric budgets remain open. |
| **G2 — reference lane** | Frozen component-conformant PQXDH and Triple Ratchet models plus a separately specified Sesame-compatible manager integration, adversarial simulator, and deterministic traces pass | Baseline-comparison implementation; composition and Signal interoperability remain separate claims unless independently demonstrated |
| **G3 — research proofs** | R1–R8 deltas each have attack/proof/benchmark justification; protocol, storage, padding/linkability, service-equivocation, and fingerprinting models pass | Scoped design-level claims |
| **G4 — implementation refinement** | Rust transition/effect core refines the model and is panic-free; cross-language vectors and WAL/backup/crash/telemetry secret-retention fault tests pass | Scoped implementation claim |
| **G5 — physical performance and observable surface** | Same-source iPad, iPhone, macOS, and physical Android matrix meets declared latency/wire/energy/state/padding/metadata budgets under frozen cache and traffic traces | Measured non-regression or Pareto claim for those cells |
| **G6 — independent review and pilot** | External cryptographic/code review plus operational fault/scale telemetry | Limited deployment claim within audited scope |

No gate may be skipped by relabeling a diagnostic as release evidence.

## 10. Claim discipline

Potential future claims, only after the corresponding gates close:

- “Continuity binds authenticated device, policy, prekey-quality, directory, and
  ratchet-state semantics to exact bytes and machine-checked state transitions.”
- “The selected sparse-ratchet profile lies on a measured security/bytes/energy
  Pareto frontier for the declared workloads and devices.”
- “The implementation refines the protocol/state model and the released device
  evidence is source-bound.”

Forbidden now and until independently established:

- “Q-Periapt already matches or exceeds PQ3 or Signal.”
- “Signal only protects the initial handshake” or “Signal has no PQ ratchet.”
- “K-CTX authenticates identities, prevents directory equivocation, or provides PCS.”
- “Merkle prekey manifests, chunking, receipts, adaptive cadence, or Triple Ratchet
  are Q-Periapt inventions.”
- “ML-DSA transcript signatures preserve Signal-style deniability.”
- “A ratchet heals a continuously active attacker, compromised RNG, or still-owned
  device.”
- “Proof-to-byte is a formal source-to-binary refinement.”
- “Performance parity” without matched, same-device, end-to-end measurements and
  explicit wire/energy/healing budgets.
- “PQ3/Signal product parity” from this pairwise-session plan; groups/MLS, calls,
  media, attachments, contact discovery, backup, abuse controls, and service-scale
  metadata defenses are outside its current scope.

## 11. Immediate research order

1. Keep the repository and paper baseline current with Signal SPQR/Triple Ratchet,
   ML-KEM Braid, Sesame, and its implementation-level verification claim. The 2026-07-11
   G0 documentation correction is complete subject to the repository validation gate.
2. Freeze the current KEM paper contribution; do not make the stateful protocol a
   hidden dependency of its theorem.
3. The public component comparison revisions and reproducible content hashes are recorded in
   `continuity/REFERENCE_BASELINE.md`; only versioned archives and the pinned Git
   commit are immutable. Archive the remaining mutable sources, specify the still-
   pending reference integration profile, then build deterministic component and
   manager state-machine simulators.
4. Choose accountable or deniable identity semantics for Continuity v1. The initial
   recommendation for SkyBridge/control-channel use is accountable hybrid identity;
   a deniable messenger is a separate research protocol.
5. Continue the focused novelty review and attempt to falsify R1–R8. The next highest-
   value implementation is not another codec: freeze the signed manifest/leaf and
   model local acceptance/tombstone, exact/conflicting replay, malicious double lease,
   directory fork, and rollback assumptions while measuring receipt linkability.
6. Select the sparse-ratchet candidate only after trace-based wire/energy/healing
   experiments, not from primitive microbenchmarks.
7. Make implementation refinement, physical-device budgets, and independent review
   release gates from the first prototype.

The current `models/q-periapt-continuity-model` artifact exercises only the candidate
effect/journal lifecycle in `continuity/G1_EFFECT_LIFECYCLE.md`. It fixes the trusted
pairwise session/current context at initialization, rejects session/device/context
grafts before reservation, deliberately exposes no context-advance API, and fixes the anchor
profile before reservation, separates provider results from service-created pin
records, persists the anchor plan before the anchor effect, replays an exact committed
release until a durable acknowledgement, and reconstructs new process objects from
abstract snapshots that retain every exact pending repository intent. Typed persist
subjects bind each stage; volatile results are scrubbed at every durable cut. A
security failure latches its first cause, reconciles that pending write, then installs
an append-only suspension intent with typed evidence that recovery can only quarantine.
Receipt application and finalization use validate/prepare-before-mutate paths, with a
private atomicity regression for invalid internal shapes. Its 31 lifecycle integration
tests, 12 canonical-context tests, eight strict prekey-selection tests, private
atomicity regression, and five-mutant
oracle are diagnostic, not exhaustive exploration or real database recovery. The
candidate role-ordered context projection and its 492-byte nested prekey-selection
record have independent Python encoders/decoders and frozen SHA3 vectors; their
EasyCrypt diagnostics cover structural injectivity and named omission collisions.
Exact state advances use version+digest CAS and a no-op anchor is
rejected before mutation. The host fsync-before-effect rule and receipt authentication
remain unimplemented adapter obligations. It is configured
with `publish = false`, has no real crypto or protocol bytes, and no product crate may
depend on it. Trusted genesis authenticity, credential/role/account/device-epoch
validation, accountable-versus-deniable protocol semantics, legal context-stage
transitions, signed manifest/leaf authenticity and membership, prekey leasing/
consumption/tombstones, directory consistency, ratchet
cursors, UKS/KCI, FS/PCS, and session-level rejection availability remain open.

The former local HQC/PQClean backend has been removed from the Continuity and product
shipping graphs. Suite code `3` is a permanent tombstone, not an agility slot to recycle.
The isolated `publish = false` RustCrypto `hqc-kem 0.1.0-rc.0`
HQC-v5/FIPS-207-draft shadow
may inform future comparisons, but it has no ABI/suite identity and cannot enter a
Continuity construction without a final-standard decision, maintained/audited binary-CT
implementation, mapped security/API proof, lifecycle integration, and fresh evidence.
NIST selecting HQC does not make this RC research lane ready.
