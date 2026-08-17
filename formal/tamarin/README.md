# Symbolic handshake proof (Tamarin)

A symbolic (Dolev–Yao) model of the q-periapt **server-authenticated PQ/T hybrid KEM
handshake** ([`crates/q-periapt-tls-demo`](../../crates/q-periapt-tls-demo)), machine-
checked with [Tamarin](https://tamarin-prover.com/). This complements the EasyCrypt
proof in [`../easycrypt`](../easycrypt): EasyCrypt establishes the *combiner's* binding
in the computational model; Tamarin establishes the *protocol's* authentication and
hybrid secrecy in the symbolic model.

This is a **four-flight demo-handshake model**, not a model of PQXDH, Signal's
SPQR/Triple Ratchet, ML-KEM Braid, Sesame, Apple PQ3, or the future Q-Periapt
Continuity work. It has no identity directory, prekey lifecycle, persistent ratchet,
multi-device state, crash/rollback behavior, or recovery. The future proof matrix is
specified in [`../../docs/CONTINUITY_RESEARCH.md`](../../docs/CONTINUITY_RESEARCH.md);
none of those claims may be inferred from the five lemmas below.
The separate `publish = false` lifecycle model exercises opaque persistence/effect
ordering only; it is not imported into this Tamarin theory and proves no session
authentication, FS, PCS, or rollback property.

> **STATUS: CI HARD GATE.** `make prove` must verify all five lemmas with the workflow-pinned
> Tamarin 1.12.0 / Maude 3.5.1 toolchain on the exact release commit.

## Independent Migration Contract V2 hard gate

The migration proof is intentionally split into compositional theories so each
boundary is executable and terminating:

- [`migration_v2.spthy`](migration_v2.spthy) models a bounded one-advance CAS
  step over replayable `StoreSnapshot` and protected `WitnessPhase`. A reservation
  does not lock the head: transition/reset may advance it, after which the stale
  session cannot pass its exact head/fence acceptance recheck. The state includes
  `global_generation`, a lineage, legal `epoch-one` genesis/reset, committed
  digest, floor, and fence. Transition and reset require ideal signed certificates
  and the closed non-downgrade floor relation. `successor_state_executable`
  additionally proves that exact successor-store reconciliation returns the new
  head to idle and permits a successor session; rollback safety is not obtained by
  halting all future progress.
- [`migration_v2_agreement.spthy`](migration_v2_agreement.spthy) models the real
  authentication split. Each role locally signs its own capability offer and
  independently verifies the peer's role-owned offer under the pinned peer
  identity key, forming the same ordered joint decision. The two Finished flights
  are role-separated shared-key hashes over the post-KEM transcript: I-Finished,
  then responder verification/acceptance and R-Finished, then initiator
  verification/acceptance.
  Finished values are not identity signatures, neither offer signature depends on
  the peer signature, and there is no third commit flight. The accepted-key
  commitment and session identifier imply agreement on the entire authenticated
  joint-decision tuple. `IssuedCapabilityOffer` is an ideal signature-provenance
  fact: it records only offers honestly issued under a pinned key. The active
  network controls delivery tokens for exact public offers, retaining drop,
  delay, replay, and cross-session mixing; unissued or altered offers cannot pass
  the provenance check. This is an EUF-CMA abstraction, not a concrete signature
  proof.

  The current Rust migration typestates and Policy Agent commands follow this
  protocol-visible I -> responder accept/R -> initiator accept order for both KEM
  directions. That correspondence is exercised by tests, not proved as a
  Tamarin-to-Rust refinement. This theory also does not model the service rule that
  durable reservation release plus in-process key/response retention must finish
  before R is exposed, IPC schema/nonce processing, or the fact that a restart does
  not recover the accepted key or cached R.
- [`migration_v2_liveness.spthy`](migration_v2_liveness.spthy) is the focused
  progress projection: it proves an authority-issued, non-downgrade successor can
  be applied, exactly reconciled, and accepted. This keeps the safety theory's
  adversarial state space from turning liveness search into a non-terminating CI
  obligation.
- [`migration_v2_rollback.spthy`](migration_v2_rollback.spthy) is the focused
  rollback-safety projection. It retains replayable old store images, a protected
  linear witness head, a reservation that does not lock advance, and the exact
  witness/store acceptance recheck. Its executable traces show both current-head
  acceptance and an old-store restore after retirement; `mig_rollback` proves the
  stale reservation cannot accept after that retirement. A transition and reset
  branch also prove `mig_no_unauthorized_fork` from the same protected linear
  head. Signature authenticity and closed-floor checks remain in the main state
  theory rather than expanding this structural witness proof's search space.
- [`migration_v2_no_witness.spthy`](migration_v2_no_witness.spthy) is an explicit
  rollback countermodel: without the protected witness an old snapshot is accepted
  again after retirement.
- [`migration_v2_negative_controls.spthy`](migration_v2_negative_controls.spthy)
  gives executable reflection and below-floor traces when Finished role domains or
  the closed floor premise are removed.

The state theory proves one arbitrary advance/reset step; its reuse as an
inductive service invariant is an explicit abstraction boundary, not a
specification-to-Rust refinement. Ideal signature authenticity for the capability
offers corresponds to a separate EUF-CMA assumption; secrecy/authenticity of the
modeled shared key is also an external KEM premise. Tamarin does not prove concrete
state serialization, keyed-hash/KDF security, fsync/crash behavior, real IPC
isolation, acceptance-response durability, or Rust correspondence.

Required migration lemmas include `migration_executable`,
`transition_authenticity`, `reset_authorization`, `mig_agree_initiator`,
`mig_agree_responder`, `mig_agree_both_accept`, `mig_rollback`,
`mig_no_unauthorized_fork`, and `mig_floor`. `make prove` also proves the three
executable negative-control traces and checks every expected summary says
`verified`.

## File: [`handshake.spthy`](handshake.spthy)

Models the four-flight handshake:

```
  1. C -> S : ClientHello    = nc
  2. S -> C : ServerHello    = ek_pq, pk_x, ns
  3. C -> S : ClientKem      = ct_pq, ct_x         (encapsulate to the static hybrid key)
  4. S -> C : ServerFinished = sign_S(transcript), confirm = KDF(secret, ctx)
```

Both parties derive `secret = COMBINE(ss_pq, ss_x, <transcript-bound agility block>)`,
where `ss_pq` is the ML-KEM shared secret and `ss_x` the X25519 DH secret. The client
pins the server's ML-DSA verifying key out of band.

### Modeling abstractions
- **ML-KEM** as an idealized KEM (`ek = kempk(dk)`, `decap(dk, encap(kempk(dk), m)) = m`)
  — custom functions, not the `asymmetric-encryption` builtin, to avoid a `pk/1` clash
  with `signing`.
- **X25519** via the `diffie-hellman` builtin (CDH holds symbolically).
- **The combiner** as a one-way hash `h(<…>)`: deriving `secret` requires **both**
  `ss_pq` *and* `ss_x` — which is exactly the hybrid property under test.
- **ML-DSA** via the `signing` builtin.
- Adversary rules `Reveal_KEM_PQ`, `Reveal_KEM_Trad`, `Reveal_SignKey` model the
  independent compromise of each primitive.

## Lemmas proved

| Lemma | Meaning |
|-------|---------|
| `executable` | the honest handshake can complete (sanity, exists-trace) |
| `server_authentication` | a client that finishes ⟹ the server ran a matching session over the same key and transcript, unless the signing key was revealed |
| `authenticated_context_agreement` | absent signing-key compromise, the context accepted by the client is exactly the context previously committed by the server for the same session key and authenticated transcript |
| `hybrid_secrecy` | the accepted session key is secret unless **both** KEM components are broken **or** the signing key was revealed |
| `hybrid_robustness_authenticated` | **the headline:** with an honest server identity, the session key survives a break of *either* the post-quantum *or* the classical KEM — only breaking **both** loses it |

The `hybrid_robustness_authenticated` lemma is the symbolic statement of the suite's
core claim: the hybrid is secure as long as **at least one** of ML-KEM / X25519 remains
unbroken (given the signature authenticates the ephemeral key material).

## Run

```sh
make prove      # prove handshake, V2 migration gates, and countermodels
make check      # parse every theory (fast)
```

These bare commands are developer conveniences. The release hard gate first verifies
the pinned Tamarin/Maude identities, clears inherited make-control variables, and passes
`TAMARIN=tamarin-prover DERIVCHECK_TIMEOUT=60` as make command-line variables so the
proof cannot use ambient tool or resource-policy overrides.
