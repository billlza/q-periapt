# Symbolic handshake proof (ProVerif)

A symbolic (Dolev–Yao) model of the q-periapt **server-authenticated PQ/T hybrid KEM
handshake** ([`crates/q-periapt-tls-demo`](../../crates/q-periapt-tls-demo)), machine-
checked with [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/). This is the
**independent second symbolic tool** alongside the Tamarin model in
[`../tamarin`](../tamarin): same protocol, same abstractions, same properties, but a
different prover and a different formalism (applied-pi processes + correspondence queries
vs. multiset rewriting). Two unrelated provers agreeing is the **assurance-diversity**
argument — a soundness bug in one tool is unlikely to be shared by the other. It also
complements the EasyCrypt proof in [`../easycrypt`](../easycrypt), which establishes the
*combiner's* binding in the computational model.

This model is deliberately limited to the current four-flight demo handshake. It is
not PQXDH, SPQR/Triple Ratchet, ML-KEM Braid, Sesame, PQ3, or a persistent session
state machine, and it proves nothing about prekey consumption, multi-device
convergence, crash consistency, rollback, or compromise-timed PQ healing. The
future-only Continuity verification gates are in
[`../../docs/CONTINUITY_RESEARCH.md`](../../docs/CONTINUITY_RESEARCH.md).
The test-only lifecycle model under `models/` is not a ProVerif protocol model and
does not extend any query in this directory.

> **STATUS: MACHINE-CHECKED.** ✅ `make prove` verifies all six queries (ProVerif 2.05).

## File: [`handshake.pv`](handshake.pv)

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
  — exactly as in the Tamarin model.
- **The combiner** as a one-way function `combine(…)` over **both** `ss_pq` *and* `ss_x`
  plus the transcript-bound agility block: deriving `secret` requires **both** component
  secrets — which is the hybrid property under test.
- **ML-DSA** via a standard signature theory (`verify(sign(m, k), pk(k)) = m`); the client
  pins the server's `vk`.
- Per-primitive reveal processes (`revealPQ`, `revealTrad`, `revealSig`) leak each
  long-term secret independently and log a matching `RevealPQ` / `RevealTrad` /
  `RevealSig` event, mirroring Tamarin's `Reveal_KEM_PQ` / `Reveal_KEM_Trad` /
  `Reveal_SignKey` rules.

### Difference vs the Tamarin model (one deliberate abstraction)
The Tamarin model uses its native `diffie-hellman` builtin for the X25519 leg (real
exponentiation, with `ss_x = ct_x ^ x`). **ProVerif's equational reasoning over
Diffie–Hellman is limited** — its `exp` theory is incomplete for the secrecy goals we
need, so it cannot reliably discharge hybrid secrecy under a raw-DH model. We therefore
model the **classical leg as a second idealized KEM** (`xpk` / `xencap` / `xdecap`),
structurally parallel to the ML-KEM leg. Both tools thus agree on the abstraction
*"a static-key key-agreement whose shared secret stays hidden unless its long-term
secret leaks"*; they differ only in **how the classical leg is idealized** (raw DH in
Tamarin, idealized KEM here). The hybrid property under test — `secret` needs **both**
component secrets — is identical, and seeing it proved under two different idealizations
of the classical leg is itself part of the diversity argument. This is the only modeling
divergence from the Tamarin file; everything else (events, reveals, transcript binding,
pinned `vk`, key-confirmation check) is one-to-one.

## Queries proved

| Query | Mirrors (Tamarin) | Meaning |
|-------|-------------------|---------|
| reachability of `ClientFinish` | `executable` | the honest handshake can complete (sanity — ProVerif reports `not event(ClientFinish) is false`, i.e. the event is reachable) |
| `inj-event(ClientFinish) ==> inj-event(ServerDone) ∥ RevealSig` | `server_authentication` | **injective** agreement: a client that finishes ⟹ a distinct prior server run over the same `(secret, transcript, context)` (no replay), unless the signing key was revealed |
| `ClientFinish(vk,k,tr,ctx) ==> ServerDone(vk,k,tr,ctx) ∥ RevealSig` | `authenticated_context_agreement` | absent signing-key compromise, the client accepts exactly the context previously committed by the server for the same key and authenticated transcript |
| `ClientFinish ∧ attacker(k) ==> (RevealPQ ∧ RevealTrad) ∥ RevealSig` | `hybrid_secrecy` | the accepted session key is secret unless **both** KEM components are broken **or** the signing key was revealed |
| `ClientFinish ∧ attacker(k) ==> RevealTrad ∥ RevealSig` | `hybrid_robustness_authenticated` (corner a) | a **lone post-quantum break is survived**: leaking the key needs the classical leg broken too (or the signature) |
| `ClientFinish ∧ attacker(k) ==> RevealPQ ∥ RevealSig` | `hybrid_robustness_authenticated` (corner b) | a **lone classical break is survived**: leaking the key needs the post-quantum leg broken too (or the signature) |

The last two queries are the symbolic statement of the suite's core claim — the hybrid is
secure as long as **at least one** of ML-KEM / X25519 remains unbroken (given the
signature authenticates the ephemeral key material). ProVerif cannot place `not(RevealSig)`
in a query hypothesis the way Tamarin's lemma does, so the headline robustness property is
encoded as the two single-break corners directly; together they are strictly stronger than
the plain secrecy disjunction.

## Run

```sh
make prove      # prove all six queries and match every expected RESULT individually
make check      # syntax/typing check only (fast, `-test`)
```

Install the CI-pinned ProVerif via OPAM (`opam install proverif.2.05`). On macOS the optional GUI dependency
needs system libs first: `brew install gtk+ expat && opam install --assume-depexts
proverif.2.05`. The CLI verifier (`proverif`) is all that `make prove` needs.
