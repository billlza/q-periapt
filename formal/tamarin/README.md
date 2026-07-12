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

> **STATUS: MACHINE-CHECKED.** ✅ `make prove` verifies all five lemmas (Tamarin 1.10.0).

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
make prove      # prove all five lemmas
make check      # parse + wellformedness only (fast)
```
