# Q-Periapt Combiner Specification

> **Status:** authoritative, byte-exact. This document pins the two combiner
> profiles of the Q-Periapt PQ/T hybrid KEM. It is written against, and must stay
> in lock-step with, the implementation in
> [`crates/q-periapt-core/src/lib.rs`](../crates/q-periapt-core/src/lib.rs)
> (`combine`, `Profile`, `absorb_lp`, `CombineInput`, `Secret`, `DOMAIN`,
> `XWING_LABEL`) and the C2PRI guard in
> [`crates/q-periapt-kem/src/lib.rs`](../crates/q-periapt-kem/src/lib.rs)
> (`HybridKem::new`). Byte-exactness of `CompatXWing` is proved by the KAT in
> [`crates/q-periapt-backends/src/xwing_kat.rs`](../crates/q-periapt-backends/src/xwing_kat.rs).
> The security argument lives in
> [`docs/BINDING_SECURITY.md`](./BINDING_SECURITY.md) — read it for the binding
> notions, the threat model, and the EasyCrypt mechanization scope. Any
> wire-incompatible change here is a breaking change and **must** bump `DOMAIN`.

---

## 0. Scope and non-goals

Q-Periapt does **not** implement any cryptographic primitive. ML-KEM-768, X25519,
HQC, SHA3-256 and SHAKE256 come from vetted backends (libcrux / HACL\*-derived,
x25519-dalek, pqcrypto-hqc, fips205). This document specifies only the
**composition** layer — how the two component KEMs' shared secrets, ciphertexts
and public keys are hashed into one 32-byte combined secret. The combiner is the
entire security-critical surface that Q-Periapt itself owns; it is deliberately
tiny, `no_std`, `deny(unsafe_code)` (with the one documented `Secret::drop` wipe),
and primitive-agnostic so it can be audited in isolation.

This is **research-grade, not production**: there is no third-party audit, and the
backends are pre-1.0 / unaudited (libcrux 0.0.9 asks you to contact maintainers
before production use). Do not deploy.

The combiner produces a `SHARED_SECRET_LEN = 32`-byte secret
([`q-periapt-core/src/lib.rs:33`](../crates/q-periapt-core/src/lib.rs)) wrapped in
`Secret`, which is securely zeroized on drop (volatile zero writes + a `SeqCst`
compiler fence — the `zeroize` technique inlined to keep the core dependency-free)
and is intentionally **not** `Clone`/`Copy`.

---

## 1. Common interface

```rust
pub fn combine<X: Xof256>(profile: Profile, input: &CombineInput<'_>)
    -> Result<Secret, Error>;
```

- `X: Xof256` is the injected hash/XOF (`new` / `absorb` / `squeeze32`). In
  production it is instantiated to SHA3-256 (`Sha3_256Xof`); the core depends on no
  concrete primitive.
- `Profile` selects the construction (`CompatXWing = 1`, `ContextBound = 2`).
- `CombineInput<'a>` carries everything either profile might bind, as byte slices:

  | Field | Type | Bound by `CompatXWing` | Bound by `ContextBound` |
  |-------|------|------------------------|-------------------------|
  | `suite_id` | `&[u8]` | no | yes (field 1) |
  | `policy_version` | `u32` | no | yes (field 2, 4-byte BE) |
  | `ss_pq` | `&[u8]` | yes | yes (field 3) |
  | `ss_trad` | `&[u8]` | yes | yes (field 4) |
  | `ct_pq` | `&[u8]` | **no** (omitted — see §4) | yes (field 5) |
  | `pk_pq` | `&[u8]` | **no** (omitted — see §4) | yes (field 6) |
  | `ct_trad` | `&[u8]` | yes | yes (field 7) |
  | `pk_trad` | `&[u8]` | yes | yes (field 8) |
  | `context` | `&[u8]` | no | yes (field 9, mandatory non-empty) |

- Return: `Secret` on success, or `Error` (`InvalidLength` / `PolicyDenied` /
  `Backend`). `Error` is deliberately coarse and carries **no** secret-dependent
  information; every variant is a publicly observable condition (§5).

The two profiles are domain-separated: `CompatXWing` is keyed by `XWING_LABEL`
(`5c 2e 2f 2f 5e 5c` = ASCII `\.//^\`, 6 bytes,
[`lib.rs:41`](../crates/q-periapt-core/src/lib.rs)), and `ContextBound` is keyed
by `DOMAIN = b"Q-PERIAPT-HYBRID-KEM/v1"`
([`lib.rs:37`](../crates/q-periapt-core/src/lib.rs)) absorbed as field 0. The two
tags are distinct in both content and length, so an honest transcript of one
profile can never alias the other.

---

## 2. Profile `CompatXWing` — byte-exact X-Wing

### 2.1 Definition

`CompatXWing` reproduces the X-Wing combiner of
`draft-connolly-cfrg-xwing-kem` **byte-for-byte**:

```
K = SHA3-256( ss_pq ‖ ss_trad ‖ ct_trad ‖ pk_trad ‖ XWingLabel )
```

where in X-Wing terms `ss_pq = ss_M` (ML-KEM-768 shared secret), `ss_trad = ss_X`
(X25519 shared secret), `ct_trad = ct_X` (the X25519 ephemeral public key),
`pk_trad = pk_X` (the X25519 recipient public key), and
`XWingLabel = 5c 2e 2f 2f 5e 5c`.

The implementation
([`lib.rs:226-239`](../crates/q-periapt-core/src/lib.rs)) absorbs, in order:

1. `ss_pq` (32 B)
2. `ss_trad` (32 B)
3. `ct_trad` (32 B)
4. `pk_trad` (32 B)
5. `XWING_LABEL` (6 B)

then squeezes 32 bytes.

### 2.2 Hard 32-byte length checks (no length prefixes)

There are **no length prefixes**: the five fields are concatenated raw, exactly as
X-Wing specifies. Raw concatenation is only injective when every field has a fixed,
known width. Therefore `combine` **hard-checks** that all four absorbed fields are
exactly `SHARED_SECRET_LEN = 32` bytes before absorbing anything
([`lib.rs:227-233`](../crates/q-periapt-core/src/lib.rs)):

```rust
if input.ss_pq.len()   != SHARED_SECRET_LEN
|| input.ss_trad.len() != SHARED_SECRET_LEN
|| input.ct_trad.len() != SHARED_SECRET_LEN
|| input.pk_trad.len() != SHARED_SECRET_LEN
{ return Err(Error::InvalidLength); }
```

Without this guard, arbitrary-length slices could collide across field boundaries
(e.g. a 33-byte `ss_pq` + 31-byte `ss_trad` would absorb identically to 32 + 32),
collapsing domain separation. `ct_pq` and `pk_pq` are **not** length-checked here
because they are not absorbed by this profile (§4). The negative unit test
`compat_rejects_wrong_length`
([`lib.rs:368-377`](../crates/q-periapt-core/src/lib.rs)) pins a 33-byte `ss_pq`
to `Error::InvalidLength`.

### 2.3 Single 134-byte Keccak block, allocation-free

The absorbed input is `32 + 32 + 32 + 32 + 6 = 134` bytes. SHA3-256 has a Keccak
rate of `136` bytes (`1088` bits), so `134` input bytes plus SHA3 domain-separation
and padding fit in **exactly one Keccak-f[1600] permutation**. The path performs
no heap allocation: each field is absorbed directly from the caller's slice into
the sponge state and 32 bytes are squeezed out. This is the parity-fast path.

### 2.4 Byte-exactness is proved, not asserted

`crates/q-periapt-backends/src/xwing_kat.rs::xwing_draft_kat_byte_exact` drives
`HybridKem::<MlKem768, X25519, Sha3_256Xof>::new(.., Profile::CompatXWing, b"", 0)`
through three official `draft-connolly-cfrg-xwing-kem` vectors (`XWING_VECTORS`).
For each vector it reconstructs X-Wing's own key expansion
(`SHAKE256(seed, 96) = ML-KEM(d‖z) ‖ skX`) and encapsulation-coin split
(`m = eseed[0..32]`, `ekX = eseed[32..64]`), then asserts **byte equality** on:

- the concatenated public key `pk_M ‖ pk_X` vs the vector's `pk`
  ([`xwing_kat.rs:50`](../crates/q-periapt-backends/src/xwing_kat.rs)),
- the concatenated ciphertext `ct_M ‖ ct_X` vs the vector's `ct`
  ([`xwing_kat.rs:76`](../crates/q-periapt-backends/src/xwing_kat.rs)),
- the encapsulated shared secret vs the vector's `ss`
  ([`xwing_kat.rs:77-81`](../crates/q-periapt-backends/src/xwing_kat.rs)), and
- the decapsulated shared secret vs the same `ss`
  ([`xwing_kat.rs:99-103`](../crates/q-periapt-backends/src/xwing_kat.rs)).

Because the public-key, ciphertext and shared-secret assertions all pass against
the published vectors, the test also exercises the libcrux ML-KEM-768 backend.

**Honest scope:** this reproduces the FIPS 203 reference output on those **three
happy-path X-Wing draft vectors**. It is not a full ACVP / FIPS 203 validation
(that is pending — see [`docs/ROADMAP.md`](./ROADMAP.md)); do not describe it as
"validates against FIPS 203."

---

## 3. Profile `ContextBound` — injective, domain-separated, hash-everything

### 3.1 Definition

`ContextBound` is the GHP / Chempat "hash-everything" combiner: every component
secret, every ciphertext, every public key, the agility block, and a mandatory
context are absorbed under an **injective, fixed-width length-prefixed,
domain-separated** encoding.

```
K = SHA3-256( Encode( DOMAIN,                          // field 0 (= LABEL)
                      suite_id, policy_version,        // fields 1–2 (agility block)
                      ss_pq, ss_trad,                  // fields 3–4
                      ct_pq, pk_pq,                    // fields 5–6
                      ct_trad, pk_trad,                // fields 7–8
                      context ) )                      // field 9 (mandatory)
```

The implementation
([`lib.rs:250-267`](../crates/q-periapt-core/src/lib.rs)) absorbs the fields in
exactly this order, each via `absorb_lp`.

### 3.2 Canonical field order

| # | Field | Encoding | Purpose |
|---|-------|----------|---------|
| 0 | `DOMAIN` (= `b"Q-PERIAPT-HYBRID-KEM/v1"`) | `LP(DOMAIN)` | domain-separation label; cross-profile separation from `XWING_LABEL` |
| 1 | `suite_id` | `LP(suite_id)` | agility / downgrade-resistance binding |
| 2 | `policy_version` | `LP(policy_version.to_be_bytes())` (4-byte BE) | agility / downgrade-resistance binding |
| 3 | `ss_pq` | `LP(ss_pq)` | ML-KEM-768 shared secret |
| 4 | `ss_trad` | `LP(ss_trad)` | X25519 shared secret |
| 5 | `ct_pq` | `LP(ct_pq)` | ML-KEM-768 ciphertext (bound directly) |
| 6 | `pk_pq` | `LP(pk_pq)` | ML-KEM-768 encapsulation key (bound directly) |
| 7 | `ct_trad` | `LP(ct_trad)` | X25519 ephemeral public |
| 8 | `pk_trad` | `LP(pk_trad)` | X25519 static public |
| 9 | `context` | `LP(context)` | mandatory non-empty caller context |

`DOMAIN` is field 0, distinct in content **and length** from `CompatXWing`'s
6-byte `XWING_LABEL`. `suite_id` and `policy_version` are bound first-class so a
suite/profile/policy downgrade or substitution changes the derived key at the KEM
layer, not only via the opaque `context`. The unit test
`context_bound_binds_suite_and_version_and_context`
([`lib.rs:380-396`](../crates/q-periapt-core/src/lib.rs)) confirms that changing
`suite_id`, `policy_version`, or `context` each changes `K`.

### 3.3 Injective encoding — fixed-width 8-byte big-endian length prefix

Every field is absorbed via `absorb_lp`
([`lib.rs:200-208`](../crates/q-periapt-core/src/lib.rs)):

```rust
fn absorb_lp<X: Xof256>(x: &mut X, data: &[u8]) {
    x.absorb(&(data.len() as u64).to_be_bytes()); // 8-byte big-endian length prefix
    x.absorb(data);
}
```

So each field is encoded as `LP(data) = be64(len(data)) ‖ data`, an **8-byte
fixed-width big-endian length prefix** followed by the raw bytes, and:

```
Encode(F0, …, F9) = LP(F0) ‖ LP(F1) ‖ … ‖ LP(F9)
```

The fixed width is mandatory: a variable-width length would itself need delimiting,
re-introducing ambiguity. Because the width is fixed at 8 bytes, no two distinct
field tuples — **including tuples that differ only in where a field boundary
falls** — can map to the same byte string. The negative test
`injective_encoding_prevents_boundary_collision`
([`lib.rs:407-417`](../crates/q-periapt-core/src/lib.rs)) pins this: the tuples
`(suite_id="AB", context="C")` and `(suite_id="A", context="BC")`, which would
collide under naive `‖` concatenation, derive distinct keys.

This injectivity is the load-bearing step of the collision-resistance → binding
reduction. In `formal/easycrypt/BindingViaCR.ec`, `encode_inj` is now a **proved
lemma**, not an axiom: the canonical encoding is modeled concretely and its
injectivity is proved, reducing only to two elementary `be8` facts (8-byte fixed
width + injectivity of `to_be_bytes`) plus collision-resistance of SHA3. See
[`docs/BINDING_SECURITY.md`](./BINDING_SECURITY.md) §3.2 and §4.2.

### 3.4 Mandatory non-empty context

`ContextBound` rejects an empty `context` with `Error::InvalidLength`
**before absorbing anything** ([`lib.rs:254-256`](../crates/q-periapt-core/src/lib.rs)):

```rust
if input.context.is_empty() { return Err(Error::InvalidLength); }
```

If `context` could be empty, the `MAL-BIND-K-CTX` guarantee degenerates. Callers
with no application context **must** pass a fixed protocol/role/version label (e.g.
`"ContextBound/v1/initiator"`). The test
`context_bound_requires_nonempty_context`
([`lib.rs:398-405`](../crates/q-periapt-core/src/lib.rs)) pins the empty-context
rejection. See [`docs/BINDING_SECURITY.md`](./BINDING_SECURITY.md) §3.3.

### 3.5 Cost vs `CompatXWing` (honest)

`ContextBound` absorbs roughly 2.3 KB more than `CompatXWing` — the full ML-KEM-768
`ct_pq` (~1088 B) and `pk_pq` (~1184 B), plus the agility block, length prefixes
and context — so its combiner hashing is deliberately ~19× more than the
single-block X-Wing path (measured in
`crates/q-periapt-backends/benches/combiner.rs`). This is the price of
binding everything with **no** assumption on the component KEMs; it is **not** a
speed win and **not** a stronger notion on the standard CT/PK axes (both profiles
hit the same `MAL` ceiling — see [`docs/BINDING_SECURITY.md`](./BINDING_SECURITY.md)
§5). The combiner is well under 1% of a handshake, so the absolute cost is
negligible.

---

## 4. The C2PRI safety guard

`CompatXWing` omits `ct_pq` and `pk_pq` from the KDF (it hashes only the
*traditional* ciphertext and public key, per X-Wing). That omission is sound
**only** when the PQ KEM is **ciphertext second-preimage resistant (C2PRI)** —
i.e. it provably binds its own ciphertext, so the combiner does not need to. This
is the load-bearing property that lets X-Wing's lean absorb stay binding.

This is encoded in the `Kem` trait
([`q-periapt-core/src/lib.rs:125-152`](../crates/q-periapt-core/src/lib.rs)) as an
associated const, defaulting to the **safe** value:

```rust
const C2PRI: bool = false; // a KEM that does not prove C2PRI is forced to ContextBound
```

Backends declare it explicitly:

- `MlKem768`: `const C2PRI: bool = true;`
  ([`backends/src/lib.rs:84`](../crates/q-periapt-backends/src/lib.rs)) — ML-KEM-768
  binds its ciphertext via the FO transform.
- `X25519`: inherits the `false` default
  ([`backends/src/lib.rs:131`](../crates/q-periapt-backends/src/lib.rs)) — raw ECDH
  does not bind its "ciphertext."
- `Hqc`: `const C2PRI: bool = false;`
  ([`backends/src/hqc.rs:65`](../crates/q-periapt-backends/src/hqc.rs)) — confined
  to `ContextBound`.

The guard is enforced once, at construction, in
`HybridKem::new` ([`q-periapt-kem/src/lib.rs:50-53`](../crates/q-periapt-kem/src/lib.rs)):

```rust
if matches!(profile, Profile::CompatXWing) && !P::C2PRI {
    // The fast profile omits the PQ ciphertext; only safe for a C2PRI KEM.
    return Err(Error::PolicyDenied);
}
```

So pairing a **non-C2PRI** PQ KEM (X25519-as-PQ, HQC, or any backend that does not
override the default) with `CompatXWing` is rejected at build time with
`Error::PolicyDenied`, confining non-C2PRI components to `ContextBound`, which
binds every ciphertext and public key directly and therefore needs **no** binding
assumption on the components. The guard is decided at the type level (`P::C2PRI`)
and exercised by the KEM-crate test that pairs a non-C2PRI toy KEM with
`CompatXWing` and asserts `Some(Error::PolicyDenied)`
([`q-periapt-kem/src/lib.rs:273-275`](../crates/q-periapt-kem/src/lib.rs)).

> **Why a guard and not a silent fallback:** failing closed (an explicit
> `PolicyDenied`) makes a profile/KEM mismatch a loud, testable construction-time
> error rather than a quietly-weakened binding. The fast path is opt-in and only
> reachable when the type system has witnessed `C2PRI = true`.

---

## 5. Error and failure-path discipline

`Error` ([`q-periapt-core/src/lib.rs:45-66`](../crates/q-periapt-core/src/lib.rs))
has exactly three variants, each a **public** condition:

- `InvalidLength` — a `CompatXWing` field was not 32 bytes (§2.2), or a
  `ContextBound` `context` was empty (§3.4). Attacker-known buffer facts.
- `Backend` — an opaque backend-primitive failure.
- `PolicyDenied` — a forbidden profile/KEM combination (§4).

No variant encodes secret-dependent information — in particular, **none** signals
"why a decapsulation failed." Component KEMs use **implicit rejection**: an invalid
ciphertext yields a pseudorandom shared secret, not an error
(`HybridKem::decapsulate`,
[`q-periapt-kem/src/lib.rs`](../crates/q-periapt-kem/src/lib.rs)), so the failure
path is value- and control-flow-indistinguishable from success at the combiner
boundary. The core provides branch-free helpers `ct_eq` / `ct_select32` /
`ct_is_zero` ([`lib.rs:272-304`](../crates/q-periapt-core/src/lib.rs)) as the
primitives for implicit rejection (run both the real and rejection derivations,
then select with a mask).

**Side-channel CI posture (honest):** failure-path indistinguishability / implicit
rejection **is** a hard CI gate (ctstats). The dudect **timing** test is
**report-only** (runs with `|| true`, not a merge gate). Binary-level constant-time
checking (ctgrind / Valgrind-TIMECOP) is **TODO**. The portable `ct_*` helpers are
best-effort in safe Rust; do not read this as "timing is gated." See
[`docs/ROADMAP.md`](./ROADMAP.md) and [`docs/THREAT_MODEL.md`](./THREAT_MODEL.md).

---

## 5b. Reference vectors

`ContextBound` is pinned by a positive KAT,
[`crates/q-periapt-backends/src/contextbound_kat.rs`](../crates/q-periapt-backends/src/contextbound_kat.rs):
fixed `(suite_id, policy_version, components, context) → K` vectors, each verified
against `combine()` **and** an independent recomputation (RustCrypto SHA3-256 over a
from-scratch encoder of this §3 layout), plus a length-prefix **collision pair** —
two transcripts with byte-identical naive concatenation but distinct keys — that makes
the injectivity property load-bearing. `CompatXWing`'s reference vectors are the
official `draft-connolly-cfrg-xwing-kem` set (`xwing_kat.rs`).

The **enhanced suite** (ML-KEM-1024 + X25519, NIST level 5) is pinned end-to-end by
[`crates/q-periapt-backends/src/enhanced_kat.rs`](../crates/q-periapt-backends/src/enhanced_kat.rs):
a real `HybridKem<MlKem1024, X25519>` `ContextBound` round-trip whose 32-byte secret is
fixed three ways — round-trip recovery, an independent length-prefixed SHA3-256
recompute over the actual ML-KEM-1024 / X25519 components (this §3 layout), and a golden
hex. Because ML-KEM-1024 + X25519 is not an external standard (X-Wing is ML-KEM-768-only),
a self-pinned, independently-cross-checked vector is the strongest available KAT for it.

## 6. Security cross-reference

The binding security argument is **not** restated here; it is owned by
[`docs/BINDING_SECURITY.md`](./BINDING_SECURITY.md). Summary of what that document
establishes, with the honest caveats:

- The core theorem `bind_le_cr` (`Adv^{X-BIND-K-*} ≤ Adv^{CR}(H)`, instantiating to
  `MAL-BIND-K-CT` / `K-PK` / `K-CTX`) is **machine-checked in EasyCrypt**
  (`formal/easycrypt/BindingViaCR.ec`, 0 admits).
- `encode_inj` (§3.3) is now a **proved lemma**, not an axiom — the §3.3 injective
  encoding is exactly the object it proves injective.
- `ContextBound` reduces binding to **collision-resistance of SHA3 alone**, with
  **no** binding assumption on ML-KEM or X25519.
- `ContextBound` is **not** "stronger binding than X-Wing" on the standard CT/PK
  axes — a correctly-implemented seed-format X-Wing reaches the same `MAL` ceiling.
  The defensible delta is **assumption-minimality and proof coverage**, plus the
  orthogonal `K-CTX` context-binding axis. Never claim "faster than X-Wing"
  (`CompatXWing` is X-Wing byte-for-byte; the generic abstraction measures tens of ns
  slower than a streaming X-Wing reference — negligible).
- Scope: H's CR is a modeling assumption; IND-CCA2 robustness is argued on paper;
  there is no spec↔impl linkage proof; `X-BIND-CT-*` is structurally impossible for
  implicitly-rejecting ML-KEM and is **not** claimed.

---

## 7. Change-control

- Any change to the absorbed bytes, field order, length-prefix width, label, or
  domain string of `ContextBound` is **wire-incompatible** and **must** bump
  `DOMAIN` (`…/v1` → `…/v2`).
- `CompatXWing` is pinned to `draft-connolly-cfrg-xwing-kem`; it **must not** be
  "optimized" or extended — its only correctness oracle is byte-equality with the
  X-Wing vectors (§2.4). Changing it breaks X-Wing interoperability.
- The KAT in `xwing_kat.rs` and the unit tests in `q-periapt-core/src/lib.rs`
  (§2.2, §3.2–§3.4) are the regression gate for this spec; CI must keep them green.
