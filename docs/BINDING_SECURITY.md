# Binding Security of the ContextBound PQ/T Hybrid KEM

> **Status:** specification + proof. The core generic transcript-projection reduction
> (`bind_le_cr`), its two standard CDM corollaries `bind_le_cr_kct` /
> `bind_le_cr_kpk`, and the separate local-wrapper corollary `bind_le_cr_kctx`
> (ciphertext / public-key / context projections, instantiated and discharged) are
> **machine-checked in
> EasyCrypt** — see [`formal/easycrypt/BindingViaCR.ec`](../formal/easycrypt/BindingViaCR.ec)
> (`make check`). `encode_inj` (injectivity of the canonical encoding) is a **proved
> lemma** — not an axiom; it bottoms out at two elementary facts about an 8-byte
> big-endian length field (fixed width + injective).
>
> **Scope of the machine-checked claim (read before citing).** The EasyCrypt file has
> two layers. (i) The generic `bind_le_cr` + corollaries are at the **transcript-
> collision** level (K an opaque adversary value). (ii) `malbind_kct_le_cr` /
> `malbind_kpk_le_cr` are the standard **KEM-aware CDM** games, while
> `malbind_kctx_le_cr` is the KEM-aware local wrapper game. In each, the MAL
> adversary supplies the (possibly inconsistent) keypairs, K is **DERIVED** via `Decaps`
> + the combiner, and the win condition is on the hybrid ciphertext / public key /
> context — reducing to `CR(H)` using **no property of Decaps**. (iii) `malbind_kct_xrej_le_cr`
> / `_kpk_xrej_` instantiate the **fully general CDM Figure 6** game, while
> `_kctx_xrej_` applies the same accepting/rejecting skeleton to the explicitly extended
> context-wrapper syntax. `Decaps` may reject, the hybrid key is `⊥` if either component
> rejects, and the **`K≠⊥` conjunct is PRESENT and LOAD-BEARING** (removing it makes the
> proof fail — verified). So we do **not**
> rely on "K≠⊥ is vacuous." **Honest scope:** `decaps_*`/`accepts_*` are **abstract,
> axiom-free** — the reduction holds for *every* Decaps (ML-KEM included) ⇒ literal "zero KEM
> binding assumption", but there is **no FIPS-203 linkage** and the shared-secret fields are
> **inert** in the argument (binding flows through the absorbed ct/pk/ctx — the hash-everything
> mechanism), so this proves nothing *about* ML-KEM's Decaps. Honest phrasing:
> *"machine-checked **commitment / transcript-binding** result — the CDM Figure-6 game
> for the standard CT/PK projections and a separately labeled context-wrapper game, each
> with both rejection styles and instantiated so that `Decaps` is **inert** (the binding
> target is forced by the encoding, not by decapsulation semantics) — over abstract
> Decaps, reducing to CR(H)."*
> A CDM-literate reader should read this as a commitment statement, not a result that exercises
> Decaps; that inertness is exactly what makes "zero KEM assumption" achievable. Remaining caveats: no spec↔implementation linkage; H's
> CR is assumed; IND-CCA2 is on paper (§4–§6).
> **Scope:** binding/committing security of the ContextBound combiner. IND-CCA2 robustness is summarized but is *not* the load-bearing contribution; the binding half is.
> **Trust base (read this first):** every theorem below is at the **abstract-spec level**, models **SHA3-256 / SHAKE256 as collision-resistant (and, for the KDF, as a PRF / random oracle)**, and is **not** linked to a verified implementation. "No binding assumption on the component KEMs" means exactly that — *no* assumption on ML-KEM or X25519 — and **nothing more**; it is **not** an information-theoretic ("unconditional") guarantee. We trade a KEM-self-binding assumption for a SHA3 collision-resistance assumption.

---

## 1. Binding / committing notions

A KEM is *binding* (a.k.a. *committing*) if an adversary cannot produce two encapsulation transcripts that **collide on one quantity** (typically the shared key `K`) while **disagreeing on another** (the public key `PK` or the ciphertext `CT`). The canonical framework is the **X-BIND-P-Q** family of Cremers, Dax and Medinger (CDM) [CDM23]:

- `P ∈ {K, PK, CT}` — the quantity that must **agree** between the two transcripts.
- `Q ∈ {K, PK, CT}` — the quantity that the adversary must make **disagree**.
- A scheme is **X-BIND-P-Q** if no adversary wins the game in CDM Figure 6: produce two transcripts with `P0 = P1`, `Q0 ≠ Q1`, both shared keys `≠ ⊥`.

Three adversary classes parameterize the game, in increasing strength [CDM23, §3]:

| Class | Key material | Meaning |
|-------|--------------|---------|
| **HON** | honestly generated | honest KeyGen, adversary controls randomness/choices downstream |
| **LEAK** | honestly generated, secrets leaked | as HON, but adversary learns the secret key(s) |
| **MAL** | **adversarially generated** | adversary supplies `pk` / `dk` of its choosing |

`MAL ⊇ LEAK ⊇ HON`: a MAL bound implies the LEAK and HON bounds for the same `(P,Q)`. CDM also prove **monotonicity** across the `(P,Q)` lattice (the "Lemma 4.4" edges in this document): e.g. `MAL-BIND-K-CT` and `MAL-BIND-K-PK` *jointly* imply `MAL-BIND-{K,CT}-PK`, `MAL-BIND-{K,PK}-CT`, and all LEAK/HON specializations — i.e. the entire **K-binds-{PK,CT}** sub-lattice.

**Related notions and how they differ (terminology matters):**

- **CCR** (*ciphertext collision resistance*) — the notion the **X-Wing** paper proves. The X-Wing authors state explicitly that *"our CCR notion is strictly weaker than the M-BIND-K-CT notion."* [XWing-CiC]. Use **CCR** for what the X-Wing peer-reviewed proof attains.
- **C2PRI** — a general KEM property: given an honestly generated ciphertext, finding a
  different ciphertext that decapsulates to the same shared secret is infeasible. The IRTF
  hybrid-KEM draft applies it to the PQ component whose ct/pk the C2PRI combiner omits.
  **Do not** conflate this honest-ciphertext second-preimage notion with CCR's arbitrary-pair
  collision target or with the traditional-group assumptions.
- **Key-committing / AEAD partitioning resistance** — the symmetric-layer analogue;
  the locally named `MAL-BIND-K-CTX` below is a syntactic wrapper analogue, not a CDM notion.

Both CCR and C2PRI are strictly weaker than collision-based `MAL-BIND-K-CT`.

---

## 2. Target notion for ContextBound, and why

### 2.1 Primary target (standard lattice)

> **`MAL-BIND-K-CT` and `MAL-BIND-K-PK`**, proven reducing **only to collision-resistance of SHA3-256 / SHAKE256**, with **no binding assumption on ML-KEM or X25519**.

By CDM monotonicity these two jointly yield `MAL-BIND-{K,CT}-PK`, `MAL-BIND-{K,PK}-CT`, and every LEAK/HON variant — the full **K-binds-{PK,CT}** sub-lattice.

### 2.2 Secondary target (self-defined context-wrapper property)

> **`MAL-BIND-K-CTX`** — *the shared key binds the length-prefixed context string.*

This is a **self-defined, non-standard** wrapper property that sits **outside** the
published `{K, PK, CT}` lattice. It is not a CDM node or axis and is **not blessed by
CDM monotonicity**. It commits only to the exact caller-supplied bytes; it does not
authenticate who chose them or what they mean. See §3.6 and §5/§6.

### 2.3 Why this is the right target

**(1) It is the standard ceiling reached the cleanest way.** A generic hash combiner is **X-BIND-K-Q-secure *if*** `Combine` is collision-resistant **and** every component KEM whose `Q`-element is *not* fed into `Combine` is itself X-BIND-K-Q ([eprint 2025/1416, Theorem 4], which gives the upper bound

```
Adv^{X-BIND-P-Q}_cKEM  ≤  Adv^{CR}_Combine  +  Σ_{i : f(Q,i)=0} Adv^{X-BIND-P-Q}_{KEM_i}
```

— a **one-directional (sufficiency) reduction**; the *necessity* of the omitted components' binding follows separately from the paper's **separating examples / Theorem 9**, not from Theorem 4). ContextBound feeds **all** of `{ss_pq, ss_trad, ct_pq, pk_pq, ct_trad, pk_trad}` into the hash, so the sum `Σ_{i:f(Q,i)=0}` is **empty** and binding reduces to **CR of SHA3 alone**. We invoke only the **sufficiency** direction, so the conclusion is robust to the "iff vs if" subtlety.

**(2) There is no standardized notion stronger than `MAL-BIND-K-CT` + `MAL-BIND-K-PK` on the CT/PK axes.** This pair **is** the ceiling on those axes; aiming higher there is impossible. In particular, **`X-BIND-CT-*`** notions (a *ciphertext* binding the key or pk) are **structurally unachievable by any implicitly-rejecting KEM**: ML-KEM never returns `⊥`, so a mutated ciphertext always decapsulates to *some* key. These are **off the table** for the hybrid and **must not be claimed** (see §5).

**(3) The context wrapper is an API/assurance distinction, not a higher lattice
point.** Native X-Wing has **no context input**, so the two APIs cannot be compared on
the locally defined K-CTX game. ContextBound's defensible statement is narrower: its
wrapper commits the derived key to exact caller-supplied context bytes, and the separate
protocol models prove authenticated agreement for the modeled transcript. That is useful
packaging for HPKE/Signal/MLS-style integrations, but it does not make the KEM primitive
categorically stronger than X-Wing and it does not replace their protocol transcript hash.

**Why MAL is the correct class.** The load-bearing attacks are all **malicious-keygen**: ML-KEM expanded-key binding failures [Schmieg, eprint 2024/523]; PQXDH re-encapsulation [Fiedler–Günther, eprint 2024/702]. ContextBound's intended venues — PQ-KEM-in-HPKE, Signal/MLS-style handshakes — accept adversarially supplied key material, so HON/LEAK would under-model the threat.

---

## 3. Construction (implementable; KAT-ready)

ContextBound derives the shared key by hashing the **full** component tuple plus a mandatory context, under an **injective, length-prefixed, domain-separated** encoding.

### 3.1 Absorbed material — hash everything

```
K = SHA3-256( Encode( LABEL,
                      suite_id, policy_version,
                      ss_pq, ss_trad,
                      ct_pq, pk_pq,
                      ct_trad, pk_trad,
                      context ) )
```

All six KEM components **and** the context are absorbed. This is the **GHP / Chempat "hash-everything" shape** [eprint 2025/1416, Table 1] and is *exactly* what makes `MAL-BIND-K-CT` / `K-PK` provable with **zero** KEM binding assumptions.

> **Do NOT optimize toward X-Wing.** Dropping `ct_pq` / `pk_pq` (X-Wing's lean absorb) re-introduces dependence on ML-KEM's FO self-binding and destroys the assumption-minimality property. The extra absorb is the *deliberate price* of the no-KEM-assumption proof (see cost note §5.4).

### 3.2 Canonical field order and fixed-width length prefixing (injectivity)

Every field, **including `LABEL` and `context`**, is emitted as a **fixed-width big-endian length prefix followed by the field bytes**. The canonical field order is:

| # | Field | Notes |
|---|-------|-------|
| 0 | `LABEL` | ContextBound domain-separation tag (§3.4) — **must be field 0** |
| 1 | `suite_id` | canonical suite identifier — agility / downgrade binding |
| 2 | `policy_version` | algorithm-policy version (4-byte BE) — agility / downgrade binding |
| 3 | `ss_pq` | ML-KEM-768 shared secret (32 B) |
| 4 | `ss_trad` | X25519 shared secret (32 B) |
| 5 | `ct_pq` | ML-KEM-768 ciphertext (~1088 B) |
| 6 | `pk_pq` | ML-KEM-768 encapsulation key (~1184 B) |
| 7 | `ct_trad` | X25519 ephemeral public (32 B) |
| 8 | `pk_trad` | X25519 static public (32 B) |
| 9 | `context` | profile requires an explicit, non-empty protocol/application label (§3.3) |

> `suite_id` and `policy_version` (fields 1–2) are bound first-class so a suite/profile/policy downgrade or substitution changes the derived key at the KEM layer (not only via the opaque `context`). They are just additional injectively-encoded fields — the CR-based binding proof is unchanged.

```
Encode(F0, …, F9) = LEN(F0) ‖ F0 ‖ LEN(F1) ‖ F1 ‖ … ‖ LEN(F9) ‖ F9
```

`LEN(·)` is a **fixed-width** big-endian field (4 bytes, or 8 bytes if any field may exceed 2³²−1; pick one width and fix it for the profile). Fixed width is mandatory: a variable-width length itself needs delimiting, re-introducing ambiguity.

**Injectivity is a first-class proof obligation, not an aside.** The CR-to-binding reduction requires that the map `(F0,…,F9) ↦ bytes` be **injective and total**: no two distinct tuples — including tuples differing only in *field boundaries* or containing empty fields — may map to the same byte string. Fixed-width length prefixes preserve the empty/non-empty distinction, so the non-empty-context product rule in §3.3 is **not** an injectivity or proof precondition. The KAT suite **must** include a **negative** sub-suite: pairs of distinct tuples that *would* collide under naive `‖` concatenation but provably cannot under fixed-width prefixing.

### 3.3 Mandatory non-empty context

`ContextBound` requires a non-empty `context` as a **profile/API rule** so every
invocation states an explicit protocol, role, version, or application label. When no
application-specific context exists, callers substitute a fixed label (for example,
`"ContextBound/v1/initiator"`). This rejects semantically empty use and makes accidental
omission observable. It is **not** required for length-prefix injectivity or for the
syntactic CR reduction: the encoding remains injective for an empty field, and the local
wrapper game only needs two distinct context values for its counterexample.

### 3.4 Domain-separation label (field 0)

ContextBound uses its **own fixed `LABEL`, distinct from CompatXWing's `XWingLabel`** (`0x5c2e2f2f5e5c`, which is the 6-byte ASCII `\.//^\`). The ContextBound label is baked in as **field 0** of the injective encoding.

> **Two deltas, jointly necessary.** Label-distinctness (§3.4) gives **cross-protocol** separation — an honest ContextBound transcript can never collide with an X-Wing transcript. Fixed-width length prefixing (§3.2) gives **within-protocol injectivity**. *Neither alone suffices*: a distinct label does not prevent a within-protocol boundary-shift collision, and injective prefixing does not prevent cross-protocol aliasing of identical contents. Recommended belt-and-suspenders: make the ContextBound label a **different length** from X-Wing's 6 bytes, since field 0 is itself length-prefixed.
>
> Note: label-distinctness is a **domain-separation / cross-protocol-agility** property, **not** a CDM binding property. It is documented here as defense-in-depth and is **explicitly outside** the `MAL-BIND` theorem statements of §4.

### 3.5 ML-KEM key-serialization boundary

The CR-based ContextBound theorem is serialization-independent: it binds `pk_pq` and
`ct_pq` directly and therefore does **not** rely on ML-KEM self-binding. The current
fixed-suite ABI intentionally uses a 2400-byte expanded ML-KEM-768 decapsulation key
for `ContextBound`; only `CompatXWing` is admitted to the X-Wing-safe seed-derived
backend. This is an API/key-format boundary, not a claim that an expanded key is
intrinsically trustworthy. The current ABI does not expose a generic imported-key
validator, so validation and provenance of externally imported expanded keys remain a
provider obligation. Do **not** describe the implemented ContextBound ABI as requiring
the FIPS 203 64-byte seed representation.

### 3.6 `MAL-BIND-K-CTX` — precise definition (over a context-parameterized KEM)

> **Well-posedness warning.** In the standard CDM API, `P` and `Q` range over `{K, PK, CT}` — all **outputs** observable from the encaps/decaps transcript. `CTX` is a caller-supplied **input** that standard `Encaps`/`Decaps` neither take nor echo. "Add `CTX` to `Q`" is therefore **not a literal CDM instantiation**; it is **ill-typed** without a syntactic change to the KEM interface.

Define a **context-parameterized KEM** syntax:

```
Encaps(pk, ctx) → (ct, K)        Decaps(dk, ct, ctx) → K
```

where `ctx` is an **absorbed-but-not-transmitted** input. The locally named
`MAL-BIND-K-CTX` game is a **self-defined wrapper game inspired by** CDM Figure 6;
it is not a literal CDM instantiation, node, axis, or monotonicity result:

> The adversary outputs two transcripts. It **wins iff**
> `K0 = K1`  ∧  `ctx0 ≠ ctx1`  ∧  `K0 ≠ ⊥`  ∧  `K1 ≠ ⊥`.

Required properties to argue (before mechanization):

1. **Conservative API extension:** fixing `ctx` leaves ordinary KEM behavior and the
   standard K-CT/K-PK games unchanged; the context wrapper game becomes vacuous,
   not another standard `X-BIND` point.
2. **Syntactic byte commitment only:** the derived `K` commits to the exact `ctx`
   bytes absorbed. The protocol must separately authenticate their origin and meaning.
3. **Collision reduction:** different absorbed `ctx` bytes yielding the same
   non-bottom key reduce to CR like any other injectively encoded hash input.

This **must** be documented as a non-standard convenience property of a
context-parameterized wrapper, *not* a superset of, or point in, the published
lattice. It is analogous to absorbing HPKE `info` or a transcript label at the KEM
wrapper layer; only the separate authenticated protocol model gives those bytes
security semantics. See §6 and the [eprint 2026/140] adjacency.

---

## 4. Proof plan

### 4.1 Tooling

| Tool | Role | Rationale |
|------|------|-----------|
| **EasyCrypt** | primary, computational | Chosen because the scoped review found directly reusable PQ-KEM/binding artifacts: verified ML-KEM IND-CCA (formosa-mlkem; [eprint 2024/843]); WIP X-Wing IND-CCA (formosa-crypto/formosa-x-wing); and SandboxAQ's binding-hierarchy library (`github.com/sandbox-quantum/EasyCrypt-KEMs`) mechanizing CDM notions and **`LEAK-BIND-K-PK` for ML-KEM**. This is a tooling rationale, not an exhaustive priority claim about every prover ecosystem. |
| **Tamarin** | symbolic protocol cross-check | Delivered as a separate handshake model with five exact lemmas, including authenticated context agreement and hybrid robustness. It does not replace the computational EasyCrypt binding proof or establish implementation refinement. |
| **ProVerif** | independent symbolic cross-check | Delivered with six individually gated queries under a second abstraction. Exact query/result matching fails closed on missing, duplicate, or extra results. |

> **Reuse premises must be audited *before* committing the plan — go/no-go gate.**
> - **formosa-x-wing IND-CCA is WIP** (tested on EasyCrypt 2024.09, completion unconfirmed). Extending a moving base is **high-risk** and is **not** the "guaranteed result" it might appear. **Recommendation: do NOT mechanize IND-CCA** (see §4.3).
> - **SandboxAQ `EasyCrypt-KEMs` IS released**, but its mechanized ML-KEM result is **only `LEAK-BIND-K-PK`**; **`MAL`-binding and FO-transform binding are future work**, and impl-to-spec linkage is unfinished. The **MAL game scaffolding and the K-CT/K-PK monotonicity edges may not exist in reusable form.** Audit the repo concretely: confirm exactly which games (HON/LEAK/MAL) and which monotonicity edges are importable. If the MAL game must be built from scratch, **that alone is a large part of the budget and is the explicit core**, not an aside.
> - Pull the **primary PDFs** of [eprint 2025/1416] (Theorem 4 concrete bounds, plus any combiner-level notion X-Wing fails), [eprint 2025/1397] (Starfighters / QSF), and [eprint 2026/140] **before** publishing any novelty claim.

### 4.2 Part (b) — Binding (load-bearing, novel half)

1. **Model SHA3-256 as collision-resistant** (game `CR`, advantage `Adv_CR`).
2. **Injective-encoding lemma** — *prove first.* The fixed-width length-prefixed concat is **injective and total** on the field tuple (structural/byte-boundary reasoning; finite combinatorics). Include **totality** (no empty-field boundary shift). This is the **soundest, most finishable, confidence-building** piece and **de-risks** every theorem that depends on it.
3. **`MAL-BIND-K-CT` theorem.** Any adversary producing two transcripts with `K0 = K1`, agreeing CT-set, and a differing element yields **either** equal hash inputs (impossible by injectivity, since the differing element appears in the input) **or** a SHA3 collision. Reduce to `Adv_CR`. Bound: `Adv_{MAL-BIND-K-CT} ≤ Adv_CR`.
4. **`MAL-BIND-K-PK`** and the self-defined **`MAL-BIND-K-CTX` syntactic extension** by the **identical collision-reduction structure** (`PK` / `CTX` is just another absorbed field). Same `Adv_CR` bound, but K-CTX is not a CDM lattice node.
5. **Standard CT/PK joint / LEAK / HON corollaries** by porting CDM monotonicity (Lemma 4.4) — reuse SandboxAQ edges if present, else re-prove (small). This monotonicity step does not apply to K-CTX.

**Crucially, no ML-KEM / X25519 binding lemma is ever invoked.** The entire binding proof is **CR-of-SHA3 + injectivity**.

### 4.3 Part (a) — IND-CCA2 robustness (summarized, recommend NOT mechanizing)

ContextBound's IND-CCA2 follows from the **GHP18-style combiner argument** ("combiner is IND-CCA if *either* component is IND-CCA"), importing ML-KEM-768 IND-CCA and X25519 strong-DH (ROM) for the classical bound, with SHA3 as a PRF/RO for the KDF.

> **Recommendation:** given that formosa-x-wing's IND-CCA is unfinished/moving, **do not mechanize this half.** Cite formosa-x-wing and the published X-Wing IND-CCA result, and give a **paper argument** that the extra hashed inputs do not break the reduction. **Reserve all mechanization budget for the binding half** — the actual novelty.

### 4.4 Declared assumptions / trust base

- CR (and PRF/RO) of SHA3-256 / SHAKE256 — **idealized in the mechanization**.
- ML-KEM-768 IND-CCA (imported; for Part (a) only).
- X25519 strong-DH in the ROM (for Part (a) only).
- FIPS 203 **seed-format `dk`** with import validation (spec requirement; **not** a binding-proof dependency).
- Abstract-spec level only; **no** verified-implementation linkage.

### 4.5 Target mechanized statement

> The standard `Adv_{MAL-BIND-K-CT}` and `Adv_{MAL-BIND-K-PK}` bounds are each
> `≤ Adv_CR(SHA3) + (negligible encoding terms)`. Separately, the self-defined
> context-wrapper collision game has the same syntactic CR bound. The latter is not
> a CDM theorem and does not authenticate context semantics. ContextBound is
> IND-CCA2 if either component is.

---

## 5. Honest claim — vs X-Wing and naive hybrids

### 5.1 What ContextBound MAY claim

1. **Assumption-minimal binding.** ContextBound achieves `MAL-BIND-K-CT` and `MAL-BIND-K-PK` (hence the joint and all LEAK/HON variants) **assuming only collision-resistance of SHA3 — no binding assumption on ML-KEM or X25519.** The defensible delta vs X-Wing is **proof coverage / minimal assumptions**, framed as an **assurance/packaging advantage**: ContextBound's binding is provable from a **single, weaker primitive assumption (CR) in one self-contained proof**, whereas the equivalent guarantee for X-Wing is currently **distributed across an IETF-draft assertion plus separate ML-KEM self-binding results**, and X-Wing's *peer-reviewed* proof attains only **CCR** (which the X-Wing authors state is strictly weaker than `M-BIND-K-CT`).

2. **Context-parameterized wrapper commitment (separate scope).** ContextBound also
   gives a CR-bound syntactic commitment to caller-supplied `ctx` bytes. X-Wing's KEM
   API has no such input, so calling X-Wing insecure or saying it "loses K-CTX" is not
   a well-typed comparison. This wrapper property is not a CDM axis or a higher
   security point; its value depends on authenticated protocol agreement (§6).

3. **Vs naive concatenation `k = KDF(ss_pq ‖ ss_trad)`.** ContextBound is provably binding for **any** component KEMs, whereas the shared-keys-only combiner inherits **no** key/ciphertext binding and is **non-robust** [GHP18]. This is where the "no KEM binding assumption at all" pitch bites hardest.

### 5.2 What ContextBound MUST NOT claim

- **(a)** That it is *"strictly stronger binding than X-Wing"* in the standard X-BIND lattice on the **K-CT / K-PK** axes. **Both hit the same MAL ceiling.** Overstating this is factually wrong.
- **(b)** Any `X-BIND-CT-PK` / `X-BIND-CT-K` / robustness / SROB property — **structurally impossible** for an implicitly-rejecting (ML-KEM-based) hybrid.
- **(c)** That ContextBound is *needed* for TLS 1.3 / QUIC — those derive CT/PK binding from the **handshake transcript hash**. The most defensible statement there is **defense-in-depth**.
- **(d)** **(corrected per review)** A K-PK *binding-strength* delta vs seed-format X-Wing. **Per Schmieg [eprint 2024/523]:** any FO-transform KEM that stores the private key **as a seed** attains **both `MAL-BIND-K-PK` and `MAL-BIND-K-CT`** (re-deriving from the seed forces an honest KeyGen, so cached `H(ek)` and rejection secret `z` cannot be mismatched). Since construction-delta §3.5 **mandates** seed-format `dk`, a **seed-format X-Wing already attains both K-CT and K-PK** on the standard axes. **Therefore:**
  > **Naive ML-KEM in *expanded-dk* format is neither `MAL-BIND-K-CT` nor `MAL-BIND-K-PK` (Schmieg); seed-format ML-KEM is *both*. The ContextBound delta on the standard CT/PK axes is NOT a binding-strength gap at all — it is purely (i) a CR-based bound independent of component-KEM binding assumptions and (ii) robustness to an implementer who ships expanded-dk. Frame it as assumption-minimality, never as a K-PK binding advantage.**
- **(e)** That K-CTX supplies identity, one-time prekey semantics, replay protection,
  key transparency, ratcheting, forward secrecy, post-compromise security,
  multi-device convergence, or recovery. It commits exact context bytes only after a
  surrounding protocol has selected and authenticated their meaning. Signal's
  published PQXDH and SPQR/Triple-Ratchet components plus a separately specified
  Sesame-compatible manager integration, and Apple PQ3, solve lifecycle problems
  outside this theorem.

### 5.3 Honest comparison scope (lead with this)

> **Vs a correctly-implemented seed-format X-Wing, the incremental binding gain is
> *zero on the standard CT/PK axes*** — both attain `MAL-BIND-K-CT` and
> `MAL-BIND-K-PK`. What ContextBound adds is **(i) assumption minimality** (binding
> from CR alone, no reliance on ML-KEM's FO self-binding), **(ii) robustness to an
> expanded-dk implementer**, and **(iii) an optional context-parameterized wrapper
> commitment whose semantics still require authenticated protocol agreement**.

Reserve the full **"no KEM binding assumption at all"** pitch for the **expanded-dk and naive-concatenation** baselines, where it bites hardest.

### 5.4 Cost honesty — where ContextBound is *merely* different/slower, not stronger

> ContextBound absorbs **~2.3 KB more** into the combiner hash than X-Wing
> (`ct_pq` ~1088 B + `pk_pq` ~1184 B, plus the context). X-Wing's lean absorb is a
> **deliberate, proven optimization**, not a binding deficiency. On the **K-CT /
> K-PK** axes this extra cost buys **assumption hygiene, not a stronger notion**. The
> optional context wrapper buys only a syntactic byte commitment; it is not a new CDM
> axis and does not replace protocol authentication.

### 5.5 The "unconditional" word — banned

The headline must **never** read "unconditional." In cryptography "unconditional" connotes information-theoretic / no computational assumption. Here the binding proof still rests on **CR of SHA3-256** (and the IND-CCA half additionally on SHA3-as-PRF and X25519 strong-DH in the ROM), all **idealized** in the mechanization. **Replace every instance of "unconditional" with "assuming only collision-resistance of SHA3-256 (no binding assumption on the component KEMs)."** We move the trust root **from ML-KEM's FO transform to SHA3 CR** — a *trade*, not an elimination.

---

## 6. Threats covered, residual gaps, effort

### 6.1 Threats covered

| Threat | How ContextBound covers it |
|--------|----------------------------|
| **Re-encapsulation / UKS under malicious keys** (PQXDH-class, [eprint 2024/702]) | Two `(pk, ct)` pairs decapsulating to the same `K` are prevented by `MAL-BIND-K-PK` + `MAL-BIND-K-CT` — defeated **at the KEM layer**, not by relying on the protocol to add `pk` to AEAD AD. |
| **ML-KEM expanded-dk binding failures** ([Schmieg, eprint 2024/523]) | Swapping cached `H(ek)` or sharing rejection seed `z` is neutralized: ContextBound hashes `pk_pq` / `ct_pq` **directly**, so it does **not trust ML-KEM's internal self-binding at all**. |
| **Cross-context / transcript confusion** | If both peers already authenticate and agree on the exact `context` bytes, the wrapper prevents the same derived `K` under different absorbed contexts except by a hash collision. The hash layer alone does not authenticate mode, role, version, or peer-identity semantics. |
| **Combiner-collision attacks** | CR SHA3 over the **injectively-encoded full tuple** prevents two distinct component-tuples mapping to the same `K`. |
| **Non-robust-concatenation pitfall** ([GHP18]) | Every ciphertext is bound into the hash input, so an attacker cannot replay a mutated ciphertext that decapsulates to the same combined key. |

### 6.2 Residual gaps

1. **`MAL-BIND-K-CTX` is self-defined and is the weakest link of the novelty story.** `CTX` is an **input**, not a Decaps output, so adding it to `Q` is **not** a published-lattice point and is **not** covered by CDM monotonicity. **Worse:** once `ctx` is a hashed input, "key binds caller-supplied context" is **nearly tautological** — of course `H(…,ctx0) ≠ H(…,ctx1)` collisions reduce to CR. The notion's *value* depends entirely on whether the surrounding protocol feeds a **meaningful, mutually-agreed** context; at the KEM level it may prove little the protocol could not already get from its own transcript hash. Two legitimate routes are:
   - **(a)** Downgrade `K-CTX` from "the genuine advantage beyond X-Wing" to *"a convenience guarantee equivalent to inlining a transcript-hash bind, provable trivially once `ctx` is absorbed"*; **or**
   - **(b)** Do the hard formal work: define the context-echoing `Encaps`/`Decaps` API (§3.6), prove the echo is **authenticated** (not adversary-controlled post-hoc), and exhibit a **concrete protocol attack** that `K-CTX` stops but that adding `ctx` to AEAD AD does **not**.

   This artifact takes route (a) at the KEM layer and keeps authenticated agreement in
   the separate Tamarin/ProVerif protocol model. There is no claim that the syntactic
   wrapper makes ContextBound categorically stronger than X-Wing.

2. **Prior work occupies the adjacent ground — do not make a priority claim.**
   **[eprint 2026/140]** *"On the Necessity of Public Contexts in Hybrid KEMs: A
   Case Study of X-Wing"* analyzes **when** public context inputs are necessary vs
   redundant for existing notions (C2PRI, multi-target domain separation).
   **[eprint 2025/1397]** (*Starfighters / QSF generality*) analyzes the safety of
   omitting components. ContextBound locally defines a context-parameterized wrapper
   collision game and mechanizes its syntactic CR bound; that does **not** establish
   that the concept, label, or mechanization is first. The defensible contribution is
   the explicit conjunction of the standard CT/PK proof, the separately scoped wrapper
   projection, authenticated protocol agreement, and proof-to-byte evidence. Any novelty
   or priority statement remains a literature-review go/no-go item.

3. **Idealization / no implementation linkage.** SHA3 CR & PRF are modeled as assumptions/ROM; the proof is only as strong as those idealizations. Impl-to-spec linkage was **unfinished** upstream (SandboxAQ). Promote the trust base **into the theorem statement** (§4.5) so no examiner reads "no KEM assumption" as "implementation-level."

4. **The current standards baseline is distributed, not weak.** IRTF hybrid-kems
   draft-12 now gives informal LEAK-BIND sketches for its frameworks, explicitly
   defers rigorous proofs, and does not prove the potential common-seed MAL
   strengthening. No peer-reviewed proof currently establishes full `MAL-BIND` for
   X-Wing (the CiC result proves **CCR**). State draft sketch, CiC theorem, and the
   local machine-checked model separately. **Do not** imply this assurance gap is a
   deployed weakness or claim that the all-field input list is novel.

5. **Reuse status is a go/no-go gate.** Confirm exactly which SandboxAQ games/edges are importable (only `LEAK-BIND-K-PK` is mechanized today; MAL is future work). Treat formosa-x-wing IND-CCA as **WIP / do-not-extend** (§4.3).

6. **Key format is an explicit API boundary, not a universal ContextBound requirement.**
   The current ABI uses expanded-dk for ContextBound and a seed-derived backend for
   CompatXWing. The binding proof does not need ML-KEM self-binding in either case;
   imported-key validation and provenance remain separate implementation obligations.
   Any future import API must specify and test those obligations instead of inheriting
   them from the combiner theorem.

7. **Primary-source verification pending.** Concrete bounds in [eprint 2025/1416, Theorem 4], the [2025/1397] results, and [eprint 2026/140] were only partially accessible. **Re-verify against primary PDFs before publishing the novelty claim** — elevate this to a **go/no-go gate**.

8. **A stateful protocol is a separate theorem and implementation.** The future
   Q-Periapt Continuity research line may reuse this encoding discipline, but it must
   separately prove authenticated device/context agreement, prekey replay and
   consumption, compromise-timed FS/PCS, ratchet epochs, downgrade lock, recovery,
   and crash/rollback invariants. The current EasyCrypt game cannot be lifted to
   those claims by adding more fields. See
   [`CONTINUITY_RESEARCH.md`](CONTINUITY_RESEARCH.md).

### 6.3 Historical effort estimate and current delivery status

> **Historical planning note:** EasyCrypt has a steep learning curve, and this estimate was written
> before the present proof artifacts were delivered. It remains useful as a maintenance warning, not
> as the current artifact status. The authoritative status is the checked EasyCrypt development,
> dependency controls, Tamarin/ProVerif gates, and claim ledger.

**Original committed plan (retained for provenance):**

| Phase | Budget | Status |
|-------|--------|--------|
| EasyCrypt ramp (pure tooling/tutorials, before any thesis-specific proof) | **8–12 weeks** | prerequisite |
| Notion definitions (`K-CT`/`K-PK` games, `K-CTX` extension §3.6, injective-encoding lemma statement, X-Wing framing) | 3–4 weeks | — |
| Spec deltas (mandatory non-empty context, fixed-width prefixing, domain label, seed-format) + reference KATs incl. negative collision vectors | 2 weeks | — |
| **Injective-encoding lemma (mechanize FIRST — de-risks everything)** | within above | confidence-building, finishable |
| **`MAL-BIND-K-CT` via CR — the single committed mechanized deliverable** | 4–6 weeks | **core** |

**Current resolution of the original stretch list:**
- K-PK plus the separately scoped local K-CTX wrapper projection are delivered in the EasyCrypt
  development; the proof remains subject to its stated model and is not implementation refinement.
- The standard CT/PK corollaries and explicit dependency controls are delivered.
- IND-CCA2 remains a paper argument only and was intentionally not mechanized (§4.3).
- Tamarin and ProVerif are now delivered as independent symbolic protocol cross-checks. They do not
  replace the computational binding proof or close the specification-to-Rust gap.

**Go/no-go gates before committing the novelty claim:** (1) audit `EasyCrypt-KEMs` for importable MAL games/edges; (2) confirm formosa-x-wing status (expect WIP → do not extend); (3) pull primary PDFs of 2025/1416, 2025/1397, 2026/140.

---

## References

- **[CDM23]** Cremers, Dax, Medinger. *Keeping Up with the KEMs: Stronger Security Bounds / Binding (committing) security of KEMs.* CCS 2024 / eprint 2023/1933. (X-BIND-P-Q framework; HON/LEAK/MAL classes; binding-targets BE = {pk, ct, k}; monotonicity lemma.)
- **[eprint 2024/523]** Schmieg. *Unbindable Kemmy Schmidt: ML-KEM is neither MAL-BIND-K-CT nor MAL-BIND-K-PK in expanded-dk form; seed-format dk attains both.* (Also keymaterial.net writeup.)
- **[eprint 2024/702]** Fiedler, Günther. *PQXDH re-encapsulation / UKS analysis.*
- **[eprint 2024/843]** *Verified ML-KEM (Kyber) IND-CCA in EasyCrypt* (formosa-mlkem).
- **[eprint 2025/1416]** *Generic hash combiner binding (GHP/Chempat "hash-everything"); Theorem 4 sufficiency upper bound; Theorem 9 / separating examples for necessity; Table 1.*
- **[eprint 2025/1397]** *"Starfighters" — QSF generality / safe omission of components in hybrid KEMs.*
- **[eprint 2026/140]** *On the Necessity of Public Contexts in Hybrid KEMs: A Case Study of X-Wing.* (Analyzes when public context is necessary/redundant for adjacent properties; distinct from the local `K-CTX` wrapper.)
- **[XWing-CiC]** *X-Wing: The Hybrid KEM You've Been Looking For* (CiC). (Proves **CCR**; states CCR is strictly weaker than `M-BIND-K-CT`. `XWingLabel = 0x5c2e2f2f5e5c` = ASCII `\.//^\`.)
- **[GHP18]** Giacon, Heuer, Poettering. *KEM combiners.* (Non-robustness of shared-keys-only concatenation; "IND-CCA if either component is" combiner.)
- **SandboxAQ `EasyCrypt-KEMs`** — `github.com/sandbox-quantum/EasyCrypt-KEMs`. (Mechanizes CDM notions; `LEAK-BIND-K-PK` for ML-KEM done; MAL / FO-binding future work.)
- **formosa-crypto/formosa-x-wing** — WIP X-Wing IND-CCA in EasyCrypt (2024.09; completion unconfirmed).
