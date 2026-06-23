# Binding Security of the ContextBound PQ/T Hybrid KEM

> **Status:** specification + proof. The core binding theorem (`bind_le_cr`:
> `Adv^{X-BIND-K-*} ≤ Adv^{CR}(H)`, instantiating to MAL-BIND-K-CT/K-PK/K-CTX) is
> **machine-checked in EasyCrypt** — see [`formal/easycrypt/BindingViaCR.ec`](../formal/easycrypt/BindingViaCR.ec)
> (`make check`). `encode_inj` (injectivity of the canonical encoding) is now a
> **proved lemma** — no longer an axiom; the proof bottoms out only at two
> elementary facts about an 8-byte big-endian length field (fixed width + injective).
> H's collision-resistance and the on-paper IND-CCA2 argument remain as scoped below
> (§4–§6).
> **Scope:** binding/committing security of the ContextBound combiner. IND-CCA2 robustness is summarized but is *not* the load-bearing contribution; the binding half is.
> **Trust base (read this first):** every theorem below is at the **abstract-spec level**, models **SHA3-256 / SHAKE256 as collision-resistant (and, for the KDF, as a PRF / random oracle)**, and is **not** linked to a verified implementation. "No binding assumption on the component KEMs" means exactly that — *no* assumption on ML-KEM or X25519 — and **nothing more**; it is **not** an information-theoretic ("unconditional") guarantee. We trade a KEM-self-binding assumption for a SHA3 collision-resistance assumption.

---

## 1. Binding / committing notions

A KEM is *binding* (a.k.a. *committing*) if an adversary cannot produce two encapsulation transcripts that **collide on one quantity** (typically the shared key `K`) while **disagreeing on another** (the public key `PK` or the ciphertext `CT`). The canonical framework is the **X-BIND-P-Q** family of Cremers, Dürmuth, Medinger and Naderpour (CDM) [CDM23]:

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
- **C2PRI** — the X25519-interface *injective-decapsulation* property of [eprint 2026/140]; a different (though related) object. **Do not** conflate CCR (ML-KEM-side, X-Wing paper) with C2PRI (X25519-side, 2026/140).
- **Key-committing / AEAD partitioning resistance** — the symmetric-layer analogue; `MAL-BIND-K-CTX` below is the KEM-level lift of that idea.

Both CCR and C2PRI are strictly weaker than collision-based `MAL-BIND-K-CT`.

---

## 2. Target notion for ContextBound, and why

### 2.1 Primary target (standard lattice)

> **`MAL-BIND-K-CT` and `MAL-BIND-K-PK`**, proven reducing **only to collision-resistance of SHA3-256 / SHAKE256**, with **no binding assumption on ML-KEM or X25519**.

By CDM monotonicity these two jointly yield `MAL-BIND-{K,CT}-PK`, `MAL-BIND-{K,PK}-CT`, and every LEAK/HON variant — the full **K-binds-{PK,CT}** sub-lattice.

### 2.2 Secondary target (lattice extension — the only axis genuinely beyond X-Wing)

> **`MAL-BIND-K-CTX`** — *the shared key binds the length-prefixed context string.*

This is a **self-defined, non-standard** notion that sits **outside** the published `{K, PK, CT}` lattice. It is **not blessed by CDM monotonicity.** See §3.6 for the precise game and §5/§6 for the honest claim and its caveats — including the well-posedness problem that `CTX` is an *input*, not a Decaps *output*.

### 2.3 Why this is the right target

**(1) It is the standard ceiling reached the cleanest way.** A generic hash combiner is **X-BIND-K-Q-secure *if*** `Combine` is collision-resistant **and** every component KEM whose `Q`-element is *not* fed into `Combine` is itself X-BIND-K-Q ([eprint 2025/1416, Theorem 4], which gives the upper bound

```
Adv^{X-BIND-P-Q}_cKEM  ≤  Adv^{CR}_Combine  +  Σ_{i : f(Q,i)=0} Adv^{X-BIND-P-Q}_{KEM_i}
```

— a **one-directional (sufficiency) reduction**; the *necessity* of the omitted components' binding follows separately from the paper's **separating examples / Theorem 9**, not from Theorem 4). ContextBound feeds **all** of `{ss_pq, ss_trad, ct_pq, pk_pq, ct_trad, pk_trad}` into the hash, so the sum `Σ_{i:f(Q,i)=0}` is **empty** and binding reduces to **CR of SHA3 alone**. We invoke only the **sufficiency** direction, so the conclusion is robust to the "iff vs if" subtlety.

**(2) There is no standardized notion stronger than `MAL-BIND-K-CT` + `MAL-BIND-K-PK` on the CT/PK axes.** This pair **is** the ceiling on those axes; aiming higher there is impossible. In particular, **`X-BIND-CT-*`** notions (a *ciphertext* binding the key or pk) are **structurally unachievable by any implicitly-rejecting KEM**: ML-KEM never returns `⊥`, so a mutated ciphertext always decapsulates to *some* key. These are **off the table** for the hybrid and **must not be claimed** (see §5).

**(3) The context axis is the only honest place to claim "beyond X-Wing."** X-Wing has **no context input**. Promoting transcript/context binding — the job TLS/HPKE/Signal currently do by hand at the protocol layer — to a **KEM-level guarantee** is ContextBound's actual selling point for HPKE/Signal/MLS. (But see §5/§6: this axis is the *weakest link* of the novelty story and must be framed carefully against [eprint 2026/140].)

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
| 9 | `context` | mandatory, non-empty (§3.3) |

> `suite_id` and `policy_version` (fields 1–2) are bound first-class so a suite/profile/policy downgrade or substitution changes the derived key at the KEM layer (not only via the opaque `context`). They are just additional injectively-encoded fields — the CR-based binding proof is unchanged.

```
Encode(F0, …, F9) = LEN(F0) ‖ F0 ‖ LEN(F1) ‖ F1 ‖ … ‖ LEN(F9) ‖ F9
```

`LEN(·)` is a **fixed-width** big-endian field (4 bytes, or 8 bytes if any field may exceed 2³²−1; pick one width and fix it for the profile). Fixed width is mandatory: a variable-width length itself needs delimiting, re-introducing ambiguity.

**Injectivity is a first-class proof obligation, not an aside.** The CR-to-binding reduction requires that the map `(F0,…,F9) ↦ bytes` be **injective and total**: no two distinct tuples — including tuples differing only in *field boundaries* — may map to the same byte string, and **no field may be empty in a way that lets a boundary shift** (this is why `context` is mandatory non-empty; the empty-context / empty-field degeneracy is exactly where naive concatenation breaks). The KAT suite **must** include a **negative** sub-suite: pairs of distinct tuples that *would* collide under naive `‖` concatenation but provably cannot under fixed-width prefixing.

### 3.3 Mandatory non-empty context

`context` **must** be non-empty for any profile claiming `MAL-BIND-K-CTX`. If `context` may be empty the `K-CTX` notion **degenerates**. Require a minimum-length, caller-supplied context; when no application context exists, substitute a **fixed protocol / role / version label** (e.g. `"ContextBound/v1/initiator"`).

### 3.4 Domain-separation label (field 0)

ContextBound uses its **own fixed `LABEL`, distinct from CompatXWing's `XWingLabel`** (`0x5c2e2f2f5e5c`, which is the 6-byte ASCII `\.//^\`). The ContextBound label is baked in as **field 0** of the injective encoding.

> **Two deltas, jointly necessary.** Label-distinctness (§3.4) gives **cross-protocol** separation — an honest ContextBound transcript can never collide with an X-Wing transcript. Fixed-width length prefixing (§3.2) gives **within-protocol injectivity**. *Neither alone suffices*: a distinct label does not prevent a within-protocol boundary-shift collision, and injective prefixing does not prevent cross-protocol aliasing of identical contents. Recommended belt-and-suspenders: make the ContextBound label a **different length** from X-Wing's 6 bytes, since field 0 is itself length-prefixed.
>
> Note: label-distinctness is a **domain-separation / cross-protocol-agility** property, **not** a CDM binding property. It is documented here as defense-in-depth and is **explicitly outside** the `MAL-BIND` theorem statements of §4.

### 3.5 ML-KEM key-serialization requirement

The profile **requires the FIPS 203 64-byte *seed* `dk` format with key-pair validation on import.** This is **belt-and-suspenders** for ContextBound — because the combiner binds `pk_pq` / `ct_pq` *directly*, it does **not need** ML-KEM self-binding — but stating it (a) keeps the X-Wing comparison honest and (b) prevents an implementer from importing an **expanded** malicious `dk` and reasoning incorrectly about the component. It is a **spec requirement**, not a proof dependency; the unconditional-on-KEM binding proof holds regardless.

### 3.6 `MAL-BIND-K-CTX` — precise definition (over a context-parameterized KEM)

> **Well-posedness warning.** In the standard CDM API, `P` and `Q` range over `{K, PK, CT}` — all **outputs** observable from the encaps/decaps transcript. `CTX` is a caller-supplied **input** that standard `Encaps`/`Decaps` neither take nor echo. "Add `CTX` to `Q`" is therefore **not a literal CDM instantiation**; it is **ill-typed** without a syntactic change to the KEM interface.

Define a **context-parameterized KEM** syntax:

```
Encaps(pk, ctx) → (ct, K)        Decaps(dk, ct, ctx) → K
```

where `ctx` is an **absorbed-but-not-transmitted** input that both parties commit to. The `MAL-BIND-K-CTX` game is a **syntactic extension** of CDM Figure 6 with `Q = {CTX}`:

> The adversary outputs two transcripts. It **wins iff**
> `K0 = K1`  ∧  `ctx0 ≠ ctx1`  ∧  `K0 ≠ ⊥`  ∧  `K1 ≠ ⊥`.

Required properties to argue (before mechanization):

1. **Conservative extension:** with `ctx` fixed/empty, the game collapses to standard `X-BIND-K-·`.
2. **Both parties commit to `ctx`** and the recovered `K` *determines* the `ctx` that produced it (binding direction is key → context).
3. **Reduces to CR** exactly like `K-CT`/`K-PK` (`ctx` is just another injectively-encoded absorbed field).

This **must** be documented as a non-standard superset guarantee, *not* a point in the published lattice, and positioned as a **KEM-level lift of HPKE's `info` / AEAD key-commitment** — "transcript/context binding promoted to the KEM layer." See §6 for the open soundness question and the [eprint 2026/140] adjacency.

---

## 4. Proof plan

### 4.1 Tooling

| Tool | Role | Rationale |
|------|------|-----------|
| **EasyCrypt** | primary, computational | Only ecosystem with reusable PQ-KEM/binding artifacts: verified ML-KEM IND-CCA (formosa-mlkem; [eprint 2024/843]); WIP X-Wing IND-CCA (formosa-crypto/formosa-x-wing); SandboxAQ binding-hierarchy library (`github.com/sandbox-quantum/EasyCrypt-KEMs`) mechanizing CDM notions and **`LEAK-BIND-K-PK` for ML-KEM**. SSProve/Coq, Lean, CryptHOL have **zero** PQ-KEM/binding artifacts. |
| **Tamarin** | *optional* motivation only | At most a single illustrative handshake lemma via the CDM Tamarin methodology — **not a deliverable** (see §6 scope-creep note). |

> **Reuse premises must be audited *before* committing the plan — go/no-go gate.**
> - **formosa-x-wing IND-CCA is WIP** (tested on EasyCrypt 2024.09, completion unconfirmed). Extending a moving base is **high-risk** and is **not** the "guaranteed result" it might appear. **Recommendation: do NOT mechanize IND-CCA** (see §4.3).
> - **SandboxAQ `EasyCrypt-KEMs` IS released**, but its mechanized ML-KEM result is **only `LEAK-BIND-K-PK`**; **`MAL`-binding and FO-transform binding are future work**, and impl-to-spec linkage is unfinished. The **MAL game scaffolding and the K-CT/K-PK monotonicity edges may not exist in reusable form.** Audit the repo concretely: confirm exactly which games (HON/LEAK/MAL) and which monotonicity edges are importable. If the MAL game must be built from scratch, **that alone is a large part of the budget and is the explicit core**, not an aside.
> - Pull the **primary PDFs** of [eprint 2025/1416] (Theorem 4 concrete bounds, plus any combiner-level notion X-Wing fails), [eprint 2025/1397] (Starfighters / QSF), and [eprint 2026/140] **before** publishing any novelty claim.

### 4.2 Part (b) — Binding (load-bearing, novel half)

1. **Model SHA3-256 as collision-resistant** (game `CR`, advantage `Adv_CR`).
2. **Injective-encoding lemma** — *prove first.* The fixed-width length-prefixed concat is **injective and total** on the field tuple (structural/byte-boundary reasoning; finite combinatorics). Include **totality** (no empty-field boundary shift). This is the **soundest, most finishable, confidence-building** piece and **de-risks** every theorem that depends on it.
3. **`MAL-BIND-K-CT` theorem.** Any adversary producing two transcripts with `K0 = K1`, agreeing CT-set, and a differing element yields **either** equal hash inputs (impossible by injectivity, since the differing element appears in the input) **or** a SHA3 collision. Reduce to `Adv_CR`. Bound: `Adv_{MAL-BIND-K-CT} ≤ Adv_CR`.
4. **`MAL-BIND-K-PK`** and **`MAL-BIND-K-CTX`** by the **identical structure** (`PK` / `CTX` is just another absorbed field). Same `Adv_CR` bound.
5. **Joint / LEAK / HON corollaries** by porting CDM monotonicity (Lemma 4.4) — reuse SandboxAQ edges if present, else re-prove (small).

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

> `Adv_{MAL-BIND-K-CT}`, `Adv_{MAL-BIND-K-PK}`, `Adv_{MAL-BIND-K-CTX}` are each `≤ Adv_CR(SHA3) + (negligible encoding terms)`, **assuming only collision-resistance of SHA3-256 (no binding assumption on the component KEMs)**; and ContextBound is IND-CCA2 if either component is.

---

## 5. Honest claim — vs X-Wing and naive hybrids

### 5.1 What ContextBound MAY claim

1. **Assumption-minimal binding.** ContextBound achieves `MAL-BIND-K-CT` and `MAL-BIND-K-PK` (hence the joint and all LEAK/HON variants) **assuming only collision-resistance of SHA3 — no binding assumption on ML-KEM or X25519.** The defensible delta vs X-Wing is **proof coverage / minimal assumptions**, framed as an **assurance/packaging advantage**: ContextBound's binding is provable from a **single, weaker primitive assumption (CR) in one self-contained proof**, whereas the equivalent guarantee for X-Wing is currently **distributed across an IETF-draft assertion plus separate ML-KEM self-binding results**, and X-Wing's *peer-reviewed* proof attains only **CCR** (which the X-Wing authors state is strictly weaker than `M-BIND-K-CT`).

2. **Context binding (orthogonal, additional).** ContextBound additionally provides `MAL-BIND-K-CTX` — a guarantee X-Wing simply **does not offer** (no context input). This is a **genuine additional / orthogonal** property, **not** a higher point in the standard lattice. *(Subject to the §6 soundness caveat — this is the weakest link.)*

3. **Vs naive concatenation `k = KDF(ss_pq ‖ ss_trad)`.** ContextBound is provably binding for **any** component KEMs, whereas the shared-keys-only combiner inherits **no** key/ciphertext binding and is **non-robust** [GHP18]. This is where the "no KEM binding assumption at all" pitch bites hardest.

### 5.2 What ContextBound MUST NOT claim

- **(a)** That it is *"strictly stronger binding than X-Wing"* in the standard X-BIND lattice on the **K-CT / K-PK** axes. **Both hit the same MAL ceiling.** Overstating this is factually wrong.
- **(b)** Any `X-BIND-CT-PK` / `X-BIND-CT-K` / robustness / SROB property — **structurally impossible** for an implicitly-rejecting (ML-KEM-based) hybrid.
- **(c)** That ContextBound is *needed* for TLS 1.3 / QUIC — those derive CT/PK binding from the **handshake transcript hash**. The most defensible statement there is **defense-in-depth**.
- **(d)** **(corrected per review)** A K-PK *binding-strength* delta vs seed-format X-Wing. **Per Schmieg [eprint 2024/523]:** any FO-transform KEM that stores the private key **as a seed** attains **both `MAL-BIND-K-PK` and `MAL-BIND-K-CT`** (re-deriving from the seed forces an honest KeyGen, so cached `H(ek)` and rejection secret `z` cannot be mismatched). Since construction-delta §3.5 **mandates** seed-format `dk`, a **seed-format X-Wing already attains both K-CT and K-PK** on the standard axes. **Therefore:**
  > **Naive ML-KEM in *expanded-dk* format is neither `MAL-BIND-K-CT` nor `MAL-BIND-K-PK` (Schmieg); seed-format ML-KEM is *both*. The ContextBound delta on the standard CT/PK axes is NOT a binding-strength gap at all — it is purely (i) assumptions that are *unconditional on the component KEM* and (ii) robustness to an implementer who ships expanded-dk. Frame it as assumption-minimality, never as a K-PK binding advantage.**

### 5.3 Honest comparison scope (lead with this)

> **Vs a correctly-implemented seed-format X-Wing, the incremental binding gain is *zero on the standard CT/PK axes*** — both attain `MAL-BIND-K-CT` and `MAL-BIND-K-PK`. What ContextBound adds is **(i) assumption minimality** (binding from CR alone, no reliance on ML-KEM's FO self-binding) and **(ii) robustness to an expanded-dk implementer**, plus **(iii) the orthogonal `K-CTX` context-binding axis** (subject to §6).

Reserve the full **"no KEM binding assumption at all"** pitch for the **expanded-dk and naive-concatenation** baselines, where it bites hardest.

### 5.4 Cost honesty — where ContextBound is *merely* different/slower, not stronger

> ContextBound absorbs **~2.3 KB more** into the combiner hash than X-Wing (`ct_pq` ~1088 B + `pk_pq` ~1184 B, plus the context). X-Wing's lean absorb is a **deliberate, proven optimization**, not a binding deficiency. On the **K-CT / K-PK** axes this extra cost buys **assumption hygiene, not a stronger notion**. The honest answer to "stronger vs merely slower" is: **on the standard axes, merely slower** (in exchange for assumption minimality); **only on the K-CTX axis is there a genuinely new property** (and even that is contested — §6).

### 5.5 The "unconditional" word — banned

The headline must **never** read "unconditional." In cryptography "unconditional" connotes information-theoretic / no computational assumption. Here the binding proof still rests on **CR of SHA3-256** (and the IND-CCA half additionally on SHA3-as-PRF and X25519 strong-DH in the ROM), all **idealized** in the mechanization. **Replace every instance of "unconditional" with "assuming only collision-resistance of SHA3-256 (no binding assumption on the component KEMs)."** We move the trust root **from ML-KEM's FO transform to SHA3 CR** — a *trade*, not an elimination.

---

## 6. Threats covered, residual gaps, effort

### 6.1 Threats covered

| Threat | How ContextBound covers it |
|--------|----------------------------|
| **Re-encapsulation / UKS under malicious keys** (PQXDH-class, [eprint 2024/702]) | Two `(pk, ct)` pairs decapsulating to the same `K` are prevented by `MAL-BIND-K-PK` + `MAL-BIND-K-CT` — defeated **at the KEM layer**, not by relying on the protocol to add `pk` to AEAD AD. |
| **ML-KEM expanded-dk binding failures** ([Schmieg, eprint 2024/523]) | Swapping cached `H(ek)` or sharing rejection seed `z` is neutralized: ContextBound hashes `pk_pq` / `ct_pq` **directly**, so it does **not trust ML-KEM's internal self-binding at all**. |
| **Cross-context / transcript confusion** | `MAL-BIND-K-CTX` stops the same `K` being reachable under two different protocol contexts (mode / role / version / peer identities in `context`) — the KEM-level analogue of AEAD key-commitment / partitioning-oracle resistance. *(Strength of this depends on §6.2 soundness.)* |
| **Combiner-collision attacks** | CR SHA3 over the **injectively-encoded full tuple** prevents two distinct component-tuples mapping to the same `K`. |
| **Non-robust-concatenation pitfall** ([GHP18]) | Every ciphertext is bound into the hash input, so an attacker cannot replay a mutated ciphertext that decapsulates to the same combined key. |

### 6.2 Residual gaps

1. **`MAL-BIND-K-CTX` is self-defined and is the weakest link of the novelty story.** `CTX` is an **input**, not a Decaps output, so adding it to `Q` is **not** a published-lattice point and is **not** covered by CDM monotonicity. **Worse:** once `ctx` is a hashed input, "key binds caller-supplied context" is **nearly tautological** — of course `H(…,ctx0) ≠ H(…,ctx1)` collisions reduce to CR. The notion's *value* depends entirely on whether the surrounding protocol feeds a **meaningful, mutually-agreed** context; at the KEM level it may prove little the protocol could not already get from its own transcript hash. **Resolution — pick one:**
   - **(a)** Downgrade `K-CTX` from "the genuine advantage beyond X-Wing" to *"a convenience guarantee equivalent to inlining a transcript-hash bind, provable trivially once `ctx` is absorbed"*; **or**
   - **(b)** Do the hard formal work: define the context-echoing `Encaps`/`Decaps` API (§3.6), prove the echo is **authenticated** (not adversary-controlled post-hoc), and exhibit a **concrete protocol attack** that `K-CTX` stops but that adding `ctx` to AEAD AD does **not**.

   Without (b), the "only honest place to claim stronger than X-Wing" framing is itself overstated.

2. **Prior work occupies the adjacent ground — reposition the contribution.** **[eprint 2026/140]** *"On the Necessity of Public Contexts in Hybrid KEMs: A Case Study of X-Wing"* analyzes **when** public context inputs are necessary vs redundant for existing notions (C2PRI, multi-target domain separation). **[eprint 2025/1397]** (*Starfighters / QSF generality*) analyzes the safety of omitting components. Neither **defines** `MAL-BIND-K-CTX`, so neither pre-empts the notion — but both must be **distinguished in writing**: *2026/140 analyzes when context is necessary/redundant for existing notions; ContextBound **defines context as a first-class binding target (`K-CTX`) and proves it**.* The most defensible framing of the thesis contribution is the **mechanization** — *"first machine-checked EasyCrypt binding proof for a context-carrying hybrid reducing only to CR"* — **not** the conceptual idea of context binding. Define `K-CTX` **in explicit relation** to the 2026/140 notion so the two are comparable, not orthogonal-by-accident.

3. **Idealization / no implementation linkage.** SHA3 CR & PRF are modeled as assumptions/ROM; the proof is only as strong as those idealizations. Impl-to-spec linkage was **unfinished** upstream (SandboxAQ). Promote the trust base **into the theorem statement** (§4.5) so no examiner reads "no KEM assumption" as "implementation-level."

4. **X-Wing baseline is distributed, not weak.** No peer-reviewed proof currently establishes full `MAL-BIND` for X-Wing (only **CCR** in CiC); the head-to-head rests partly on an **IETF-draft assertion** for X-Wing. State **both** baselines (draft-claim vs CiC-theorem) explicitly. **Do not** imply the CCR-vs-`MAL-BIND` delta is a *weakness* in X-Wing — the gap is largely *"not yet mechanized in one paper,"* and the same applies symmetrically to ContextBound.

5. **Reuse status is a go/no-go gate.** Confirm exactly which SandboxAQ games/edges are importable (only `LEAK-BIND-K-PK` is mechanized today; MAL is future work). Treat formosa-x-wing IND-CCA as **WIP / do-not-extend** (§4.3).

6. **Seed-format / import-validation is a spec requirement implementations may violate** (expanded-dk libraries exist). The binding proof does not need it; the *comparison narrative* does. Implementation drift is **out of scope** of the proof.

7. **Primary-source verification pending.** Concrete bounds in [eprint 2025/1416, Theorem 4], the [2025/1397] results, and [eprint 2026/140] were only partially accessible. **Re-verify against primary PDFs before publishing the novelty claim** — elevate this to a **go/no-go gate**.

### 6.3 Effort estimate (honest, single undergraduate)

> **Reality check (critical):** EasyCrypt has a notoriously steep learning curve. A first machine-checked **reduction-with-oracles** (which both IND-CCA and the binding games are) typically costs an **expert weeks-to-months per theorem**, and a stuck proof has **unbounded tail latency**. Completing **all** listed artifacts in one thesis cycle is **not realistic** for a single student.

**Committed plan (success criterion = ONE fully-mechanized theorem):**

| Phase | Budget | Status |
|-------|--------|--------|
| EasyCrypt ramp (pure tooling/tutorials, before any thesis-specific proof) | **8–12 weeks** | prerequisite |
| Notion definitions (`K-CT`/`K-PK` games, `K-CTX` extension §3.6, injective-encoding lemma statement, X-Wing framing) | 3–4 weeks | — |
| Spec deltas (mandatory non-empty context, fixed-width prefixing, domain label, seed-format) + reference KATs incl. negative collision vectors | 2 weeks | — |
| **Injective-encoding lemma (mechanize FIRST — de-risks everything)** | within above | confidence-building, finishable |
| **`MAL-BIND-K-CT` via CR — the single committed mechanized deliverable** | 4–6 weeks | **core** |

**Stretch goals (clearly labeled, paper-proof-plus-stretch):**
- `MAL-BIND-K-PK` and `MAL-BIND-K-CTX` mechanization.
- CDM monotonicity port for joint/LEAK/HON corollaries.
- IND-CCA2 — **paper argument only**, do **not** mechanize (§4.3).
- Tamarin — **cut, or** at most one illustrative lemma; a second prover is a classic scope-creep trap. **Not a deliverable.**

**Go/no-go gates before committing the novelty claim:** (1) audit `EasyCrypt-KEMs` for importable MAL games/edges; (2) confirm formosa-x-wing status (expect WIP → do not extend); (3) pull primary PDFs of 2025/1416, 2025/1397, 2026/140.

---

## References

- **[CDM23]** Cremers, Dürmuth, Medinger, Naderpour. *Keeping Up with the KEMs: Binding (committing) security of KEMs.* (X-BIND-P-Q framework; HON/LEAK/MAL classes; Figure 6 game; monotonicity "Lemma 4.4".)
- **[eprint 2024/523]** Schmieg. *Unbindable Kemmy Schmidt: ML-KEM is neither MAL-BIND-K-CT nor MAL-BIND-K-PK in expanded-dk form; seed-format dk attains both.* (Also keymaterial.net writeup.)
- **[eprint 2024/702]** Fiedler, Günther. *PQXDH re-encapsulation / UKS analysis.*
- **[eprint 2024/843]** *Verified ML-KEM (Kyber) IND-CCA in EasyCrypt* (formosa-mlkem).
- **[eprint 2025/1416]** *Generic hash combiner binding (GHP/Chempat "hash-everything"); Theorem 4 sufficiency upper bound; Theorem 9 / separating examples for necessity; Table 1.*
- **[eprint 2025/1397]** *"Starfighters" — QSF generality / safe omission of components in hybrid KEMs.*
- **[eprint 2026/140]** *On the Necessity of Public Contexts in Hybrid KEMs: A Case Study of X-Wing.* (Defines C2PRI for the X25519 interface; analyzes when public context is necessary/redundant — adjacent prior work to distinguish from `K-CTX`.)
- **[XWing-CiC]** *X-Wing: The Hybrid KEM You've Been Looking For* (CiC). (Proves **CCR**; states CCR is strictly weaker than `M-BIND-K-CT`. `XWingLabel = 0x5c2e2f2f5e5c` = ASCII `\.//^\`.)
- **[GHP18]** Giacon, Heuer, Poettering. *KEM combiners.* (Non-robustness of shared-keys-only concatenation; "IND-CCA if either component is" combiner.)
- **SandboxAQ `EasyCrypt-KEMs`** — `github.com/sandbox-quantum/EasyCrypt-KEMs`. (Mechanizes CDM notions; `LEAK-BIND-K-PK` for ML-KEM done; MAL / FO-binding future work.)
- **formosa-crypto/formosa-x-wing** — WIP X-Wing IND-CCA in EasyCrypt (2024.09; completion unconfirmed).
