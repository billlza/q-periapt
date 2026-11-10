# Independent final mathematical review

Reviewer: literature agent. Scope: frozen full-manuscript increments and the forthcoming Connection A supplement.

## Frozen manuscript increments: completed

**Verdict:** no substantive mathematical error found in the two reviewed increments under their stated interfaces.

- `manuscript/guarded-provenance.tex` — SHA-256 `f7b36ef86bdd4733af0b882c9f192e52ad40ef041ae22046e63e1584e2c897ca`.
- `manuscript/acquisition-nonadditivity.tex` — SHA-256 `50cd83948e5e03329eacfbc380af9f7a99b63abab3cc6e3e75f0edf7f3dcd297`.

### Guarded normalization

The normalization is exact for the stated finite immutable containment DAG with fixed public key-derivation edges independent of recovered plaintext. The forward inclusion traces first record derivations back to an acquired record; every guard key lies in the key closure. The reverse inclusion performs the matching derivations along a satisfied path. Direct source disclosures are accounted for in both sides. The pointwise argument applies at every adaptive-history prefix without an independence assumption.

The source sort represents protected-value derivability, while origin identifiers may already be public. Canonical actual-key identities prevent treating equal key aliases as independent conjuncts. Seeded key cycles are handled by least reachability, whereas an unseeded cycle contributes no new keys. Record containment remains acyclic. The record source sets are declared inputs; native source-label preservation is not silently inferred from the equality theorem.

The cumulative-acquisition model supports the deletion and late-disclosure corollary. The finite checker and theorem use this same convention. The additional complexity paragraph correctly treats the route table as a declarative normal form that may have exponentially many paths, while the finite rule closure has at most N strict-growth rounds and can be evaluated in O(N(N+M)) time and O(N+M) space under the stated indexed representation.

### Acquisition nonadditivity

The two singleton exposure sets are empty and the joint exposure set is nonempty. Therefore no fixed per-object union representation can be exact for all four input subsets. This is a statement about the expressly declared derivability rules, and the proposition does not confuse public origin identities with seed disclosure. The separate independent-uniform XOR example has the stated conditional entropies and exact reconstruction relation; its single-observation guessing success is 2^(-lambda). The text does not identify that toy distribution with the protocol encryption scheme.

## Connection A opaque renderer: completed independent review

**Reviewed version:** `theory_increment.md`, version 1.2, SHA-256 `98e0df8b8536d5d43cd191a0a9851676345e8c20aebe82a298c4d86dd6b8035e`.

**Verdict:** the explicit simulator, equality lemma and statistical coupling establish the claimed result for the declared finite typed interface. No remaining substantive error was identified in this version. The composition is valid under the expressly retained hypotheses of the existing record-commitment hop. This is a completed algorithmic increment for that subinterface: the simulator operates without the selected KEM reservation coins.

### Detailed findings

| Item | Review result |
| --- | --- |
| Byte equality and cache identity | On pairwise-distinct sealing nonces, different fresh image invocations differ at the same explicit nonce offset. Identical image handles refer to immutable bytes. For intents, the complete canonical prefix is part of the key, each tag fixes its prefix length, and the same image has one fixed deterministic authentication key. These facts prove both directions of the equality equivalence. The cache does not identify a fresh seal with an exact replay or identify two objects merely because they have the same reservation source. |
| Equal source values | Two distinct reservation origins may accidentally contain equal atom bytes; the equality proof does not need to discover or exclude that event. Fresh sealing nonces still separate the complete image wires. |
| Nonce collision accounting | With independent uniform 192-bit fresh nonces and at most M sealing invocations, adaptive invocation decisions do not invalidate the union bound. The loss is min(1, choose(M,2) / 2^192) for a terminal bit and at most twice that for a score in [-1,1]. M includes all fresh seals, including renderable atom-free images and attempts whose later persistence fails. Exact replay consumes no new nonce. |
| Opaque versus renderable rows | Only designated images containing an opaque atom and their intents get independent cached ideal digests. Atom-free objects retain their actual bytes and real shared-oracle hashes. Image-encryption and intent-authentication keys are known local inputs. Therefore an allowed atom-free acquisition can be serialized and checked consistently, including an adversary hashing its returned bytes. |
| Allowed computation and oracle access | Branch-driving metadata and recipe lengths are available without opening atoms; other private-byte observations are outside the typed operation list. The local encryption and intent authentication maps are fixed deterministic byte functions. Public computation and the common functional interface retain their specified calls; the result does not silently grant arbitrary new oracle-dependent maps. |
| Terminal tests | Version 1.2 restricts the same terminal test to the common public view, available metadata/event ledger, F outputs, and its own independent test coins. The retained application challenge bit is explicitly a test coin. A test cannot inspect the designated private nonce, unknown atom or materialized private wire. This keeps the coupling statement and commitment composition on the same allowed observation interface. |
| Digest composition order | First replace raw-handle equality by structural equality in the real-digest experiment, charging the nonce term. This removes that raw-nonce-dependent observation before applying the existing commitment hop. Its resulting structural, ideal-commitment game has an exact opaque-table implementation. Thus the bit loss is bounded by delta_nonce + epsilon_rec, capped at 1; the signed-score loss is twice that, capped at 2. Without private-wire equality, the extra nonce term is unnecessary. |
| Commitment budgets and confinement | The intent-digest interface is explicitly restricted to the five existing domains, with the image head as the sixth domain. The bound q_i <= 1 + 5 K_i is therefore matched to the operation inventory. Atom-free images have q_i = 0 for replacement accounting; their actual oracle work still belongs in the ordinary Q_i budget. All designated private rows retain the original commitment theorem's per-nonce confinement and fixed-input conditions. |
| Unknown KEM coins | The simulator never computes a designated image ciphertext or its private intent MAC. It samples nonces, maintains handles and recipe lengths, answers ideal digest queries through the keyed cache, and calls the declared functional interface F for protocol outputs. The record-commitment hop precedes KEM embedding, when the real source experiment can construct its record inputs; the resulting opaque algorithm then supports the adapter. There is no call to a hidden trusted renderer or request for the challenger's generation/encapsulation tape. |
| Fixed-candidate stopping | The successful acquisition event must be determined from provenance and must permanently invalidate the stipulated fixed-candidate score before private serialization. A failed capture, ordinary error, unrelated acquisition, or merely inconvenient public output does not meet this condition. |
| Adaptive target stopping | For F_j = Eligible AND Attr AND (I = j), stopping requires a computable ledger event that makes F_j false for every continuation and every still-admissible final coordinate choice attributed to j. The note explicitly states this stronger condition. The fixed-target result is not presented as a proof that every native adaptive-pair instance already satisfies it. |
| Native correspondence | The source nonce position [80,104), complete target embedding and fixed tag-dependent prefix layouts support the declared constructor shapes. Full native call-site compilation into the typed interface remains a separate source-correspondence statement. No new native execution or full computational recovery theorem is claimed by this supplement. |

### Issues resolved during review

1. **Renderable acquisitions need all cryptographic inputs.** An atom-free recipe and a locally sampled nonce alone do not ensure an intent can be serialized if its authentication key is unavailable. The final version makes image-encryption and intent-authentication keys known local inputs and preserves real rendering for these objects.
2. **An acquired raw record cannot retain an independently replaced head under the nonce-confinement hop.** If its head were independently random, the adversary could hash the acquired bytes and compare. The final version replaces only designated private rows; atom-free rows keep real digests and q_i = 0 in the replacement sum.
3. **Adaptive invalidation must be permanent for the scored event.** Invalidating one current candidate does not justify terminating a run that may select another target. The final text states the all-continuations condition for F_j and retains the proved fixed-candidate result.
4. **Terminal-test randomness cannot include hidden storage nonces.** The final version permits the test's own independent randomness, explicitly excluding access to the designated nonce, wire and atom. This avoids creating an extra nonce channel when applying the commitment bound.

The image/intent equality proof, the exact replay cache, the nonce bound and the all-continuations condition were checked by direct reasoning. The current source shapes were also compared with the local `durable.rs` and `durable/write_intent.rs` excerpts and the existing `HIDDEN_RECORD_COMMITMENTS_V1.md` / `MULTI_RECORD_COMMITMENTS_V1.md` interfaces. This review did not run native experiments or perform a new literature search, and it did not modify the frozen manuscript.

### Result that can be used now

For the declared typed fixed-candidate image/intent subinterface, the coin-free renderer is explicitly constructed and proved to preserve the idealized observations, with the stated statistical loss when raw-handle equality is admitted. Together with the existing conditional commitment hop, it gives the displayed real-to-opaque bound. The remaining source correspondence and any broader adaptive-pair or cleanup-report composition should be stated as their own claims, rather than counted as consequences of this finite lemma.
