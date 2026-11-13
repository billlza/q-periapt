# Reservation-to-ordinary signature security

Date: 2026-11-08 UTC. Full reduction and source correspondence for the accompanying manuscript module. Independent proof review and finite/source-audit receipts are provided alongside this document.

## 1. Results and model

This note establishes a generic bridge for a signer whose fresh internal tape is produced by an independent keyed hedging function. It then constructs a direct bridge for the native ML-DSA-65 algorithm in a shared random-XOF model. The native construction includes key generation, rather than assuming that real key-generation blocks are independent of the public oracle.

Nonce-based security and hedged signatures have an established literature: Bellare–Tackmann develop nonce-based cryptography and hedged extractors; Aranha et al., Grilo et al., and Kosuge–Xagawa analyze hedged Fiat–Shamir or ML-DSA security under nonce/fault interfaces [5–8]. The results here specialize the connection to persistent reservations, their original-operation replay and complete private-invocation ledger, and give an explicit shared-keygen/shared-hedge XOF comparison for the native ordinary signer. The generic hedging principle is used as background, without a first-result claim.

For one protected signing family, the generic result is

\[
 p_{\rm res}(A)\le p_{\rm euf}(B)
 +\epsilon_{\rm prf}(D_0)+\epsilon_{\rm prf}(D_1)
 +\beta_n(q),\qquad
 \beta_n(q)=\min\{1,\tbinom q2 2^{-n}\}.                 \tag{G}
\]

Here `q` bounds distinct executed `(original randomizer, public descriptor)` pairs, and the ordinary signer draws and hides a fresh outer randomizer on each call. Exposed Reserve draws do not enter the birthday term.

Every displayed query budget is a fixed worst-case cap over the relevant complete experiments and hybrids, including adaptive descriptor computation; it is not a distinct-pair count measured in one realized native trace. The original Execute-call cap always provides a valid conservative cap for `q`.

For the specified native ML-DSA-65 interface, let `q_*^res` and `q_*^ord` bound the remaining SHAKE256-oracle calls that can address a 34-byte or 128-byte input in the two complete experiments defined below. Then

\[
 p_{\rm res}^{\mathcal H}(A)
 \le p_{\rm euf}^{\mathcal H}(B)+\beta_{256}(q)
 +\delta(q_*^{\rm res})+\delta(q_*^{\rm ord}),          \tag{N}
\]

where

\[
 \delta_{\rm ROM}(v)=\min\{1,v2^{-256}\},\qquad
 \delta_{\rm QROM}(v)=\min\{1,2v2^{-128}\}.             \tag{1}
\]

The QROM statement has a quantum public-XOF interface and classical Reserve/Open/Execute and signing interfaces. It is a reduction to ordinary hedged ML-DSA EUF in the *same* oracle model; the ordinary-EUF term retains its own computational assumptions and resource bounds. Equation (N) uses a direct statistical oracle coupling, so it contains no separately assumed native-PRF term. Its proof is in Sections 5–7.

### 1.1 Owners, aliases, and the two ledgers

An owner family is created by an independently generated signing instance. References and imports that copy that instance retain its family index. This lineage is maintained by the controller and is independent of the value of secret bytes. A fresh independent generation receives a new family index, including when its public key happens to coincide with another public key. Equal public keys alone do not identify secret signing states.

The native **actual-key ledger** contains every honest private signing invocation under the same actual signing state, across purposes and exact owner aliases. This is the freshness criterion already used by the source-attribution result. A successful native output is also stopped by acquisition of its actual target key or target owner file.

For the reductions, a **family ledger** records every executed original message in that family, including through declared aliases. It is a subset of the actual-key ledger. A family exposure stop occurs immediately before any secret key, seed, expanded key, or secret-containing owner-file bytes of a member of that family would be returned. It includes files that are protected at rest: acquiring the file is the modeled exposure event.

Actual-key freshness and actual-key non-exposure imply the corresponding family conditions. We therefore upper-bound the native success event by the more permissive family-fresh, family-stopped event. This step avoids testing accidental equality of hidden secret states inside a simulator or its final predicate. All success implications go in the required direction. The simulator does not merge independently generated owners merely because their public keys agree.

An owner view before its family stop consists of public key/identity information, reservation records, controller bookkeeping, and permitted signing results. Its bookkeeping and alias decisions do not inspect secret bytes. Secret-dependent commitments, readable owner-file bytes, and side-channel observations are not in this interface. This is the same opaque-owner interface used by the accepted signature adapter. Non-target owners may be generated locally and exposed as specified in Section 4.

### 1.2 Reservation semantics

All reservation operations are classical. `Reserve(h,M)` stores the exact original message and samples its original `r` from `{0,1}^n`. `Open(i)` returns this `r` and the permitted public record, before or after execution. `Execute(i)` uses the stored original message and randomizer. Its first private invocation enters `M` in the family ledger **before publication**. A simulated publication failure suppresses the response but does not remove the signing-oracle query, signature cache, or ledger entry. A retry of the same retained operation returns the same deterministic result.

The adversary can create many reservations, open them, and select which ones to execute. Distinct slots may contain the same pair. The controller invokes signing only on each slot's retained exact tuple. The native raw reservation method compares a hash binding; its admitted controller supplies the original retained tuple, as established by the earlier source audit. This bridge does not add a raw tuple-retargeting interface.

If the native game offers repeated Verify calls and remembers a successful fresh-message event before later exposure, the reduction outputs at the first successful family-fresh target verification and halts. That predicate uses only the public verifier and family ledger. An actual-key-fresh success supplies such a candidate no later than its own occurrence. The final-forgery presentation below therefore covers the saved-event convention without an extra guessing factor.

Write `d_pk(M)` for a publicly computable descriptor. The entire signing computation must factor as

\[
 \operatorname{Sign}(s,K,M;r)
 =S^\mathcal O(s,d_{pk}^\mathcal O(M);
                   F_K^\mathcal O(r,d_{pk}^\mathcal O(M))),             \tag{2}
\]

where `S` is deterministic given its arguments and the fixed public oracle(s). Verification and freshness retain the **original message**. Public purposes and context strings are part of the original message domain or its unambiguous framing.

The simulator has a separate cache for each family, indexed by `(r,d_pk(M))`, and a separate raw-message ledger. A descriptor collision reuses the exact signature when the randomizer also agrees; every executed original message is entered in the ledger. This is why the bridge needs no descriptor collision penalty. It uses ordinary EUF, with message freshness, rather than strong unforgeability.

## 2. Generic independently keyed bridge

Generate each base state `s_h` with its public key using the public companion oracle `O`, and independently generate the hedging keys `K_h`. Independence is from the entire base-owner state and all initial side information, conditional on the specified public-oracle experiment. The ordinary wrapper signing oracle samples a fresh hidden `u` and evaluates (2).

The required multiuser joint-PRF game has per-family indexed private evaluation interfaces and the same public oracle access as the signature experiment. Its real interfaces use `F_{K_h}^O`; its ideal interfaces use independent private random functions `R_h`, independent of `O`. Calls to the private interfaces are classical. A quantum distinguisher may query the public `O` in superposition. Simulators must be able to create the base-owner states without receiving a challenge hedging key. Accidental equal hedging keys in the real multiuser game are part of that game and its advantage; exact owner aliases retain one indexed interface.

**Theorem G (globally protected families).** Consider `U` protected families. Stop the experiment before any secret/key-file return from any protected family. Suppose the number of distinct executed pairs in family `h` is at most `q_h`. There are an ordinary multiuser wrapper-EUF adversary `B` and two joint-PRF distinguishers `D_0,D_1` such that

\[
 p_{\rm res}(A)\le p_{\rm euf}^{\rm mu}(B)
 +\operatorname{Adv}_{F,\mathcal O}^{\rm mu\text{-}prf}(D_0)
 +\operatorname{Adv}_{F,\mathcal O}^{\rm mu\text{-}prf}(D_1)
 +\min\left\{1,2^{-n}\sum_{h=1}^{U}\binom{q_h}{2}\right\}.            \tag{3}
\]

Each distinguisher and `B` makes at most `q_h` private primitive queries for family `h`. All public descriptor work, other public-oracle access, local key generation, memory, and simulation time are included in their respective resource bounds. The number of Reserve/Open calls contributes storage and time but not the displayed birthday loss.

### Proof

First replace the hedging interfaces in the reservation game by independent `R_h`. Distinguisher `D_0` generates the independent base states, samples all original randomizers, maintains slots and ledgers, and requests one evaluation per new executed pair. The joint-PRF experiment supplies the public companion oracle, so every other base/oracle call is unchanged. This gives the first PRF term.

Next run the following efficient simulator `B` with ordinary wrapper signing oracles. It samples visible reservation randomizers locally. On every first slot execution it records its original `M`. On a new pair `(r,d_pk(M))`, it queries its family's ordinary signing oracle on that `M`, caches the resulting signature, and applies the requested publication outcome. A repeat pair retrieves the cache. A retry after failed publication uses the retained cached value. An exposure call for a protected family stops the simulation before secret bytes are requested.

Temporarily replace the ordinary challenger's hedging interfaces by `R_h`. On each new cache miss, the ordinary challenger samples a fresh hidden `u` and evaluates `R_h(u,d_pk(M))`. Until this hidden input repeats within its family, these internal tapes are independent uniform values. Couple them in order with the independent tapes associated with the reservation game's distinct visible pairs. All classical transcripts and quantum adversary states agree in this middle coupling; the public companion oracle is the same and is independent of the private random functions.

The `t`-th ordinary call for one family has conditional repeat probability at most `(t-1)/2^n`. The descriptor can be chosen adaptively; `u` is drawn only after that choice and remains fresh. A union bound over fixed per-family call caps gives the last term of (3). This is a collision among **hidden ordinary-challenger draws**. Repeated visible pairs, including collisions selected after opening arbitrarily many reservations, are handled exactly by the cache.

Finally replace the ordinary challenger's random functions by its real hedging functions. Distinguisher `D_1` knows the independent base states, runs `B`, samples the ordinary hidden randomizers, and forwards the required indexed evaluations. This costs the second joint-PRF advantage. Every ordinary signing query on the selected family was caused by an executed original message in that family. Thus a family-fresh output is an ordinary-fresh output. The stronger native actual-key-fresh event is already a subset. Verification is unchanged. This proves (3).

If the primitive assumption is instead ordinary EUF of the randomized **base** signer `S(s,d;fresh tape)`, the middle simulator can obtain one independent tape-induced signature per distinct visible pair directly from that oracle. There is one PRF term and no outer-randomizer birthday term. This is a separate corollary with a different primitive assumption.

### 2.1 Why per-slot caching is insufficient

Consider a toy outer-randomizer space of size `N`. Open many reservations for one message, choose two equal randomizers, and execute only those slots. Their true signatures are identical. A simulator issuing two independent ordinary queries can return different signatures. The probability of finding the visible collision is controlled by the number of Reserve draws, not by the two executions. A cache keyed by the complete `(r,d)` pair reproduces this behavior exactly and leaves only the hidden-challenger collision term in (3).

### 2.2 The independent-key hypothesis has content

The exploratory note gives a generic separation when the base signer also uses the same hedge key: a reversible keyed mask can make the visible signature appendix equal to `r XOR secret`, while hidden fresh `r` preserves ordinary EUF. Opening `r` then recovers the secret. That separation is not an ML-DSA attack. The native proof below checks how `K` is actually used and replaces the shared oracle jointly, rather than applying Theorem G to real FIPS keygen without its independence hypothesis.

## 3. Descriptor and failure accounting

No injectivity of `d_pk` is required. Suppose distinct original messages `M_0,M_1` satisfy the same descriptor and use the same `r`. Factorization (2) gives the same signature. `B` queries one representative message but records both executions locally. Its ordinary signing-query ledger is a subset of its local raw-message ledger. Consequently a local fresh output is primitive-fresh, even if it has the descriptor of a previously signed message. Any such successful output is already a valid ordinary-EUF forgery.

If private computation finishes and publication fails, `B` has already made the ordinary query. Repeated execution on the original reservation preserves the signature. Erasing the failed invocation from the freshness ledger would change the security game; the accepted source-attribution game retains it. Recomputing a deterministic result internally may use additional public-oracle calls and time, which belong in the native resource accounting, but does not create a new primitive signing query in the cache simulator.

The cache is indexed by the full exposed randomizer and public descriptor, not by a digest of that pair. The implementation may use a collision-free finite dictionary representation. Its exact table equality is a simulation device, not a claim that an unqualified hash-binding API is injective.

## 4. Adaptive owner creation and non-target exposure

The no-extra-factor multiuser theorem uses a global stop for its protected set. To preserve the accepted native game's ability to expose other owners, use a guessed target family and a single-user primitive challenger.

Let `U` bound the number of fresh independently generated honest families. Sample `J` uniformly from `{1,...,U}` before the run. Count fresh creations, including adaptive ones; references/import aliases do not increment the count. At creation `J`, embed the challenger public key. Generate every other family locally, including its complete secret state, and answer its permitted key/file disclosures. Stop immediately before a disclosure from the selected family or one of its declared aliases. If family `J` is never created, or the final candidate concerns another family, output failure.

For every successful native execution there is a designated accepted target-family index `i`. With probability `1/U`, `J=i`; all its allowed pre-stop behavior is simulated. Actual-key freshness implies freshness against the selected ordinary signing oracle. A key disclosed from an unrelated generation that accidentally has the same secret state only makes the native exposure condition stricter than the lineage-stopped auxiliary experiment. No secret-equality predicate is needed by the reduction.

Write `A_J` for this target-selected experiment and let all other owners be part of its local environment. For a uniform bound `epsilon_euf` on the resulting single-user ordinary adversary and corresponding uniform bridge terms, the adaptive-target corollary has the form

\[
 p_{\rm native}(A)\le
 \min\{1,U(\epsilon_{\rm euf}+\epsilon_{\rm bridge})\}.                \tag{4}
\]

Equivalently one can retain the sum of the actual per-target bounds instead of a common maximum. For the generic result, the bridge terms are the two single-target joint-PRF advantages and `beta_n(q_J)`; known non-target hedging keys are evaluated locally in both PRF experiments. For the native result they are given by (N), with the other owners' original shared-XOF calls included in each `q_*` budget.

This construction distinguishes three notions: declared owner lineage determines simulation routing; actual signing-state identity determines native freshness/exposure; public-key equality alone changes neither routing nor the key-generation distribution. There is no conditioning on distinct public keys.

## 5. Native ML-DSA-65 source correspondence

The checked repository is `billlza/q-periapt` at commit `358b921ab3469ce49f166633fc9a762ff6ed7e3d`. Both relevant lockfiles select `fips204 0.4.6`, archive SHA256

`c9fb5a367b9846933e271a3c2a992930743f82ae5e8cb7faa780715a80fa0b15`.

The official crate archive was downloaded and its digest matched this lockfile value. Its `.cargo_vcs_info.json` identifies upstream commit `8d456d989dce681233ef963d3c3306da8f76d7c7`. The extracted source files' Git blob identities match the same files fetched from that upstream commit. `source_identity.json` records exact local and upstream identities.

FIPS 204 Algorithms 6 and 7 and the checked source give, with byte lengths shown,

\[
 (\rho_{32},\rho'_{64},K_{32})
   =H(\xi_{32}\Vert k_1\Vert\ell_1,128),\quad
 \mu=H(\operatorname{tr}\Vert M',64),\quad
 c=H(K_{32}\Vert r_{32}\Vert\mu_{64},64).              \tag{5}
\]

For ML-DSA-65, `(k,ell)=(6,5)`. The source `key_gen_internal` reads the three consecutive blocks from one SHAKE256 reader. `sign_internal` reads `cap_k` only for the hedge derivation in (5). The remaining signature calculation is a deterministic function of the remaining key, `mu`, and `c`, using the original shared SHAKE256 and SHAKE128 operations. The private-to-public-key computation explicitly ignores `cap_k`. Key serialization includes it, which is why the opaque-owner stop is part of the interface.

The native backend passes the retained 32 bytes to `try_sign_with_seed`. The upstream implementation uses a `DummyRng` whose 32-byte fill returns those exact bytes, and signing performs one such fill before the internal algorithm. Hence the exposed reservation contains FIPS `rnd`, not the later masking vector or expanded internal randomness. The present theorem concerns this precise original-randomizer interface.

The continuity signer uses the fixed ASCII context

`Q-PERIAPT-CONTINUITY-IDENTITY-CANDIDATE/v1`

and frames its ML-DSA message as `context || purpose_byte || BE32(body_length) || body`. The FIPS message wrapper adds `0 || context_length || context`. Thus the descriptor is publicly computable from the verification key, context, purpose, and body. All ledger and primitive freshness statements retain this complete original framed message.

## 6. Exact shared-XOF construction

Fix one selected honest family, and model SHAKE256 by a public random XOF `H`. For each complete input string `x`, `H(x)` is an independent infinite random bit string; every requested output length returns the corresponding prefix. A quantum query uses the standard reversible XOR interface on the chosen finite output prefix. SHAKE128 and the other public algorithms retain their own declared interfaces and are independent of the sampled random-XOF table. They are the same in the two games.

Sample independently:

- a uniform 32-byte `xi`;
- uniform blocks `rho` (32 bytes), `rho_prime` (64 bytes), and `K` (32 bytes);
- a public random-XOF table `H_0`;
- a private random function `R:(r_32,mu_64)->{0,1}^512`.

Set

\[
 g=\xi\Vert[6]\Vert[5],\qquad
 \mathcal S_K=\{K\Vert r\Vert\mu:r\in\mathbb B^{32},
                                      \mu\in\mathbb B^{64}\}.        \tag{6}
\]

The singleton `g` has input length 34 bytes; every member of `S_K` has length 128 bytes. These sets are disjoint. Define a second XOF table `H_*` as follows:

1. At `g`, its first 128 output bytes are `rho || rho_prime || K`; all later output bits are the corresponding tail of `H_0(g)`.
2. At `K || r || mu`, its first 64 output bytes are `R(r,mu)`; all later bits are the corresponding tail of `H_0(K || r || mu)`.
3. At all other complete inputs, it equals `H_0`.

This defines full XOF strings, so overlapping output requests are automatically consistent. It also preserves calls that squeeze further blocks from one reader.

### 6.1 Exact real-world distribution

Condition on `xi` and the 128-byte key-generation output. Then `K` and the selected slice `S_K` are fixed. Every other `H_*` input still has an independent uniform full output string: its first block either comes from a fresh private `R` entry or from `H_0`, and its tail is independent. Consequently `H_*`, the keygen seed, and the selected blocks have **exactly** the joint distribution of native uniform-seed key generation with a public random XOF. The fact that the slice is selected using part of the keygen output creates no further correlation among those other independent output strings.

Run native key generation with these sampled blocks directly, in place of every designated target-lineage call to `H_*(g,128)`. This includes seed re-expansion when a target owner or one of its declared aliases is reopened or reconstructed. During target signing, use `R(r,mu)` directly in place of every designated call to `H_*(K || r || mu,64)`, including recomputation after failed publication. These are exact rewrites by the definition of `H_*`, even when the designated call repeats. All remaining public, base-signing, key-expansion, descriptor, verification, and non-target-owner calls still use `H_*`.

Call this rewritten real experiment `Real_*`. Replace only those *remaining* oracle calls by `H_0`, retaining the same sampled blocks and private `R`; call the resulting experiment `Ideal_0`. In `Ideal_0`, neither `xi` nor `K` is used by any remaining observable computation. Secret serialization and return are excluded before the selected family stop; the two designated computational uses have already been rewritten. The remaining base key can depend on `rho`, `rho_prime`, `H_0`, and other public algorithms, all independent of `xi,K`.

Other owners keep their original native generation and signing algorithms, using the current public XOF. Their calls count in the comparison. In particular, another seed input coinciding with `g`, or another owner using the same `K` prefix, is a query into the difference set. It is already covered by the bound below, even if that owner's key is subsequently disclosed. We do not apply a hidden-prefix claim to a disclosed non-target key.

### 6.2 Classical query bound

In an ideal execution, the target `xi,K` are uniform and independent of every remaining query distribution. A query whose input length is 34 can equal `g` with probability at most `2^-256`. A query of length 128 has the target prefix with probability `2^-256`. These lengths are disjoint, so a single query has probability at most `2^-256` of addressing

\[
 \mathcal D=\{g\}\cup\mathcal S_K.                     \tag{7}
\]

All other input lengths have zero probability. The two experiments are identical up to the first query in `D`. With at most `q_*` calls that can address one of these lengths, their output-event probabilities differ by at most `delta_ROM(q_*)` in (1). This reasoning includes the verifier deciding the final success event.

### 6.3 Quantum query bound

Fix `H_0,R,rho,rho_prime` and all other ordinary experiment randomness; retain the uniform hidden `xi,K`. Purify the common computation, including classical interfaces and its final event measurement. The ideal query-register reduced state is independent of `xi,K`: dormant secret registers are unread after the exact rewrites and can be omitted from the observable computation. Let `p_t(D)` be its squared query-register mass on complete inputs in `D`. A query can have amplitude on both relevant lengths, but the masses on those disjoint length sectors sum to at most one. Therefore

\[
 \mathbb E_{\xi,K}[p_t(\mathcal D)]\le 2^{-256}.         \tag{8}
\]

Let `O_*` and `O_0` be the two prefix-consistent XOR oracles. They agree off `D`, and for any ideal state `psi_t`,

\[
 \|(O_*-O_0)|\psi_t\rangle\|_2\le2\sqrt{p_t(\mathcal D)}.             \tag{9}
\]

Apply the telescoping hybrid with the **ideal prefix state** at each replaced query. Equivalently, induct on the real/ideal state distance and insert the ideal state before the next oracle. Common operations preserve or contract distance. The final Euclidean distance is at most the sum of (9). Jensen's inequality and (8) give an expected distance at most `2 q_* 2^-128`. The difference in any final event probability is at most the trace distance, which for these purified states is at most their Euclidean distance. This proves `delta_QROM(q_*)` in (1).

Calls with input length certainly outside `{34,128}` use exactly the same oracle operator and can be treated as common operations. An arbitrary quantum public-XOF query can be decomposed by its input-length register into a possibly changed query and common safe-domain operations; charge one possible changed call to each such public query. Thus `q_*` is a worst-case bound on possibly changed calls in this composed computation, rather than an expected number of classical hits.

For an implementation with potentially unbounded safe-domain rejection loops, perform this same comparison with a finite computation cutoff `T`. The bound is independent of `T` provided the number of sensitive-capable calls is bounded by `q_*`. Let `T` tend to infinity, treating nontermination as failure; terminal-event probabilities converge. This yields the same statistical bound without a rejection-loop tail. Running time and all oracle work remain part of the ordinary-EUF resource accounting. An implementation lacking this domain restriction can instead use total-query budgets and explicit one-sided truncation tails; an expected rejection count is not silently used as a deterministic budget.

This is the elementary oracle-query hybrid of Bennett, Bernstein, Brassard and Vazirani, with the exact hidden support and companion-oracle distribution supplied above. No adaptive oracle programming by the reduction is required.

## 7. Native reservation-to-ordinary theorem

**Theorem N (one selected native family).** Use the native algorithm and opaque-owner controller above. Other families are generated locally and may be exposed. Let `A` execute at most `q` distinct target pairs. Construct `B` by the pair-cache simulator in Theorem G, with the ordinary **native hedged** ML-DSA signing challenger and the same public XOF. Let `q_*^res` and `q_*^ord` bound sensitive-capable remaining calls in, respectively, the complete reservation experiment with `A` and complete ordinary experiment with `B`, after the exact designated-call rewrite of Section 6. Then (N) holds in the ROM and QROM, with the respective `delta` in (1).

### Proof

First upper-bound actual-key success by the family-stopped, family-ledger success event. Apply the Section 6 comparison to the reservation experiment. This changes success by at most `delta(q_*^res)` and yields the ideal split-key game with private `R` independent of the public XOF.

In this ideal game, signatures factor through `(mu,R(r,mu))`. Run `B` and couple independent private tapes for distinct visible pairs with those generated by its ideal ordinary challenger. Exactly the same hidden-outer-randomizer argument as in Theorem G costs at most `beta_256(q)`. Public `mu` collisions are handled by the pair cache and original-message ledger.

Apply the Section 6 comparison in the other direction to the complete ordinary experiment with `B`, costing `delta(q_*^ord)`. This returns the genuine native ordinary signer with the original shared public XOF. A successful family-fresh message has never been queried to that signer. This proves (N).

`B` needs only the ordinary signing oracle, public key, and public XOF. It neither knows nor programs the target `xi` or `K`. The exact rewrites and the hidden-support hybrid compare complete challenger experiments; they are not additional capabilities granted to `B`.

### 7.1 Audited native call lengths and a usable budget

For the fixed ML-DSA-65 parameter set, the relevant source-level XOF input lengths are:

| Operation | Oracle | Complete input length (bytes) | In the difference set? |
|---|---|---:|---|
| Target seed expansion | `H`/SHAKE256 | 34 | Exact designated rewrite |
| Target hedge | `H`/SHAKE256 | 128 | Exact designated rewrite |
| Secret-vector expansion | `H`/SHAKE256 | 66 | No |
| Mask expansion in every rejection attempt | `H`/SHAKE256 | 66 | No |
| Challenge-to-ball sampling | `H`/SHAKE256 | 48 | No |
| Commitment hash | `H`/SHAKE256 | 832 | No |
| Public-key hash | `H`/SHAKE256 | 1952 | No |
| Matrix expansion | `G`/SHAKE128 | 34 | Different oracle; unchanged |
| Ordinary external-message descriptor | `H`/SHAKE256 | `64+2+|ctx|+|M|` | Charge if potentially 128 |
| Protocol-framed descriptor | `H`/SHAKE256 | `71+2|ctx|+|body|` | Always greater than 128 |

The fixed native context has 42 bytes, so the protocol-framed descriptor length is `155+|body|`. All remaining target honest H calls have a safe input length, including repeated signing computations and the cache simulator's public descriptor work. For an unrestricted external-message interface, conservatively charge one descriptor call per signing or verification invocation whose input length might be 128.

A direct protocol-domain budget is

\[
 q_*\le q_{\rm public\ H}
        +g_{\rm other}
        +s_{\rm other}
        +d_{\rm other,128},                            \tag{10}
\]

where `q_public H` counts all arbitrary public SHAKE256 queries by the adversary and any simulator/environment work not otherwise classified; `g_other` counts native key regenerations/expansions for non-target owners; `s_other` counts their native hedge invocations, including recomputations; and `d_other,128` counts other honest descriptor invocations whose inputs can have length 128. For the same protocol framing on every honest owner, the last count is zero. Count seed expansion each time it actually occurs; a logical alias does not authorize omitting a real regeneration query. Arbitrary adversary verification or hashing calls are included in `q_public H` even if most happen to use safe lengths.

Use the corresponding complete-experiment counts separately for the reservation and ordinary sides. The bridge changes how many internal recomputations and descriptor calls occur; no equality of their numeric budgets is assumed. Equation (10) is a source-level accounting consequence, not a measured runtime claim.

### 7.2 Multiuser native consequence

Apply Theorem N inside the random-target construction of Section 4. With at most `U` fresh owner families and uniform per-target resource bounds,

\[
 p_{\rm native}(A)\le \min\left\{1,
 U\left(\epsilon_{\rm MLDSA}^{\rm euf}
       +\beta_{256}(q)
       +\delta(q_*^{\rm res})+\delta(q_*^{\rm ord})\right)\right\}.     \tag{11}
\]

The single-user ordinary-EUF advantage includes the full local simulation of the other owners and their disclosures. Independent owner creation remains adaptive. Exact aliases share the chosen index. Accidental equality of public keys, keygen seeds, or hedge keys is preserved in the native experiment; seed/hedge cross-hits occur among the counted remaining public-XOF calls in the selected-target comparison. This is why (11) does not append a separate all-user birthday term for those values.

For a global protected-set theorem without other-owner disclosures, one can instead compare several hidden slices simultaneously, but then independently idealized keygen/slice collisions require their own accounting. Equation (11) deliberately uses the selected-target construction, which directly matches the allowed non-target disclosure interface.

## 8. Relation to the accepted source-attribution result

The new result discharges the original-randomizer component of the accepted conditional ML-DSA adapter **in the declared shared random-XOF model**, replacing that component's reservation-EUF assumption by ordinary native hedged-EUF plus the explicit losses above. The accepted actual-key exposure event, complete signing ledger, exact signed-message framing, and read-only authoritative controller remain unchanged. The earlier source-association and KEM-correctness terms also retain their existing meanings.

For the native ML-DSA/P-256 pair, the target family is inherited from the full pair owner. The selected ML-DSA oracle's message ledger is a subset of that target family's native pair ledger, which in turn is a subset of the native actual-pair-key ledger. This is the freshness implication used by the component projection. It does not require freshness against a ledger aggregating every independent owner whose ML-DSA component happens to coincide. Such other pair owners are generated locally in the selected-target reduction, with their original component distribution and permitted disclosures. No distinct-component-key assumption is introduced.

The concrete SHAKE256 implementation is represented by the declared random-XOF model; timing, arbitrary secret-dependent owner commitments, and post-exposure target signing are outside the modeled owner interface. This is the single model boundary relevant to interpreting this bridge. The proof introduces neither a new correctness claim about the lattice signature primitive nor a broader protocol authentication theorem.

## 9. Primary references and reproducibility

1. **NIST, FIPS 204 (2024).** Section 3.7, Algorithms 2, 6, 7, 29, 31, 33, and 34. [Official standard](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf).
2. **Bennett, Bernstein, Brassard and Vazirani, Strengths and Weaknesses of Quantum Computing.** SIAM Journal on Computing 26(5), 1510–1523 (1997). Query-magnitude/hybrid argument, Theorem 3.3. [Author version](https://arxiv.org/abs/quant-ph/9701001), [paper PDF](https://arxiv.org/pdf/quant-ph/9701001), [publisher DOI](https://doi.org/10.1137/S0097539796300933). Equations (8)–(9) above supply this application and its probability-distance convention explicitly.
3. **IntegrityChain fips204 0.4.6.** [Official package archive](https://static.crates.io/crates/fips204/fips204-0.4.6.crate), [pinned internal algorithms](https://github.com/integritychain/fips204/blob/8d456d989dce681233ef963d3c3306da8f76d7c7/src/ml_dsa.rs), [pinned hashing](https://github.com/integritychain/fips204/blob/8d456d989dce681233ef963d3c3306da8f76d7c7/src/hashing.rs), [pinned traits](https://github.com/integritychain/fips204/blob/8d456d989dce681233ef963d3c3306da8f76d7c7/src/traits.rs), [pinned parameter/API definitions](https://github.com/integritychain/fips204/blob/8d456d989dce681233ef963d3c3306da8f76d7c7/src/lib.rs).
4. **Q-Periapt integration checkpoint.** [Native signing owner](https://github.com/billlza/q-periapt/blob/358b921ab3469ce49f166633fc9a762ff6ed7e3d/research/continuity-identity-candidate/src/crypto.rs), [contract framing](https://github.com/billlza/q-periapt/blob/358b921ab3469ce49f166633fc9a762ff6ed7e3d/research/continuity-identity-candidate/src/contract.rs), [backend](https://github.com/billlza/q-periapt/blob/358b921ab3469ce49f166633fc9a762ff6ed7e3d/crates/q-periapt-backends/src/mldsa.rs).
5. **Bellare and Tackmann, Nonce-Based Cryptography: Retaining Security when Randomness Fails.** EUROCRYPT 2016; [author manuscript and primary metadata](https://eprint.iacr.org/2016/290).
6. **Aranha, Orlandi, Takahashi and Zaverucha, Security of Hedged Fiat-Shamir Signatures under Fault Attacks.** EUROCRYPT 2020; [author manuscript and primary metadata](https://eprint.iacr.org/2019/956), [publisher DOI](https://doi.org/10.1007/978-3-030-45721-1_23).
7. **Grilo, Hövelmanns, Hülsing and Majenz, Tight Adaptive Reprogramming in the QROM.** ASIACRYPT 2021; [author manuscript and primary metadata](https://eprint.iacr.org/2020/1361), [publisher DOI](https://doi.org/10.1007/978-3-030-92062-3_22).
8. **Kosuge and Xagawa, The Security of ML-DSA against Fault-Injection Attacks.** ASIACRYPT 2025; [author manuscript and primary metadata](https://eprint.iacr.org/2025/904), [publisher DOI](https://doi.org/10.1007/978-981-95-5096-8_20). The prior-work positioning here uses its primary abstract; no claim about omissions from its full model is made.

The identity record distinguishes byte-level source correspondence from proof review. A finite checker can test cache/ledger controls and the source call-length inventory; it does not execute the lattice algorithms or formally verify the ROM/QROM proof. Independent review findings are recorded separately in this directory.
