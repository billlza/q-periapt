# Independent review of the reservation signature bridge

Independent internal mathematical review
Date: 2026-11-08 UTC

## Mathematical assessment

The generic bridge and the direct native shared-XOF bridge have sound reductions under the interfaces stated in the draft. The native result reaches ordinary **native hedged ML-DSA EUF** in the same ROM/QROM. It uses two statistical comparisons of complete experiments; it does not assume that the real FIPS key-generation blocks are independent of their public SHAKE oracle, and it does not insert an unproved native-PRF premise.

The exact reviewed draft and proposed-fragment identities are recorded separately in `independent_bridge_review_identity.json` once author revisions are stable. The draft was read in full. I independently checked the source path from the continuity framing through the backend, `try_sign_with_seed`, `DummyRng`, the internal signing algorithm, and the relevant SHAKE256 inputs. The finite controls below support specific accounting and distribution claims; the ROM/QROM argument was reviewed mathematically.

All precision requests are resolved in the reviewed versions. Query caps are fixed worst-case bounds over the relevant complete hybrid experiments; hidden-key independence is stated for the ideal query-register reduced state, with dormant registers removed. The proposed native theorem explicitly constrains the distinct-pair budget, states the companion-oracle independence, and conditions the distribution argument on both seed and key-generation output. These clarifications preserve the formulas.

## 1. Generic construction and resource accounting

For family `h`, let the signer factor as

\[
\operatorname{Sign}_h(M;r)=S_h(d_h(M);F_{K_h}(r,d_h(M))),
\]

where the whole base result is deterministic given the descriptor, internal tape, fixed base key and public companion oracle. The hedge key is independent of the base-owner state in the specified joint-oracle experiment. Public contexts and purposes remain part of the original message domain.

The reservation simulator maintains two different objects:

1. a family cache indexed by the **complete** exposed pair `(r,d_h(M))`;
2. a ledger of all original messages whose slot has had its first private execution.

On every first slot execution it enters the original message in the ledger. A cache miss causes one ordinary signing query on that original message. A cache hit reuses the stored signature. A publication failure suppresses delivery after the query and ledger update; it does not erase either. Repeated slots and retries retain their original tuple. The ordinary signing-query ledger is therefore a subset of the local raw-message ledger, which supplies the required EUF freshness implication.

After the first PRF replacement, different visible cache keys receive independent tapes from a private random function. After the second replacement is performed temporarily on the ordinary challenger, a cache miss receives the tape associated with a fresh hidden ordinary randomizer `u` and its descriptor. Until a hidden complete input repeats, these two tape sequences can be coupled exactly. An adaptive descriptor choice does not change the conditional upper bound `(t-1)/2^n` on the next hidden input repeat, because `u` is sampled after that choice.

Thus a global-stop multiuser experiment with fixed per-family caps `q_h` has loss

\[
\operatorname{Adv}^{\rm mu\text{-}prf}(D_0)
+\operatorname{Adv}^{\rm mu\text{-}prf}(D_1)
+\min\!\left(1,2^{-n}\sum_h\binom{q_h}{2}\right)
\]

in addition to the ordinary-wrapper EUF term. Each primitive interface receives at most `q_h` evaluations. Reservation and opening counts affect time and storage. They do not create a birthday penalty in this correct simulator. Public-oracle work and all local owner generation remain in the resource bounds.

Descriptor collisions need no additional collision term. Equal descriptors and equal original randomizers produce identical base signatures by factorization. Both executed original messages still enter the ledger. A fresh message that has a previously signed descriptor is a fresh ordinary-EUF candidate, since the ordinary query was on its earlier representative. The argument does not require strong unforgeability.

For quantum adversaries, the PRF premise is a **joint-oracle** premise: real `(F_K^O,O)` versus ideal `(R,O)` with private `R` independent of the same public `O`. Private reservation/signing interfaces are classical; the public oracle may be queried coherently. A standalone PRF claim without this companion-oracle interface would not justify the replacements.

## 2. Owners, aliases, and exposure

The manuscript's actual-key ledger pools exact signing-state identities and exact owner aliases. It does not pool every owner whose verification key merely has the same bytes. Independently generated instances retain separate lineage indices, including coincident public keys. Declared references to an existing instance route to its existing family cache and signing interface.

The actual-key ledger contains the corresponding lineage ledger, and actual-key nonexposure excludes declared lineage exposure. Therefore actual-key fresh/unexposed success implies the more permissive lineage-fresh, lineage-stopped success. This one-way relaxation is sufficient. The ideal predicate need not inspect hidden private-key equality, so it preserves the secret-independence needed for the native oracle hybrid.

A global-stop theorem can use ordinary indexed multiuser signing oracles for every protected family. If foreign honest owners can be exposed while a final target remains protected, the simple all-users-via-ordinary-oracles simulation is insufficient. Its earlier signatures were generated with hidden ordinary randomizers rather than the original visible reservation randomizers, and a disclosed foreign key can reveal that inconsistency. The correction in the draft is valid: guess the eventual target family, generate all other families locally, and stop before the selected lineage's key or secret-containing owner-file return. At most `U` fresh families gives the usual `U` loss, or a sum of per-target bounds. Exact declared aliases do not consume new indices.

For saved pre-exposure verification events, stopping at the first publicly verifiable family-fresh target candidate is valid. It occurs no later than an actual-key-fresh target success, and its message is fresh for the selected ordinary signing oracle. Future disclosures need not be simulated after producing the forgery.

## 3. Native random-XOF coupling

The checked native structure is

\[
H(\xi\Vert[6]\Vert[5],128)=\rho\Vert\rho'\Vert K,
\qquad
c=H(K\Vert r\Vert\mu,64),
\]

with byte lengths `xi32`, `rho32`, `rho_prime64`, `K32`, `r32`, `mu64`.

Sample these key-generation blocks independently, a random XOF `H_0`, and a private random function `R(r,mu)` of 64 output bytes. Program `H_*` only as follows:

* at the 34-byte seed point `g = xi || [6] || [5]`, replace its first 128 output bytes by `rho || rho_prime || K`;
* at every 128-byte input `K || r || mu`, replace its first 64 output bytes by `R(r,mu)`;
* retain the corresponding independent `H_0` tails and every other input unchanged.

The two input domains are disjoint. Conditional on the seed and its key-generation output, the selected `K` slice is fixed and every other full output string is independent uniform. The programmed joint distribution is consequently exactly that of native key generation with a public random XOF. Selecting the slice using the key-generation output does not bias those other oracle entries. Retained independent tails make arbitrary finite output lengths and repeated prefix requests consistent.

Every designated target-lineage seed expansion must be rewritten using the sampled blocks, including owner reconstruction and reopening. Every target hedge call must use `R`, including retries and failed-publication recomputation. The draft now makes these repeat cases explicit. Non-target key generation and hedge calls remain calls to the public oracle and are counted.

After changing the remaining oracle from `H_*` to `H_0`, the ideal query distribution is independent of the hidden target `xi,K`. Neither value participates in the remaining observable computation. Unread secret registers can be removed; owner-secret bytes and byte-dependent owner observations are excluded by the stated pre-exposure interface.

For any ideal public-XOF query, expected query-register mass on the difference set is at most `2^-256`. A 34-byte sector can hit only `g`; a 128-byte sector can hit only the secret-prefix slice. Their sector weights add to at most one, so this is one `2^-256` bound, not a sum of two full-query bounds. Other lengths contribute zero.

The classical identical-until-hit bound is `q_* / 2^256`. For coherent access, the two oracle operators differ on an ideal query state by Euclidean norm at most `2 sqrt(p_t)`. A telescoping hybrid using ideal prefixes and Jensen's inequality gives expected final-state distance at most `2 q_* / 2^128`; final-event probability distance is bounded by the same value. Truncate both at one. The proof does not grant the ordinary reduction an ability to program an unknown challenge key: the oracle construction compares complete challenger experiments.

Apply this comparison to the complete reservation experiment, apply the exact pair-cache/hidden-draw comparison in the ideal game, then apply the oracle comparison back to the complete **ordinary native** experiment. For one selected family the result is

\[
p_{\rm res}^{H}(A)
\le p_{\rm euf}^{H}(B)
 +\min\!\left(1,\binom q2 2^{-256}\right)
 +\delta(q_*^{\rm res})+\delta(q_*^{\rm ord}).
\]

The two `q_*` budgets concern their respective complete experiments, including adversary work before target creation, other owners, and final verification. They need not have identical numerical values. A forced identical global cap can itself alter the cache simulator's completion behavior; the draft avoids that error.

## 4. Source-level safe domains

I independently counted the exact continuity context as **42 bytes** and verified its use both in the framed message and in `sign_ctx`. The resulting descriptor input is `155 + |body|` bytes. The draft corrected an earlier tentative count of 39.

| SHAKE256 use | Complete input bytes |
|---|---:|
| Target seed expansion, removed by exact rewrite | 34 |
| Target hedge, removed by exact rewrite | 128 |
| Secret-vector and masking expansion | 66 |
| ML-DSA-65 challenge-to-ball sampling | 48 |
| ML-DSA-65 commitment hash | 832 |
| ML-DSA-65 public-key hash | 1952 |
| Continuity message descriptor | `155 + |body|` |

Matrix expansion uses the separate SHAKE128 oracle. All remaining honest target SHAKE256 calls in this framed domain are therefore identical in the two oracles. Rejection-loop calls have zero oracle-difference norm. They can be treated as common operations. For a finite computation cutoff, the statistical bound depends only on sensitive-capable calls; taking the cutoff to infinity preserves the bound with nontermination treated as failure. Full execution cost still belongs in the ordinary-EUF resource term. This is a statistical accounting result, not a measured runtime claim.

The exact package archive SHA256 is `c9fb5a367b9846933e271a3c2a992930743f82ae5e8cb7faa780715a80fa0b15`; its VCS record names `8d456d989dce681233ef963d3c3306da8f76d7c7`. The repository checkpoint is `358b921ab3469ce49f166633fc9a762ff6ed7e3d`. My byte audit checked the package archive and 24 identified source, metadata and license files: 15 source/identity files and nine license files. The native files were checked both in the repository and in the self-contained source packet. The continuity contract is included in the independent context count.

Primary-source locators are the [official fips204 archive](https://static.crates.io/crates/fips204/fips204-0.4.6.crate), [pinned internal algorithms](https://github.com/integritychain/fips204/blob/8d456d989dce681233ef963d3c3306da8f76d7c7/src/ml_dsa.rs), [pinned hashing implementation](https://github.com/integritychain/fips204/blob/8d456d989dce681233ef963d3c3306da8f76d7c7/src/hashing.rs), [pinned API](https://github.com/integritychain/fips204/blob/8d456d989dce681233ef963d3c3306da8f76d7c7/src/lib.rs), and [continuity contract](https://github.com/billlza/q-periapt/blob/358b921ab3469ce49f166633fc9a762ff6ed7e3d/research/continuity-identity-candidate/src/contract.rs). The audit inspected the locally materialized bytes identified by these source records.

## 5. Independent finite controls and scope

`review_generic_controls.py` contains independent small-model enumerations. Normal Python and `python -O` produce byte-identical receipts. Checks use explicit exceptions rather than removable assertions.

| Control | Coverage and result |
|---|---|
| Visible reserve-and-select collisions | 1,024 five-draw histories in a four-point space; exact pair cache succeeds. A per-slot simulation has discrepancy `3/8`, exceeding the invalid two-execution birthday charge `1/4`. |
| Hidden ordinary inputs | 64 three-draw histories; same-family/descriptor collision probability `5/8`, and descriptor/family partition examples `1/4`. |
| Raw ledgers, descriptor aliases and owner aliases | Failed/cached execution retains the original-message ledger; ordinary queries are a subset; equal-pk private states are not merged; 15 actual-state-to-lineage freshness implications hold. |
| Foreign-owner exposure | 256 assignments exhibit the all-users-via-ordinary-oracles inconsistency: real check probability 1 versus simulated `5/8`. The globally stopped/fixed-target correction removes the unsupported interface. |
| Secret-selected XOF coupling | 16,384 toy assignments produce 2,048 joint `(xi,H_*)` outcomes with equal multiplicity 8. Disjoint input sectors give one hidden-support mass bound. |
| Identical global-cap countermodel | One descriptor call versus two can make equal numeric caps yield different completion events. Separate complete-experiment accounting is required. |

Receipts are `review_generic_controls.json` and `independent_bridge_review_checks.json`. These are finite classical controls and a source identity audit. They do not execute the lattice signer, simulate a quantum attack, or formally verify the proof. The declared random-XOF and opaque-owner interface is the interpretive boundary of the new theorem; concrete SHAKE security remains represented by that model. No additional protocol-authentication or KEM-correctness claim is introduced by this review.
