# Independent review of the current signature bridge

Review date: 8 November 2026. Reviewed manuscript commit: `621ae301da5f479fa2401689893c78399512548e`.

## Assessment

The generic independent-hedging reduction and the native ML-DSA-65 reservation bridge are mathematically sound in their declared interfaces. The native result reaches ordinary hedged ML-DSA EUF in the same shared random-XOF model, with the two stated hidden-support comparison costs and the hidden ordinary-randomizer birthday term. No blocking mathematical defect was found in this review.

The manuscript maintains complete `(r, mu)` caching, a ledger of every private original-message invocation, failed-publication retention and exact aliases. These features support the reduction for adversarial selection among previously opened reservations. Descriptor collisions need no extra statistical loss because the ordinary-oracle query ledger remains a subset of the original-message ledger.

The exact XOF construction resamples the hidden key-generation point and the selected hedge slice jointly. Their different complete input lengths make them disjoint. Conditional on the seed and key-generation blocks, all other strings are independent uniform, so the constructed real world has the required native distribution. After designated target seed/hedge uses are rewritten, the ideal visible computation does not use `xi` or `K`. The expected support mass is bounded by `2^-256`, counting the two length sectors within one query. The classical identical-until-hit and quantum ideal-prefix telescoping arguments therefore yield the stated costs.

The selected-family simulation correctly supports disclosures of locally generated other owners. Declared lineage governs routing; native actual-key freshness only strengthens the success requirement. Accidental seed, key or public-key equality is preserved and charged by the original primitive game or the remaining oracle queries as specified.

## Source and operational checks

I read the complete proof, manuscript fragment, source-attribution adapter, and the fixed native and upstream signing path. I verified the 42-byte context and consequent `155 + |body|` message-representative input, independent ML-DSA/P-256 seed generation, use of `K` only in the ML-DSA hedge, and the native safe input lengths. FIPS 204 Algorithms 6 and 7 support the key-expansion and hedge equations.

The existing authenticated source checker was executed once against the current native checkout and the original crate archive. It passed, including 24 source/metadata/license identities, the original package checksum, source call lengths, and its finite controls. This execution verifies the specific source correspondence and finite checks. The unbounded and QROM statements were assessed from their mathematical proof.

The exact file hashes and model assumptions are recorded in `signature_bridge_review.json`. Each recorded reviewed file's Git blob identity was compared with the newly fetched exact remote tree and matched. This review initially read the already materialized corresponding bytes from the preceding worktree; their Git blob identities match the current remote tree.

## Continuation

The reservation-aware ML-DSA instantiation task can be treated as complete within the stated shared-XOF and opaque-owner model. The next proposed mathematical increment is native authentication-event composition. It should use a fresh Boolean event and its own record/component/correctness comparisons, then prepend those bit costs to the existing uniform-root confirmation/message theorem. Confidentiality's signed-score comparison terms should retain their existing meanings.

Primary sources inspected: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf and https://arxiv.org/abs/quant-ph/9701001. Native and upstream exact identities are in the JSON receipt and the existing `source_identity.json`.
