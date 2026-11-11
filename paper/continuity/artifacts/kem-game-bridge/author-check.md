# Deferred ML-KEM challenge bridge: author check and integration map

## Scope and status

This is a proposed new proof module against integration `0e2ca2d79ab0000bed79130cec97b31181e936ea`, whose paper is canonical `4fde471641150c68a08b56e728067c72b39ab346`. No existing manuscript source, theorem, formula, implementation, experiment, or remote branch has been changed by this draft. This file records author checking; it is not an independent-review claim.

The gap addressed is precise: `paper/continuity/contextbound-connection.tex` defines its component advantage in the actual two-stage experiment, while the inherited ordinary KEM note described an up-front challenge. The present canonical theorem is valid under its stated two-stage advantage. The new proposition gives an ordinary IND-CCA instantiation with an explicit prechallenge collision cost. It does not replace source acquisition stops with corruption access in the primitive game.

## Reduction and coefficient

The ordinary-game adversary withholds `(c*,K_beta)` and gives the two-stage distinguisher only its public key. It forwards prechallenge decapsulations except that a query equal to `c*` stops with zero. On a request, it releases the retained pair, then enforces the ordinary postchallenge exclusion. It never needs the selected random tapes or secret key.

The proof analyzes the full real decapsulation prefix, not the simulated prefix conditioned on previous misses. Its query list is independent of an unused uniform encapsulation message `m*` after fixing the entire static public-oracle functions and the honestly generated key. This also holds for the conditional density operator of a quantum adversary: each prefix operation is independent of `m*`; computing a hidden challenge earlier neither changes the oracle function nor acts on the adversary register. All randomness or measurements used to select the classical decapsulation inputs remain part of this prefix.

Deterministic K-PKE decryption associates at most one 32-byte message with each length-admitted query ciphertext. If the honest challenge decrypts to `m*`, a hit puts `m*` in a set of at most `q_pre` such messages. The cost is therefore `zeta=min(1,q_pre/2^256+delta_mr)`, where `delta_mr` is K-PKE message-recovery failure on the honest challenge distribution, not equality failure of final KEM shared keys. The latter remains the adapters' existing `delta_j`.

The two-stage real/uniform-key branches have exactly the same prechallenge process and therefore the same hit probability `p`. If the ordinary reduction stops with zero, each removed output-one mass lies in `[0,p]`; their difference is at most `p`. Thus each Boolean distinguishing advantage needs one `zeta`, not two. A direct score comparison using `(1+Z)/2` uses two; the current manuscript's `a_j^+` and `a_j^-` each get one under substitution. This proof also includes a distinguisher that never requests a challenge; its unused honest sample is private and its branch-independent hit contributions cancel.

## Checked interfaces

| Interface | Draft treatment |
| --- | --- |
| Challenge selected adaptively | Its request is part of the original prechallenge process. The independent challenge tape is withheld until that request. |
| Prechallenge query equals eventual challenge | Its genuine answer is retained in the two-stage experiment. Only the ordinary reduction stops, charging the event. |
| Repeated prechallenge ciphertext | Set bound counts it once; a call-count budget remains a valid upper bound. |
| Malformed ciphertext | Cannot equal the properly generated challenge; native error routing remains the adapter's existing behavior. The stated budget counts admissible selected-key queries. |
| Quantum public-oracle queries | Static common functions are fixed for the independence argument. No quantum query is measured, guessed, or reprogrammed. |
| Other honest owners with equal public bytes | Their local secret material and operations stay inside the original distinguisher. The bridge only forwards the selected component's oracle requests. |
| Before/after original reservation | The operational adapter has already connected opaque retained slots to the primitive challenge at first private computation. The bridge changes only the primitive challenger interface and leaves that source theorem intact. |
| Selected tape or owner opening | Existing local source/record stop happens before unavailable bytes are returned. The primitive game gains no reveal oracle. |
| Crash, failure, exact retry | Replayed native calls use their existing cache. There is one primitive challenge and no resampling on replay. |
| Bootstrap consistency checks | Their existing fresh-encapsulation collision monitor remains necessary to establish the later hidden-component raw-use premise. The bridge does not replace it. |
| Shared-key correctness | Retains the existing adapter term. Message-recovery failure is separately named and not silently identified with it. |
| Time / oracle resources | Adds one ciphertext comparison per classical component request, no new decapsulation or public-oracle queries; whole original preparation and continuation remain counted. |

## Primary-source check

Official FIPS 203, https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf, checked 2026-11-10:

- Algorithm 15 / printed page 31: deterministic K-PKE decryption returns a 32-byte message.
- Algorithm 16 / printed page 32: ML-KEM secret-key format includes the K-PKE decryption key.
- Algorithm 17 / printed page 33: encapsulation encrypts its 32-byte input under K-PKE with prescribed derived coins.
- Algorithm 20 / printed page 37: the external encapsulation samples its 32-byte input uniformly.

The existing bibliography key `fips203` suffices. The proof uses these algorithmic properties and explicitly retains the message-recovery failure probability. It makes no numerical claim about that probability and introduces no ideal-independent SHA3 instance.

## Exact insertion and prose

Preferred bounded insertion: add `\\input{kem-ordinary-bridge}` immediately after `\\input{contextbound-connection}` in `paper/continuity/computational-roadmap.tex`, then install the accompanying TeX module as `paper/continuity/kem-ordinary-bridge.tex`. This keeps the existing theorem blocks byte-identical and places the ordinary-game instantiation before the live-core corollary.

Optional one-sentence addition to the roadmap's proof-dependency paragraph after the sentence ending “whole-execution query budget”:

> Proposition~\\ref{prop:kem-deferred-challenge} bounds each operational component term by an ordinary ML-KEM IND-CCA advantage and its explicit prechallenge ciphertext-intersection cost.

Optional contribution-paragraph replacement in `introduction.tex`:

Current: “An original-operation adapter carries this execution through the operational ML-KEM experiment, complete ContextBound tuple, root initialization, confirmation and traffic derivation.”

Proposed: “An original-operation adapter carries this execution through the ML-KEM challenge, complete ContextBound tuple, root initialization, confirmation and traffic derivation. A deferred-challenge bridge instantiates its component terms with ordinary IND-CCA advantages while retaining the real prechallenge decapsulation history.”

No abstract update is mathematically required. No old main bound needs to be rewritten: the substitution paragraph gives exact per-test use for native confidentiality, native Boolean authentication, online message integrity and both bootstrap profiles.

## Independent review requested

Root should verify the full-prefix independence argument with fixed shared oracles, the common-bad-event coefficient, the distinct K-PKE failure definition, and the mapping of selected-tape stops to the already established operational distinguisher. The proposition is short enough to check directly; a new benchmark or finite cryptographic test would not settle these proof obligations.
