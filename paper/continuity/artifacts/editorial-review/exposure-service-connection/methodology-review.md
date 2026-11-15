# Q-periapt methodology and contribution review — 2026-11-15

Reviewed manuscript base: `4b8cda65727e91508a4d258d550d9de610a21815`, in `/workspace/scratch/a71865d4660c/q-periapt`.

This pass is a read-only review of the experiment/proof connection and local definitions. Yesterday's candidate-local stopping, original-operation ML-KEM bridge, and reserved-randomizer ML-DSA bridge were not re-audited wholesale. No remote actions or CI runs were performed. This note records source inspection and algebraic verification, not a new native cryptographic execution.

## Findings that can be closed

1. **The current comparison design supports the stated configuration-level claims.** `matched-opportunities.tex`, “Comparison target,” distinguishes cross-profile services from the within-Continuity budget comparison and the retry-readiness ablation. Authentication, ACK, retry, and persistence boundaries are disclosed. The manuscript reports admitted work, actual logical delivery, full emitted frames, and queued demand together; it does not infer a primitive-only efficiency ranking from those rows.
2. **The exposure denominator is correct.** The capture is after opportunity 0 and its checkpoint, and before opportunity 1 computation. Exactly one first commitment precedes that cut. The denominator is therefore total first commitments minus one, including the age-four schedules with an undelivered final commitment. The revised interpretation retains this denominator.
3. **The captured-chain positive derivations are concretely checked.** In `artifacts/retry-readiness/sources/retry_age_driver.rs.txt`, `Snapshot::capture` checks epoch zero and no pending rekey entropy (lines 101–115); `predict` computes the native HMAC chain independently from the captured seeds (117–133); the caller compares candidate and actual keys, decrypts the actual frame, and rejects an altered seed (243–247). The predictor has no journal, fixture, future-RNG or signer-owner access. Its epoch-nonzero return is `None`, so the later security statement belongs to the eligible-message theorem, rather than to an empirical test of all adversaries. Current prose already identifies the specified predictor; the new link should make its positive role especially clear.
4. **Retry readiness is the isolated scheduling intervention.** The counter advances in the sender's own designated opportunities, and eligibility is elapsed sender-turn age at least four. Exact retries obtain the retained ciphertext through `resume`. The rest of cyclic arbitration, control planning, ACK handling, first admission, request list, cut, and protocol source are retained. Current source supports the stated causal interpretation within those configured runs.
5. **The numerical statements inspected match the retained analysis.** Alternating immediate/age-four rows are 688/971 deliveries at budget 32 and 718/999 at budget 64; derived counts stay 63 and 127. Unit byte costs decrease 11.41% and 19.70%, while total emitted bytes and total `sync_data` calls increase. The manuscript correctly distinguishes these denominators. No wall-clock throughput inference is made.

## A directly provable strengthening

For a fixed epoch with per-direction cap `b`, let `n_d` be first allocations before the cut and `N_d` first allocations afterwards. Then `0 <= n_d <= b` and `N_d <= b - n_d`, so

`N_A + N_B <= 2b - n_A - n_B`.

This inequality holds for every subsequent scheduling or retry-readiness policy that preserves the native allocation cap and exact-retry semantics. A retry consumes an opportunity but reuses its original allocation. The measured cut has `n_A + n_B = 1`, giving `2b - 1`; a one-way continuation additionally has `N_B = 0`, giving `N_A <= b - 1`.

The bound concerns first allocations of the same captured epoch. It gives the precise capacity whose occupied elements the native captured-seed computation reconstructs. The security of a later selected message under a new source is supplied by `thm:native-online-message` and its original acquisition and reservation predicate. This is a positive connection between the measured accounting and the proved security interface, not an additional experimental requirement.

This strengthening was sent to `paper_edit` and is present in its proposed `matched-opportunities.tex` change.

## Optional exact accounting from existing data

For alternating traffic, four frame classes partition 2,048 opportunities:

| Budget | Fewer application retries | More first applications | More ACK frames | More control frames |
|---|---:|---:|---:|---:|
| 32 | 588 | 283 | 265 | 40 |
| 64 | 571 | 281 | 274 | 16 |

Each row balances exactly. This explains why removing retry competition does not convert each freed opportunity into a new first application: additional completed service also incurs ACK and control work. These are algebraic differences from `artifacts/retry-readiness/analysis.json`, not new measurements.

## Two local wording clarifications, now incorporated

These do not invalidate the respective results. Root explicitly authorized direct natural-language refinements within the affected formal blocks, and the final candidate incorporates them without surrounding duplicate explanations.

* `guarded-provenance.tex`, `cor:guarded-history` (lines 121 and 129 in the base), previously said copying “adds routes” and that a source-preserving copy “changes a route's record identity or key guards.” The final corollary now states that copying/rewrapping preserves existing routes and may add routes to the same source. Its proof explicitly distinguishes the identical record/route reused by an exact ciphertext copy from record-identity or guard changes in source-preserving rewrapping. This agrees with the original-record cache semantics. The monotonicity conclusion is unchanged.
* `established-results.tex`, `prop:counter-separation` (line 91 in the base), previously called `min(c_A,c_B)+1` an upper bound “on exposed epochs.” The final proposition explicitly says “on the index of an exposed epoch.” The counterexample remains index two against the proposed bound one. It is therefore unambiguously a statement about epoch index, not the cardinality of an exposed-epoch set.

## Independent review of the final editorial candidate

Candidate inspected in `/workspace/scratch/a71865d4660c/paper-nov15/paper/continuity`: `evaluation.tex`, `established-results.tex`, `matched-opportunities.tex`, `discussion.tex`, and the final two sentences in `guarded-provenance.tex`.

* The `n_d/N_d` calculation and the one-way specialization are correct under the fixed experiment policy.
* The later-message connection names the native live-core theorem and the original eligibility predicate; it does not turn the allocation count into an unconditional leakage bound.
* The shortened online-controller account preserves selection before first computation across endpoint aliases, including failed receive advancement, and retains exact retry semantics.
* The shortened bootstrap account retains the reply-source and initial-source profiles, per-profile immutable-version acquisition contributions, and the separate joint journal/derived-key interface. Its family-count statement correctly leaves the multiplicity on the later tail terms after the whole-source joint-entry comparison. It does not assert a zero-residual captured-byte simulation.
* The final exposure paragraph states that the retained captured-seed predictor reconstructs every post-capture epoch-zero application, with actual key and AEAD checks. This exactly matches the source boundary above.
* The component snapshot corpus's reconstructed keys and the common-opportunity experiment's admitted applications/service retain their distinct outcome types.

An independent comparison of the 40 manuscript input modules against base commit `4b8cda65727e91508a4d258d550d9de610a21815` is saved in `editorial-semantic-preservation.json`. It finds 57 formal statement blocks, 52 proof blocks and 169 displayed-math blocks. Exactly two statement blocks and one proof block contain the three authorized natural-language refinements above; all other 55 statements and 51 proofs, and all 169 displays, are byte-identical. The record includes the complete before/after blocks and each module's source hashes. The changed statements retain the same mathematical assumptions, quantities and conclusions, and the proof retains its monotonicity argument.

No demonstrated core theorem defect, experimental numerical inconsistency, or unsupported cross-profile claim was found in this pass. Optional new workloads or broader leakage interfaces are not completion gates for these already stated results.
