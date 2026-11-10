# Independent authentication cross-review

**Verdict: PASS for integration.** The final confirmation/first-message proposition has consistent event definitions, quantum-oracle accounting and classical-verification coupling. No blocking mathematical finding remains.

Reviewed fragment SHA-256: `a87f4b713a71e5def995ea93b9f602f0a7d8bb9cb3c5335270947c87ae17833e`. Source pin: `228c944fc476e3e57d6c08063cacb19bca5b360e`, with checked rekey/crypto files byte-identical in candidate `1c68aa666db22d36ee136be1ec712545a9e74f03`. This is a source and mathematical review; it records no new native execution or proof-assistant run. The companion `independent_auth_review.md/json` files are preserved and cover the native receive/cache/consumed boundary independently.

## Probability accounting

Applying the joint-schedule theorem to the union's available terminal bit charges `Delta_sched` once. In its independent-key world, bound confirmation and message integrity separately:

- Confirmation replaces the three adaptive HMAC rows, costing `Delta_conf`, then charges `V * 2^-256` for a fresh-digest equality and `chi_H` for a fresh full core with an already issued digest.
- Message integrity directly embeds the selected key in the one-key, at-most-one-encryption integrity experiment, costing `eps_INT`. The remaining confirmation, ACK, successor-root and subsequent-chain computations use locally known independent material.

Their union produces the displayed sum with its cap at one. Each term is an output-bit probability cost. The separate qualified confidentiality statement correctly retains the existing factor two for signed scores.

Both terminal events are available from the origin ledgers, classical messages and actual native outcomes. Neither requires the terminal test to inspect a hidden key or private random-function table. The proof can fix an independent application challenge bit and average afterward.

## Classical verification with quantum public queries

The final coupling stops at the first internal equality for an unissued digest, before later persistence or a public response. This timing is essential because a successful MAC equality may affect internal computation even if a later write fails.

In the forced-reject comparison, unissued random-function values stay private and the visible rejection reply is fixed. Up to the first hit, both executions give the same classical replies and therefore the same induced transformations of the adversary's quantum state. Each attempted tag has marginal match probability `2^-256` in this comparison; a union bound over all `V` attempts handles repeated guesses as well. The argument does not require incorrectly treating a real transcript conditioned on earlier rejections as having an unchanged conditional guess probability.

For a fresh complete core whose digest was already issued, the reduction records the honest and new core strings. The source's eight-byte length framing makes them distinct full inputs to the same hash, yielding the required collision witness. A new signature encoding of a previously logged core remains attached to that original core.

## Query budgets and source mapping

The appropriate primitive is the multiple-message adaptive HMAC-row lemma. `T_d` includes distinct construction and verification inputs after exact caching; `V_d` includes repeated verification attempts. For order `r,f,a`, `q_d = B_c + 4 sum_(e>d) T_e` is conservative: earlier rows are ideal, later rows are real, and each uncached 32-byte HMAC has two pad calls and two remaining compression calls. `B_c` includes preparation, the application, all other real primitives and terminal tests. The replaced row's internal work remains in its own row bound. Independent key-byte coincidences remain part of the shared-oracle comparisons.

Direct source reading confirms the 153-byte common prefix, 185-byte response prefix, 1305-byte response core, 225-byte final core and 257-byte receipt core. The MAC inputs are 32-byte core digests. The response/final/receipt network paths perform identity and structural checks before relevant MAC acceptance. The selected traffic interface keeps the fixed nonce and single original send ownership; retries use its original encryption result.

The final Incoming description now matches storage: its authenticated receive-intent digest and plaintext are retained, while the exact AAD/ciphertext pair is in the proof's ghost ledger. Cached inbox returns and `PreviouslyConsumed` refer to earlier receive history. They do not create a fresh authentication event. The companion native review traces successful AEAD decryption through inbox insertion and the enclosing persistence operation.

## Primary collision reference

I directly opened the [published paper](https://www.rintonpress.com/xxqic15/qic-15-78/0557-0567.pdf) and [publisher record](https://www.rintonpress.com/journals/doi/QIC15.7-8-2.html). Theorem 7 on printed page 562 bounds collision production by a universal constant times `(q + 2)^3 / N`. The fragment and bibliography now use that published numbering and expression. Setting `N = 2^256` and including all ordinary and honest hash work in the derived algorithm's budget yields the displayed operational `chi_H`. The independent auxiliary compression oracle can be fixed and averaged. The constant remains symbolic.

## Integration boundary

The delivered proposition starts at the uniform epoch-root game `G_R`. Extending it to a native authentication probability requires the record, component and root comparisons for that event's own terminal bit. The final paragraph makes this explicit. The confidentiality costs `a_j^+` and `a_j^-` retain their original signed-score event meanings. This scope supports integration of the new proposition without claiming a completed native authentication reduction beyond its stated entry interface.
