# Actual rekey confirmation and first-message security

## Outcome and scope

The selected application is the native durable **next rekey**: responder confirmation, final confirmation and receipt confirmation, followed by the first message of a freshly marked directional traffic allocation. This application already exists in the pinned source. Its three confirmation keys, two directional seeds and ACK keys are outputs of the joint schedule proved in the manuscript. The new proposition derives a confirmation-origin and first-message integrity bound from that established uniform-root interface. A companion corollary instantiates the original native confidentiality accounting with the existing live-core record simulation.

The SDK purpose-key theorem remains a separate source-backed result. Production bootstrap derives its initiator-confirmation key and also exports the underlying shared secret for its own schedule (`bootstrap.rs`, `initial_body`). The current SDK theorem's KDF-only parent-use hypothesis therefore does not automatically cover that combined bootstrap application. The durable rekey's own schedule has the completed source connection needed here.

Paper input: `da521d8388f5f0c64697387bf80b0b5b7837fb34`. Native source: `228c944fc476e3e57d6c08063cacb19bca5b360e`. Development checkpoint: `1c68aa666db22d36ee136be1ec712545a9e74f03`. Twelve directly inspected files are byte-identical at these source revisions and their worktrees. `interface_check_receipt.json` records exact blobs, SHA-256 hashes and immutable public URLs.

## Complete actual interfaces

The hash operation is the source's SHA3-256 digest of `BE64(domain.len) || domain || BE64(data.len) || data`. The control domain `DR` has 40 bytes, and the message domain `DM` has 43 bytes. Whole SHA3 `H` and the SHA-256 compression oracle `h` remain separate, independent public quantum-accessible oracles. Protocol invocations and cryptographic service inputs are classical.

| Operation | Full input and actual effect | Source location |
|---|---|---|
| Device signing | Signature context, one-byte purpose, `BE32(body.len)`, complete body; actual verifier checks both signature components | `crypto.rs`: `signed_message`, `PublicKey::verify` |
| Generation | Reserve original randomness; set transaction-private `Plan::Key`; persist; then execute the retained token | `durable/messages/rekey.rs`: `prepare_rekey_offer` |
| Response | Control tag/profile/context/session/current and target epoch/role/parent, whole-offer digest, 1120-byte hybrid ciphertext; 1305-byte core | `rekey/response.rs`: `prefix`, `respond_rekey_offer` |
| Response MAC | HMAC-SHA256 under the responder key on `H_DR||response-core(core)` | `rekey/response.rs`: `confirmation`, `check_body` |
| Final | Corresponding control prefix, complete offer and response wire digests, closing length; 225-byte core | `rekey/completion.rs`: `core_prefix`, `make_body`, `control_mac` |
| Receipt | Corresponding completion fields plus whole-final digest; 257-byte core | Same functions and `verify_control_body` |
| Traffic material | Actual whole signed response is part of `H_traffic-transcript(offer || response)`; full info is regenerated in every hybrid | `rekey/completion.rs`: `State::add_epoch` |
| First encryption | ChaCha20-Poly1305; nonce `0^96`; AAD `DM || aead || header[93] || BE16(ad.len) || ad` | `durable/messages/traffic.rs`: `send_input` |
| New receive | Validate header and bounds, derive candidate key on transaction-private state, decrypt, add inbox entry, persist before delivery | `traffic.rs`: `receive`; `messages.rs`: `receive_message` |
| Retry | Recover exact saved input or return cached original wire; public request contains only the message ID | `messages.rs`: `resume_message` |
| Consumed status | A message below the receive floor can return `PreviouslyConsumed`; it identifies historical consumption | `durable/messages/delivery.rs`: `receive_delivery` |

The source guard order includes signature and exact-prefix checks before the relevant MAC verification. The analysis safely counts all MAC checks actually reached; an upper bound counting more public requests is conservative. A verifier's internal expected-tag calculation enters the row-query ledger. Only an honest tag-construction operation enters the origin ledger.

The protected message's plaintext and retained send-intent digest stay with the honest application. Received plaintext is delivered to that private application. Public state transitions, errors, status, ciphertexts and ACKs retain their actual behavior. Original encryption and tag-construction identities are logged at first private computation, including computations followed by write failure. Reopening and copies retain those identities.

## Authentication derivation

Let `Bad_conf` be a successful confirmation check of a complete core that has no earlier honest private tag construction under the same logical role-key entry. A repeated complete core has an origin even when the new outer signature encoding differs. This is a statement about a core's construction source; it does not assert the peer has already persisted a later protocol phase.

Let `Bad_msg` be a new authenticated inbox installation under the selected first-message key for an AAD/ciphertext pair absent from the original encryption ledger. An existing native inbox entry keeps its original authenticated receive-intent digest and plaintext; a cached return refers to that earlier receive. The exact original AAD/ciphertext pair is recorded in the proof's ghost origin ledger. A historical consumed status makes its recorded consumption statement. These definitions preserve the exact API behavior.

After the existing schedule comparison, the confirmation keys and selected message key are jointly independent uniform samples. For confirmation, apply the retained adaptive HMAC-row bound to the responder, final and receipt rows in a fixed order. The messages to these rows are all 32 bytes. A full HMAC evaluation costs at most four compression calls; repeated private calls can be cached exactly. With distinct-message bounds `T_d`, all-attempt bounds `V_d` and all other compression work bounded by `B_c`, use `q_d = B_c + 4 sum_{e>d} T_e`. The row lemma's own private-query work is charged in that primitive, and `B_c` covers all remaining preparation, application, primitives and final testing.

In the final independent-tag-table game, compare with an execution that returns failure for every unissued digest. Stop the coupling at the first internal MAC equality on an unissued digest, before later writes or public replies. Until that point the classical interaction and its transformation of the adversary's private quantum state agree. In the reject execution, the corresponding unissued table cell remains independent of the available prefix. Each guessed tag matches with probability `2^-256`; at most `V = sum V_d` guesses give `V / 2^256`, including repeated guesses for one digest. This argument uses no observation of a superposition query. Quantum access to public `h` is accounted for by the preceding HMAC-row comparisons.

If a different complete core reuses a digest already used in an honest construction, the reduction has two classical, distinct framed inputs with the same `H` value. It can output them as a collision. Use the **published** Zhandry collision theorem, Theorem 7, which gives a universal-constant bound `C (Q+2)^3 / N`; here `N = 2^256` and `Q` includes all honest and adversarial H evaluations in the complete derived experiment. The constant is retained symbolically. The older author preprint uses a different theorem number and an equivalent shifted-query convention; the delivered citation and formula both follow the published version.

Message integrity uses a one-key, at-most-one-encryption operational INT-CTXT game with classical decryption and the same additional public oracles. The reduction knows all other leaf values, so it computes the actual confirmation, ACK and future-chain behavior. Every fresh successful selected-key decryption outside the encryption ledger is an integrity win. Committing an unauthored inbox entry entails such a win. Replays consume the existing encryption cache.

The union event therefore obeys

\[
\Pr_{G_R}[\mathsf{Bad}_{\rm conf}\lor\mathsf{Bad}_{\rm msg}]
\le\min\{1,\Delta_{\rm sched}+\Delta_{\rm conf}
+V2^{-256}+\chi_H(Q_H^{\rm conf})+\varepsilon_{\rm INT}\}.
\]

The schedule comparison is paid once for the union's output bit. Within its ideal-key game, a union bound combines the confirmation reduction and the independent message-integrity reduction. Numerical coincidences between independent keys remain in the experiments; the comparisons use the common compression oracle and never condition on all key samples being distinct.

The existing confidentiality score stays `2 Delta_sched + 2 epsilon_AEAD`. Its AEAD reduction samples the other leaves locally and simulates real confirmation verification directly. Authentication-error terms are not necessary additions to that already established privacy bound.

The theorem starts at `G_R`. The earlier uniform-contribution and ContextBound comparisons can precede it at their bit costs when their controller hypotheses hold. A full native authentication theorem additionally needs its own terminal-event component distinguisher, record comparison and exposure treatment. The existing `a_j^+` and `a_j^-` denote the particular confidentiality score events and are not relabelled as a different authentication event.

## Explicit native confidentiality result

The existing live-profile source induction and record-to-table theorem already give

\[
\rho_j\le2\min\{1,\epsilon_{{\rm com},j}+\delta_{{\rm seal},j}\},
\quad
\epsilon_{{\rm com},j}\le\min\{1,\sum_i\Phi_{192}(d_{j,i},Q_{j,i})\},
\]

with `delta_seal = min(1, binom(M_seal,2) 2^-192)` when the private-wire equality comparison is present. The arguments count every fresh outer seal, including one followed by commit failure; copies retrieve their original handles. Deterministic budgets cover every comparison world.

In the live core's exhaustive observation surface, whole target-session captures invoke the original acquisition stop, ordinary metadata uses the constructed simulation, and the only partial secret-field projections are the already admitted phase-checked successor root and next seed. The application uses private Send and delivery with public Resume. Thus the core has an empty charged projection event and `eta_proj^nat = 0`. The general report/fragment extensions retain their own declared residuals.

Substitution into the existing native theorem yields the delivered live-core corollary. It keeps the general `eta_attr^nat` term. This is a concrete reduction of previously symbolic costs using completed source evidence; it changes no eligibility condition.

## Attribution: established obstruction and remaining bridge

The general experiment permits the selector to name original handles by metadata, including draws whose subsequent operation fails. Take `c < res(g1) < res(g2)`, with `res(a2) > c`. Let the first persistence of `Plan::Key(g1)` fail before any complete pending target or image is durable. Reopening the original authoritative state permits a new draw `g2`. Complete the honest exchange with `(g2,a2)` and its selected first message. Keep signing keys and target entropy unexposed and acquire no post-cut target-session version. Naming `(g1,a2)` passes the stated reservation metadata checks but fails unique usable attribution. No signature forgery or transcript collision is involved. An uncertain commit with a retained target is a different storage outcome and resumes `g1`.

This blocks the proposed stronger claim that signature security alone makes the **general** attribution residual zero. The original accounting already handles the execution correctly.

A source-resolved challenge interface can register the retained plan's original slot when it first reaches actual private KEM computation. This assigns `g2` in the witness, before the computation returns. Signatures bind the actual purpose and complete body; response/completion prefixes bind the full retained wires through framed hashes. These observations give a promising precise source-association construction. A complete positive theorem must also prove the adapter for the actual signing owner. `SigningReservation::encode` persists signing randomness; exact retries must use its original signature and retained objects may expose permitted parts of the signing environment. A standard signing oracle that simply returns a randomized signature does not automatically materialize those matching reserved coins. The remaining obligation is the native signing-owner/retained-record bridge, or an explicitly justified stronger operational signature assumption. The delivered main-text corollary keeps attribution explicit.

## Reproducible checks and counterexamples

The full pinned-source command documented in `README.md` passed **39 of 39** checks: twelve source identities, source framing/ordering/nonce assertions, finite verifier enumeration and explicit model witnesses. Its portable `--finite-only` mode separately passed **19 of 19** self-contained checks. The verifier enumeration checks 585 all-failure-prefix strategies over sixteen random tag tables, for 9360 table executions; exact maxima for zero through three attempts are `0, 1/4, 1/2, 3/4` in a four-tag space. This validates the finite classical guessing calculation used in the proof.

The witnesses cover repeated-core aliases, aliases across copied owners, precommit private computations, digest collisions, failed-reservation selector mismatch, source-resolved online registration, historical consumed statuses, competing sender nonce reuse, same-ID plaintext retry leakage and the distinct power of coherent verification. They are small interface/model checks. The actual mathematical bounds follow from the written reductions and their primary primitive results.

No new native Rust, Tamarin or full-proof mechanization run is claimed by this artifact. Existing CI and retained native evidence keep their recorded identities.

## Primary references

- [Published quantum collision theorem, Theorem 7, p. 562](https://www.rintonpress.com/xxqic15/qic-15-78/0557-0567.pdf): Mark Zhandry, *Quantum Information and Computation* 15(7–8), 557–567, 2015.
- [Author preprint, used to cross-check the theorem's history](https://arxiv.org/pdf/1312.1027): Theorem 3.1 has the preprint query-shift convention. The delivered TeX cites the published version.
- [Pinned Q-Periapt source](https://github.com/billlza/q-periapt/tree/228c944fc476e3e57d6c08063cacb19bca5b360e): exact file URLs and hashes appear in the receipt.
- Manuscript dependencies, individually hash-bound in the receipt: `joint-continuation.tex`, `joint-primitive-bounds.tex`, `contextbound-connection.tex`, `candidate-local-accounting.tex`, `security-model.tex`, `opaque-rendering.tex`, `primitive-inputs.tex`, and the retained `artifacts/live-profile/source_profile.md`.
