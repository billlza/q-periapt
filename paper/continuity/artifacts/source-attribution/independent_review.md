# Independent review of executed-source attribution

**Verdict: accepted for manuscript integration under the stated authoritative-history and signing-owner interfaces.** The retained-plan invariant, accepted-source association, two signature-component adapters, and generic signing-coin separation are supported by the inspected source and the arguments reviewed below. The executed-slot selector receives an explicit signature/hash attribution bound. The existing metadata selector retains its own experiment and counterexample.

This review was performed separately from the author of `source_attribution_proof.md`, `source-attribution.tex`, and `check_source_attribution.py`. The reviewer did not edit those files. Corrections were communicated to the author and are present in the frozen versions identified below. Native source was checked at integration commit `72acaaccde1ca9ea27e5af022da5fbce932ed4e9`.

## 1. Accepted mathematical statements

| Result | Accepted statement | Decisive evidence |
| --- | --- | --- |
| Stable executed sources, Lemma A | Within one authoritative local history and epoch, at most one original generation slot and one original encapsulation slot reach their respective private computations. | Both native paths persist the original token before computation; later phases retain that token or its result; clearing the plan advances the epoch. |
| Source association, Proposition B | For the executed-slot selector, `E ∧ ¬A ⇒ Bad_sig^0 ∨ Bad_H`, hence `eta_attr_exec ≤ min(1, epsilon_sig + chi_H(Q_H))`. | The signed-body ledger and complete-wire digests connect proposer and responder plans to their registered original operations. The signature event is stopped before target key/file disclosure. |
| Signature adapters, Proposition C | The reservation-aware pair advantage is bounded by the reservation-aware ML-DSA multiuser advantage; for classical adversaries it is also bounded by the exact native deterministic P-256 multiuser EUF advantage. | The other constituent and all required reservation bytes are simulated exactly. The single-user P-256 form pays the explicit factor `U` and full simulation cost. |
| Coin-disclosure separation, Proposition D | Ordinary EUF-CMA and unforgeability with original signing-coin openings admit a generic separation. | The appendix `r XOR s` is independently uniform in the ordinary game and reveals `s` when the same original `r` is opened. The two ordinary-game reductions preserve success probability with their running-time overhead counted. |

The source theorem identifies the original matching calls and their bindings. Primitive encapsulation/decapsulation correctness remains in the existing `delta_j` term. Thus the substitution affects exactly the attribution term of the retained live-core bound:

\[
\operatorname{Adv}_{\rm msg}\le
\min\!\left\{\frac12,\frac12\!\left(
\Delta_{\rm attr}+\sum_{j\in J}
\left(2\varepsilon_{{\rm rec},j}+a_j^++a_j^-+2\delta_j+B_j^{\rm cont}\right)
\right)\right\},
\qquad
\Delta_{\rm attr}=\min\{1,\varepsilon_{\rm sig}+\chi_H(Q_H)\}.
\]

This does not introduce another joint-schedule charge. The original sampling indices in `[G] × [C]`, the cut times, and the candidate-local score factors retain their existing meanings.

## 2. Source invariant and failure paths

In `prepare_rekey_offer`, a missing plan first produces a generation reservation, installs `Plan::Key`, and awaits `store_message_state` with error propagation. Only the subsequent path invokes `recovery.generate_key`. A failed first write therefore has two relevant recovered outcomes: an intact target retains the original token, or no target survives and that original draw has never reached generation. The latter outcome can be followed by a new original draw. Recording the executed source at computation distinguishes these cases without changing when either slot was sampled.

The generation path carries the same token through `Key`, `Signing`, and `Ready`. It compares the recomputed complete body with the saved signing body. The completion path retains the offer, response, and derived root; it does not replace the generation token with a new source. The responder likewise saves `Stage::Encapsulation` and the exact offered wire before encapsulation. Every continuation checks that offered wire, and subsequent stages preserve its computed result and pending root. Inspection of the plan-clearing transition confirms that normal completion advances the epoch before clearing the plan.

`store_message_state` reaches the journal persistence path, and persistence errors close the active owner. Pending-write recovery reconciles a retained complete target. These facts support an induction over successful and uncertain writes, cancellation, process loss, and reopening within the declared authoritative history. The induction concerns the identity of a causal source; equal public keys, ciphertexts, or output bytes do not merge distinct original draws.

The independent two-journal control demonstrates why the history premise is substantive. Give two responder journals the same signer, session, epoch, and parent. Each can retain its own encapsulation and honestly sign a response to the same offer. A proposer can accept the second response while a separately designated responder register names the first origin. No fresh signed body or hash collision is needed. The native rekey prefix omits the journal identity although the private operation scope includes it. Consequently local persistence safety alone is not a proof of global single-history ownership. The revised theorem declares that ownership condition directly. This control is a countermodel to dropping that condition, not a claimed native bootstrap exploit.

## 3. Accepted wires, aliases, and the signing ledger

At a proposer installation, `accept_rekey_response` begins with its own retained ready offer and token. It verifies the responder signature and the complete response prefix, including the digest of its own complete offer, before selected decapsulation. In the absence of the fresh-message event, the response body has a private honest signing origin. The configured signer and the complete context/session/epoch/role/parent fields locate that origin in the same permitted history. The responder invariant supplies its unique original encapsulation. Equality of complete-offer digests, outside the distinct-input collision event, identifies the exact offer supplied to that encapsulation. Native regeneration additionally compares the public key with the saved offer.

At a responder installation, `finish_rekey` verifies a final against both its retained complete offer and its retained ready response before allocating traffic. The honest final-signing origin is therefore a proposer transition of the preceding kind. The two complete-wire digest comparisons identify the same source pair. Receipt acceptance advances state without another root allocation.

An alternative valid signature encoding of an issued body is not a fresh-message forgery. The reviewed finite matrix, which is also consistent with the retained native alias-test source, is:

| Changed valid signature encoding | Proposer traffic allocation | Responder traffic allocation | Proposer receipt acceptance |
| --- | --- | --- | --- |
| None | Accept | Accept | Accept |
| Offer | Reject | Reject | Reject |
| Response only | Accept | Reject | Reject |
| Final only | Accept | Accept | Reject |

A response alias leaves the ciphertext, KEM context, response core, and source pair unchanged. Its complete wire can change the traffic information string. The existing joint schedule already indexes that full information, so no whole-response uniqueness premise is needed. The permitted proposer send remains available before joint peer confirmation.

The native honest ledger is keyed by actual signing material and contains every honest private invocation across public purposes and exact owner aliases. It is populated before later persistence or publication. A computed signature whose wire is never published remains an honest query. The signed purpose byte and complete body length prevent a different public purpose from being silently identified with the selected control message. Absence from the actual-key ledger implies absence from the projected owner-index ledger used by the component game.

## 4. Signature simulation and precise disclosure boundary

The exposure-stopped event is essential to the probability statement. Native executions can disclose a target key on paths with `E = 0`; a subsequent valid signature on a fresh body could then be trivial. The final proof instead defines `Bad_sig^0` before the first target key or signer-file disclosure, stops immediately before returning such bytes, and retains whether the event already occurred. The native and stopped prefixes have the same classical interaction and quantum-state transformation. On eligible executions, this stop is never reached. This establishes the required event coupling without returning an unknown challenger secret.

The distinction between the signing reservation and the signing-owner file is correct in the revised draft. `SigningReservation::encode` carries a 32-byte public binding and the original 32-byte ML-DSA randomizer. The `QPSIGN01` owner file encrypts a `QPSMAT01` plaintext containing both 32-byte secret seeds and the public pair. The declared primitive wrapper supplies the former exactly and exposes no earlier byte-dependent observation or commitment of the latter. Capturing the actual target signer file invokes the model's existing permanent identity-exposure stop. Public independent owner IDs and lifecycle bookkeeping remain available.

For the ML-DSA adapter, a private eager `Open` obtains the challenger reservation's original randomizer before any native reservation serialization. These calls are counted. They do not cause the network adversary to learn the coins until the original observation interface requests them, and opening coins is itself permitted by the primitive game. This resolves the difference between simulator knowledge and adversary disclosure.

For the classical adapter, locally generated ML-DSA keys and randomizers supply every reservation byte and randomized constituent. The P-256 challenger supplies the deterministic constituent at the original private computation, followed by the native low-`s` canonicalization. The checked `Cargo.lock` pins `p256 0.14.0` and `ecdsa 0.17.0`. The published source of the latter routes `Signer::try_sign` through its digest/prehash path to `sign_prehashed_rfc6979` with empty additional data. The exact signing-oracle distribution is therefore specified; a generic randomized ECDSA oracle would be a different simulator.

The multiuser games retain an index per independently generated signing owner. Exact reuse and reopening preserve that index. Accidental key coincidences remain in the distribution, and native admission checks are executed normally. This indexed definition supplies the claimed component projection even if only one component coincides across pair users. There is no additional signer factor in the multiuser inequalities. A single-user P-256 reduction guesses one of the `U` owner indices, simulates other owners locally, and pays `min(1, U * epsilon_P256_EUF_single)` with complete simulation time and at most the original Execute-query budget. The selected native endpoints also reject shared signature components during admission.

The exact-tuple reservation service describes the controlled native call surface. Native `SigningReservation::sign` stores and compares a hash binding, whereas its caller supplies the retained original operation, purpose, and body. The theorem does not silently treat that hash as an injective encoding for an additional arbitrary tuple-retarget API.

For post-quantum adversaries, the remaining signature assumption is explicitly the reservation-aware ML-DSA advantage with these original-coin openings and public-oracle interfaces. An additional reduction of that advantage to a conventional ML-DSA game would strengthen the primitive instantiation. Broader pre-stop observations of secret owner-file bytes would require their own correspondence argument. Neither extension is used by the accepted classical adapter or the present conditional source-association theorem.

## 5. Independent checks and resolved review points

The author checker was rerun independently and passed **44 checks**, including its exact source audit. Its two recovered-state graphs each contain 34 states with at most three original draws across two epochs. Six deliberately changed transition rules produce counterexamples: compute before persistence, discard an executed plan, and renumber a retry, each for generation and encapsulation. The fixed alias matrix and the publication-failure ledger control were inspected separately from the expected outcomes.

The separate `review_adversarial_controls.py` imports none of the author checker's implementation. It passed **30 checks**, comprising:

* Exact identity comparison of 13 native/dependency files with the named integration commit.
* 234 distinct framed messages spanning all 39 native public-purpose tags.
* 936 combinations of purpose, body, exact owner alias, and private computation followed by failed publication.
* 24 source/alias combinations including failed earlier draws and coincident public-key bytes.
* 9,331 public-event histories of length at most five for the pre-disclosure event coupling.
* All 36 `(U, winning owner)` assignments for `U` from one through eight, plus component-key and full-owner-alias controls.
* Explicit countermodels for omitted single-history ownership, a publication-only ledger, a label-only identity ledger, the unqualified post-exposure forgery event, and a forced distinct-input hash collision.

Both checkers also passed under `python -O`; their validation is not removed with Python assertion optimization. The retained receipts identify the scripts, sources, and exact reviewed proof artifacts. These checks are finite semantic controls and source audits. They execute neither the native Rust protocol nor a formal verifier and do not estimate a cryptographic forgery probability.

The review's requested refinements are all present in the frozen text: the exposure-stopped event; eager private randomizer openings; the distinction between source matching and KEM correctness; explicit native RFC6979 signing; indexed multiuser accounting and its single-user factor; all-purpose actual-key issuance; the controlled original-tuple interface; and success-preserving separation reductions with simulation overhead counted. No mathematical blocker remains for integrating these four results within their declared hypotheses.

## 6. Reproduction and primary implementation reference

Run from the repository root:

```sh
python paper/continuity/artifacts/source-attribution/check_source_attribution.py --output paper/continuity/build/source-attribution-review-rerun.json
python -O paper/continuity/artifacts/source-attribution/check_source_attribution.py --output paper/continuity/build/source-attribution-review-rerun-opt.json
python paper/continuity/artifacts/source-attribution/review_adversarial_controls.py --output paper/continuity/build/source-attribution-independent-controls.json
python -O paper/continuity/artifacts/source-attribution/review_adversarial_controls.py --output paper/continuity/build/source-attribution-independent-controls-opt.json
```

Primary dependency source inspected for the deterministic signing path: [RustCrypto `ecdsa` 0.17.0, `signing.rs`](https://docs.rs/ecdsa/0.17.0/src/ecdsa/signing.rs.html). The proof's algorithm references are [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979.html) and [FIPS 204](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf).

## 7. Exact review identity

<!-- REVIEW_IDENTITY -->

The following SHA-256 identities bind this review to the proof, main-text module, checkers, and inspected native files. The complete machine-readable review and retained check results are in `independent_review.json`.

### Proof and checker artifacts

| File | SHA-256 |
| --- | --- |
| `paper/continuity/artifacts/source-attribution/source_attribution_proof.md` | `86f36ea6864242a3c55cd834702ffacbf0a5eec0d13996ad8034722d789e42e3` |
| `paper/continuity/source-attribution.tex` | `30c558ea3ab4f7eb79944fbeb6c437a7beeb8d49f609fb6e17c12e153d9e85e4` |
| `paper/continuity/artifacts/source-attribution/check_source_attribution.py` | `b381aef5d318bf274908f741d20955d0fa5885806ff571c93fbbfe2c9b319aee` |
| `paper/continuity/artifacts/source-attribution/source_identity.json` | `5dde1719d0c0ac7386f5fcbfc81f57427253714d332508ee13f6c5cee5785cc3` |
| `paper/continuity/artifacts/source-attribution/review_adversarial_controls.py` | `94966c79dbebc30876cceb1273181a244b7047d5238e85d6312a85a13843a173` |

### Inspected native and dependency files

Every row equals its bytes at integration commit `72acaaccde1ca9ea27e5af022da5fbce932ed4e9`.

| File | SHA-256 |
| --- | --- |
| `research/continuity-identity-candidate/src/crypto.rs` | `612dfaa0244219602a559cee7e14c5de5dde496d0f2c72e2d86864d39071f5a4` |
| `research/continuity-identity-candidate/src/crypto/persistence.rs` | `f502bef3368bedec46cefd7f8955d4706550d45ab9baf2c7d6bca8ee45b4d405` |
| `research/continuity-identity-candidate/src/contract.rs` | `3e6285fee34e5a785655d60cebf0704ba1a1d1385e6fb3e945ee79f682108f7e` |
| `research/continuity-identity-candidate/src/bootstrap.rs` | `f72bce264806a900affe2cac33beb449e77aeaa45e6e264549eaa0f2ece7a286` |
| `research/continuity-identity-candidate/src/durable.rs` | `664bc3bfad790cc4639168b54bea30fdcdb80520310454cddd80ac66a5b37c42` |
| `research/continuity-identity-candidate/src/durable/write_intent.rs` | `502bbd9de26958575704edbd0207c6579c4a07e3b9ed4a57650f407f3fdb312d` |
| `research/continuity-identity-candidate/src/durable/messages.rs` | `3a8c16f24214fcd624ff5de77144a5b3ece9f0981cc2e4c80d4290685f894d82` |
| `research/continuity-identity-candidate/src/durable/messages/rekey.rs` | `74f8b76dad4fc7f95a5cbaf47bc7cf51ef2231f18bc1f940e68793a050483a10` |
| `research/continuity-identity-candidate/src/durable/messages/rekey/response.rs` | `e2c1dfe4122c9f2ae41101dfb7b392abcd801f09dd63b5f39e6722f3585cee59` |
| `research/continuity-identity-candidate/src/durable/messages/rekey/completion.rs` | `d2ba085119db3cff2ebda780f4824b8b4cbd3a9f6e44531df45db48144a65c1e` |
| `research/continuity-identity-candidate/src/durable/messages/tests/classical_alias.rs` | `2bdedc294d4907d5ae418722c428ade9c2b2f67da252cf76154a2eac6d881cb1` |
| `research/continuity-identity-candidate/Cargo.lock` | `fda2e0592f7e013816b343d461da1e32346b4256603eda317d12b4ebd200c26b` |
| `crates/q-periapt-sdk/src/expert/replay.rs` | `cc95985cd212a2c2f224dcce22bc7fba5f4f331dc190e263085a0261dd0a3713` |

### Retained execution receipts

| File | SHA-256 |
| --- | --- |
| `paper/continuity/build/source-attribution-independent-controls.json` | `3d8ef6fb8f2dc0878910e33fb2e87f28100eebd6592cee38fd803bcc4b3995ad` |
| `paper/continuity/build/source-attribution-independent-controls-opt.json` | `3d8ef6fb8f2dc0878910e33fb2e87f28100eebd6592cee38fd803bcc4b3995ad` |
| `paper/continuity/build/source-attribution-review-rerun.json` | `bd959d7ad5edc497fd030c0dc9bbfb5616fa6a28a5d29e51eadc66c3387735f3` |
| `paper/continuity/build/source-attribution-review-rerun-opt.json` | `bd959d7ad5edc497fd030c0dc9bbfb5616fa6a28a5d29e51eadc66c3387735f3` |
