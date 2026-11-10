# Academic and theoretical review of the 35-page JoC research draft

Reviewed source: `work/paper_round2/manuscript` and its retained proof/review artifacts.
Round-3 changes are proposed independently; the reviewed source files were not modified.

## 1. Main assessment

The paper has a coherent research problem and several mathematically usable results. Its strongest computational content is the explicit simulation of durable records without the selected reservation tape, together with the reverse-order composition of immutable reports whose messages contain earlier report keys. These results address an actual reduction problem caused by persistence: the component challenger supplies public values and a shared-secret challenge while withholding the original coins that the implementation stores.

The origin model, guarded exposure closure and nonadditivity example make that problem precise. They are supporting semantics, rather than contributions of the same mathematical depth as the unknown-tape simulation. The multi-epoch symbolic theorem and concrete disclosure executions provide separate kinds of evidence. Presenting these layers in their own roles makes the paper stronger; no evidence needs to be discounted merely because it belongs to a different layer.

I found no contradiction in the previously reviewed finite-interface theorems under their stated interfaces. The material issue is a connection between them and the opening computational accounting proposition. The new candidate-local lemma resolves that identification problem at the level of the actual available interface bounds. It does not purport to supply a numerical or negligible bound for an unmeasured disclosure residual or the remaining joint root/message continuation.

## 2. A precise applicability issue and the resolution

### What the current proposition states

`computational-roadmap.tex`, Proposition `prop:adaptive-accounting`, assumes one common real-component virtual game `V`, one native-to-`V` record comparison, and separate component-override worlds `V_j`. Its inequality is valid under those hypotheses. The proof correctly partitions only the score in `V` and retains the separate ideal-world selectors.

### What the existing constructions actually give

The opaque record construction is for a fixed candidate. Choosing `X_j` determines which bytes are unavailable, which records receive designated private commitments, and which raw outputs require a stop. The report construction adds the candidate's online raw-key dependency closure and its charged projection event. These choices may differ with `j` before the component KEM hop.

Consequently, the collection of proved local constructions does not by itself identify one common real-component `V` whose single record error can be charged globally. This is an uninstantiated identification, not a counterexample to the conditional proposition. Folding the local report residuals into a purported common `epsilon_rec` without their actual game/score correspondence would silently change the proof input.

### The round-3 connection

`candidate_local_composition.md` and `candidate-local-accounting.tex` use one original native game throughout the score decomposition. They then permit a distinct stopped native and virtual continuation for each candidate. The exact decomposition charges attribution failure and the finally attributed candidate's actual projection once in the native game. Each local cryptographic error and ideal continuation retains its own game.

The previous common-`V` result remains a useful special-case route when an actual common comparison is established. It should not be the prerequisite through which the current candidate-local constructions are forced to pass. The new local formulation directly matches those constructions.

This is best presented as a technical connection lemma and accounting proposition, not a major standalone cryptographic discovery. Its value is to prevent a real interface mismatch and to make the eventual native instantiation auditable.

## 3. The all-continuations stop is stronger and more useful than a fixed-cut assertion

The new source certificate uses a reservation that has already occurred, a captured intact session version with a matching subject, and the certified inequality `res(o) <= save(v)`. If the final target is ever eligible and attributed to the candidate containing `o`, its cut must be earlier than `res(o)`. The captured version is therefore necessarily post-cut for that selected session. This contradicts the original acquisition predicate in every continuation.

This argument does not require the other member of the KEM pair, the challenge send, or the final cut selection to exist yet. It also does not require decryption: the original predicate uses acquisition. The native constructor facts supporting reservation-before-save and immutable subject/save metadata supply a concrete way to check the certificate.

The mathematical condition is slightly broader than token retention. Retention supplies the causal inequality, but any independently recorded later save of the same session also suffices. The exact temporal part of eligibility is `L_s <= cut < min(res(g),res(a))`, where `L_s` is the largest **original version save time** among acquired matching versions. This characterization leaves the authentication, entropy, accepted-send and attribution conditions intact. It must not use the latest physical-image seal time instead.

A protected report flag is not this certificate. In particular, a batch-only key fragment has no intact member-version witness solely because the corresponding MAC input contained that member's state. The charged projection residual retains those actual branches. This is the required distinction between causal report dependence and session-record acquisition.

## 4. Theorem hierarchy and a more concentrated contribution statement

The current first contribution in `introduction.tex` contains the origin model, alias normalization, guarded closure, finite checker, opaque simulation, dependent report composition, adaptive accounting, symbolic theorem and positive witness. Readers must infer the hierarchy themselves. The introductory heading also promises a symbolic theorem while much of the paragraph concerns computational simulation.

A more concentrated structure would give three contributions:

1. **A cryptographic interface for persistent reservations.** Define reservation and version origins, then emphasize the explicit unknown-tape image/intent simulator and dependent-report composition. State their quantitative interfaces and the candidate-local connection in one short paragraph.
2. **Recovery at the actual reservation boundary.** State the multi-epoch symbolic recovery theorem and its key acquisition/freshness condition. The guarded semantics and positive instance support this statement; the independent replay gives its certificate.
3. **Constructive boundary witnesses and controlled reference evidence.** Combine the native generation/encapsulation, delayed-receipt and aggregate-copy witnesses with the pinned reference corpora. Keep the concrete interpretation of each result, without treating a reference-only comparison as a completed matched Continuity experiment.

An alternative is to put the origin model and symbolic theorem first, followed by the computational connection. Either ordering is clear if the explicit simulator and report-dependency result are not buried inside a general bookkeeping item.

The elementary nonadditivity proposition is useful as a short explanation of why a record and key jointly enable disclosure. It can be reduced to a brief example in the main text, with the full proposition/XOR illustration in the appendix. The guarded-path theorem should remain an exact semantics result, not be described as a new cryptographic assumption or a confidentiality theorem. The finite checker corroborates its implementation; it is not the reason the general equality holds.

## 5. Primitive games should be self-contained in the paper

The report subsection refers to an “existing one-row” lemma and immediately writes `DFH` and `E_NMAC`. The artifact appendix identifies the repository notes and explains their role, but the mathematical game should be understandable without opening those notes.

A short operational definition is enough: sample one hidden independent uniform key; execute and count the full common-oracle preparation; allow one classical chosen transcript and exact repeats/identifier comparisons; compare real HMAC to one independent cached uniform tag; forbid an extra direct channel for the challenged key; count all ordinary quantum compression queries and the continuation. Define `epsilon_row` as a bound for this game's allowed algorithms. Ordinary public-oracle evaluations under other locally known independent keys remain allowed, including accidental equality with the challenged key.

The detailed compression-QROM instantiation and its precise functions can then be stated in an appendix with primary references and exact parameter regimes. This is a self-containment improvement, not a change to the dependent-report theorem. The image commitment parameter can be organized similarly: give its real/ideal observation game first, then the concrete QROM expression.

## 6. Scope statements should follow the declared experiment

The threat model in `security-model.tex` explicitly grants read-only captures and does not grant replacement of the authoritative journal. This is a definite model choice. Arbitrary modified storage import is therefore not an unfinished requirement of the current read-only-capture theorem. It belongs to a different interface if that adversarial operation is later admitted.

The paper currently repeats variants of that boundary in the report theorem, the native correspondence, and supporting artifacts. State the storage authority and legitimate reopening rule once in the threat model and refer to it where needed. Keep the distinction between a trusted original-handle validation and a new attacker-chosen MAC transcript in the formal operation list. This removes repetitive negative prose while preserving the exact adversarial power.

The same editorial principle applies to derivability versus indistinguishability. The guarded section needs a clear definition that its output is a set of constructively derivable protected values, followed by the separate message game. A repeated catalogue of cryptanalysis, timing, guessing and other interfaces adds little after those definitions have fixed the semantics.

The public/audience distinction for reports should stay explicit. Closure and abandonment return metadata; closed-epoch resolution returns unconsumed plaintext to the authorized application. A tag simulation does not change that audience. This is an interface fact used by the proof, rather than a generic caveat after each result.

## 7. Assumptions worth keeping explicit

These assumptions have concrete work in the existing proofs and should remain near their use:

* **Known local storage keys.** The opaque renderer can render permitted atom-free objects and their real digests because all encryption/authentication inputs for those objects are available. This prevents a fake-real-digest inconsistency after raw acquisition.
* **Complete prefix and fixed per-image intent key.** The equality proof needs both directions of its identity relation. Same image and complete canonical prefix must determine the same deterministic MAC, not merely distinguish different prefixes.
* **Fresh sealing invocation versus replay origin.** Nonces and private-commitment budgets count all fresh attempts, while copies keep the original cache. This is why retries do not multiply the wrong resource.
* **Immutable report transcript and causal key references.** Later raw-key dependencies are forward-closed; earlier fixed transcripts predate the selected unknown key. Those properties, rather than a declaration that all report outputs are independent, implement the reverse-order reduction.
* **Same-game continuation and complete oracle work.** The final selector, eligibility and dependent controls are evaluated anew in each comparison world, and every reduction counts its actual prefix and continuation. This is particularly important for the component KEM and future root/message views.
* **Actual stopped-game source correspondence.** The candidate-local error `rho_j` must compare the specified stopped native machine with its specified local real-component continuation. A free-stop certificate settles the score on certified paths; it does not manufacture the bytes or statuses on the other paths.

These are finite, named interface conditions. They should be used to organize the constructive proof rather than be repeated as a general uncertainty about the entire project.

## 8. What can be concluded now

The record simulation and report-family composition can be presented as established finite-interface results. The new candidate-local accounting makes their place in the adaptive native reduction precise and supplies a computable stop certificate valid before target coordinates are finalized. The symbolic recovery theorem, its replay certificate, the positive ground witness and the native disclosure executions retain their established evidence.

For the next computational step, the manuscript has a concrete target: bound the local random-component continuation `b_j` for the joint root, confirmation, traffic, ACK and successor-epoch view, and instantiate the local native correspondence/residuals on the chosen acquisition profile. The existing records/report analysis is the input to that task. Additional comparison experiments improve empirical claims where they are made; they are not a prerequisite for the validity of these algebraic and simulation results, nor a new gate for the separate software release.
