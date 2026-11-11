# Q-Periapt JoC research state

## Current direction

The manuscript is **Exposure and Recovery with Persistent Randomness Reservations**, targeting Journal of Cryptology. Its continuous branch is `paper/joc-persistent-recovery`, with [manuscript PR #119](https://github.com/billlza/q-periapt/pull/119) against `main`. Continue this same PR for manuscript and directly used proof/evidence updates. [WORKFLOW.md](WORKFLOW.md) records the build and update procedure.

The confirmed author is **Ziang Li (李子昂)**, Department of Engineering, Durham University. Correspondence: **2403871950@qq.com**. Alternative contact: **bhmq03@durham.ac.uk**. The current author list contains one person.

On 11 November 2026, the author confirmed no research funding, no relevant
financial or non-financial competing interests, and responsibility for all
current research and manuscript contributions. The Declarations section and
`author-metadata.json` now record these facts. Any future manuscript review is
recorded when it occurs. The assembled submission awaits the author's final
review and approval.

## Joint schedule and retained source profile

The prior origin-normalization, guarded record-exposure, private-image simulation, reverse-report composition and candidate-local accounting results remain in place. The preceding computation increment established:

1. **Lemma 5.9:** an exact HKDF block-table representation for adaptive complete information strings. Applied before the selected-seed Extract hop, it removes the parent row's internal input containing that seed.
2. **Theorem 5.10:** a joint shared-compression-oracle continuation from a uniform epoch root to the first message key of a designated fresh traffic allocation. Its finite M budget retains full-info aliases, zero-salt/session-salt aliases, real confirmation/ACK verification and successor-root/next-seed disclosure.
3. **Corollary 5.11 and the recovered-contribution entry:** the one-message AEAD reduction and the actual root Extract/Expand comparison, with their explicit score factors and complete query budgets.

The target material and direction are marked before that new material produces any blocks. Repeated complete information strings keep the same material identity. The network interface uses plaintext-free Resume; the honest application owns plaintext-bearing Send and delivery. The source profile records the same-ID guess-Send counterexample for an enlarged public caller interface. Existing eligibility and original-game projection accounting are preserved.

The full frozen proof and its 22-point cross-check are in [the joint-continuation artifact](../artifacts/joint-continuation/README.md). The [live profile](../artifacts/live-profile/source_profile.md) and source map bind actual constructors and observations to the declared experiment. Twenty-four inspected files are byte-identical at source pin `228c944fc476e3e57d6c08063cacb19bca5b360e` and development checkpoint `1c68aa666db22d36ee136be1ec712545a9e74f03`.

## Accepted operation to recovered contribution

The attributed-original-operation-to-uniform-contribution connection is established for the next rekey of an established authoritative session and its marked first-message interface:

1. **The complete-tuple hidden-component lemma** (`lem:cb-hidden-component` in `contextbound-connection.tex`) applies the cited adaptive hidden-input theorem to the complete ten-field LP8 ContextBound encoding, with bit gap `Phi_256(d_j,Q_H,j)`. Exact repetitions are cached by the effective tuple, including the other shared secret. Origin metadata and hash-table identity remain distinct.
2. The **operational component adapter** installs the ML-KEM-768 public key at the original generation and creates its one challenge at the original encapsulation's first actual computation. It preserves prechallenge answers; afterwards the selected PQ ciphertext is intercepted regardless of traditional ciphertext/context. X25519 and its failures remain actual native computations. The stated component advantages refer to this two-stage experiment; no unproved conversion to a different game is assumed.
3. **The native root-use lemma** (`lem:cb-native-root-use`) proves that the original target tuple uses one old-root/complete-root-info pair. The induction applies online to every supported continuation of the matching immutable binding, including failed, crashed and ultimately unaccepted executions, independently of future eligibility. The target is allocated at its earliest private computation through any alias.
4. **The next-rekey connection theorem** (`thm:cb-next-rekey`) substitutes that comparison into the retained candidate-local bound. The random-component score obeys `|b_j| <= min(1, 2 Phi_256(d_j,Q_H,j) + 2 Delta_init,j + 2 Delta_sched,j + 2 epsilon_AEAD,j)`. Original-game attribution/projection residuals, local correspondence, actual component-event gaps and correctness costs retain their previous locations. The labels identify the canonical statements independently of later insertion and renumbering.

The [frozen proof and independent review](../artifacts/contextbound-connection/README.md) include the complete game chain, source induction, counterexamples and exact file hashes. The self-contained checker has 36 format/adapter cases. The separate source audit has 14 files and 12 static assertions at the unchanged native/development pins. These executable checks support concrete interfaces; the mathematical claim is supported by its proof and statement-by-statement review.

The two oracle interfaces are explicit: whole SHA3-256 for ContextBound and independent SHA-256 compression for HMAC/HKDF. Preparation, other native work, continuation and terminal tests are all counted. The operational profile retains private honest application data and plaintext-free public resumption. Raw X25519 is not assumed to be a uniform-256-bit KEM challenge.

## Finite multiple-root entry

**The finite multiple-root entry theorem** proves the finite entry service from one hidden uniform contribution to several adaptive root descriptors. The cryptographic identity is the full pair `(Gamma(r), I)`, with `Gamma(r)` the two public HMAC pad states and `I` the complete root information. Its table is shared across callers, aliases and resumptions; source provenance remains in the separate origin ledger.

One hidden-contribution column comparison and a sequence of adaptive class-row comparisons produce a private table of independent roots. The finite bounds distinguish available salt strings `D`, pad-state classes `C` and complete information entries `N_i`. The ordinary-query budgets are `q_S = B + 2D + 5 sum_i N_i` and `q_i = B + 2D + 5 sum_(k>i) N_k`, with the complete surrounding execution in `B`.

A mark selects a descriptor before its first root evaluation. It may select a new information entry in a class that already produced other roots. All aliases of that target share the retained schedule handle. Unmarked roots are available to the controller and may become later salts. **Its first-message corollary** composes this entry with the retained first-message theorem, giving `min(1, 2 Delta_mr + 2 Delta_sched + 2 epsilon_AEAD)`. The ContextBound comparison supplies the preceding `2 Phi_256` term for a candidate whose stopped execution realizes this controller.

The [multiple-root artifact](../artifacts/multiple-root-entry/README.md) contains the integrated theorem, a complete constructive proof, a worked controller and a 25-point independent review. It distinguishes PRK allocation from target-root allocation and preserves numerical key coincidences through the shared oracle. This completes the finite multiple-root mathematical extension proposed after the next-rekey result.

## Owned SDK purpose-key correspondence

The concrete broader workload is now the SDK's `SharedSecret::derive_key` interface. A length-parameterized form of the finite entry comparison covers its exact information strings, including the suite, ContextBound profile, authenticated policy state, trust-root digest, purpose, protocol label, context and output size. The fixed 27-byte salt has the same HMAC padded key block as its 32-byte zero-extended representation.

Complete information strings index one shared key table. Each accepted derivation creates a separate `DerivedKey` owner, so repeated descriptors preserve key bytes while close and export operations follow their own guards. Source closure, runtime closure and exported copies keep the source's actual lifecycle behavior. The proof uses a finite lifetime descriptor budget; Rust in-flight admission and FFI handle capacity retain their distinct operational meanings.

The entry comparison permits all derived keys to be exported and establishes their joint pseudorandom separation while the parent contribution and Extract value remain within the KDF interface. The existing five-purpose dual-peer workload has five descriptors, 144-byte information strings and 145-byte row messages. Its conservative ordinary-query budgets are `B + 32` for the hidden-contribution column and `B + 2` for the hidden-PRK row. At full SDK limits the row length is 65,899 bytes and the compression length parameter is 1,031.

A separate one-key application experiment marks a fresh descriptor before its first private evaluation and routes every target alias through one controlled AEAD interface. Its qualified score bound is `min(1, 2 Delta_sdk + 2 epsilon_AEAD)`. The complete-tuple ContextBound term composes when the stopped contribution family realizes the stated controller. The durable rekey driver retains its established 97-byte root-information profile.

The [SDK correspondence artifact](../artifacts/sdk-purpose-connection/README.md) contains the full proof, native source map, independent review and retained Rust test outcomes. The completed current-source CI already passed the five relevant native tests; the manuscript update performs a separate source and mathematical review.

## Native live core and authentication

The live-core corollary now explicitly substitutes the existing source correspondence into the native confidentiality bound. For candidate `j`, the image/intent record cost is the whole-query commitment sum plus the 192-bit sealing-nonce structural-equality term, capped at one; its score contribution is twice that bit cost. The complete declared live interface admits the named successor-root and next-chain-seed projections and complete-object acquisitions. Its original-game projection residual is zero. Optional report and additional partial-secret interfaces retain their own accounting.

The general attribution residual remains explicit. An original draw `g1` can enter a transaction-private key plan whose persistence fails before any pending target or image is durable. After reopening the prior authoritative state, a new `g2` can produce the honest accepted exchange with `a2`. A selector naming `(g1,a2)` may satisfy the general reservation metadata and cut conditions while missing the actual exchange. This witness is already covered by the original attribution term and requires no signature forgery.

The confirmation/message proposition starts at the established uniform epoch-root interface. It bounds the union of fresh accepted confirmation cores and new authenticated first-message inbox installations by the joint-schedule cost once, adaptive confirmation-row costs, classical tag guessing, a full-core quantum hash-collision cost and a one-key ciphertext-integrity term. Exact private tag/encryption origins are logged before later persistence or release. `PreviouslyConsumed` and an existing inbox entry retain their actual historical status. The same controller retains the existing qualified confidentiality result.

The new result uses the actual three next-rekey confirmation keys and the marked traffic allocation. The SDK five-purpose workload retains its established derive/export interpretation. The production bootstrap's separate raw contribution use retains its own construction analysis.

The complete proof, fixed-source map, finite semantic controls and independent reviews are in [the live-core and authentication artifact](../artifacts/confirmation-traffic/README.md). No new native Rust, Tamarin or performance execution is claimed by this mathematical increment.

## Executed-source attribution and original signing coins

The focused attribution construction is now integrated in `source-attribution.tex`, with a complete proof and independent review in [the source-attribution artifact](../artifacts/source-attribution/README.md).

The executed-slot selector records existing original generation/encapsulation indices immediately before first private computation; sampling times and original `[G] x [C]` budgets are unchanged. A persist-before-compute induction gives one executed source of each role per authoritative local epoch. Complete signed-body and wire checks then give `E AND NOT Attr => Bad_sig^0 OR Bad_H`, with `Bad_sig^0` evaluated before the first target key or signer-file disclosure. This yields the explicit attribution cost `min(1, epsilon_sig + chi_H(Q_H))` for this selector. The general metadata selector keeps its existing counterexample and residual.

The signing experiment explicitly exposes original reservation randomizers and exact retries. Its owner interface contains public-key/lifecycle metadata and signing-reservation records, stops before a target key/file return, and has no earlier byte-dependent observation of the target secret-seed file. For this interface, projection to the reservation-aware ML-DSA component is exact. A second exact adapter through the native RFC 6979 P-256 component gives an ordinary EUF-CMA instantiation for classical adversaries; its multiuser and single-user factors are stated. A generic signature construction gives transcript-preserving ordinary-EUF reductions while allowing complete key recovery when its own reserved randomizer is disclosed. This distinguishes the experiments and is not an attack on native ML-DSA.

The finite/source checker passes 24 self-contained checks and 44 including seven exact source files. Generation and encapsulation each have 34 reachable recovered states within the declared three-draw/two-epoch model; the two graphs have 486 call-boundary edges. All six deliberate source-tracking mutations produce counterexamples. The independent signature-alias matrix preserves proposer allocation under an issued-body response alias and responder allocation under an issued-body final alias. The exact presented wires still determine traffic information and later transcript links. No new native Rust, Tamarin or performance execution is claimed by this increment.

The related-work addition cites Damm et al.'s 2026 JoC result on leakage of internal ML-DSA masking coefficients. The actual retained field here is the external 32-byte `rnd`; FIPS 204 derives internal masks through a secret-key-dependent seed. These observation objects remain distinct.

## Reservation-to-ordinary ML-DSA connection

The native original-randomizer bridge is now established in the shared ROM/QROM. The reduction caches by the complete `(r,mu)` pair and records every private original-message invocation before publication. A private-random-function coupling preserves selected visible collisions; its birthday term counts hidden ordinary-challenger draws. A joint comparison of the hidden 34-byte key-generation input and 128-byte hedge slice returns to the original shared-XOF ordinary native signer. Its classical loss is `v / 2^256` per comparison and its quantum loss is `2v / 2^128`, each capped at one. The two complete experiments carry separate worst-case query budgets.

For `U` adaptively created owner families, a random target-family embedding allows other owners to be generated and disclosed locally. Exact aliases retain their family; public-key coincidences remain in the native distribution. The selected ordinary ML-DSA query ledger is contained in the native pair owner's ledger, which gives the fresh-message implication. The resulting bound instantiates the executed-source attribution term. The full proof, exact crate/source identities, finite controls and independent internal mathematical review are retained in [the signature-bridge artifact](../artifacts/signature-bridge/README.md).

This completes the preceding focused task of replacing the reservation-aware ML-DSA term by ordinary native hedged EUF with explicit losses in the declared shared-XOF model.

## Native selected-root authentication composition

The native event composition now connects the original eligible next-rekey execution to confirmation and first-message integrity under its selected recovered root. It preserves the original executed-slot attribution, online tuple/root/allocation marks, exact aliases and private honest-origin ledgers. The proof first partitions the event in the one native game, then applies candidate-local record, operational component, ContextBound, root-initialization and uniform-root authentication comparisons to the same recomputed Boolean predicate.

For the live core, the bound is `Pr[E AND Bad_auth] <= min(1, eta_attr + sum_j min(1, epsilon_rec,j + a_auth,j + delta_j + Omega_auth,j))`. The component advantage is the output-bit advantage of this event's actual adapter. `Omega_auth` collects the complete-tuple, initialization, schedule, confirmation-row, tag-guessing, framed-collision and one-key integrity costs. The explicit report/projection extension retains its original selected-candidate residual. The executed-slot attribution term uses the completed ordinary-signature connection above.

The complete manuscript proof and independent review are retained with 160 compatible Boolean assignment checks and explicit event/scope countermodels in [the native authentication artifact](../artifacts/native-authentication/README.md). This completes the previously identified authentication-event composition task for the declared marked controller.

## Focused continuation

The retained reference analysis now presents all seven schedules for five profiles, with 35 configuration/schedule pairs and all 420 snapshots. Four original corpus files match both the native evidence pin and integration checkpoint `358b921ab3469ce49f166633fc9a762ff6ed7e3d`. A deterministic source-bound analysis generates the manuscript table; a separate integer-arithmetic review confirms all 70 displayed numeric cells and rejects eight altered-input controls. These are a complete reanalysis of the existing executions, with their original native evidence identities.

The matched Continuity/SPQR/whole-KEM comparison has now completed its 49 native/reference executions and is integrated in Section 7.4. Every profile receives the same 2,048 directed opportunities, each with one offered 32-byte request; control, ACK and exact-retry frames consume that budget. Captures occur after opportunity 0 and before opportunity 1, with separately stated session/authority objects. The manuscript tables preserve committed and delivered service, post-capture denominators, exact reconstructed sets, emitted bytes and the native/reference persistence boundaries. Continuity budgets 32/64 produce 63/687 and 127/717 derived post-capture commitments while delivering 688/718 applications in the alternating runs. The one-way control remains at epoch zero, exposes all 31/31 or 63/63 post-capture commitments, and records the outstanding demand as uncommitted.

The completed experiment is fixed to research head `fec8472060728cc1bb35cf15042c117dda00e336`, synthetic checkout `0d12e77d0c7c1cfb4760b654947f2838bb05d4ee`, protocol source `358b921ab3469ce49f166633fc9a762ff6ed7e3d` and run 42537214047. The [matched artifact](../artifacts/matched-comparison/README.md) contains the exact executed report, original public-audit receipts, independent trace recount and deterministic table projection. Its fourteen input controls and the hardened launcher both pass.

The retry-scheduling experiment is complete. Run 42551086845 executed fourteen fresh immediate-policy reproductions and fourteen age-four cases under that same opportunity, identity and capture contract. Every immediate row reproduces the retained baseline. All twelve bidirectional or resumed cases deliver more applications; alternating deliveries rise from 688/718 to 971/999 while reconstructed counts remain 63/127. The complete service, emitted-byte and physical-persistence accounting is integrated in the [retry-readiness packet](../artifacts/retry-readiness/README.md), including the unchanged one-way admission boundary. The native authentication composition and ordinary ML-DSA bridge remain completed mathematical connections.

## Online finite-chain continuation

The joint recovered-root schedule now admits selection of a message at an online chosen index within one designated fresh traffic direction. The controller marks before the index's first private step computation across all aliases, including receive-side skipped-key computation and failed attempts. Earlier message keys can be disclosed and influence selection. Prefix seeds remain within the declared chain/opaque-persistence interface; after the marked step, its successor seed can be disclosed and the suffix proceeds through real chain computation.

The proof uses the original three joint-root/traffic comparisons and two comparisons per potentially protected prefix index. Each Extract/Expand pair is followed by an exact block-table rewrite that removes the next hidden seed's raw parent-row occurrence. The next reduction installs its challenge seed when the predecessor pair is allocated, at which point the predecessor's mark is already fixed. Fixed lifetime budgets cover every reached or unvisited branch, so the proof makes no retrospective guess of the selected index. The resulting corollary gives selected-key confidentiality and fresh selected-key inbox integrity.

The [chain-prefix packet](../artifacts/chain-prefix/README.md) retains the complete proof, source map, executed finite controls and review. Three source files have identical blobs at the manuscript's original source pin and integration checkpoint `6a0ac0bbd7a5be77443e10b22c20a31f4b3be271`. Exact finite controls enumerate 128 binary online marking policies and eight four-valued policies, and exercise retrospective marking, prefix-seed exposure, alias timing and private encryption origins.

## Native online-chain composition: completed

The native online selected-message theorem (`thm:native-online-message` in `native-chain-composition.tex`) completes that connection. Its controller preserves the root tuple's original selection point, designates the full fresh traffic entry and direction before allocation, and marks a message immediately before its first private step at either endpoint. The ledger includes receiver-side skipped-key computations and failed attempts. Exact retries preserve the earlier selection and the original private encryption tuple; the source inspection confirms that the sender persists its bound plan before reaching encryption.

The original eligibility predicate, accepted-send provenance, candidate-local record stops and executed source slots remain in the experiment. Earlier-key observations are individual outputs of pre-Mark continued steps; the marked successor seed supplies the real suffix. Acquiring a complete image remains a complete-version acquisition, including when that image contains an otherwise available successor seed. Thus the live-core projection residual remains zero under the stated observation interface.

For each candidate, the confidentiality continuation cost is `B_chain = min(1, 2 Phi_256 + 2 Delta_init + 2 Delta_prefix(L) + 2 epsilon_AEAD)`. Substitution gives `Adv_msg <= min(1/2, (eta_attr + sum_j (2 epsilon_rec,j + a_j^+ + a_j^- + 2 delta_j + B_chain,j))/2)`. The corresponding original eligible selected-message integrity event costs `eta_attr + sum_j min(1, epsilon_rec,j + a_j^msg + delta_j + Omega_chain,j)`, capped at one, with `Omega_chain = min(1, Phi_256 + Delta_init + Delta_prefix(L) + epsilon_INT)`. The executed-slot selector replaces each original-game attribution residual by its established signature-and-collision bound. There is no additional combinatorial message-index guess; every whole-execution budget includes the longer controller.

The [native online-chain packet](../artifacts/native-online-chain/README.md) retains the complete statement, source mapping, proof review and executable controls. The controls cover 19,440 traces with marking choices, 77,760 first-call decisions, 450 stop-time assignments, 256 signed/Boolean partition identities, receive-before-send event history and 18 source-order anchors. All six inspected native files match the original evidence pin and integration checkpoint `a4c089570c787522210d16226219c0cc8aa9b05e`. The 49 matched and 28 retry executions retain their exact prior packets.

The contribution and proof-dependency consolidation is complete. The computational roadmap now maps the exposure, record, contribution, continuation and attribution interfaces to their establishing results. Its accounting paragraph distinguishes signed-score comparisons from Boolean-event comparisons, keeps each terminal test's whole-execution budget, and recomputes eligibility and provenance in the current comparison world. The introduction retains the first-message scope of the original live-core result and the later online-chain extension. The discussion expresses the native signing bound through the assumed ordinary ML-DSA advantage with its explicit losses.

An independent semantic review binds the three revised modules and thirteen unchanged proof modules in `artifacts/editorial-review/proof-dependencies/`. A complete source comparison preserves all 107 formal environments and 95 display blocks in the 36 canonical modules. The 49 matched and 28 retry executions keep their original evidence identities. Final build and source-export receipts are indexed by `integration_record.json`.

The citation audit is also complete for the declared scope: all 28 keys resolve, the principal metadata of 27 external entries matches primary records, and the named core theorem/standard locators retain their correct full-version numbering. `artifacts/editorial-review/citations/` records the per-source coverage and access outcomes; no bibliography correction was required.

## Original-source bootstrap authentication: completed

The reply-source bootstrap section connects the original reply-key generation and response
encapsulation reservations to historical responder activation. It retains
actual restored-owner validation, full signed-wire descriptors, two-endpoint
capture accounting and online registration before the first private ACK use.
The first contribution and traditional material are available in the concrete
profile, and the initiator signing identity may be disclosed. Appendix D
supplies the joint short/long entry comparison for either surviving
contribution under the shared compression oracle.

The terminal theorem uses a one-sided acquisition, record and HMAC-row
comparison. Every serialized registered ACK-key version and containing object
is marked before the real-to-opaque record step; the row endpoint then supplies
the tag-guessing bound. The online experiment declares its bootstrap/ACK
operation surface once. The full source census, proof notes and separate
mathematical review are in [the bootstrap packet](../artifacts/bootstrap/README.md).

The complementary initial-source composition is integrated in
`bootstrap-initial-source.tex`. Its two-level localization applies the
original-source and complete joint-entry costs once before partitioning by the
later long-PRK rank; the heterogeneous family size multiplies the terminal tail.
`thm:bootstrap-initial-schedule` and `cor:bootstrap-initial-terminal` give the
schedule and historical-activation consequences. The full proof, 35 pinned
source files, 29 source assertions and 49,152 finite endpoint executions are
retained in `artifacts/bootstrap/initial/`. This manuscript integration is
complete. Current label locations are indexed by `integration_record.json`.

## Ordinary KEM connection and submission focus: completed

`kem-ordinary-bridge.tex` connects each actual two-stage ML-KEM component
advantage to ordinary IND-CCA security. The reduction withholds the ordinary
challenge until the original controller requests it, preserving genuine
prechallenge decapsulation except at a separately charged ciphertext hit.
The hit cost is `min(1, q_pre / 2^256 + delta_mr)`, where `delta_mr` is the
honest K-PKE message-recovery failure probability. It is distinct from the
existing KEM shared-key correctness term. Fixing the common static oracle
functions gives independence of the full real prefix from the unused
encapsulation message, including a quantum adversary's conditional state.
The common bad event costs one term per Boolean advantage. The complete proof
and independent internal mathematical review are in
[the KEM connection packet](../artifacts/kem-game-bridge/README.md).

The abstract and introduction now organize the contribution around original
sources, private-state simulation and native message security. Component
bridges and bootstrap/purpose-key instances explain how that construction is
used. Five primary references add the state/randomness-compromise and adaptive
composition context, with explicit per-source reading coverage in
[the positioning audit](../artifacts/editorial-review/submission-readiness/primary-sources.json).

All four bootstrap checkers are part of `make check`. The current PDF, abstract,
bibliography, visual review and independently compiled nine-file source export
are bound by `integration_record.json`. Historical artifact records retain
their original source and run identities. Engineering release admission
continues through current-source checks and platform artifacts on PR #121;
[the submission readiness note](SUBMISSION_READINESS.md) separately records the
completed editorial review, confirmed author declarations and final submission
approval.

## SkyBridge allocation

[skybridge-scope.md](skybridge-scope.md) reads the real SkyBridge original and later manuscripts. The JoC appendix now states their connection through authenticated transcript handling, operation admission and recovery release. SkyBridge's migration contract, forward-secrecy analysis, platform realization and migration experiments remain a coherent independent research line. The ContextBound substrate is from the earlier Q-Periapt binding manuscript and is identified separately.

## Validation identity

`integration_record.json` is the current local verification snapshot. It binds the PDF, single-file source, proof modules and source profile. The manuscript and exported source are compiled for each integrated update. New mathematical reviews and build checks have separate receipts; executable finite-model checks retain their exact execution identity. Historical native, formal-model and reference-corpus evidence keeps its recorded source and execution dates. Remote workflow outcomes are attached to the dedicated PR's actual head commit.

The manuscript uses one title and stable deliverable filenames. Git commits and artifact hashes identify its updates. [The layout decision](../format/layout_decision.md) records the official JoC instructions and an inspected single-column published example. Connected arguments organize the text; precise interface conditions remain in definitions and theorem hypotheses.
