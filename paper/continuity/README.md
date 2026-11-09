# Exposure and Recovery with Persistent Randomness Reservations

Research manuscript for Journal of Cryptology.

**Author:** Ziang Li (李子昂), Department of Engineering, Durham University. **Correspondence:** 2403871950@qq.com. The alternative contact, bhmq03@durham.ac.uk, is retained in `author-metadata.json`.

The repository maintains one manuscript on **`paper/joc-persistent-recovery`**, through [manuscript PR #119](https://github.com/billlza/q-periapt/pull/119). The reading copy is [continuity.pdf](continuity.pdf). External copies use the stable filenames `Q-Periapt_JoC_Manuscript.pdf` and `Q-Periapt_JoC_Research.zip`; Git commits and artifact hashes identify the research history.

## Research structure

The paper models original randomness reservations and the acquisition of their persistent representations. Alias normalization preserves the original operations, and the guarded-path characterization identifies the combined effect of captured ciphertexts and disclosed keys. Native separating executions and the retained multi-epoch symbolic theorem give concrete recovery statements for that model.

The computational development constructs private-record and dependent-report simulations, connects them through candidate-local accounting, and carries a recovered contribution through root initialization, confirmation, traffic derivation and a selected first message. The complete ContextBound tuple comparison and original-operation adapter connect the actual ML-KEM component game to this continuation. The next-rekey source induction supplies one concrete native instance.

The live-core instantiation supplies the explicit native image/intent comparison cost and its complete admitted observation interface. The same joint key table also supports a confirmation and first-message authentication bound, with private origin ledgers, classical verification and quantum public-oracle queries. An executed-slot selector now registers original KEM sources before their first computations return. Its retained-plan induction and complete signed-transcript checks bound source-association failure by fresh-body signature and hash-collision events. The general metadata selector keeps its original residual and failed-reservation counterexample.

The native authentication composition carries the selected confirmation and first-message integrity event through the record, operational component, complete-tuple, root-initialization and joint-schedule comparisons. It localizes the joint event with original eligibility in the native game; each Boolean comparison contributes once. The same admitted online marking and exact-alias rules identify the recovered root and first-message allocation throughout.

The online finite-chain composition now connects a target selected after earlier message-key disclosures to the original native application experiment. Separate online marks identify the complete root tuple, fresh traffic direction and first private computation of the selected step. A monotone original-computation ledger includes skipped receive steps, failed authentication and exact retries across endpoint aliases. Complete record acquisitions retain their original eligibility and candidate-local stopping behavior. The resulting native confidentiality and selected-message integrity bounds use the existing executed-source attribution and ordinary-signature bridge, with the prefix comparison supplying the chain cost and no additional message-index guess.

The signing connection preserves original randomizers, exact replay and the declared signing-owner observation interface. It has an exact classical reduction through the native deterministic RFC 6979 P-256 component. The native ML-DSA bridge now connects original-randomizer opening to ordinary hedged unforgeability in the shared ROM/QROM. Its exact pair cache preserves visible collisions and replay, while a joint hidden-seed and hedge-slice comparison accounts for shared SHAKE256 use. Adaptive owner creation and non-target disclosure have an explicit single-user conversion. Source maps, finite controls and independent internal argument reviews accompany the proof.

The multiple-root entry theorem extends the initialization interface to a finite family of available salts and complete information strings. Its exact descriptor table preserves HMAC pad-state aliases and supports an online fresh target in a previously used class. Other generated roots remain available to the controller, and every target alias retrieves one retained schedule handle. The complete-query bound and first-message consequence appear together in the finite multiple-root entry section.

The variable-length form now applies that comparison to the native SDK purpose-key interface. Complete information strings index the key table, while each returned owner keeps its own lifecycle. The source correspondence covers the fixed salt, exact field encoding, repeated derivation, export and close operations. The existing five-purpose dual-peer workload supplies a concrete finite instance; a separate application experiment gives the selected-key AEAD consequence.

The reference evaluation now presents all seven retained communication schedules for pinned SPQR, its isolated 64-byte chunk variant and the three whole-KEM controls. Its deterministic analysis binds four original corpus files and checks 35 configuration/schedule pairs and 420 snapshots. The full table uses one common capture coordinate and places reconstructed message sets alongside component bytes per send. Independent integer-arithmetic recomputation and source-mutation controls accompany the analysis.

The matched comparison adds 49 newly executed native/reference profile--schedule pairs under 2,048 directed transmission opportunities. Its manuscript tables report post-capture derived sets together with first commitments, logical delivery, emitted bytes and native durability work. The report retains exact source/execution identities, complete 49-row JSON/CSV, a source-bound table generator and fourteen directed incorrect-report controls. A separate trace recount exposes the immediate-retry policy's measured communication cost. The one-way control records epoch-zero admission suspension and the resulting demand backlog.

A paired native scheduling experiment sets minimum application-retry age to four public sender turns. Its 28 executions include fourteen fresh reproductions of the retained immediate baseline and fourteen age-four runs. At fixed opportunity budgets, every bidirectional or resumed case delivers more applications; alternating deliveries rise to 971/999 while the reconstructed counts remain 63/127. Complete frame and persistence accounting records the schedule-dependent unit costs, the unchanged one-way service and the committed-but-undelivered requests at the observation boundary.

The proofs and independent reviews are retained by subject:

- [Candidate-local accounting](artifacts/candidate-local/): the stopped source/record interface and original-game score accounting.
- [Joint continuation](artifacts/joint-continuation/README.md): the root-to-message schedule and its shared-compression primitives.
- [Online finite-chain selection](artifacts/chain-prefix/README.md): adaptive target selection after earlier-key disclosure, with a complete prefix comparison and selected-key confidentiality/integrity corollaries.
- [Native online-chain composition](artifacts/native-online-chain/README.md): the original native experiment, exact first-computation controller, record-stop correspondence, source attribution and complete selected-message confidentiality/integrity bounds.
- [ContextBound connection](artifacts/contextbound-connection/README.md): complete encoding, component adapter and next-rekey source induction.
- [Live-core and authentication connection](artifacts/confirmation-traffic/README.md): explicit record cost, source selection, accepted confirmation cores and first-message integrity.
- [Executed-source attribution](artifacts/source-attribution/README.md): retained-plan source association, signature component adapters, original-randomizer observations and finite fault/alias checks.
- [Reservation-to-ordinary signature bridge](artifacts/signature-bridge/README.md): exact pair caching, native shared-XOF ROM/QROM reduction, adaptive owners and pinned source correspondence.
- [Native authentication composition](artifacts/native-authentication/README.md): the selected eligible native event, complete Boolean proof chain and independent accounting controls.
- [Multiple-root entry](artifacts/multiple-root-entry/README.md): finite class-row comparison, adaptive target embedding and complete budgets.
- [SDK purpose-key correspondence](artifacts/sdk-purpose-connection/README.md): variable-length entry comparison, exact native descriptors and separate owner states.
- [Matched directed opportunities](artifacts/matched-comparison/README.md): 49 native/reference executions, complete report projection, service/communication tables, independent trace recount and capture/accounting controls.
- [Retry readiness](artifacts/retry-readiness/README.md): 28 native executions, fourteen repeated-baseline/age-four pairs, public retry-age recount and regenerated service/cost table.
- [Complete reference schedule comparison](artifacts/reference-comparison/README.md): retained source corpora, all 420 snapshot cases, generated seven-schedule table and independent recomputation.

[RESEARCH_HANDOFF.md](notes/RESEARCH_HANDOFF.md) records the established connections and the remaining manuscript synthesis and final review. [The SkyBridge scope note](notes/skybridge-scope.md) explains the earlier transcript, admission and recovery-release mechanisms; its migration and platform results remain their independent research line.

## Edit, build and review

Edit `main.tex` and the section modules. From the repository root, run:

```sh
make -B -C paper/continuity check PYTHON="sh $PWD/artifact/python-run.sh"
sh artifact/python-run.sh paper/continuity/artifacts/chain-prefix/check_prefix.py
sh artifact/python-run.sh paper/continuity/artifacts/native-online-chain/check_native_chain.py
sh artifact/python-run.sh paper/continuity/artifacts/contextbound-connection/check_contextbound_adapter.py --output paper/continuity/build/contextbound-check.json
sh artifact/python-run.sh paper/continuity/artifacts/source-attribution/check_source_attribution.py --finite-only --output paper/continuity/build/source-attribution-finite.json
sh artifact/python-run.sh paper/continuity/artifacts/signature-bridge/check_bridge.py --crate-archive paper/continuity/artifacts/signature-bridge/sources/fips204-0.4.6.crate > paper/continuity/build/signature-bridge-check.json
sh artifact/python-run.sh paper/continuity/artifacts/signature-bridge/review_generic_controls.py > paper/continuity/build/signature-bridge-review.json
sh artifact/python-run.sh paper/continuity/artifacts/reference-comparison/analyze_reference.py --check
sh artifact/python-run.sh paper/continuity/artifacts/matched-comparison/analyze_matched.py --check
sh artifact/python-run.sh paper/continuity/artifacts/matched-comparison/check_input_controls.py
sh artifact/python-run.sh paper/continuity/artifacts/retry-readiness/analyze_retry.py --check
sh artifact/python-run.sh paper/continuity/artifacts/native-authentication/review_auth_bit_accounting.py
make -C paper/continuity source PYTHON="sh $PWD/artifact/python-run.sh"
```

The source-attribution finite checks run from the manuscript checkout alone.
The full source audit additionally reads the seven native files at checkpoint
`72acaaccde1ca9ea27e5af022da5fbce932ed4e9` from a separate checkout supplied with
`--repository`. The [artifact reproduction instructions](artifacts/source-attribution/README.md#reproduce-the-finite-and-source-checks)
provide the exact sparse checkout and full command. Manuscript CI uses that
pinned checkout and uploads both the check receipt and `native-source-commit.txt`.

The signature-bridge source packet is self-contained. Its checker authenticates
the original crate archive and the retained native/upstream source identities;
the independent finite controls exercise exact caching, shared-XOF distribution
and owner-ledger accounting. Manuscript CI runs both through the same isolated
launcher and uploads their separate receipts. The supplement also retains
normal/optimized Python comparisons and source-tampering controls.

The build expands the modules into **`joc-submission.tex`**, compiles that source and copies its PDF to `continuity.pdf`. `flatten_manifest.json` binds the generated source to its modules. `make check` verifies references, citations, overflow, author/contact metadata and source identities. `make source` produces `build/joc-source.zip` with the single-file entry and its dependencies. The exported package is also compiled in a clean directory and its extracted text compared with the reading copy.

The [update workflow](notes/WORKFLOW.md) maintains stable manuscript names, complete proof records and a connected academic narrative. The manuscript CI compiles the actual PR head, runs the retained finite-record and ContextBound checks, and uploads the PDF, source package and verification receipts.

CI and the repository commands above use the common isolated Python launcher. The Makefile supplies absolute script and output paths so that the launcher's repository-root working directory preserves the manuscript's build locations.

## Publisher format

The unchanged official Springer Nature `sn-jnl.cls` supplies the single-column authoring layout. The [current layout decision](format/layout_decision.md) records the journal-specific instructions and a visually inspected recent JoC publication. The numerical bibliography is ordered alphabetically by author surname and includes all authors, using the named derivative `joc-basic.bst`; the original publisher style and template provenance are retained in `format/`.

The current build statistics, PDF hash, visual review and independent source-export result are recorded in `integration_record.json`.

## Evidence identity

Native source facts and retained protocol evidence are pinned to `228c944fc476e3e57d6c08063cacb19bca5b360e`, with inspected development checkpoint `1c68aa666db22d36ee136be1ec712545a9e74f03`. The retained live profile compares 24 files. The ContextBound audit separately compares 14 files and checks 12 static assertions; all inspected files match the two stated revisions.

The finite-record model covers 5,360 assignments, 360 histories, 2,160 prefix checks and 17 independent expected cases, together with mutation and invalid-input controls. The ContextBound checker has 36 format and finite-adapter cases. Each receipt records its own execution and scope. New mathematical results have their complete proof and independent argument review; historical native, Tamarin and benchmark evidence retains its source and execution identity.

The source-attribution supplement passes 24 self-contained checks and 44 checks including seven exact native-source identities. Its two fault models each explore 34 reachable recovered states, and all six deliberate source-tracking mutations yield counterexamples. These checks validate the finite model and recorded source interfaces; they execute neither Rust nor a formal verifier.

`integration_record.json` binds the current local document and research checks. Prior integration records are archived in `artifacts/prior-integration/`. Remote CI outcomes are attached to the dedicated PR's actual head commit.
