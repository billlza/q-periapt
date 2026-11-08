# Exposure and Recovery with Persistent Randomness Reservations

Research manuscript for Journal of Cryptology.

**Author:** Ziang Li (李子昂), Department of Engineering, Durham University. **Correspondence:** 2403871950@qq.com. The alternative contact, bhmq03@durham.ac.uk, is retained in `author-metadata.json`.

The repository maintains one manuscript on **`paper/joc-persistent-recovery`**, through [draft PR #119](https://github.com/billlza/q-periapt/pull/119). The reading copy is [continuity.pdf](continuity.pdf). External copies use the stable filenames `Q-Periapt_JoC_Manuscript.pdf` and `Q-Periapt_JoC_Research.zip`; Git commits and artifact hashes identify the research history.

## Research structure

The paper models original randomness reservations and the acquisition of their persistent representations. Alias normalization preserves the original operations, and the guarded-path characterization identifies the combined effect of captured ciphertexts and disclosed keys. Native separating executions and the retained multi-epoch symbolic theorem give concrete recovery statements for that model.

The computational development constructs private-record and dependent-report simulations, connects them through candidate-local accounting, and carries a recovered contribution through root initialization, confirmation, traffic derivation and a selected first message. The complete ContextBound tuple comparison and original-operation adapter connect the actual ML-KEM component game to this continuation. The next-rekey source induction supplies one concrete native instance.

The live-core instantiation supplies the explicit native image/intent comparison cost and its complete admitted observation interface. The same joint key table also supports a confirmation and first-message authentication bound, with private origin ledgers, classical verification and quantum public-oracle queries. The general source-attribution residual remains explicit; its selector counterexample identifies the interface required for a stronger source-resolved result.

The multiple-root entry theorem extends the initialization interface to a finite family of available salts and complete information strings. Its exact descriptor table preserves HMAC pad-state aliases and supports an online fresh target in a previously used class. Other generated roots remain available to the controller, and every target alias retrieves one retained schedule handle. The complete-query bound and first-message consequence appear together in the finite multiple-root entry section.

The variable-length form now applies that comparison to the native SDK purpose-key interface. Complete information strings index the key table, while each returned owner keeps its own lifecycle. The source correspondence covers the fixed salt, exact field encoding, repeated derivation, export and close operations. The existing five-purpose dual-peer workload supplies a concrete finite instance; a separate application experiment gives the selected-key AEAD consequence.

The proofs and independent reviews are retained by subject:

- [Candidate-local accounting](artifacts/candidate-local/): the stopped source/record interface and original-game score accounting.
- [Joint continuation](artifacts/joint-continuation/README.md): the root-to-message schedule and its shared-compression primitives.
- [ContextBound connection](artifacts/contextbound-connection/README.md): complete encoding, component adapter and next-rekey source induction.
- [Live-core and authentication connection](artifacts/confirmation-traffic/README.md): explicit record cost, source selection, accepted confirmation cores and first-message integrity.
- [Multiple-root entry](artifacts/multiple-root-entry/README.md): finite class-row comparison, adaptive target embedding and complete budgets.
- [SDK purpose-key correspondence](artifacts/sdk-purpose-connection/README.md): variable-length entry comparison, exact native descriptors and separate owner states.

[RESEARCH_HANDOFF.md](notes/RESEARCH_HANDOFF.md) records the established connections and the next focused research question. [The SkyBridge scope note](notes/skybridge-scope.md) explains the earlier transcript, admission and recovery-release mechanisms; its migration and platform results remain their independent research line.

## Edit, build and review

Edit `main.tex` and the section modules. From the repository root, run:

```sh
make -B -C paper/continuity check PYTHON="sh $PWD/artifact/python-run.sh"
sh artifact/python-run.sh paper/continuity/artifacts/contextbound-connection/check_contextbound_adapter.py --output paper/continuity/build/contextbound-check.json
make -C paper/continuity source PYTHON="sh $PWD/artifact/python-run.sh"
```

The build expands the modules into **`joc-submission.tex`**, compiles that source and copies its PDF to `continuity.pdf`. `flatten_manifest.json` binds the generated source to its modules. `make check` verifies references, citations, overflow, author/contact metadata and source identities. `make source` produces `build/joc-source.zip` with the single-file entry and its dependencies. The exported package is also compiled in a clean directory and its extracted text compared with the reading copy.

The [update workflow](notes/WORKFLOW.md) maintains stable manuscript names, complete proof records and a connected academic narrative. The manuscript CI compiles the actual PR head, runs the retained finite-record and ContextBound checks, and uploads the PDF, source package and verification receipts.

CI and the repository commands above use the common isolated Python launcher. The Makefile supplies absolute script and output paths so that the launcher's repository-root working directory preserves the manuscript's build locations.

## Publisher format

The unchanged official Springer Nature `sn-jnl.cls` supplies the single-column authoring layout. The [current layout decision](format/layout_decision.md) records the journal-specific instructions and a visually inspected recent JoC publication. The numerical bibliography is ordered alphabetically by author surname and includes all authors, using the named derivative `joc-basic.bst`; the original publisher style and template provenance are retained in `format/`.

The current build statistics, PDF hash, visual review and independent source-export result are recorded in `integration_record.json`.

## Evidence identity

Native source facts and retained protocol evidence are pinned to `228c944fc476e3e57d6c08063cacb19bca5b360e`, with inspected development checkpoint `1c68aa666db22d36ee136be1ec712545a9e74f03`. The retained live profile compares 24 files. The ContextBound audit separately compares 14 files and checks 12 static assertions; all inspected files match the two stated revisions.

The finite-record model covers 5,360 assignments, 360 histories, 2,160 prefix checks and 17 independent expected cases, together with mutation and invalid-input controls. The ContextBound checker has 36 format and finite-adapter cases. Each receipt records its own execution and scope. New mathematical results have their complete proof and independent argument review; historical native, Tamarin and benchmark evidence retains its source and execution identity.

`integration_record.json` binds the current local document and research checks. Prior integration records are archived in `artifacts/prior-integration/`. Remote CI outcomes are attached to the dedicated PR's actual head commit.
