# Exposure and Recovery with Persistent Randomness Reservations

JoC working manuscript, revised 7 November 2026: **62 pages**, a **235-word abstract**, seven keywords and 17 references.

**Author:** Ziang Li (李子昂), Department of Engineering, Durham University. **Correspondence:** 2403871950@qq.com. The alternative contact, bhmq03@durham.ac.uk, is retained in `author-metadata.json`.

PDF SHA-256: `7b976133ed0f2206d990a74241d03d1d678ff071f0b52df7e2ddeb9aca27fc18`.

## Read, edit and build

The reading copy is [continuity.pdf](continuity.pdf). Edit `main.tex` and the section modules. Run:

```sh
make -B check
make source
```

The build expands the modules into **`joc-submission.tex`**, compiles that source with pdfLaTeX/BibTeX/latexmk, and copies the result to `continuity.pdf`. `flatten_manifest.json` binds the generated source to its modules. The editable vector figure is in `figures/`.

`make check` verifies references, citations, overflow, author/contact metadata and source identities. `make source` produces `build/joc-source.zip` with the single-file entry and its dependencies. The exported package was also compiled in a clean directory; its extracted PDF text matches the reading copy.

To compile the already flattened source directly:

```sh
latexmk -pdf -interaction=nonstopmode -halt-on-error joc-submission.tex
```

The continuous paper branch is **`paper/joc-persistent-recovery`**, with [draft PR #119](https://github.com/billlza/q-periapt/pull/119) targeting `main`. [The update workflow](notes/WORKFLOW.md) describes the dedicated PR. Its manuscript CI compiles the actual PR head, runs the retained finite-record model and the ContextBound encoding/adapter checker, and uploads the PDF, source package and verification receipts. Repository-wide checks retain their existing triggers.

## Publisher format

The class is the unchanged official Springer Nature `sn-jnl.cls`, package v3.1 (December 2024). This is the selected publisher authoring template. JoC's numerical, alphabetically sorted bibliography uses explicit numeric natbib options and `joc-basic.bst`, a renamed derivative of `sn-basic.bst` retaining every author. The original style is included. Source and policy provenance is in `format/`.

The current build has no unresolved citations/references and no overfull boxes. All fonts are embedded. The underfull notices were reviewed in the rendered pages; no clipping or overlapping formulas was observed.

## Research structure and this increment

The paper develops original-reservation and acquisition semantics, exact guarded record exposure, private-image simulation, reverse-order dependent-report composition and candidate-local native accounting. Its multi-epoch symbolic theorem and separating native executions retain their original evidence.

The preceding revision established **Lemma 5.9, Theorem 5.10 and Corollary 5.11**, plus the shared-compression-oracle derivations in **Appendix C**. The joint continuation carries a uniform recovered root, or the separately justified uniform-contribution entry, through confirmation, traffic and the first selected message. It handles adaptive complete traffic information, shared-salt aliases, actual confirmation/ACK verification, and successor-root/next-seed disclosure. The exact target-allocation and application interfaces appear with the statements. These proof modules remain unchanged.

This revision adds **Lemma 5.12, Lemma 5.13 and Theorem 5.14**. The complete ten-field ContextBound encoding admits the hidden-component QROM comparison. The original-operation adapter supplies an explicit two-stage ML-KEM-768 challenge game while retaining native X25519 and its failures. A pinned-source induction shows that the selected complete tuple feeds one old-root/complete-info pair during the next rekey of an established authoritative session, including failed and ultimately unaccepted continuations. These results discharge the formerly explicit ContextBound term and connect the selected component to the established first-message continuation. Original-game residuals, component costs and the selected live interface remain explicit.

The [complete new proof, independent review and source/adapter checks](artifacts/contextbound-connection/README.md) are frozen with exact hashes. The two hash oracles and their complete preparation/continuation budgets remain separate; exact hash aliases use complete effective tuples rather than origin IDs.

The [frozen proof and 22-point cross-check](artifacts/joint-continuation/README.md) and [live source profile](artifacts/live-profile/source_profile.md) provide the intermediate research record. The preceding candidate-local theorem remains Proposition 5.8; its frozen proof and 12-point review are in `artifacts/candidate-local/`. The common-virtual accounting variant is now Appendix D.

[The research checkpoint](notes/RESEARCH_HANDOFF.md) records that the accepted-operation-to-contribution connection is complete for this profile and identifies the next extension: a finite multiple-root entry interface for broader target selection. [The SkyBridge scope note](notes/skybridge-scope.md) records which earlier mechanisms motivate this paper and which retain their independent research question.

## Evidence identity

Native source facts and retained protocol evidence remain pinned to `228c944fc476e3e57d6c08063cacb19bca5b360e`. The retained live profile checked 24 used files against `1c68aa666db22d36ee136be1ec712545a9e74f03`; all are byte-identical. Their manifest and exact function map are in `artifacts/live-profile/`.

This integration executed the manuscript/source builds and finite-model checks: **5,360 assignments**, **360 histories**, **2,160 history-prefix checks** and **17 independent expected cases**, including the retained mutation and invalid-input controls. It also executed **36** ContextBound format/adapter checks and an explicit **14-file, 12-assertion** source audit against both pinned revisions and the supplied native worktree. Existing native, Tamarin and reference-corpus receipts retain their own execution dates and revisions.

`integration_record.json` binds the current local results and hashes. Earlier integration records are archived in `artifacts/prior-integration/`. Current remote CI results are attached to the dedicated PR's actual head commit.

The author list and correspondence are confirmed. Applicable final declarations and human-author review accompany actual journal submission. This remains an editable research manuscript; no journal submission has been made.
