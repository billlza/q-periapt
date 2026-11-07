# Manuscript development workflow

The continuous research branch is `paper/joc-persistent-recovery`; [draft PR #119](https://github.com/billlza/q-periapt/pull/119) targets `main`. Continue manuscript updates on this same branch and PR. Changes on this branch concern the manuscript, directly used research artifacts, and the manuscript build. Native source observations retain their immutable source revisions.

Maintain one manuscript title and stable reading/source filenames. The repository reading copy is `continuity.pdf`; external deliverables use `Q-Periapt_JoC_Manuscript.pdf` and `Q-Periapt_JoC_Research.zip`. Git commits and the artifact hash records identify changes. Keep the title, abstract and contribution narrative focused on the research results. Historical proof/evidence snapshots retain their original identities for traceability.

## Edit and review

1. Edit `main.tex` and the section modules; use `author-metadata.json` for the confirmed author identity. The displayed corresponding address is `2403871950@qq.com`; `bhmq03@durham.ac.uk` is the alternative contact.
2. State a research question, construction and exact experiment before adding a result. Preserve the actual source of each theorem and observation.
   Develop the narrative through definitions, established properties and their implications. State an interface condition at its definition or theorem, and explain its effect there. Use negative statements where they carry mathematical content, such as a counterexample or a genuine impossibility; consolidate repeated scope commentary into the relevant interface description.
3. Save a complete proof note and a separate review record when adding a mathematical result. Keep unresolved calculations in dated checkpoints rather than in the contribution list.
4. Run `make -B check`, `python3 artifacts/contextbound-connection/check_contextbound_adapter.py --output build/contextbound-check.json`, and `make source`. Inspect the rendered pages changed by the revision. The build checker records source/document consistency; the ContextBound checker records encoding and finite interface witnesses. Mathematical results retain their proof and review records.
5. Commit the modular and flattened sources, current PDF, supporting notes and current integration record to the same branch. The PR's manuscript workflow compiles the submitted head and uploads the PDF, single-file source and execution receipts.

The default branch's existing repository CI retains its own triggers and results. A completed manuscript build is evidence about this document. Each protocol, formal-model and benchmark result keeps its own version and recorded execution.

## Source identity

The current native model/evidence pin is `228c944fc476e3e57d6c08063cacb19bca5b360e`. The development checkout used for source inspection is `1c68aa666db22d36ee136be1ec712545a9e74f03`; each additional source audit checks the selected files against the declared pin. This paper branch does not implicitly change that pin.

The current author list contains Ziang Li (李子昂) only. Author additions are recorded when the author confirms them.
