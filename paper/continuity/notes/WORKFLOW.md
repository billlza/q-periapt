# Manuscript development workflow

The continuous research branch is `paper/joc-persistent-recovery`; its pull request targets `main`. Changes on this branch concern the manuscript, directly used research artifacts, and the manuscript build. Native source observations retain their immutable source revisions.

## Edit and review

1. Edit `main.tex` and the section modules; use `author-metadata.json` for the confirmed author identity. The displayed corresponding address is `2403871950@qq.com`; `bhmq03@durham.ac.uk` is the alternative contact.
2. State a research question, construction and exact experiment before adding a result. Preserve the actual source of each theorem and observation.
3. Save a complete proof note and a separate review record when adding a mathematical result. Keep unresolved calculations in dated checkpoints rather than in the contribution list.
4. Run `make -B check` and `make source`. Inspect the rendered pages changed by the revision. The checker records build/source consistency, not mathematical validity.
5. Commit the modular and flattened sources, current PDF, supporting notes and current integration record to the same branch. The PR's manuscript workflow compiles the submitted head and uploads the PDF, single-file source and execution receipts.

The default branch's existing repository CI retains its own triggers and results. A completed manuscript build is evidence about this document. Each protocol, formal-model and benchmark result keeps its own version and recorded execution.

## Source identity

The current native model/evidence pin is `228c944fc476e3e57d6c08063cacb19bca5b360e`. The development checkout used for source inspection is `1c68aa666db22d36ee136be1ec712545a9e74f03`; each additional source audit checks the selected files against the declared pin. This paper branch does not implicitly change that pin.

The current author list contains Ziang Li (李子昂) only. Author additions are recorded when the author confirms them.
