# Independent review of confirmed author declarations

## Conclusion

The declaration update faithfully records the author's confirmations of 11 November 2026: this research received no funding, there are no relevant financial or non-financial competing interests, and Ziang Li completed the current research and manuscript work. The sole author, affiliation and both recorded email addresses remain unchanged. Possible future reviews by others have not been converted into authorship or acknowledgements. Final submission approval remains pending review of the assembled submission.

The comparison uses the exact canonical baseline `87fee58926f8b849a142018efb6d7502cbad673f`, paper subtree `dae7ffda4ed5431a69b17167e1aad4268d64192a`. Among the 40 canonical TeX modules, 39 remain byte-identical. The complete change to `declarations.tex` is accounted for by the three confirmed declaration paragraphs, the Declarations/subsection headings and confirmation comments.

## Exact preservation results

| Content | Baseline | Current | Byte-identical | Changed |
| --- | ---: | ---: | ---: | ---: |
| Canonical TeX modules | 40 | 40 | 39 | 1 |
| Formal statement/definition/remark blocks | 57 | 57 | 57 | 0 |
| Proof blocks | 52 | 52 | 52 | 0 |
| Displayed mathematical environments | 60 | 60 | 60 | 0 |
| Bracket-delimited displays | 108 | 108 | 108 | 0 |
| Total displayed mathematical groups | 168 | 168 | 168 | 0 |

Every canonical module's label sequence is unchanged. The existing Data and code availability and AI-assisted preparation paragraph bodies are byte-identical, including their original line breaks. Their headings now appear as subsections within Declarations.

## Declaration fidelity and author identity

The funding paragraph states “This research received no funding.” This matches the author's confirmation without adding an external-funding qualifier. The interests paragraph declares no financial or non-financial competing interests relevant to this work. The contribution paragraph assigns the current conception, models and proofs, implementation, experiments, analysis and manuscript preparation/revision to Ziang Li, as confirmed by the author. The retained preparation disclosure continues to describe the recorded assistance.

All original fields of `author-metadata.json` are semantically unchanged. The sole addition is declaration metadata, which agrees with the three paragraphs and explicitly records `final_submission_approval` as `pending review of the assembled submission`. The complete `main.tex`, including its author and affiliation definitions, is byte-identical to baseline.

## Source identities and method

- Baseline `declarations.tex` SHA-256: `6cffd05abd8352442c9dc5349bc5fd9a3a49eb85d3d295955ce3ded022c80771`.
- Current `declarations.tex` SHA-256: `f5bd2d2e1433dd8ae1fc19ce8a871eb9a663518a54b70d62cdc994cab4fbaf2a`.
- Baseline `author-metadata.json` SHA-256: `a4654fb096735dd2277cf4251ad37866fe00b3a8333a5e6731155308ad495ec8`.
- Current `author-metadata.json` SHA-256: `f8804e0627b9509830905091b2a5aa27f2b7de1fb4c65563e93c2765bf8c4d87`.

`source-preservation.json` records every canonical module's baseline/current byte lengths and SHA-256 digests, exact formal-block counts, ordered block-hash digests, label-sequence equality and the two preserved disclosure-body hashes. The comparison read the fixed baseline through Git and compared current file bytes directly. It uses the same formal/proof/display-environment categories as the preceding journal-facing preservation record. A final reread confirmed that the reviewed canonical files and author metadata had not changed during comparison.

This review covers source and declaration fidelity. The generated `joc-submission.tex` is excluded from modular counts to avoid duplication. Build/export verification is recorded separately; this review executed no manuscript build or mathematical experiment.
