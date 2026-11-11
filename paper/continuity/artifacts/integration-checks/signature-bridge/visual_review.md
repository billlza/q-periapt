# Internal visual and reading review: signature bridge

**Result: passed; no manuscript change required.**

The reviewed PDF has **82 pages**, **244 abstract words**, and SHA256 `b60c5174235b537cbc5e7f4c0c7f21f48767a865b4a60709b553b5dc3e2d5a8e`. Its byte length is 991,554. The PDF remained unchanged throughout this review.

## Coverage

All seven contact sheets were visually inspected, covering pages **1–82**. Reading-scale inspection used fresh 150 dpi renders of pages **1, 3–6, 51–55, 65–69, and 75**: 16 pages in total. Pages 6 and 55 complete the related-work and theorem continuations beyond the originally requested ranges. Every listed reading render was opened and read; image hashes and contact-sheet coverage are in `visual_review.json`.

The full-document overview found no clipped page blocks, overlapping elements, unexpected blank pages, or broken page numbering. Reading-scale checks found the text and mathematical symbols clear within the text area.

## Findings

- **Title and abstract.** The single-author line, affiliation, correspondence and complete abstract display correctly. The new sentence connects original-randomizer disclosure to ordinary native ML-DSA unforgeability affirmatively.
- **Introduction and related work.** The new contribution resolves to Theorem 5.22. The discussion keeps external `rnd` distinct from the internal masking vector and acknowledges the nonce/hedging literature. It does not claim precedence over those results.
- **New mathematics.** Proposition 5.21, Theorem 5.22, equations (24)–(26), their tags, binomial expressions and ROM/QROM losses are legible. The family/actual-key and component-projection wording remains present. The proof and its continuation into the Proposition 5.18 signature term are complete across pages 51–55.
- **Discussion.** The ordinary hedged-signature term, exact-replay coupling and shared-XOF query loss agree with the new theorem. The contribution is integrated into the argument without a repeated catalogue of unproved claims.
- **Bibliography and authors.** All 28 entries were read at display scale. The five new references [1], [4], [5], [17] and [20] show their complete source author lists. Reference text contains no author-list “et al.” abbreviation. Diacritics, DOI strings and long URL wrapping remain readable and inside the page margins.
- **Artifact map.** Appendix A.11 identifies the new supplement and both exact source revisions, retains the applicable licensing correspondence, and distinguishes internal mathematical review from finite/source checks. Its long identifiers and the adjoining Appendix B mathematics fit correctly.

Text extraction corroborates **zero unresolved `??` markers** and **zero Unicode replacement characters**. It was used as an additional cross-reference/glyph check; layout conclusions came from the rendered pages.

## Rendering record

An initial PNG for page 51 was truncated as an intermediate render. A fresh JPEG was rendered directly from the same unchanged PDF, decoded successfully and visually inspected. The successful replacement is recorded in the reading-render manifest. The PDF and manuscript sources needed no change.

## Scope

This is an independent **internal integration, visual and editorial review** by the paper-research agent. All 82 pages received overview inspection, and the 16 specified pages received detailed reading-scale inspection. The separate frozen mathematical review remains the record for the proofs. Proof and source modules were not edited during this review.
