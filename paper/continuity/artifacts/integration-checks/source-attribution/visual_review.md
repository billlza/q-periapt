# Independent PDF visual review: executed-source attribution

**Result: pass.** The inspected PDF has 77 A4 pages. All seven supplied contact sheets were visually inspected, covering pages 1–77, and nine pages were separately rendered at 160 dpi and read at full-page scale. No clipping, text or equation overlap, table overflow, missing glyphs, or damaged page numbering was observed within that coverage. No layout correction is requested by this review.

## Reviewed document identity

| Field | Observed value |
| --- | --- |
| PDF | `paper/continuity/continuity.pdf` |
| Title | Exposure and Recovery with Persistent Randomness Reservations |
| Author metadata | Ziang Li |
| Pages | 77 |
| Page size | A4, 595.276 × 841.89 pt |
| File size | 968,427 bytes |
| SHA-256 | `a3c86055403dcf5e7cbb3c7152c643523bd50b858e0a5511b3447145fe038959` |

The PDF hash was checked before rendering and again when this record was saved. The reviewer performed read-only inspection of the manuscript and produced only review records and page renders.

## Whole-document contact-sheet inspection

The supplied `build/visual-review/contact-1.jpg` through `contact-7.jpg` cover pages 1–12, 13–24, 25–36, 37–48, 49–60, 61–72, and 73–77 respectively. The page grids were inspected in full. Body blocks and footer positions are consistent; tables and displayed mathematics remain inside the page area. No unexpected blank document page or obvious displaced object was seen. The unused cells in the final contact sheet are outside the five displayed document pages.

This pass establishes an overview of all page layouts. Detailed text and glyph inspection was performed on the pages listed below; it is not represented as full-resolution proofreading of every page.

## Detailed page observations

| PDF page | Content inspected | Observed result |
| --- | --- | --- |
| 47 | End of confirmation proof; Section 5.9 heading and source-controller introduction | Heading has following body text; the introduction is readable and continues naturally onto page 48. Proof end symbol and footer are separated from the text. |
| 48 | Lemma 5.17, its proof, signed-message display, all-purpose ledger, Proposition 5.18 and Eq. (23) | Lemma and proposition labels, subscripts/superscripts, implication and attribution bound are intact. Equation (23) and its number fit within the text block without interference. |
| 49 | Source-association proof; signing-coin interface and owner-file observation boundary | Paragraphs, inline mathematical symbols and proof end symbol are legible. The owner-interface paragraph continues normally onto page 50. |
| 50 | Indexed-user accounting, RFC6979 reference, Proposition 5.19 and proof, Proposition 5.20 | Both component bounds and the single-user `U` factor render clearly. Citations [18], [20], and [22] are resolved visually. The separation construction and complete proposition statement fit before the page break. |
| 51 | Separation proof; attribution substitution paragraph; transition to Section 5.10 | The proof resumes in the expected place. References to Eq. (23), Corollary 5.15, Proposition 5.19, and Appendix A.10 are readable. The following section heading and displays have normal spacing. |
| 64 | Bibliography entries [8]–[15] | Hanging labels align; long titles, DOI strings and URLs wrap within the available width. Accented names and mathematical/cryptographic titles render without missing-glyph boxes. |
| 65 | Bibliography entries [16]–[23]; transition to Appendix A | The FIPS 204, RFC6979 and RustCrypto implementation entries are readable. Long URLs and the fixed repository checkpoint wrap inside the block. Appendix A begins with a complete heading and readable introductory paragraph. |
| 66 | Source/evidence map table, certificate hash, beginning of Appendix A.1 | Table columns and row text remain separated. Wrapped source paths stay in their cells. The full SHA-256 display fits; it does not overlap the surrounding prose. |
| 70 | Appendix A.9; new Appendix A.10; transition to Appendix B | The new appendix heading, artifact path, inline native revision and validation description are readable. The long commit identity fits on its line; source-path wrapping remains within the text area. No residual overfull footnote or clipped URL appears. |

Normal paragraph and proof continuations at pages 47/48, 49/50, and 50/51 preserve the reading sequence. They do not leave a standalone section heading without its opening text or truncate a displayed result.

## Rendering and evidence

The selected pages were rendered directly from the PDF using:

```sh
pdftoppm -f 47 -l 51 -r 160 -png paper/continuity/continuity.pdf paper/continuity/build/visual-review/reviewer-source
pdftoppm -f 64 -l 66 -r 160 -png paper/continuity/continuity.pdf paper/continuity/build/visual-review/reviewer-bibliography
pdftoppm -f 70 -l 70 -r 160 -png paper/continuity/continuity.pdf paper/continuity/build/visual-review/reviewer-appendix
```

The accompanying `visual_review.json` records the PDF identity, page coverage, per-page findings, renderer version, and hashes and dimensions of every inspected contact sheet and full-page render. This visual review is separate from the retained mathematical review and the root agent's build, reference, abstract-length, and first-page checks.
