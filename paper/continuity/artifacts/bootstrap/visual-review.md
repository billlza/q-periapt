# Focused manuscript PDF visual QA

**Result: passed.** No concrete layout defect was found in the reviewed pages. No paper edit is requested by this QA pass.

## Verified PDF

- SHA-256: `e575119c4858e2e37d2ea4cbe245565f4ea531428c55b969ad1b15ae691494b8`
- File size: 1,135,699 bytes.
- Length: 111 A4 pages.
- Source: `paper-work/paper/continuity/continuity.pdf`.
- Source hash checked before and after rendering; source file left unchanged.

## Visual coverage

All 33 pages in the following ranges were rendered with Poppler at 140 dpi and inspected individually through seven contact sheets. Pages 1, 72, 75, 76, 77, 78, 94, 108, 109 and 110 were additionally inspected at their full rendered page resolution.

| Pages | Reviewed material | Outcome |
| --- | --- | --- |
| 1-5 | Title, abstract, introduction, contribution narrative, related work | Clear typography, contained text, stable page breaks |
| 71-79 | New bootstrap section and following section transition | Equations (43)-(49), theorem/proof blocks and headings fit cleanly |
| 88-91 | Discussion, new bootstrap discussion, conclusion | Headings have accompanying text; paragraph continuations are orderly |
| 91-94 | References 1-29 | URLs and identifiers wrap without clipping or overlap |
| 94-102 | Source/evidence map and new A.17 bootstrap entry | Table continuation retains its column header; paths/hashes remain inside the text area |
| 108-111 | New joint-entry appendix and following accounting appendix | Equations (55)-(58), proofs and transitions are legible and contained |

The page-72 online experiment and page-108 joint-entry theorem continue naturally onto the following page. Appendix E begins on page 109 with its introductory paragraph; Proposition E.1 retains its statement and displayed bound on page 110, followed by its proof on page 111. The final page's remaining whitespace is ordinary end matter, not a missing-content or pagination symptom.

## Whole-document support checks

All 111 page footers match their PDF page numbers. No extracted `??` reference marker was found. Text bounding boxes stay away from the physical page edges, and the font inventory reports embedded fonts with Unicode maps throughout. These checks supplement the rendered-page review; they do not substitute for it.

The exact scope, font count, source identity and page inventory are recorded in `QA_RECEIPT.json`. Rendered pages are under `pages/`; `contact-01.png` through `contact-07.png` retain the inspected page groups. This is a rendering review of the identified PDF; the mathematical review receipts are maintained separately.
