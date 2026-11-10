# Continuity manuscript citation audit — 2026-11-09

## Result

The bibliography and the checked core theorem locators require no correction. The current manuscript can proceed without a bibliography edit.

The inspected file is `paper/continuity/references.bib`, SHA-256 `cf692417f60a293777dc23c59e10310b380149f81b0cb70bd6153806cbe83ce5`. It contains 28 unique entries. A scan of the continuity TeX sources found that all 28 entries are cited, with no duplicate bibliography keys or unresolved citation keys.

The audit checked the identities and principal publication metadata of the 27 external entries against publishers, official conference programs, standards publishers, author or institutional publication pages, and author-submitted ePrint records. The remaining entry is the project's own fixed-checkpoint research artifact. The seven rows in the next section are the substantive source locators checked; the other ledger entries are metadata checks. Exact title capitalization and typographic dash conventions were treated as formatting choices when they preserved the published title.

## Core source locators

| Manuscript reference | Primary-source check | Result |
|---|---|---|
| Don–Fehr–Huang, Theorem 2 | The author manuscript at [arXiv:2206.08132](https://arxiv.org/pdf/2206.08132), pp. 9–10, is the adaptive hidden-input result used by the primitive proof. The publisher confirms TCC 2022, Part I, LNCS 13747, pp. 33–51, and DOI `10.1007/978-3-031-22318-1_2`. | Correct source and metadata. Theorem conditions were also checked in the accompanying bootstrap review. |
| Hosoyamada–Iwata, Proposition 4 | The [full version, ePrint 2021/774](https://eprint.iacr.org/2021/774.pdf), gives the construction `F1(u,v) = h(v,f(u))`, a `max{Q,q_h}` query parameter, and the square-root cubic asymptotic bound in its stated regime. | The manuscript's proposition number and stated asymptotic form match the full version. |
| Hosoyamada–Iwata, Proposition 6 | The same full version, printed p. 25, gives the NMAC square-root bound with numerator `(q_h + Q)^3 * ell^5`, with injective length-dependent padding. | The manuscript's proposition number and stated NMAC asymptotic form match. |
| HMAC swap-PRF source | The [CRYPTO 2023 publisher record](https://link.springer.com/chapter/10.1007/978-3-031-38548-3_22) and [ePrint 2023/861](https://eprint.iacr.org/2023/861) agree on authors and the feasibility characterization. | Correct identity and characterization. |
| Triple Ratchet, Remark 4.3 | The [cited author PDF](https://cs.nyu.edu/~dodis/ps/triple-ratchet.pdf), printed p. 22, discusses key material sampled for the next epoch while distribution is still in progress. | The cited remark supports the manuscript's comparison. |
| Double Ratchet specification, §8.5 | [Revision 4, 2025-11-04](https://signal.org/docs/specifications/doubleratchet/), retains §8.5 on deferring generation of a new ratchet key and sending chain until sending. | Correct section, authors, and revision date. |
| FIPS 204, Algorithm 7 | The [final standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf), printed p. 25, takes a 32-byte `rnd`, derives the message representative, and then computes the private seed from `K || rnd || mu`; `ExpandMask` derives the masking vector from that seed and a counter. | The citation supports the distinction between the external randomizer and internal masking vector. |

The Hosoyamada–Iwata publisher chapter preview refers to its F1 result as Proposition 1, whereas the full version calls it Proposition 4. The existing bibliography already identifies and links the full version. Accordingly, the current Proposition 4 and Proposition 6 citations match the full-version source used by the manuscript.

## Current 2026 metadata

| Entry | Verified metadata |
|---|---|
| `doubleratchet2026` | The [authors' Oxford publication record](https://mrg.cs.ox.ac.uk/publications/automated-formal-analysis-of-signals-double-ratchet-attacks-fixes-and-security-proofs/) gives Cheval, Jacomme, and Richards; IEEE S&P 2026; pp. 1522–1538; DOI `10.1109/SP63933.2026.00120`. |
| `spqr2026` | The [official CCS 2026 schedule](https://www.sigsac.org/ccs/CCS2026/program/schedule.html) lists the exact title and five authors in the manuscript's order. The listed presentation date is November 16, 2026. The existing forthcoming-publication note is appropriate on the audit date. |
| `squirrel2026` | The same official schedule and [author-submitted ePrint 2026/1912](https://eprint.iacr.org/2026/1912) agree on the title and four authors. The existing forthcoming-publication note and ePrint number are correct. The audit confirms this entry's publication identity and metadata. |
| `damm2026` | The [publisher article](https://link.springer.com/article/10.1007/s00145-026-09584-7), [issue 39(4)](https://link.springer.com/journal/145/volumes-and-issues/39-4), and [45-page publisher PDF](https://ir.cwi.nl/pub/36609/36609.pdf) confirm all five authors, the title, 2026, article 28, and the DOI. The article-relative range `28:1–28:45` is consistent with the PDF. |
| `rustcryptoEcdsa017` | The [RustCrypto package changelog served by docs.rs](https://docs.rs/crate/ecdsa/latest/source/CHANGELOG.md), observed as version 0.17.0, dates that release to July 2, 2026. The bibliography's 2026 year is correct and its source link is explicitly version-pinned. |

The SPQR implementation account remains separately identified as Bhargavan's October 2, 2025 [Cryspen article](https://cryspen.com/post/signal-spqr-verification/). Its description of ProVerif models and hax/F* checks for panic freedom and selected correctness goals matches the attribution in the manuscript.

## Complete external-entry ledger

| Key | Primary metadata source | Check |
|---|---|---|
| `signal2020` | [Author publication page](https://www.douglas.stebila.ca/research/papers/JC-CCDGS20/) and its publisher DOI link | Authors, title, journal, year, volume, page range, DOI identity agree. |
| `robustchannels2024` | [Publisher](https://link.springer.com/article/10.1007/s00145-023-09489-9) | Authors, title, 2024, volume 37, article 9, DOI agree. |
| `scka2025` | [USENIX](https://www.usenix.org/conference/usenixsecurity25/presentation/auerbach) | Author list, title, proceedings, August 2025, pp. 6717–6736 agree. |
| `sessionhandling2023` | [USENIX](https://www.usenix.org/conference/usenixsecurity23/presentation/cremers-session-handling) | Authors, title, proceedings, 2023, pp. 1235–1252 agree. |
| `stateloss2025` | [Author publication list](https://people.cispa.io/cas.cremers/publications/index.html), [CISPA record](https://cispa.de/en/research/publications/84384-impossibility-results-for-post-compromise-security-in-real-world-communication-systems), and [ePrint](https://eprint.iacr.org/2024/1886) | Author order, title, and S&P 2025 publication agree. The ePrint's 2024 identifier is its preprint identifier, not an error in the conference year. |
| `tripleratchet2025` | [Publisher](https://link.springer.com/chapter/10.1007/978-3-031-91101-9_11) | Authors, title, 2025, LNCS 15608, pp. 302–331, DOI agree. |
| `doubleratchet2025` | [Signal specification](https://signal.org/docs/specifications/doubleratchet/) | Authors, title, revision 4 and date agree. |
| `doubleratchet2026` | [Author institutional record](https://mrg.cs.ox.ac.uk/publications/automated-formal-analysis-of-signals-double-ratchet-attacks-fixes-and-security-proofs/) | Authors, title, year, pages, DOI agree. |
| `spqr2026` | [Official program](https://www.sigsac.org/ccs/CCS2026/program/schedule.html) | Title, authors, venue, forthcoming status agree. |
| `spqrverification2025` | [Cryspen](https://cryspen.com/post/signal-spqr-verification/) | Author, title, date agree. |
| `squirrel2026` | [ePrint](https://eprint.iacr.org/2026/1912) and official CCS program | Authors, title, year, venue, ePrint identity agree. |
| `hmacswap2023` | [Publisher](https://link.springer.com/chapter/10.1007/978-3-031-38548-3_22) | Authors, title, year, LNCS 14083, pp. 661–693, DOI agree. |
| `rfc5869` | [RFC Editor](https://www.rfc-editor.org/rfc/rfc5869.html) | Authors, title, RFC number, May 2010 agree. |
| `rfc2104` | [RFC Editor](https://www.rfc-editor.org/rfc/rfc2104) | Authors, title, RFC number, February 1997 agree. |
| `gojournal2021` | [USENIX](https://www.usenix.org/conference/osdi21/presentation/chajed) | Authors, title, venue, July 2021, pages and ISBN agree. |
| `dfh2022` | [Publisher chapter](https://link.springer.com/chapter/10.1007/978-3-031-22318-1_2) and [proceedings](https://link.springer.com/book/10.1007/978-3-031-22318-1) | Authors, title, editors, year, part, volume, pages and DOI agree. |
| `hmacqrom2021` | [Publisher](https://link.springer.com/chapter/10.1007/978-3-030-84242-0_21) and [full version](https://eprint.iacr.org/2021/774) | Authors, title, editors, year, volume, pages, DOI and full-version identity agree. |
| `zhandryCollision2015` | [Publisher DOI record](https://www.rintonpress.com/journals/doi/QIC15.7-8-2.html) | Author, title, 2015, volume 15, issue 7–8, pages and DOI agree. |
| `rfc6979` | [RFC Editor](https://www.rfc-editor.org/rfc/rfc6979.html) | Author, title, RFC number and August 2013 agree. |
| `fips204` | [NIST](https://csrc.nist.gov/pubs/fips/204/final) | Corporate author, title, final publication date August 13, 2024, publication number and DOI agree. |
| `rustcryptoEcdsa017` | [Package release record](https://docs.rs/crate/ecdsa/latest) and changelog | Version 0.17.0 and 2026 release year agree. |
| `damm2026` | Publisher article, issue and PDF listed above | Authors, title, 39(4), article 28, 45 pages, year and DOI agree. |
| `bennett1997strengths` | [SIAM](https://epubs.siam.org/doi/10.1137/S0097539796300933) | Authors, title, volume 26, issue 5, pp. 1510–1523, 1997 and DOI agree. |
| `bellare2016nonce` | [Author ePrint record](https://eprint.iacr.org/2016/290) | Authors, title, year, report number and EUROCRYPT 2016 association agree. |
| `aranha2020hedged` | [Publisher](https://link.springer.com/chapter/10.1007/978-3-030-45721-1_23) | Authors, title, EUROCRYPT 2020 and DOI agree. |
| `grilo2021reprogramming` | [Publisher](https://link.springer.com/chapter/10.1007/978-3-030-92062-3_22) | Authors, title, ASIACRYPT 2021 and DOI agree. |
| `kosuge2025mldsa` | [Publisher](https://link.springer.com/chapter/10.1007/978-981-95-5096-8_20) and [ePrint](https://eprint.iacr.org/2025/904) | Authors, title, ASIACRYPT 2025, DOI and ePrint identity agree. |

The publisher records also supply optional volume/page fields for the final three conference entries: Aranha et al., LNCS 12105, pp. 644–674; Grilo et al., LNCS 13090, pp. 637–667; Kosuge and Xagawa, LNCS 16246, pp. 641–674. These fields enrich already identifiable references and are not corrections. No enrichment patch was prepared.

## Disposition

No active manuscript file was edited. No additional experiment or baseline is introduced by this audit. `audit.json` binds the inspected bibliography, the key-resolution result, the cited source URLs and retrieval reference identifiers, and this review text.

## Retrieval record and coverage

The following access outcomes are retained so that metadata verification can be distinguished from full-text inspection:

- Direct retrieval of the Squirrel full PDF at `https://eprint.iacr.org/2026/1912.pdf` failed. Its ePrint metadata page and the official conference program were retrieved. This audit verifies that entry's identity and publication metadata; it does not newly assess the manuscript's account of that paper's compromise model.
- Direct retrieval of the pinned docs.rs crate page failed. Primary docs.rs indexed release and changelog records both identified version 0.17.0 and July 2, 2026. The pinned `signing.rs` source was not re-inspected in this metadata audit.
- Initial direct retrievals of ePrint 2021/774's PDF and the Auerbach and GoJournal USENIX pages returned access errors. The HMAC PDF was subsequently retrieved through its primary search result, including the full Proposition 6 statement. The USENIX primary search results supplied their official BibTeX records.
- Subsequent subsection access to the DFH Springer chapter failed; its initial chapter record and the publisher's TCC proceedings record supplied the cited metadata. The DFH Theorem 2 check carries forward the exact author-PDF inspection performed in the bootstrap proof review in this work session.
- DOI resolver access for the Signal 2020 article and the Zhandry 2015 article failed. The Signal author's page exposed the exact publisher DOI as its link target; the Rinton Press DOI record independently supplied Zhandry's DOI and complete journal metadata.
- The initial RFC URLs without the `www` host failed. The canonical RFC Editor source pages were subsequently retrieved.
- The internal `qperiaptSymbolic2026` entry retained its existing fixed repository checkpoint. Its citation-key resolution was checked; the November 4 replay was not rerun as part of this bibliography task.

Every statement marked as checked in the ledger is tied to the observed primary record listed in that row. This audit makes no whole-paper semantic coverage claim.
