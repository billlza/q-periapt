# Journal-facing manuscript review - 11 November 2026

## Disposition

The title, abstract, introduction and closest-work comparisons support one
connected contribution: original-source exposure through acquired persistent
records, constructive simulation of the resulting observations, and native
message security after the next rekey. The current comparisons and contribution
statements are retained. The sole manuscript edit expands `KEM` to `key
encapsulation` in the abstract, implementing the journal's instruction to avoid
undefined abbreviations. The abstract has 234 words and seven keywords.

The baseline is canonical paper commit
`11e113f27d7708474cd55713d4a22cc028f80944`. `review.json` binds the reviewed
sources and records each abstract claim's supporting result. The accompanying
preservation receipt compares all 40 modular sources with that baseline. The
theorem, proof and displayed-mathematics contents are unchanged. The complete
document build, independent nine-file submission export and rendered-page
inspection have their own receipts in this directory.

This completes the planned journal-facing editorial pass. It records an
inspection of the author's submission materials, without asserting the
author's final approval to submit. The author-specific declarations listed
below remain concrete inputs to the eventual submission.

## Abstract and title

The title, **Exposure and Recovery with Persistent Randomness Reservations**,
names the analyzed observation boundary and recovery question. It makes no
comparative performance or optimality assertion. Its PDF metadata and running
title agree with the manuscript title.

| Abstract statement | Existing support | Disposition |
| --- | --- | --- |
| An operation can complete after compromise while using an exposed reservation. | `established-results.tex`, native reservation and delayed-receipt executions; Proposition `prop:counter-separation`; immutable execution sources in Appendix `app:artifacts`. | Retained: the executions exhibit the stated behavior. |
| Original sources and acquired encrypted records determine recovery eligibility. | Definitions `def:reservation-origin`, `def:record-acquisition`, `def:recovery-game`, and equation `eq:eligibility`. | Retained: the model tracks original events and subsequent key disclosures. |
| Alias normalization and guarded paths preserve origins and characterize readability. | Lemma `lem:alias-normalization`, Theorem `thm:guarded-normalization`, Corollary `cor:guarded-history`. | Retained: the characterization uses the declared record fragment. |
| Retained private records and causally dependent reports can be simulated from public operation outputs. | Theorem `thm:opaque-rendering` and Theorem `thm:report-reverse-composition`, with their common functional interface and observation rules. | Retained: the simulator explicitly handles retained identity, equality, exact retries and report order. |
| Candidate-local accounting preserves the adaptively selected native cut. | Lemmas `lem:adaptive-origin-stop` and `lem:native-local-score`; Proposition `prop:native-local-accounting`. | Retained: localization precedes candidate-specific comparisons in the original game. |
| The next rekey establishes confidentiality and integrity for an online selected, previously uncomputed message step after earlier-key disclosure. | The online controller and Theorem `thm:native-online-message` in `native-chain-composition.tex`; Corollary `cor:online-chain-message`. | Retained: the introduction states the established-session setting, original-source eligibility and allowed observations together. |
| Operational component interfaces connect to ordinary key-encapsulation and hedged-signature security. | Proposition `prop:kem-deferred-challenge`, Theorem `thm:native-mldsa-reservation-bridge`, and the component connection in `source-attribution.tex`. | Retained: the complete reductions retain their stated correctness, intersection and shared-oracle terms. |
| Joint key-entry comparisons retain confirmation and traffic in the stated quantum random-oracle models. | Theorem `thm:joint-message-leaf`, Proposition `prop:confirmation-message-auth`, and the complete-query primitive interfaces. | Retained: the abstract explicitly ties this claim to the stated models. |
| Complementary bootstrap instances protect either original contribution and historical transcript activation. | Theorems `thm:bootstrap-source-schedule`, `thm:bootstrap-terminal`, `thm:bootstrap-initial-schedule`; Corollary `cor:bootstrap-initial-terminal`. | Retained: each profile keeps its own origin, family and complete-transcript interface. |
| A mechanized symbolic theorem establishes multi-epoch secrecy. | Theorem `thm:symbolic`; the fixed Tamarin query, certificate and replay receipt in Appendix `app:artifacts`. | Retained as a symbolic conclusion, with its provenance condition. |
| Native executions cover pre-restart reservations, aggregate copies and delayed receipts. | The corresponding three constructions in `established-results.tex` and their immutable source/evidence map. | Retained: these are the recorded native observations. |
| Finite checks and 49 matched native/reference executions measure exposure with service and work. | Section `sec:guarded-checks`; Section `sec:matched-opportunities`; the hash-bound 49-row artifact and independently regenerated tables. | Retained: the statement describes the executed schedules and recorded metrics. |

The abstract introduces no undefined abbreviation after the edit. Its
cryptographic and symbolic conclusions remain separate, and the finite and
native executions retain their original evidential roles. The title and
abstract add no superiority claim that would require a new baseline.

## Closest-work distinctions

The following primary materials were inspected on 11 November 2026. The five
state/randomness/adaptive-compromise entries use their publisher abstracts for
the particular high-level statements in `related-work.tex`. The exact SCKA,
Triple Ratchet and Squirrel model locators were checked in the full author or
conference PDFs. The earlier bibliography audit and retained primary-source
audit continue to identify the other reference metadata and source locators.

| Primary source and inspected locator | Relationship to the manuscript |
| --- | --- |
| [Auerbach et al., USENIX Security 2025 PDF](https://www.usenix.org/system/files/usenixsecurity25-auerbach.pdf), Definition 3.2 and Theorem 3.3, printed p. 6724. | The source specifies direction, epoch and index-sensitive vulnerable-message sets, including future keys and pending messages. The manuscript attributes that result explicitly, then identifies original reservations and separately acquired durable representations as its analyzed objects. |
| [Dodis et al., Triple Ratchet author PDF](https://cs.nyu.edu/~dodis/ps/triple-ratchet.pdf), Remark 4.3, printed p. 22. | The source already identifies compromise of next-epoch material sampled during distribution. The manuscript's added distinction concerns each durable representation's acquisition and key history while preserving the original source. |
| [Jaeger and Stepanovs, CRYPTO 2018](https://link.springer.com/chapter/10.1007/978-3-319-96884-1_2), abstract. | Repeated fine-grained state compromise and key-updating encryption/signatures are attributed to their channel framework. The present record-acquisition and constructive-simulation questions are stated directly. |
| [Balli, Roesler and Vaudenay, ASIACRYPT 2020](https://link.springer.com/chapter/10.1007/978-3-030-64840-4_21), abstract. | The source jointly models local secrets and attacks on execution randomness, and identifies the key-updatable primitive required by its strong RKE notion. The manuscript gives that work credit before describing original-source readability. |
| [Collins, Colombo and Schaeffler, PKC 2025](https://link.springer.com/chapter/10.1007/978-3-031-91823-0_6), abstract. | Bounded leakage between sends, unidirectional RKE, and the distinct indistinguishability and one-way formulations match the comparison. |
| [Jaeger and Tyagi, CRYPTO 2020](https://link.springer.com/chapter/10.1007/978-3-030-56784-2_1), abstract; [Jaeger, EUROCRYPT 2023](https://link.springer.com/chapter/10.1007/978-3-031-30620-4_4), abstract. | The existing adaptive-compromise framework and shared-ideal-primitive composition are acknowledged. The manuscript identifies its explicit retained-image/report simulators and candidate-local provenance certificates. |
| [Signal Double Ratchet, revision 4](https://signal.org/docs/specifications/doubleratchet/), Section 8.5. | The source defers generation of a new ratchet key and sending chain. The manuscript explains how an earlier persistent reservation determines the relevant source lifetime. |
| [Herouard et al., Squirrel author PDF](https://adrienkoutsos.fr/papers/26-secrecy-ratchet.pdf), pp. 2-3 and Section 4.2. | The source treats two participants, unbounded ratchet steps, and a fixed non-adaptive compromise scenario; it distinguishes non-deduction from real-or-random secrecy. The manuscript retains those conclusion types and states its private-record simulation contribution separately. |

The checked distinctions describe specific state objects, interfaces and
constructions. None requires a claim that the preceding work lacks security
or that the current implementation has globally better performance. No
related-work edit is required by this pass.

## Journal presentation and declarations

The [JoC submission instructions](https://link.springer.com/journal/145/submission-guidelines),
checked on 11 November 2026, request a concise title, author affiliations and
corresponding email, an abstract of 150-250 words without undefined
abbreviations, and 5-10 keywords. The current presentation meets those items
after the abbreviation expansion. The existing numerical, alphabetically
ordered bibliography and sole-author metadata are retained.

The title page identifies **Ziang Li**, Department of Engineering, Durham
University, and **2403871950@qq.com**. These fields agree with the confirmed
`author-metadata.json`. No second author or unprovided ORCID has been added.

The data/code statement correctly directs readers to the immutable source and
execution identities in Appendix `app:artifacts`. The existing preparation
disclosure is retained. The linked [Springer journal policies](https://link.springer.com/brands/springer/journal-policies),
under *Disclosures and declarations*, *Author contributions* and *Competing
interests*, request funding, relevant interests, and author responsibility
information. The current task contains no author declaration of funding or
financial/non-financial interests. Those facts, and the author's final
contribution/responsibility wording, must be supplied before journal
submission; this review does not replace them with inferred statements. The
eventual declarations can then be assembled under the publisher's requested
heading. These are publication inputs, with no change to the established
research conclusions.

## Validation identity

`review.json` records the primary-source coverage and exact manuscript hashes.
`source-preservation.json` records the unchanged formal blocks and complete
label sequence. `build-check.json`, `source-export-check.json` and
`visual-review.json` identify the compiled manuscript, fresh source-export
build and inspected page images. The prior integrated-consistency record is
preserved under `artifacts/prior-integration/integrated-consistency.json`.

The independent local Rust inventory check at the same baseline also passed
all 48 tests in `test_codeql_rust_quality.py`, including the test that failed
on the older `bee17822` paper head. The canonical inventory is 174 sources:
106 current sources plus 68 pinned archive sources. This author pass leaves
that gate unchanged; hosted CI remains associated with its actual published
commit.
