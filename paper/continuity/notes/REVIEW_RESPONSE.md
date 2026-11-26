# Manuscript revision record

Date: 26 November 2026.

The revision starts from `947297e59be9d7fc8febb5d81a4e2b945e328208`.
Its 128-page reading copy has SHA-256
`bac15196e4b467a1804fcd7872c0a65f5142aed16638394cd02ab448f211e90e`.
The manuscript title and reading/source filenames remain stable.

## Definitions and proof interfaces

The historical-activation theorem now defines the verification budget as
distinct triples consisting of the registered complete class, the complete
authenticated ACK string and the proposed tag. Comparisons followed by a
floor rejection enter this budget. The proof charges the first keyed equality,
so different targets using the same proposed tag are accounted for separately.
The initial-source corollary inherits that definition. The displayed
probability bound is unchanged.

Appendix B.1 now states per-nonce confinement as an interface condition and
gives the native framing, point-probability argument, all-nonce separation
and fresh-sealing-order hybrid. The source correspondence identifies the
mapped image, intent, fence and checkpoint paths that supply this condition.
The original comparison bound, complete oracle budgets and separate
structural-equality collision term are retained.

The computational opening connects three existing results: exact exposure
under the declared record/derivation rules, sufficient recovery eligibility,
and real-record to opaque-table simulation. The existing selection table
locates the contribution, traffic-material and message-step choices. The
main-result interface also states the provisioned signer-owner observation
boundary, private application surface and complete-record acquisition rule.
The abstract specifies the previously designated traffic entry and direction.
The earlier continuation cross-reference now points to its computational
sections.

## Related work and reproducibility

The related-work section compares the original reservation/version/image
model with Lehmann and Tackmann's updatable encryption. The bibliography
identifies the EUROCRYPT 2018 publication and its revised full version.

Availability and Appendix A.2 give the complete immutable evidence
distribution at the starting commit above. Original experiment source pins
and receipts retain their identities. The exported source archive binds its
own inputs through `SHA256SUMS.json`; manuscript CI supplies the exact
checked revision in `source-commit.txt`.

The matched and retry experiments now have a seven-row schedule table
covering sender order, drops, reorder release, duplication, offline recovery
and terminal draining. Appendix A.13 locates `sender()` and `schedule()` in
`artifacts/matched-comparison/sources/schedule.py.txt` and gives the direct
command for its schedule manifest. The retained measurements and generators
are unchanged.

## Validation record

`integration_record.json` records the current reading-copy and source hashes,
local checks and visual inspection. The dedicated PR attaches remote results
to the submitted commit. Original native, Tamarin and benchmark executions
keep their own source and execution identities.
