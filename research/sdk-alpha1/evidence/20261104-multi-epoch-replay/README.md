# Independent joint replay of multi-epoch secrecy

The current repository entry point independently replayed the retained certificate
on 2026-11-04 using Tamarin 1.12.0 and Maude 3.5.1 on Apple Silicon macOS.
`multi_epoch_fresh_reservations_recover_symbolic_message_secrecy` and all 24
reusable dependencies passed together. The replay took 816.903 seconds with the
unchanged 900-second process limit, 12-GiB RTS heap, one worker, `-c30`,
60-second derivation check and `--quit-on-warning`.

The final certificate is byte-identical to the retained input:
`dde5d06a071b1560da0d4c28c3f1fd81a3c39708f9fd8564ee391ddc362bcf7f`.
No search, rule change, query removal or change to the threat model occurred.
The fixed-tool contract passed, and executable hashes were unchanged before and
after execution. The source base was `6084f3bf`; the concurrent OpenSSL evidence
repair and directory CLI test work do not change this symbolic input.

All 40 queries remain present: 27 are verified and 13 remain incomplete.
The latter are eleven multi-round execution witnesses and two unused historical
all-trace queries. This is not an all-queries pass or completed multi-round
non-vacuity evidence. The exact recovery and disclosure assumptions remain those
of the [original certificate](../20261031-multi-epoch-secrecy/README.md).
Computational composition, implementation correspondence, platform qualification
and external security review remain separate obligations.

The executed command was the documented `artifact/continuity_multi_epoch_search.py`
entry point through `artifact/python-run.sh`, with an explicit Python interpreter
and the selected formal-tool directory on `PATH`. The output directory was
`target/multi-epoch-replay/replay-01`. The accepted terminal receipt records the
complete argv, resource bounds, streams and every query result.

A subsequent standalone version probe omitted that `PATH` and failed to find
Maude. This was after the successful replay. Its partial output and original
capture remain retained; a correctly scoped version probe then completed.
That probe failure is not relabeled as a proof failure or as a successful probe.

`CAPTURE.zip` retains the complete input/output certificates, stdout/stderr,
started and terminal receipts, exact checker sources, tool hashes and identity
probe history. All 30 members were read back byte-for-byte. `MEMBERS.json` pins
the members and `VERIFICATION.json` records the archive digest and remaining
queries. `release_claim_eligible` remains false.

The later [two-round witness search](../20261104-two-round-witness-search/README.md)
keeps the operational model and all query formulas/modes but enables two already
checked phase-uniqueness invariants for the original execution witness. Its
isolated exploration copy retains all reusable proofs and projects other
nonreusable proof bodies. It exhausts the unchanged 12-GiB heap before its
900-second deadline and produces no certificate. The failed inputs and streams
are retained; this does not change the successful main replay or close a witness.
