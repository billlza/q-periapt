# Independent review of indexed exposure evaluation

Review date: 15 November 2026.

Initial implementation review: local commit `8f7fa51`.

Initial reviewed `indexed_exposure.py` SHA-256:
`29c00093270aa05b0d177465d35a38c67fc7a1418a3c5788aa5fda41da84a5cc`.

The integrated implementation loads its retained model by an exact adjacent
source path so it also runs through the repository's isolated Python launcher.
This integration changes module loading while retaining the evaluator classes.
The independent logical oracle was rerun through `artifact/python-run.sh`
against implementation SHA-256
`2096c4d30902671eadf1282c3f7ff1ed6a54f3d374c706cefad2c2131ba8211c`;
all 2,592 comparisons passed. The accompanying receipt binds that integrated
implementation and the explicit-path review driver.

## Conclusion

The inspected indexed evaluator implements the manuscript's fixed-graph
record/key/source least closure. Its two arrival handlers enable record
decryption regardless of whether the matching key or ciphertext becomes
available first. The opened-record latch retains each enabled payload once.
The graph constructor uses Kahn's algorithm to validate record acyclicity and
does not instantiate the path-enumerating reference model. Key-derivation
cycles and self-loops retain their least-closure meaning.

The implementation agrees with the incremental-evaluation proposition's
cost model. Each cumulative state queues each key and record at most once,
visits each stored derivation and guard incidence once, and scans each
opened record's payload once. Its constructor makes a constant number of
passes over the indexed input. Source updates emit disjoint deltas, and no
event log is retained. Full snapshots are explicitly output-sensitive;
requesting all normalized paths remains outside the indexed bound.

The graph is fixed. The stated `O(N+M+U)` time and `O(N+M)` working-space
bounds use indexed identities and constant-time set operations, with the
corresponding expected-operation interpretation for Python dictionaries.
External identity normalization and complete output exports are accounted
for separately. These conditions match the implemented interface.

## Independent logical oracle

`review_indexed_exposure.py` checks the evaluator against a third oracle
that does not perform forward derivation. For each generated typed Horn
theory, it enumerates every Boolean valuation satisfying the theory. For
each possible initial seed set, it intersects all satisfying valuations
that include those seeds. Definite Horn theories are closed under
intersection, so this is their least model containing the seeds. The
script compares all three resulting atom sets with the indexed evaluator.

All 2,592 seed sets across 24 deterministically generated small graphs
passed. Record, key and source atoms deliberately share literal names
across sorts; source knowledge creates no key or record fact. The seed is
`20261115`. Every seed set and every Boolean valuation of each generated
graph is checked; the 24 graphs are a fixed sample of graph shapes, rather
than an enumeration of all possible graphs.

This check complements the implementation's 5,360 historical fixture
assignments, 2,189 history prefixes, explicitly expected cases, and
structural scale controls. The general proof establishes correctness and
the asymptotic bound; the checks bind the executable realization to those
semantics. They provide no additional wall-clock measurement or native
cryptographic security claim.

## Replay

From this artifact directory:

```sh
python3 review_indexed_exposure.py --output indexed-review-results.json
```

The script also runs by absolute path from another working directory:
its default module and output directories resolve relative to itself.
Use `--module-dir` and `--output` only when explicitly reviewing a separate
checkout. The machine-readable receipt records both the implementation
and review-driver SHA-256 hashes. Its decisive comparisons remain active
under Python optimization.
