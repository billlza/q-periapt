# Indexed evaluation of guarded exposure

The indexed evaluator computes the same finite record/key/source closure as
the retained `check_exposure.py` scan evaluator. It maintains that closure
through cumulative acquisitions and disclosures. The separate path-normalized
checker remains an independent oracle for the declared small fixtures, with
its source and historical receipts unchanged.

## Algorithm and cost

`indexed_exposure.py` builds a key-to-derived-key index and a key-to-guarded-record
index. An arriving key or record is queued only when it becomes known for the
first time. A record opens once both its ciphertext and its wrapping key are
available; an `opened` latch permits exactly one visit to its payload. Direct
source disclosures add source facts without deriving keys backwards. Record,
key and source identities remain separate sorts, including when their string
representations coincide.

The constructor validates the record DAG using Kahn's algorithm. It uses no
recursive traversal or path enumeration. Key derivation may contain cycles or
self-loops: an existing key seeds those cycles, and each key is processed once.
The graph stays fixed during an evaluation. Local deletion changes the
availability of a later local acquisition and preserves knowledge already
acquired by the evaluator.

Let `N` be the number of record, key and source atoms, and let
`M = |D| + sum_r(1 + |children(r)| + |origins(r)|)`, counting the stored
derivation, guard and payload incidences, including duplicate tuple entries.
Preprocessing plus `U` acquisition/key/source-disclosure events costs
`O(N + M + U)` time and `O(N + M)` working space under indexed identities and
constant-time dictionary/set operations. Python's dictionaries and sets supply
the expected-time realization of that model; hashing or normalizing arbitrary
external byte strings has its own input-size cost. A legal local-deletion event
has constant cost, and the fixed record set permits at most `|R|` such events.

`IndexedClosure.acquire`, `disclose_key` and `disclose_origin` return only
newly exposed sources. Across a history these deltas contain each source at
most once. `IndexedHistory.step` uses the same delta convention and retains no
event log. `is_exposed` answers one source-membership query. Explicit
`snapshot()` exports all known sources, records and keys and costs its output
size; exporting that state at every prefix adds the sum of those output sizes.

`IndexedModel.forward` accepts the retained scan evaluator's three input sets
and returns its `(exposed, available, keys)` tuple of sets. `routes` and
`normalized` are explicit compatibility requests for the retained small-graph
path oracle. Only those requests construct the reference `Model`; enumerating
all witnesses can take exponential space and time and is outside the indexed
closure bound.

This is an indexed implementation of the established positive derivation
rules. The manuscript attributes the underlying Horn/worklist method to prior
work and uses the implementation to make its leakage oracle efficiently
evaluable.

## Reproducible validation

Run from this directory or pass the complete script path:

```sh
python3 check_indexed_exposure.py --output indexed-results.json
```

The driver records source hashes in `indexed-results.json` and uses explicit
checks that remain active under Python optimization. Its current result is:

- All 5,360 acquisition/key/direct-source assignments across the seven retained
  fixture graphs agree with the scan evaluator on all three closure sorts and
  with the guarded-path oracle on source exposure.
- The 360 legal event permutations, ten directed histories and an additional
  duplicate-event history produce 2,189 matching prefixes. Delta outputs are
  disjoint, and their cumulative union agrees with the old full-state result.
- Seventeen independently specified cases cover arrival order, partial-route
  conjunction, cycles, self-loops, duplicate incidences, distinct atom sorts
  sharing one name, snapshot isolation and explicit lazy oracle calls.
- Thirteen invalid-input cases reject malformed graphs, undeclared atoms and
  invalid local-store operations. Rejected state updates preserve the state
  and its operation counts.
- Structural counters check that keys, records, derivation edges, guard
  incidences and opened-record payload incidences are processed at most once.

The scale controls compare operations rather than wall-clock speed:

| Reversed key-chain edges | Repeated full-scan key-edge visits | Indexed key-edge visits | All indexed visits |
| ---: | ---: | ---: | ---: |
| 32 | 1,056 | 32 | 68 |
| 128 | 16,512 | 128 | 260 |
| 512 | 262,656 | 512 | 1,028 |

The scan column directly instruments the retained `Model.forward` with a
counting iterator over its derivation edges on that deliberately reverse-ordered
chain, including its final no-growth pass. Its complete closure is checked
against the explicit expected source, record and key sets. The final column
also includes queue pops, record-guard checks and payload incidences. These
counts establish the intended scheduling difference on that family; they are
not wall-clock performance measurements.

An additional 128-layer, two-wide DAG has 257 records, 510 containment edges
and `2^128` root-to-source paths by direct combinatorial counting. The indexed
closure processes 1,027 indexed visits and emits the one source once. Another
2,000 repeated acquisition/key events leave the indexed-visit count unchanged.
A depth-4,096 record chain requires 12,289 indexed visits without recursion.
Throughout every scale control the indexed module's reference-model constructor
is patched to raise an exception, so accidentally invoking path enumeration
through the new evaluator fails the run. The directly instrumented old scan
uses a one-record reference graph with exactly one containment path.

These checks establish implementation correspondence and the measured work
in the declared finite graph model. The manuscript's general closure argument
supplies the correctness and asymptotic bounds; its cryptographic reductions
remain separate results.
