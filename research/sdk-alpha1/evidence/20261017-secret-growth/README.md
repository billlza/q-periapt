# Secret state buffer growth — 2026-10-17

An actual enrolled-owner connection at source base
`d71c6fc126fa78b56ab1073a574b13e7a99168e1` demonstrates that final-drop
zeroization does not cover earlier moving reallocations in `State::encode`.
The existing serializer writes the 32-byte rekey field at offsets 73–104 into
a growing `Zeroizing<Vec<u8>>`, then appends epochs and control state. The pinned
`zeroize` 1.9.0 source explicitly documents this buffer-reallocation limitation.

This is an avoidable serialization-copy concern, distinct from the earlier
[VM footprint measurements](../20261017-vm-footprint/README.md). It does not prove
a native macOS allocation residue, memory disclosure exploit or remote attack.
The existing storage contract also excludes stronger claims about paging,
compiler copies, historical pages and backups.

## Counterexample and isolated candidate

A separate source clone adds a safe observation call immediately after the
rekey field is written. A separate helper crate supplies a legal global allocator
which implements moving reallocation as allocation, raw copy and release through
`System`. Before handing the old allocation to `System.dealloc`, it inspects only
the registered, initialized secret range. It never reads freed memory or
uninitialized capacity and publishes no pointer, secret bytes or secret-derived
digest. This verifies the serializer's behavior before the underlying allocator
release; it makes no claim about the allocator's later treatment of the pages.

Two controls precede each actual connection: a growing zeroizing buffer must
produce one nonzero old-allocation observation and one zeroed final release;
a sufficiently preallocated buffer must produce only the zeroed final release.
The controls use synthetic data and are reset before the product-path census.

| Isolated execution | Watched state buffers | Moving reallocations with a nonzero rekey range | Zeroed final releases | Native assertion |
| --- | ---: | ---: | ---: | --- |
| Existing serializer | 7 | 14 | 7 | Fails, exit 101 |
| Exact-capacity State/Traffic prototype | 7 | 0 | 7 | Passes, exit 0 |

Each fresh process completes enrollment/bootstrap, authenticated hybrid TLS
delivery, confirmed consumption and one durable business effect before the
zeroization assertion. Both business files are independently read back. No
watched buffer remains live, and neither run observes a nonzero final-drop
range. The old test failure is retained as a failure; the collection command's
successful observation does not turn it into a passing SDK test.

The isolated candidate measures length through the same serializer, allocates
once and refuses a mismatch between the measured and written lengths. Traffic
epochs write directly into that state buffer, avoiding their intermediate
encoded vectors. It remains safe Rust in the engine. The unsafe allocator
observer is confined to the separate diagnostic crate.

## Admission still required

At this checkpoint the prototype was **not applied to the product branch**.
The subsequent [persistent encoding correction](../20261017-secret-encoding/README.md)
extends it to related secret-bearing paths and supplies broader compatibility,
capacity/recovery and compiler checks. The original experiment below retains
its narrower scope. This one real connection
establishes the observed failure and a working candidate for that path. It does
not establish byte-for-byte v21 storage compatibility for every message/control
variant, maximum-capacity behavior, crash/reopen correctness or performance under
the native allocator. Existing test call sites also need adaptation to the
prototype's fallible internal encoder before the complete library test suite
can compile and run.

The outer journal `seal` still constructs a growing zeroizing vector and must
be addressed before claiming this serialization family is hardened. Capacity
failures must retain their existing persistence/owner-close semantics; merely
adding an earlier rejection is not an equivalent fix. Other secret-producing
encoders require a focused inventory rather than a blanket erasure claim.

The observer hooks, diagnostic dependency and moving allocator must never enter
the product distribution. The current candidate uses an internal observation
method only to register the same initialized field during the write pass; that
method is part of the isolated patch, not a proposed product API.

## Evidence

[OBSERVATION.json](OBSERVATION.json) binds the two executables, source base,
results and scope. [CAPTURE.zip](CAPTURE.zip) contains 105 public members,
including both exact source patches, allocator source, fixtures, build/run
commands and terminal outputs. Every member is read back and hashed in
[CAPTURE.json](CAPTURE.json). Archive SHA-256:
`27c76536857008d5db9977b68276347e8bb97be164fabab49d3cbd99b909f01d`.

An initial lock-resolution attempt selected six newer cached registry packages
and was rejected before compilation by the dependency-provenance check. Its
fixture and failure record remain preserved. The successful builds reuse the
previously verified pinned observer lock, admit only the local diagnostic helper
and retain the registry-subset check. Both use Rust 1.98.1 Release, thin LTO,
overflow checks and warnings as errors. Private state, keys, executables and
compiler caches are excluded from the public archive. The original private
cohorts remain sealed, and 0.2.0 release qualification remains open.
