# Single-root ideal-oracle calculation

The [current statement](../../../../docs/continuity/SHARED_ROOT_ORACLE_V1.md)
establishes a finite conditional coupling for one uniformly hidden root used as
both a key and a message in one ideal quantum random function. With the
half-trace-norm convention, its bound is
`min(1, 2*min(1, 2*q*sqrt(2/2^n)) + t/2^n)`.

The real-game statement starts from oracle-independent auxiliary state and
charges **all** preparatory and subsequent ordinary oracle queries to `q`.
Classical root interfaces, exact repeated selectors and the row/column
intersection are explicit. The derivation uses ideal prefixes with real
suffixes, keeps the root and selector history through the trace-distance
comparison, and compares unnormalized good branches for the classical Bad event.

The retained [draft](DRAFT.md) had an incomplete identification of its constructed
K game with a real oracle-correlated prefix. A single uncounted preparatory query
gives a distinguishing probability gap `2^(-n)*(1-2^(-n))` when the advertised
post-prefix counters are zero. The [internal independent check](REVIEW.md)
preserves this counterexample and verifies the literal I/J/K bound. The primary
author rechecked its expansion, trace-distance constants, Bad-event argument and
counterexample before recording the [corrected statement snapshot](STATEMENT.txt).
The attacker's actual prefix queries remain allowed and are counted.

[RESULT.json](RESULT.json) records the precise conclusions and exclusions.
[FILES.json](FILES.json) binds the original draft, reviewed source-note snapshot
and final statement. The review contains one disclosed-path normalization with
both original and archived hashes; its original remains under
`target/continuity-aggregate-diagnosis`. Relative links inside source snapshots
refer to their recorded original repository locations.

This is an internally checked mathematical argument. It is not a machine proof,
an external security audit, a verified HMAC-SHA256 instantiation, an accepted-prefix
simulation, or the completed multi-epoch protocol proof. It does not select a new
product security assumption. Persistent-state/leakage correspondence, message/ACK
separation, authentication and multi-epoch composition remain separately open.
The primary references support the stated general mathematical tools; no
third-party book or paper is redistributed here.
