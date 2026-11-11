# Joint bootstrap Extract: source and encoding controls

This packet supports
[Joint bootstrap Extract with one surviving contribution](../../../../docs/continuity/BOOTSTRAP_JOINT_ENTRY_V1.md).
The assessed source is
`b1cff2a045d23aecf75aef12122e5080a8419676` (9 November 2026).

The proof gives both surviving-contribution primitive services: the 64-byte
Extract when the second half is hidden, and the joint 32/64-byte service when
the first half also feeds initial confirmation. Its shared-oracle table
comparison preserves the actual initial/long first-input alias and complete
pad-state descriptors. The original source contribution/disclosure adapter
and terminal full-transcript reconciliation retain their separate roles in
the construction assessment.

## Reproduction

`SOURCE_PINS.json` binds seven exact implementation, assessment and proof
inputs by byte length, SHA-256 and Git blob SHA-1. The document assessment is
subsequently updated by this increment, so use a checkout/export of the
stated source when reproducing these historical pins.

```sh
python research/sdk-alpha1/evidence/20261109-bootstrap-joint-entry/check_entry.py \
  --source-root /path/to/source-at-b1cff2a0 \
  --output /tmp/bootstrap-joint-entry-result.json
```

`RESULT.json` is the actual output of this command against the pinned
source export. The check stops on a mismatched source file or failed control.
It has no network dependency and uses the Python standard library.

| Executed control | Result |
| --- | --- |
| Exact downloaded implementation/assessment/proof inputs | 7 source files matched |
| Independently evaluated SHA-256 compression equations versus standard-library HMAC | 32 short and 32 long equations matched |
| 27-byte SDK salt and its 32-byte zero extension | Both complete pad states equal |
| Known suffix equal to the 32-byte padding suffix | Short and long first private points equal; their actual descendants remain distinct |
| Incorrect 64-byte padding variants | Both omission of the extra padding block and an incorrect consumed-length field were distinguished |
| Raw hidden-half encodings | 8,192 concrete points checked across both orientations, 256 declared secret values and 16 descriptors |
| Tagged short-outer/padding encodings | 1,280 points checked; all-secret fixture freshness and fixed-query injectivity passed |
| Ordering, effective aliases, exact retries and query bound | All 720 order/insertion fixtures passed: 120 long-call permutations and six SDK-short insertion positions |
| Global versus per-slot short budgets | One distinct short outer call per execution; the SDK raw class occupied each of three allocation slots across fixtures |
| Faulty cache keys | Salt-name, alpha-only, missing-beta and split short/long raw caches each exposed a specific mismatch |
| Numerical equality of independently allocated intermediate values | Real computations retained the common-oracle correlation; ideal table slots retained their distinct allocation identities |

The forced pad-state aliases and numeric collisions are deliberate model
controls. They are not reported as collisions found in SHA-256. The final-table
symbols check the identity partition of table handles; they represent independent
sampling slots, whose sampled bytes may still coincide.

The mathematical proof uses injective encodings over the full 256-bit domain
and the cited quantum hidden-input theorem. These finite controls check public
equations, source identity and table semantics. They do not execute native Rust,
ML-KEM, ML-DSA, CI, platform adapters or an external review.

## Review bindings

The independent review receipt binds the final proof document, checker,
source pins and reproduced result by SHA-256. The computation and the review
record retain their own precise scopes.
