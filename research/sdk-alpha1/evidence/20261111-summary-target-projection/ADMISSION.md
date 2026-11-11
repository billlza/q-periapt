# Admission boundary for the Stage4 projection prototype

This prototype is compiled and structurally checked. It is not installed into the active workflow and is not runtime-admitted. The existing 39-query, tool/source, cache, capsule, full-result and five-hour gates remain unchanged.

## Identity needed for a separate candidate

- Original CLI archive remains the authenticated Rust 2.27.2 bundle, 98,247,028 bytes, SHA-256 `acf2050189aeede5b9aa566f8fb382b02ac1ace72f534778f68b06fce5371cea`.
- All 39 root query sources match their original hashes, including full SummaryStats `7278d53373afb4f8069122e287c9c036a959ba0d167c152d67cd0de885881d67`. The other 38 QLX files remain byte-identical to the original bundle.
- The full summary's transitive source is deliberately changed: one vendor library file in `codeql/dataflow@2.1.15`. This must be declared as a vendor patch, not described as byte-identical transitive query source.
- `CANDIDATE_SOURCE.json` binds the upstream library SHA-256, exact patch SHA-256 and effective library SHA-256. `DEPENDENCY_IDENTITY.json` and the compressed inventories establish that among 1,175 embedded dependency files only that file changes and that compilation leaves that dependency inventory unchanged.
- The compiler input key is `70fcc50b9809b694b26b77a11722cdbb`, distinct from the original all-plan key `209f28c6b9e8d5465a3f8417573e42d6`.
- `CANDIDATE_CAPSULE.json` enumerates the QLX and its complete 15-stage closure. The 620,156-byte capsule SHA-256 is `1fe6db109a540d6063fca24e25e9d6c56a88f972a5c248d74fd95f7248fb6132`.

The current fixed-plan installer will reject this different manifest/key/capsule. A future explicitly selected prototype mode must admit this separate vendor patch and effective source identity, rather than weakening the existing all-plan admission or accepting arbitrary patched dependencies. No such installer or workflow modification is included here.

## Completed checks and remaining execution evidence

The fixed CLI successfully compiled the correctly bound candidate within the 180-second supervisor bound. RA shows the six-column target relation inside the Stage4 forward recursive layer and the unchanged eleven-column relation outside it. Exact source-body comparison and the least-fixed-point proof preserve full read semantics for reverse and PathGraph consumers. These checks establish QL legality and that the compiler produced the intended structural plan.

No database evaluation was performed. No fresh BQRS equality, runtime relocation admission, retained-project completion or performance result is claimed for this capsule. Those remain the concrete execution inputs needed before adopting it; the previously defined complete 39-result comparator remains authoritative. This review packet can be published as implementation evidence without selecting it for production or initiating a hosted run.

## Binding defect found during preparation

The first attempted candidate compile selected the published query pack's embedded `.codeql/libraries` instead of the external `--additional-packs` overlay. Its original compiler key and byte-identical original RA exposed that error. `CANDIDATE_COMPILE.binding.json` marks it `invalid-candidate-binding`; its successful exit is not counted as candidate validation. The corrected attempt modifies the isolated pack's actually resolved embedded dependency, verifies the full dependency inventory and changed input key before compilation, and records that new input key in the compiler log.
