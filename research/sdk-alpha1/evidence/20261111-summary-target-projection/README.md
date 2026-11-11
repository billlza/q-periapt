# Stage4 projected-read prototype: compiled feasibility result

A concrete Stage4-only plan candidate was prepared in an isolated copy of the authenticated CodeQL 2.27.2 pack. It compiles successfully and the resulting RA exhibits the intended change: the recursive component maintains the exact six-column read-target projection; the full eleven-column read relation is evaluated after that component and remains available to its other consumers.

This packet contains the reviewable patch, the least-fixed-point equivalence argument, exact source/dependency identities, the complete prototype QLX/stage capsule, compiler receipts/logs, full compressed original/candidate RA and focused excerpts. It contains no CLI installation or upstream library tree. Repository source, active CI branches, query selection, time budget and existing admission code were not changed.

## Observed original plan and concrete transformation

The original all-plan already uses the two seminaive read-join branches (deltaRead0 with previousCons, and deltaCons with previousRead0), discards the irrelevant unit-type columns from the candidate relation, and projects target columns at the fwdFlow0 consumer. There is no documented per-predicate projection/semijoin switch in the retained exact compiler help. A simple extra projection after the wide relation would repeat existing work.

The remaining opportunity is the recursive storage boundary. Original fwdFlowRead/11 is a relation in the forward recursive layer. Its only non-self consumer there is fwdFlow0's six-column target projection. After that layer, readStepFwd projects source/content/edge information. Source-level PathGraph.localStep also retains its complete read relation use.

The patch adds `fwdFlowReadTarget` with the original join and every guard, existentially eliminating only the five source/content witnesses ignored by the forward consumer. A default-false StageParam switch enables it only in Stage4. The original full fwdFlowRead body, readStepFwd and PathGraph consumers remain intact. This is a local vendor-library implementation change with unchanged root query sources, not another global allocation or timeout experiment.

## Compiler and structural evidence

| Operation | Result | Wall seconds | Input key |
|---|---|---:|---|
| Original all-plan RA export | exit 0 |77.936|209f28c6b9e8d5465a3f8417573e42d6|
| First attempted candidate compile | invalid-candidate-binding; original source selected |76.900|209f28c6b9e8d5465a3f8417573e42d6|
| Correctly bound candidate compile | exit 0 |78.385|70fcc50b9809b694b26b77a11722cdbb|

Every compilation had a 180-second supervisor bound, 2 compiler threads and 3,072 MiB JVM/compiler budget. No evaluator/database run occurred.

`IR_COMPARISON.json` enumerates every original and candidate Stage4 full-read reference. The candidate target declaration is recursive at RA line 175226 and is consumed by fwdFlow0 at 176877. Full fwdFlowRead is nonrecursive at 177233; readStepFwd remains after it at 177268. No full-read reference remains in the candidate forward recursive layer, and no other Stage acquires the target helper. This directly rules out the optimizer folding the candidate back into the original wide recursive relation.

The source transformation received independent read-only review. The reviewer checked all original guards, the exact five eliminated witnesses and the constant Stage4-only selection; no source-level counterexample was identified. `EQUIVALENCE.md` supplies the least-fixed-point argument, and `SOURCE_EQUIVALENCE_CHECK.json` verifies the preserved full definition and byte-identical join/guard suffix.

## Source and capsule identity

The actual resolved dependency tree contains 1,175 files. Its path set is unchanged and exactly one file differs. Its post-compile inventory is unchanged. All 39 root query sources and the other 38 compiled queries match their original identities.

The prototype capsule contains one full-summary QLX plus 15 referenced stages, 617,144 uncompressed bytes. The 620,156-byte ZIP has SHA-256 `1fe6db109a540d6063fca24e25e9d6c56a88f972a5c248d74fd95f7248fb6132`. The vendor patch SHA-256 is `282378060da1b9929c84ae040cbd99f64b7424874a364a76d6f5f46af47ceba9`.

## Adoption boundary

This establishes a reviewable implementation prototype, source-level equivalence and the intended compiled plan shape. It does not provide a database semantic readback or a performance measurement. The unchanged full relation may still have substantial post-closure cost. `ADMISSION.md` identifies the required explicit vendor-patch/capsule identity extension and the existing runtime/full-result checks before any future selection. The current capsule admission is not relaxed, and no new hosted run is started by this packet.

`MANIFEST.json` inventories all packet files. The compressed RA can be decompressed and compared with the raw SHA-256 values in the receipts and IR report. The invalid binding attempt is retained separately so its successful exit cannot be mistaken for prototype validation.
