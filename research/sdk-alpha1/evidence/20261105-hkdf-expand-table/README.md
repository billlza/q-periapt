# Ideal HKDF-Expand table source readback

The [manual interface lemma](../../../../docs/continuity/HKDF_EXPAND_TABLE_V1.md)
proves an exact representation identity after one private HMAC row has already
been validly idealized. Complete info bytes and the final one-byte block counter
make first-visit row inputs distinct. An Expand-only caller therefore sees the
same distribution from a prefix-consistent table of independent blocks. This
argument does not assume distinct random output values and adds no error term
inside that already idealized interface.

The exclusive interface and cache identity matter. The note gives explicit
distinguishers against independent outputs per requested length, an untouched
separate raw-row oracle, and independent tables for equal actual PRKs. It keeps
prior HMAC/QROM reduction costs and the child-key initialization/alias obligations
open. It neither idealizes the actual source by itself nor closes multi-root,
leakage, AEAD or the main Continuity recovery theorem.

At source `cc38ea0718400bc78b79a03e0ccc3c3a8fa725f6`, the reader checks five
candidate source/manifest files against that Git object. Six concrete HKDF
call sites cover 32-byte root/confirmation values, the 64-byte chain step,
128-byte epoch material and 160-byte initial material. The cached `hkdf 0.13.0`
source is byte-identical to the prior root-QROM capture's vendor copy. Its
length guard, previous-block update, ordered info, checked counter, output copy
and full-block retention are checked in source order. Third-party license files
are included unchanged.

This validation is a source/dependency readback, not a new HKDF execution,
statistical experiment, proof-tool run or independent external review. The
mathematical input-indexing argument remains separate from those literal
source checks. The existing real dependency encoding probes retain their own
scope and are not relabeled as multiblock runtime tests.

`CAPTURE.zip` retains the five candidate files, dependency implementation and
licenses, reader, note and source audit. All 15 members were
reread byte-for-byte: 52,087 bytes, SHA-256
`9dbb79200a4f48b6732e98ec15902c0f9a7aedfcf386ba50122c6fff13def4bd`.
`FILES.json` binds every member; `SOURCE_AUDIT.json` names the six call sites and
all conclusions not established here. No product code, security predicate,
hosted workflow or remote branch changed.
