# Formal Android distribution construction and review

This increment supplies the local 0.2.0 Continuity Android AAR/Maven assembler,
its independent capsule reader and the existing release-manifest distribution
identity projection. The implementation contract and operator commands are in
[`ANDROID_DISTRIBUTION_0_2.md`](../../../../docs/continuity/ANDROID_DISTRIBUTION_0_2.md).

## Verified implementation

The full hardened regression command passes **64 tests**: 20 new Continuity
distribution tests and 44 shared Android ELF/AAR tests, including two new LOAD
geometry regressions. Root and an independent reviewer separately reran it.
`ROOT_REGRESSIONS.json` binds the unchanged five code/test files before and after
execution and the exact retained log. The review receipt separately binds all
six final code/test/document files.

```sh
sh artifact/python-run.sh -m unittest -v \
  test_continuity_android_distribution test_android_elf
```

The composed control executes `produce` followed by independent `verify` against
a real temporary Git source fixture. It uses explicitly synthetic class/ELF
inputs and LLVM inspection doubles, and confirms that the existing release
verifier accepts the emitted `PACKAGE_IDENTITY.json`. Separate controls change
the native input and the independently selected selection file after capture;
both fail at final reread before an output is admitted.

Coverage also includes exact class/JNI descriptors, the 158-symbol native export
contract, Android-note metadata, R8 rules, license inventory, canonical AAR
framing, exact Maven coordinate/source/checksum inventory, stale/legacy build
receipts, native-tool diagnostics, altered capsule claims and owned-output
cleanup. The new test module is included by the existing general CI discovery
command (`test_*.py`); no workflow change is required to run these controls.

The independent review found and verified fixes for:

1. The shared ELF helper accepted `p_align = 0x6000` and incongruent LOAD file
   offsets/virtual addresses. It now requires power-of-two alignment and exact
   congruence. The new binary reader also checks LOAD file/memory bounds.
2. The proposed producer initially checked fresh source digests without binding
   the bytes it had actually consumed. It now incorporates all 76 captured
   source snapshots in the selected canonical digest.
3. A live Java-source scan could omit a temporarily removed tracked source.
   One selected tracked-path inventory now drives initial/final digest checks
   and every Java capture; the missing source is rejected.

`independent_controls.py` reproduces source replace/read/restore, temporary
inventory omission, all 23 native/three callback C/Java/JNI descriptor
comparisons, and eight archive framing/path/mode controls in copied fixtures.
Run it through the hardened entrypoint with the checkout root as its argument:

```sh
sh artifact/python-run.sh \
  research/sdk-alpha1/evidence/20261109-formal-android-distribution/independent_controls.py \
  "$PWD"
```

## Source and execution provenance

`SOURCE_PINS.json` verifies 195 inputs against integration source
`b1cff2a045d23aecf75aef12122e5080a8419676`: 117 unchanged transitively imported
local modules, 76 consumed contract/source files, and the two modified shared
files' original base bytes. Every Git blob matches. Publication can apply the
listed changes to a descendant while retaining these original base identities;
it must check the two modified files still have the selected base content.

The local hardened launcher selected CPython **3.12.3**
(`/usr/bin/python3.12`). These retained runs are local structural regressions;
the canonical CI Python 3.14.7 execution remains the hosted lane's result.
No Cargo, Rust compiler, Java compiler, Clang or NDK LLVM inspection tool was
available here. The original reports preserve their local log paths and their
actual scope.

## Artifact disposition

The existing 6 November Android capture retains its original `0.0.0` name,
source and hashes. Its original `READBACK.json` grounds the selected arm64
SONAME/dependency sets, 16 KiB profile and API 23/NDK r29 notes; it is not a
0.2.0 build receipt. No historical archive was edited or repackaged.

This increment builds no real native library or classes JAR and produces no
selected release AAR. A fresh Android build must provide the separately pinned
0.2.0 native/class receipts and bytes described by the new contract. The new
assembler and reader can then produce and check its formal capsule, followed
by the already scoped installed consumer/R8/device qualification for those
actual hashes. No additional platform, release gate or workflow is introduced.

The producer's `PACKAGE_IDENTITY.json` is directly consumable by the existing
release-manifest distribution-identity grammar. Its static assessment is
separate from the retained compilation reports, and it leaves existing lock
files, release admission flags and registry publication unchanged.
