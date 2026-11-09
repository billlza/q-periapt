# Continuity Android 0.2.0 distribution construction

`artifact/continuity_android_distribution.py` assembles and independently reads
the selected Continuity Android companion at
`dev.qperiapt:q-periapt-continuity-android:0.2.0`. It consumes separately pinned
native libraries, Java classes and their original build reports, produces an
AAR and Maven directory, and emits the existing release-manifest distribution
identity. The commands operate locally; registry publication remains with the
existing release tooling.

This implementation completes the bounded assembly and static readback path.
The retained 6 November AAR remains `0.0.0` with its original source and hashes.
Fresh native/class compilation, an installed AAR consumer, R8 execution and
device execution for the selected 0.2.0 artifact have not been executed by this
increment. Its tests use explicitly synthetic ELF/class fixtures and simulated
LLVM output. The producer's original compilation inputs must come from an
actual fresh build before a 0.2.0 capsule can be produced.

## Selected package surface

| Item | Selected contract |
| --- | --- |
| Maven identity | `dev.qperiapt:q-periapt-continuity-android:0.2.0`, packaging `aar` |
| Java namespace | `dev.qperiapt.continuity.android`; the tracked main-source inventory determines the top-level class set |
| Native target | `aarch64-linux-android`, packaged only under `jni/arm64-v8a/` |
| C interface | `qpc-owner/1`, package version `0.2.0`; current 158 exported C functions |
| C library | `libq_periapt_continuity_c_consumer.so` |
| JNI library | `libqperiapt_continuity_jni.so`; only `JNI_OnLoad` exported |
| JNI registration | Exact current 23 static native methods and three static callback descriptors read from `continuity_jni.c` |
| Compilation profile | Rust `1.98.1`, Android NDK `29.0.14206865`, Java 25 with `--release 11` |
| Android compile floor | API 23 in both manifest and ELF Android note |
| ELF load geometry | Power-of-two alignment at least 16 KiB, congruent file offset/virtual address, bounded LOAD file ranges and `filesz <= memsz` |
| Runtime linker surface | Exact SONAME and NEEDED sets, NOW and RELRO, nonexecutable stack, no RPATH/RUNPATH/TEXTREL |
| Release content | Stripped libraries, release binary scan, unchanged R8 keep rules and project/compiler/dependency license texts |

The compile API is a build parameter. Runtime and device qualification retain
their separately recorded environment and artifact bindings. This change adds
no ABI or device to the existing supported profile.

The native C Cargo package remains an unpublished qualification harness at its
existing version. Its package name is used to identify the resolved production
license closure. The formal distribution's version is `0.2.0`; changing that
harness version is not required to identify the engine and distributed AAR.

## Independent input selection

The caller supplies an immutable selection document and its SHA-256 separately.
Every input reference has exactly `path`, `bytes` and `sha256`. Paths are
canonical relative names under the selected input directory; all six input
paths are distinct. Regular-file, no-symlink snapshots reject substituted
bytes, traversal, aliasing, duplicate JSON keys and non-finite numbers.

The selection has exactly these fields:

```text
schema_version: 1
kind: qperiapt.continuity_android_distribution_inputs
name: q-periapt-continuity-android
version: 0.2.0
abi: qpc-owner/1
target: aarch64-linux-android
source: {commit, tree, tree_sha256}
native_package_id: <the selected native row ID in the release manifest>
native: {c: <file reference>, jni: <file reference>}
classes: <classes.jar file reference>
licenses: <dependency-license ZIP file reference>
native_receipt: <original native-build JSON file reference>
classes_receipt: <original classes-build JSON file reference>
```

`commit` and `tree` are exact 40-character Git identities. `tree_sha256` is the
repository's existing canonical source-input digest. All three are checked
against the independently selected clean checkout. One captured tracked-path
inventory drives the digest and the Java source reads. Every consumed engine
manifest, ABI snapshot/header, Java source, JNI bridge, keep-rule and license
snapshot participates in the final digest as the exact bytes consumed; a
replace/read/restore of source bytes or a temporarily missing tracked Java file
cannot turn into a different packaged source set under the original identity.

The selected native dependency row ID is carried into `PACKAGE_IDENTITY.json`.
It must name the actual native companion row when the full release manifest is
assembled. The existing release verifier checks dependency order and identity
consistency in that full cohort.

### Native compilation receipt

The native input report retains these required fields:

```text
schema_version: 1
kind: qperiapt.continuity_android_native_build
completed: true
source: <exact selection source object>
package: {name: q-periapt-continuity, version: 0.2.0}
artifacts: {c: <exact selected reference>,
            jni: <exact selected reference>,
            licenses: <exact selected reference>}
toolchain: {rust: 1.98.1, ndk: 29.0.14206865,
            target: aarch64-linux-android}
```

Its original build diagnostics and qualification details may remain as
additional fields. A `failure` field or any identity, source, completion,
artifact or toolchain mismatch is rejected. The report is a fresh build input;
the distribution command does not synthesize it from old binary files.

The license ZIP contains only `THIRD_PARTY/rust/` entries collected from the
actual production dependency resolution for
`q-periapt-continuity-c-consumer`. The existing `third_party_licenses` verifier
checks its canonical inventory, target, package/license-file identities and
exact retained text bytes. Compiler-library and project licenses come from
the selected source checkout separately.

### Java compilation receipt

The Java report uses `kind: qperiapt.continuity_android_classes_build`, the same
schema/completion/source rules, package
`{name: q-periapt-continuity-android, version: 0.2.0}`,
`artifacts: {classes: <exact selected reference>}` and
`toolchain: {java_major: 25, release: 11}`. Its classes JAR contains the compiled
main classes without test classes or unrelated resources.

`artifact/continuity_android_classes.py` reads bounded Java 11 classfile
framing, constant-pool identities, methods and attributes using the
[JVMS classfile structure](https://docs.oracle.com/javase/specs/jvms/se25/html/jvms-4.html).
It checks each class's archive path against its own declared identity and the
selected source namespace, requires every tracked top-level class, and checks
the complete JNI native/callback descriptor and static-method contract.
The JVM/ART verifier retains bytecode verification; this parser performs the
package and JNI checks required before installed execution.

## Output and independent readback

The AAR has an exact inventory: manifest, empty `R.txt`, selected `classes.jar`,
exact `proguard.txt`, AAR metadata, embedded input selection, the two arm64
libraries, three source-bound project/compiler license files and the selected
Rust dependency license inventory/texts. An extra ABI/library, missing class,
unexpected resource, changed loader metadata or altered license is rejected.
The outer archive uses the existing canonical ZIP framing: sorted uncompressed
regular-file members and fixed timestamps/permissions. This defines the archive
representation; it makes no cross-host compiler reproducibility claim.

The output directory contains 20 files:

- Fifteen Maven files: AAR, POM and sources JAR, each with MD5, SHA-1, SHA-256 and
  SHA-512 transport checksum files. SHA-256 remains the independent content pin.
- `INPUT_SELECTION.json`, `native-build.json` and `classes-build.json`, retaining
  the original selected reports byte-for-byte.
- `PACKAGE_IDENTITY.json`, using the existing
  `qperiapt.continuity_distribution_identity` schema.
- `DISTRIBUTION.json`, the static construction/readback assessment and complete
  payload file inventory.

The Maven reader independently checks the exact file inventory, coordinate,
POM, all checksum bytes and the source JAR's source/license contents. The capsule
reader checks every on-disk file against a separately supplied
`DISTRIBUTION.json` SHA-256. It rejects extra files/directories and altered receipt
claims, and reruns actual AAR/class/native/license readback. LLVM inspection uses
the selected NDK, bounded subprocess output and a minimal environment; tool
bytes and input bytes are checked again before completion.

`PACKAGE_IDENTITY.json` supplies the existing release-manifest `distribution`
metadata: formal name/version, Git commit/tree, selected native dependency row,
`continuity_c` interface, and exact AAR/POM/sources references. The surrounding
release row uses the same dependencies/interfaces/artifacts and pins this
metadata file. `DISTRIBUTION.json` is an assessment, with separate original
compilation reports retained alongside it. Paths in these documents are relative
to the capsule root; a combined release inventory must preserve that common
root or produce a separately checked path projection for its chosen layout.
The existing specification lock and historical manifests are not modified by
the producer.

`completed: true` describes successful distribution construction/static
readback. The report explicitly records that this command did not run native or
Java compilation, ART, a physical device, or publication. Release eligibility
remains with the existing coordinated admission process. Output must be fresh
under the checkout's `target/`; caught write/readback exceptions and Python
interrupts remove only the newly created output directory. Process loss or
`SIGKILL` can leave an incomplete directory, which the reader rejects unless its
complete inventory and retained receipt verify. Existing output/evidence is
never overwritten.

## Commands

After the actual fresh build has supplied the six pinned inputs and independently
selected source/selection identities:

```sh
sh artifact/python-run.sh artifact/continuity_android_distribution.py produce \
  --inputs "$selected_inputs" --selection INPUT_SELECTION.json \
  --selection-sha256 "$selected_input_selection_sha256" \
  --source-commit "$selected_source_commit" --source-tree "$selected_source_tree" \
  --source-tree-sha256 "$selected_canonical_source_sha256" \
  --ndk "$selected_ndk_29_0_14206865" \
  --output "$PWD/target/continuity-android-0.2.0"
```

Retain the resulting assessment hash independently, then invoke the separate
reader against the actual directory:

```sh
sh artifact/python-run.sh artifact/continuity_android_distribution.py verify \
  --inputs "$selected_inputs" --selection INPUT_SELECTION.json \
  --selection-sha256 "$selected_input_selection_sha256" \
  --source-commit "$selected_source_commit" --source-tree "$selected_source_tree" \
  --source-tree-sha256 "$selected_canonical_source_sha256" \
  --ndk "$selected_ndk_29_0_14206865" \
  --capsule "$selected_capsule" \
  --distribution-sha256 "$selected_distribution_assessment_sha256"
```

The repository's host JNI lane already records real Java/native lifecycle
qualification, but its native products are macOS libraries. The retained Android
cross-build controllers are inside the historical capture archive, rather than
an executable current-source build lane available in this checkout. This
increment provides no guessed cross-compiler invocation or rewritten workflow.
Connecting an actual Android build to the explicit receipt interface above is
the remaining producer integration; installed AAR/R8/device qualification then
binds to the newly selected artifact hashes.

The focused local verification command is:

```sh
sh artifact/python-run.sh -m unittest -v \
  test_continuity_android_distribution test_android_elf
```

Its negative controls cover legacy-version/source/receipt substitution,
selection/path/symlink errors, JNI/class drift, exact AAR inventory, license text
mutation, binary Android-note and LOAD geometry, native exports/dependencies and
tool diagnostics, rehashed Maven metadata/source changes, capsule claims and
cleanup, and transient source byte/inventory substitution. A composed control
uses a real temporary Git fixture with explicit LLVM inspection doubles to run
`execute()` through production and separate readback, checks the existing
release verifier's acceptance of the emitted distribution identity, and rejects
input/selection changes between capture and final reread. These tests do not
substitute for executing the selected native artifacts.
