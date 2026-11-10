# Current AAR consumed by a minified Android application

The [current arm64 AAR](../20261106-current-android-aar/README.md) at source
`5678d1019861fa1b04f3a219ba3fde7e0ddaaba8` now passes a real AGP Release consumer
build and independent inspection of the resulting APK. The application compiles
the existing device instrumentation and its device-namespace probes against the
actual AAR, without compiling the library from source or adding application keep
rules for its JNI bridge. No APK signing, installation or Android execution occurs.

## Actual build and inspected program

The AAR SHA-256 is
`a21d016d0cbe69dc7bb363c488ce9d984017625ea811c17218dea4e60ab66c7e`.
The unsigned APK is 7,874,919 bytes, SHA-256
`d94654dbd7879ddd321f706e5bbf54bbc789d5ff30a038a41e62f68da7b028f3`.
AGP 9.4.1, Gradle 9.7.1 and the same private JDK 25.0.5 compile 43 exact device
sources with `-Xlint:all -Werror`. The build runs 43 tasks, including javac, R8,
release lint and APK packaging. Warning mode remains `fail`; the retained stdout
and stderr pass the existing diagnostic checker. The R8 mapping records compiler
9.4.24 and minimum API 36.

This qualification application's compile/target/minimum API 36 settings follow
the previous accepted instrumentation build. They do not change the library's
API 23 compile floor, establish API 23 runtime support, or request an API 36
phone. The previously accepted API 37 phone remains sufficient for applicable
device execution.

Independent tools inspect the actual APK, not a proposed source configuration:

- The 172,656-byte DEX, SHA-256
  `40af615f6e67797b77240799206eeff6a8d80565220f322c11743fe7b2d0e367`,
  has 117 class definitions after shrinking. All 23 registered native methods
  retain their exact descriptors and static/native flags; the three JNI-called
  static callbacks and three instrumentation entrypoints remain concrete.
- The original library keep rule appears once in the merged R8 configuration.
  The optimized default ProGuard file matches its existing pinned digest, and
  `Native` retains its required name. The only application entrypoint rule comes
  from the manifest-generated instrumentation rule.
- Both arm64 libraries are byte-identical to the AAR. Their uncompressed APK data
  begins at offsets 180,224 and 7,782,400, each aligned to 16 KiB. A separate
  `zipalign -c -P 16 -v 4` check succeeds. This complements the AAR's ELF alignment
  checks; it is not a 16 KiB runtime result.
- The compiled manifest identifies this isolated qualification application and
  original instrumentation, disables backup, uses uncompressed native libraries
  and has no debug/test-only flag. It requests only the existing Internet
  permission. The APK contains no enrolled-account inputs, private keys or assets.

The compile task records the actual JVM, all 43 source digests and six classpath
file digests. Its seventh entry is the declared output of the empty Kotlin task.
The recorder admits that absent directory only at its exact path when the actual
task has executed with `noSource=true` and no failure; it does not invent file
bytes or turn an error into an empty input. All project and source bytes are
rechecked after the build.

## Preserved preparation failures

The first build stopped in the diagnostic classpath recorder before javac because
it tried to read that absent Kotlin output as a file. It also reported missing
platform-tools in the private SDK. The corrected recorder distinguishes file,
directory and the narrowly checked no-source output. Official stable
platform-tools 37.0.1 is installed under the same project-private SDK after its
exact size and publisher checksum match. No warning suppression, license
acceptance command or global installation is used; these diagnostic drivers
issue no ADB command.

The second build reached javac and exposed an overly broad diagnostic source
selection: it had included ten host JNI boundary probes. One uses a host Java
covariant `ByteBuffer.position` return that Android's compile stubs do not expose.
Those ten classes are outside the original device namespace; none of the 43
device sources references them. The third build uses the complete device
namespace and original instrumentation. All ten host sources remain unchanged,
their hashes are retained, and the separate original host-JNI gates continue to
cover them. No applicable device operation, product source, R8 rule or compiler
check is removed. Both failed projects' inputs, reports and logs remain captured.

## Tool provenance, retention and limits

The original Gradle distribution pin is
`acd53f1edaf02f1a8ff99879f8a34b302661a057d9b063ae9e35b552f804d20a`.
Official Android repository metadata selects build-tools 36.0.0, platform 36
revision 2 and stable platform-tools 37.0.1. Downloads are bounded and verified
before extraction; all files are installed below the project's `target/` tree.
The SDK inspection tools contain arm64 slices. Tool manifests, licenses, URLs,
publisher checksums and observed SHA-256 values remain in the capture. The large
original downloads and private Gradle cache remain local; this is not a complete
offline rebuild kit.

[CAPTURE.zip](CAPTURE.zip) contains 556 members, 48,778,527 bytes and has SHA-256
`d67939e4f22138c4877d43a5143857e6d4728c8ebb8d5da1edde78da65e0a47e`.
It includes the actual AAR and unsigned APK, all six classpath files, AGP plugin
JAR, source and project inputs, tool preparation records, failed and successful
build logs, R8 outputs, actual DEX/manifest/alignment dumps, and readers.
[FILES.json](FILES.json) pins every member; each was reread after ZIP creation.
[CLASSPATH.json](CLASSPATH.json) maps the retained compile files, and
[READBACK.json](READBACK.json) records the successful independent APK inspection.
The native tools were run against the actual APK before capture; no second
archive-only execution of those tools is claimed.

The artifact is unsigned and has no runtime input bundle. APK installation,
native loading under ART, actual owner/lifecycle operations, necessary device
regressions and mobile resource observations remain unexecuted for this artifact.
This build does not admit Continuity into product ABI 2, qualify other ABIs,
complete the surrounding JNI runs, publish the candidate or close release gates.
