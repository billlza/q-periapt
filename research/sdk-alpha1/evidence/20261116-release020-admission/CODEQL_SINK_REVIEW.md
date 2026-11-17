# Current bounded-command sink review

Assessed source: `8abbf8d2e73a27af7794528fd92d13fe3be2942d`, tree
`733e2e6e17be2241d85264ea5e15e07a35f04527`. Review date: 17 November 2026.
`CODEQL_READBACK.json` pins the downloaded Python SARIF, its original hosted
source identity and the inspected source files. Artifact `14275579692` belongs
to CodeQL run `43964930828`; the actual downloaded ZIP matches the API's
SHA-256 `cea2d0f0e89125af5d0020fe63bd624f99f842785549f1e31cb701147319e016`.

## Population and completed scope

The current full-source Python SARIF has 1,415 raw results: 1,307 path-injection,
53 file-permission, 52 command-line, one code-execution and two other results.
These are raw analysis records, not a PR comparison count or a count of proven
defects. This review addresses the shared `bounded_process.py` command sink and
two test-fixture findings. Other raw results retain their individual review
requirements; no alert is dismissed or suppressed here.

The command-sink record identifies **24 related origins**. Its four emitted
code-flow traces represent origins 1–4. The historical
[11 November review](../20261111-ci-completion/codeql-alert-review.md) traced
those four and left 19 of its then-23 origins outside scope. All six files used
for that earlier core review (`bounded_process.py`, `python_bootstrap.py`,
`git_provenance.py`, `android_runtime_control.py`, `android_sdk_package.py` and
`apple_sdk_profile.py`) retain identical Git blobs between that review's
`834c67183c403fd10d65600252ecbcb950c1af11` source and the selected source.

The table below disposes of all 24 origins at the selected source. Origins
5–24 were traced from their entry points through their actual command builders;
the SARIF does not contain twenty additional detailed traces. No additional
path from low-trust application data to executable selection or command code
was found in this inspected set. This closes the specific previously untraced
shared-sink origins, without claiming disposition of every raw Python result.

## Source-specific dispositions

Line numbers below identify the original SARIF origins at the selected commit.

| ID | Origin | Actual selection and command boundary |
| --- | --- | --- |
| 1 | `android_runtime_control.py:434` | The runner/operator supplies the SDK installation. `Control` selects its fixed `platform-tools/adb`; serial, package and lifecycle operations follow the existing bounded controller. This is selection of an installed tool, not executable selection from an app response. The historical reviewed source is unchanged. |
| 2 | `android_sdk_package.py:193` | The explicitly selected `JAVA_HOME` determines `bin/java`/`bin/javac`; injected JVM and loader overrides are removed. Version qualification checks the selected JDK. The unchanged historical review retains the operator's tool-trust responsibility. |
| 3 | `android_sdk_package.py:308` | `--gradle` explicitly chooses the build tool. The build tasks and project paths are constructed by the producer; artifact contents do not replace the executable. The historical reviewed source is unchanged. |
| 4 | `apple_sdk_profile.py:458` | `host_target` is selected from the producer's closed supported-target set before entering fixed compiler commands. The historical reviewed source is unchanged. |
| 5 | `ci_protoc.py:78` | `RUNNER_TEMP` selects a canonical private temporary installation directory, with CR/LF rejected. The executable is `bin/protoc` extracted only after the fixed HTTPS archive's size and SHA-256 match. Version and real schema compilation precede publishing the environment entries. |
| 6 | `codeql_memory_control.py:330` | `--codeql` explicitly selects a trusted execution tool. `--profile` maps a closed set to fixed heap/native/thread values; retained database/query identities and result-directory rules remain checked. Database bytes do not select a different program. |
| 7 | `codeql_summary_control.py:917` | CodeQL is an explicit tool input; allocation and summary modes are enums, with pinned database/query/plan inputs. The selected launcher's hash check occurs after version/help/ram invocations. Consequently the caller must select a trusted tool; this is not pre-execution isolation of an arbitrary malicious launcher. |
| 8 | `continuity_android_build.py:430` | Explicit canonical Rust/NDK/Java roots select fixed `bin/cargo`, `rustc`, `javac` and Clang paths. Source/report/tool identities, fixed native/class commands, offline resolution and removal of compiler/loader/JVM/Git overrides bind the build. |
| 9 | `continuity_host_exchange.py:226` | Native peers and provider are explicit code inputs, canonicalized and snapshotted. Fixed source-bound Python drivers receive them as parameters. The independent wheel is compared against source modules/licenses before an offline, hash-required installation. |
| 10 | `continuity_independent_install.py:92` | The executable is the current Python, with fixed isolated pip arguments, no index/dependencies/bytecode compilation and required hashes. The wheel is first compared with the selected source and copied to a captured URI; wheel fields do not become a command program. |
| 11 | `continuity_independent_python_run.py:437` | Bootstrap/probe/scenario programs are copied from compared source and run with fixed Python. Native/provider inputs explicitly select counterpart code; the public directory has a closed file inventory. Public receipts do not supply executable paths. |
| 12 | `continuity_package.py:646` | Compiler/JDK/Gradle/OpenSSL inputs explicitly select tools; build profiles and permitted combinations are closed. Clean source, SDK report and archives are checked before fixed build tasks and newly generated consumers are run. |
| 13 | `continuity_recovery_proof.py:258` | User inputs select an output location and a closed proof profile. Models/certificates/groups/thread/heap values come from the pinned catalog. The tool is the version-qualified `tamarin-prover`; proof content does not become command code. |
| 14 | `fanout_latency_review.py:171` | The expected head must be exactly forty lowercase hexadecimal characters before use in fixed `git archive` arguments; the baseline and prefix are fixed. Recorded executable paths are compared, not executed again. |
| 15 | `fanout_latency.py:212` | Host selection is closed and checked against the actual host. Cargo output must identify one canonical executable from the expected source inside this run's target directory; execution uses the fixed test and argument shape. |
| 16 | `jvm_sdk_package.py:358` | `JAVA_HOME` is absolute and PATH Java must agree with it. JVM/loader injection variables are removed; Java and javac are the explicitly chosen JDK's tools. Checking a version does not sandbox a malicious selected JDK. |
| 17 | `jvm_sdk_package.py:502` | `--gradle` deliberately selects the build program. Tasks are fixed; native archive/manifest pins, Maven/bytecode/dependency checks and installed-consumer checks retain their separate duties. Executing the selected project's build code is the intended operation. |
| 18 | `policy_maintenance_package.py:274` | A canonical toolchain root and recorded tools are explicit inputs. Cargo configuration/credential overrides are rejected; selected SDK archives/source and target/features are checked. Consumers are the newly built maintenance executable and its independently extracted counterpart. |
| 19 | `sdk_connection_performance.py:64` | `reconnects` is an integer restricted to 200–1000; output is a fresh directory under `target/`. Fixed build tools and captured binaries receive that number in a fixed measurement argument slot. |
| 20 | `sdk_installed_connection.py:246` | Explicit toolchains and independently pinned Swift/Rust archives are checked with override rejection, source/tool snapshots and actual static-link-map/archive identities. The final client must remain inside its owned build tree. |
| 21 | `test_codeql_rust_profile.py:364` | A test deliberately creates caller/checkout compiler scripts and `PATH=bin`, then verifies that changing the working directory cannot redirect the already selected caller tool. This is a controlled regression fixture. |
| 22 | `verify_anchor_vectors.py:235` | `--openssl` explicitly selects the independent oracle. Public fixture bytes become bounded message/key/signature files; fixed OpenSSL operations and arguments do not derive the executable from those bytes. |
| 23 | `verify_public_vectors.py:385` | The same explicit OpenSSL boundary applies. The rekey switch is boolean; algorithms/purposes and command shapes come from source, with independent grammar, length and signature rejection controls. |
| 24 | `wasm_sdk_package.py:328` | Node/npm are explicit canonical tool inputs. Archive/manifest pins and source comparisons precede use; npm uses `--offline --ignore-scripts`, scripts come from source and `node -p` code is fixed. Tools and artifacts are resampled after execution. |

`bounded_process` supervises process resources, output and ownership; it does
not isolate arbitrary toolchains. It validates argv elements and uses a separate
executable with no shell. Those mechanics support the source-specific boundaries
above. The caller's choice of compiler, CodeQL, OpenSSL, Node/npm, provider or
native counterpart is a choice of code to execute, not an ordinary low-trust
business input.

## Other inspected fixture records

The clear-text record at `test_release_binary_scan.py:210` writes public synthetic
test bytes into a temporary fixture, then requires scanner refusal without
echoing those bytes. It does not read or store a production credential.
The SHA-1 record at `test_apple_distribution.py:996` computes a compatibility
fingerprint over a synthetic certificate with `usedforsecurity=False`; the
fixture separately retains SHA-256. Neither observation changes a product
cryptographic algorithm or credential-storage path.

## Validation and remaining scope

`VALIDATION.json` records executed controls separately from this source review.
Existing tests exercise authenticated protoc intake, bounded argv/environment,
selected executable identity, target/source confinement, installed tool
replacement and archive/interface/runtime substitution. Historical runtime
qualification retains its original source identities; this review does not
rename it as a new native execution.

The completed dispositions above establish no new product/runtime defect in
their inspected scope. The remaining raw findings still need their applicable
source-specific dispositions in the aggregate release assessment. A green
analysis run and the existence of this review are not substitutes for that
remaining work, a normative freeze, signing or publication receipts.
