# Current CodeQL finding delta and selected source review

## Result

The Linux dependency bootstrap adds **11 Python path findings**. Their reported
sources are the runner's `RUNNER_TEMP` (nine findings), `GITHUB_ENV` (one), and
`GITHUB_PATH` (one). The existing 1,404 Python result identities are all retained;
the three C/C++ results also remain unchanged. The review of the new installer,
the three rare Python rules, and all 53 permission findings identifies no source
repair required for those specific reported flows under their documented local
operator, test, and public artifact roles.

This is an internal disposition of the flows named below. GitHub's aggregate
check remains failed and reports missing Rust/Swift configurations plus 12
critical and 513 high PR findings. Those 525 findings are not declared resolved.
The previous 14-annotation review is a different scope and is not reused here.
No findings, queries, assertions, or platform checks were suppressed or dismissed.

## Exact inputs

| Input | Previous | Current |
| --- | --- | --- |
| SDK source | `75eda8f54a721dbed16a0bed43cdc493c9071485` | `2f42d2ce913421f9b7a7df39fbc56845d55717de` |
| Analyzed PR merge | `b72f7f8e8e6f2526ebab4b825b7d47402ac9835f` | `706207d11ddfc6371176698fd302b20d7714bbdb` |
| Tree | `e992a9077e657e63c6b698527d26fe81ad67c535` | `81e8aa8047e9e54e9f98ea18fc25c616cb557425` |
| Workflow run | [43050342732](https://github.com/billlza/q-periapt/actions/runs/43050342732) | [43059460437](https://github.com/billlza/q-periapt/actions/runs/43059460437) |
| Aggregate check | [130632435561](https://github.com/billlza/q-periapt/runs/130632435561) | [130659838915](https://github.com/billlza/q-periapt/runs/130659838915) |
| Aggregate PR finding count | 12 critical / 502 high | 12 critical / 513 high |

The aggregate summary and complete SARIF census are different scopes. Current
Python SARIF contains 1,415 results: 1,307 path injection, 52 command injection,
53 overly permissive file, and one each code injection, cleartext storage, and
weak hashing. Current C/C++ SARIF has three path results; Actions and Java/Kotlin
have zero. `READBACK.json` reproduces these counts from the six original ZIPs and
verifies their API sizes, SHA-256 digests, member bytes, and source receipts.

Result identity here means the tuple of rule ID, primary URI/region, and CodeQL
partial fingerprints. All 1,404 previous Python identities are preserved and
exactly 11 new identities point to `artifact/ci_protoc.py`. Removing only SARIF
table-index fields leaves 1,388 complete prior Python result structures equal;
16 retained identities have different flow/related-location representations.
Those representations are not called identical. The changed representations
mention 55 source files: all 54 existing files have identical Git blobs between
the two SDK sources, and `ci_protoc.py` is new. The shared process finding also
gains a related source at `ci_protoc.py:78`; this added caller is assessed below.
All three C/C++ complete result structures are equal after table-index removal.

The connector supports the commit check collection and workflow artifacts but
rejects direct check annotation and code-scanning alert endpoints. The retained
aggregate reports 103 annotations; the 525 PR-alert-to-annotation mapping was
therefore not reconstructed. The source review uses the actual full SARIF files.

## New installer and shared process boundary

| Reported sink | Actual source and behavior | Disposition |
| --- | --- | --- |
| `ci_protoc.py:48` (two), `53`, `55`, `59`, `64`, `69`, `71`, `78` | `RUNNER_TEMP` at line 78 selects the runner-owned temporary parent. `mkdtemp` creates a fresh private child. Exact release size and SHA-256 are checked before extraction; archive entries do not select the parent. Child paths are fixed `bin/protoc`, `bootstrap.proto`, `bootstrap.pb`, and `include`. | Intended CI filesystem authority. A job operator already controls its runner paths; the bootstrap does not accept these values from package or protocol input. |
| `ci_protoc.py:85` | `GITHUB_ENV` at line 79 selects GitHub's per-step environment command file. Publication follows exact archive verification, compiler version checking, and actual imported-schema compilation. | Intended runner command-file output. The generated path is confined to the new private child and the parent rejects CR/LF before publication. |
| `ci_protoc.py:87` | `GITHUB_PATH` at line 80 selects GitHub's path command file. The exported executable directory is the verified private child's fixed `bin`. | Intended runner command-file output under the same trust boundary. |
| Existing `bounded_process.py:356` command finding, added related source `ci_protoc.py:78` | The installer calls fixed `/usr/bin/curl` with fixed HTTPS URL/options; subsequent calls select the newly hash-authenticated `bin/protoc`, with fixed flags and private fixture paths. `Popen` uses an argument list, `executable=command[0]`, and `shell=False`. Download and execution are bounded. | This caller intentionally executes the authenticated tool. The shared helper enforces process ownership and budgets; it is not an authorization layer for arbitrary command selection by other callers. Existing callers retain their own review scope. |

Source and workflow call-site identities are retained in `source-bindings.json`.
Changing the runner environment is not a network-input exploit in this reported
flow. This disposition does not authorize exposing the installer or shared
process helper as a service that accepts untrusted paths or commands.

## Rare Python rules

| Finding | Exact data and source role | Disposition |
| --- | --- | --- |
| `py/code-injection`, `python_bootstrap.py:44` | The source is local `sys.argv[1:]`; `-c` intentionally compiles and executes the operator's supplied Python expression. The launcher is the isolated equivalent of a Python CLI, with `-I -S -B`, repository import roots, and cleared Python startup environment. | Intended local interpreter interface. Isolation protects startup/import behavior; it does not sandbox deliberately supplied Python code. No remote protocol-to-code source is present in this reported flow. |
| `py/clear-text-storage-sensitive-data`, `test_release_binary_scan.py:210` | A unittest writes the public synthetic literal `ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345` into a disposable `secret.bin`, then asserts that `scan_release_file` rejects it as a GitHub-token-shaped string and does not echo it. | Deliberate scanner rejection fixture, not storage of an operational credential. |
| `py/weak-sensitive-data-hashing`, `test_apple_distribution.py:996` | A unittest's certificate bytes are the literal `pinned-developer-id-certificate`; SHA-1 is computed with `usedforsecurity=False` to model an Apple identity fingerprint. The fixture separately computes SHA-256 for the certificate binding. | Test identity-format fixture; no trust decision using SHA-1 is established by this reported sink. |

## All 53 permission findings

`permission-findings-context.json` retains every path, line, containing class /
method, exact source excerpt, and CodeQL message. There are **six runtime public
artifact operations** and **47 operations inside unittest classes**.

| Source file | Count | Reviewed role |
| --- | ---: | --- |
| `platform_distribution.py` | 4 | `assemble` creates the public release directory as 0755 and public distribution inputs, manifest, and checksum list as 0644. The input filenames are the closed public release asset contract, not private publication receipts. No group/world write bit is granted. |
| `third_party_licenses.py` | 2 | `_publish_inventory` writes distributable license texts and `INVENTORY.json` as 0644. These are public package contents. No group/world write bit is granted. |
| `test_apple_release_verification.py` | 4 | Unsafe executable and directory modes are deliberately introduced, followed by rejection assertions before external tool use. |
| `test_apple_stable_publication.py` | 7 | Disposable public distribution, result, and extraction fixtures, including owned group-readable workspace-parent setup. Private receipt and verification roots remain private in these fixture setups. |
| `test_bounded_process.py` | 1 | Deliberately changes a private stdin fixture to 0644 and asserts the mode-0600 admission requirement rejects it. |
| `test_deterministic_archive.py` | 1 | Changes a public README's mode to verify deterministic archive normalization. |
| `test_crates_io_publication.py` | 2 | One wrong-mode journal rejection fixture and one test-only `os.open` forwarding wrapper used to inject a resampling race. |
| `test_platform_candidate_verifier.py` | 3 | Public fake executable plus non-private root rejection cases. |
| `test_platform_candidate_attestation.py` | 3 | Non-private parent/root/snapshot mutations, each followed by admission rejection. |
| `test_platform_distribution.py` | 4 | Corrupts public assets, inventory, and checksums to exercise race/drift rejection. |
| `test_platform_stable_publication.py` | 6 | Public release simulation, asset mutation, and owned-parent versus world-writable/symlink-parent qualification. |
| `test_publication_receipt_io.py` | 13 | Private-boundary mode mutations and their rejection assertions, owned-parent setup, and five test-only `os.open` forwarding wrappers for open/close/rename interruption tests. |
| `test_source_results_assembler.py` | 3 | Public result fixtures at `PUBLIC_FILE_MODE` exercise exact source-blob and baseline admission. |

The six forwarding-wrapper findings (one crates-publication test and five receipt
tests) inherit the `os.open` default mode in their signatures and pass through the
real caller's mode. The reviewed production receipt creation sites pass
`PRIVATE_FILE_MODE` (0600); opens without `O_CREAT` do not create a file using the
default mode. These wrappers exist within rejection / fault-injection tests.
The world-writable chmod cases likewise occur within tests deliberately creating
unsafe metadata. No production world-writable permission sink appears among
these 53 results. The public 0644/0755 distribution operations should retain
their readable modes; restricting them would change the intended release format.

## C/C++ retained findings

The three identical C/C++ path results occur in the qualification consumer:
`setup_client.c:20` and `sync_probe.c:89,95`. They use explicit harness environment
variables for the probe target/log. Existing opens require absolute paths and
use `O_NOFOLLOW`; target/log metadata checks enforce current ownership, ordinary
files, mode 0600, and one link where appropriate. Log creation uses `O_EXCL` and
0600. These are controlled sync-fault observation hooks. This review identifies
their source role and confirms unchanged results; it does not mark the aggregate
or unrelated package consumers clean.

## Reproduction

Run `python3 qualify_alert_delta.py` in this directory. The script is read-only
with respect to the original ZIPs and regenerates `READBACK.json`. Source bindings
can be checked against the exact SDK commits using `git show <commit>:<path>`.
This review changed no repository source and launched no new CI job.
