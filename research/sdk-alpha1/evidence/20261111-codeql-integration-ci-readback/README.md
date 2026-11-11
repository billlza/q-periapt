# Post-integration CI readback: 0aa4da50

This packet records the observed CI state for source commit `0aa4da50f6a28ad4abf3d15205452864346683b1`, tree `380aa20d15853c214b5d82f3f9f4f2228b62d8e6`. The workflow-job snapshot was taken at **2026-11-11 20:20:41 UTC**; the original failed-job log was independently read back at **20:22:16 UTC**. These are snapshots of ongoing workflows, not an all-jobs terminal result.

## Binary CT preparation failure

In [CI run 43091923386](https://github.com/billlza/q-periapt/actions/runs/43091923386), job [130771136263, Binary CT [x86_64-portable]](https://github.com/billlza/q-periapt/actions/runs/43091923386/job/130771136263) failed while preparing Valgrind:

| Boundary | Observed result |
| --- | --- |
| Valgrind preparation step | 20:04:51–20:05:12 UTC; failure |
| Actual failing command | `apt-get update` inside the fixed `artifact/ci_apt.sh` |
| Mirror and suite | `https://mirrors.edge.kernel.org/ubuntu`, `resolute` |
| IPv6 endpoint | `2605:f480:58:1:0:1994:3:14`: network unreachable |
| IPv4 endpoint | `142.0.200.124`: connection timed out |
| Exit code | 100 |
| CT harness build and Memcheck consumers | All four subsequent build/test steps skipped |

The log records failed InRelease retrieval for the base, updates, security and backports pockets. The source executes update before install under `set -euo pipefail`; update failed before Valgrind installation and CT execution. This observed failure is a repository-connection failure, not a signature or package-downgrade rejection.

The exact fixed helper is retained in `source/ci_apt.sh`. It uses the same isolated source/list/cache configuration for update and install, the runner's Ubuntu archive keyring, HTTPS, signed repository metadata, explicit date/validity checks, and a shared 360-second deadline. It preserves APT's configured architectures and variants. The existing authentication and downgrade protections were not relaxed.

`FAILED_JOB.log` is the full retrieved log: **40,715 Unicode characters / 40,717 UTF-8 bytes**, SHA256 `fc67ef7f11459edc2311768ebbafb0da7eefc9d78f812ac6881c64e48286e139`. The root agent successfully obtained it through the workflow-job-log connector and retained public Git blob `600380ddd58f5b824b7f8001ac236916999eb8ad`. The publishing agent independently fetched that blob and checked the complete bytes. `FAILURE_EVENTS.json` provides exact line references into that unmodified log.

## Actual rerun request and rejection

At **2026-11-11 20:13:26 UTC**, the root agent requested a rerun of job `130771136263`. GitHub returned HTTP 403:

> The workflow run containing this job is already running

`ROOT_RERUN_REJECTION.json` retains the request identity and a serialized copy of the root's actual tool response, explicitly attributed to the root. **No rerun succeeded.** The publishing agent did not invoke or repeat that request.

## CodeQL snapshot

[CodeQL run 43091923478](https://github.com/billlza/q-periapt/actions/runs/43091923478) was still incomplete:

| Job or group | Snapshot result |
| --- | --- |
| Python, Java/Kotlin, C/C++, Actions analyses | All four completed successfully |
| Rust WASM, job 130770903434 | In progress; entered `Compile and extract the actual target` at 20:19:52 UTC |
| Rust native, job 130770903018 | Pending; no steps recorded |
| Swift, job 130770904124 | Pending; no steps recorded |
| Prepare Rust (macos), job 130770904678 | Pending; no steps recorded |

The WASM progress is compilation/extraction. Its complete security-query step had not yet executed in this snapshot. The original run-level API state is also retained without alteration; the job table above uses the actual job and step records rather than inferring progress from the coarser run-level label.

### Aggregate check comparison

The current head's CodeQL aggregate check `130771382809` and previous source `3b042375d4ac8e40b10d07941595341a6cc9b807` check `130713518049` both report **failure** with title **“2 configurations not found”**. Both complete summaries list missing `/language:rust` and `/language:swift` configurations and report **12 critical / 513 high** alerts.

The two titles and complete summary strings are byte-for-byte equal. Each summary is 641 UTF-8 bytes, SHA256 `a65d4fce89513bc456380f19645cff5477a94b86ea636c7ab7d8225b33036c0a`; both objects report `annotations_count=103`. This comparison covers the aggregate text and count metadata. Individual annotation contents were not retrieved or compared.

The two complete selected API objects are retained in `CODEQL_AGGREGATE_CURRENT.json` and `CODEQL_AGGREGATE_PREVIOUS.json`. Retrieval used only `commits/<sha>/check-runs`; no individual check-run or annotations route was called.

## JoC result and provenance

[JoC run 43091923693](https://github.com/billlza/q-periapt/actions/runs/43091923693), bound to the same source commit, completed successfully.

`PROVENANCE.json` states exactly which files preserve connector-returned text, which are complete selected API objects reserialized as JSON, and which are derived summaries. Source, run and job identities remain separate. `SOURCE_COMMIT_API.json` records the source tree and its three parents. `SNAPSHOT.json` is a compact derived index into the original records.

This packet is a child of evidence commit `f0e0e4950319973cf202b368c9ad360f0bb6f970`. `MANIFEST.sha256` covers every published file other than itself. Publication used only Git-data objects and readback; no reference, production source or workflow was changed, and no new experiment was launched.
