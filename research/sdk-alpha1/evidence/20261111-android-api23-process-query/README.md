# Android API 23 framework process query

The framework readiness failure is explained by the Android 6 process selector, while the service checks already succeed. The patch replaces `pidof system_server` with `pgrep '^system_server$'`. It preserves the existing single-PID and process-incarnation checks and the readiness time budget.

## Observed failure

SDK source `faabcff16fc49e1a99388c68f0991a2bfd64d509`, run `43010024394`, job `130507717890` failed before installing the consumer on the API 23, x86_64, 4 KiB emulator. The original diagnostic artifact is `13857122005`: 182,335 bytes, SHA-256 `14e0532aa10e451fbf0b3ae71396e0f51791b3e5885fa8699585e9f34133f50f`.

All 67 recorded samples have guest status 65 and an empty body for both process-identity probes. In every sample, both boot checks, both decrypt checks, Settings, Package Manager and package absence succeed. The 66 completed observations report `guest-query-nonzero`; the final owner check reaches the existing shared deadline. The before/failure process snapshots both contain a live `system_server` at PID 1932.

The original frame correctly preserves the guest failure even though this legacy ADB transport reports host exit zero. The failure is therefore visible in the retained evidence and is not masked by the successful service queries.

## Platform source and repair

The official Android 6.0.0 Toybox `names_to_pid` implementation compares `basename(cmd)` and `basename(name)` in one `strcmp`. The corresponding Bionic POSIX implementation returns the same thread-local output buffer for both calls. The second result overwrites the first, admitting unrelated readable processes for a nonabsolute name. Toybox `pidof` prints the resulting PIDs separated by spaces, which the current single-PID guard rejects.

AndroidX also records the API 23 behavior explicitly. `SOURCE_REFERENCES.json` binds the official source URLs, decoded byte sizes, SHA-256 values and Git blob identities. The failed image identifies itself as `6.0/MASTER/6695544`; its raw `pidof` text was not retained, so the platform-source explanation is distinguished from a direct execution or binary attestation of that image.

Android 6.0.0's `Android.mk` builds and installs `pgrep`, and `generated/config.h` enables `CFG_PGREP`. The anchored pattern uses the regex success result. It deliberately avoids the old `-x` implementation, which inspects match offsets after compiling with `REG_NOSUB`.

Only the lookup command changes. The existing guard continues to reject empty, multiple and noncanonical PIDs; the host parser still requires matching PID/stat identity, the exact process name, a live state, boot UUID and start time. The before/after service checks, consecutive samples, five-second stable interval, 120-second total budget and owned-runtime checks remain intact.

## Executed verification

| Verification | Result |
| --- | --- |
| Original process query with the real generated shell program and the legacy `pidof` fixture | Expected failure; guest exit 65; 1 test in 0.025 seconds |
| Revised query and all framework-related tests | 10 tests passed in 2.587 seconds |
| Missing/failed query; empty, multiple, malformed and space-suffixed PID outputs | Rejected with preserved guest status |
| Existing zombie, PID reuse, reboot, provider, ownership and deadline cases | Passed in the same 10-test set |
| Git whitespace check | Passed |

The shell fixtures execute the production-generated guest program on the host. They do not launch an emulator or execute the Android image's binaries. The original red log and the final green log are preserved unchanged, with exact source hashes in their receipts.

The patch is local commit `b5ebe15063e2dc2c55f84c6cf6dd53d77fe2fceb`, tree `6f61d301ec0b20e42ab5b537a6ad324a8877149d`, parent `df766de8eeeb99d55d3a161e1ca57c47a25db604`. Author and committer are the project owner's explicit identity. No remote ref or device run was changed by this diagnosis.
