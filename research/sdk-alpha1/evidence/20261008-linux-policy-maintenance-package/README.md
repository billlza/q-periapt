# Native Linux policy maintenance packages

PR CI run `37778711512` completed both Ubuntu 22.04 native package jobs:
arm64 `113319596512` and x86_64 `113319596680`. Each built the offline maintenance
command from the same-run exact crate cohort and executed all seven installed
migration/refusal/retry scenarios. This is native execution, not cross-compilation.
The reports retain glibc 2.35 and the actual Azure kernel; their broader
`minimum_os_execution_qualified` field remains false.

The workflow head is `33ca8c5c`; the tested PR merge commit is `6766bca4`.
Their full Git tree hashes are equal. Both identities and parent commits are
retained explicitly. Downloaded GitHub artifact IDs `11551810817` and
`11550934473` match the API-provided SHA-256 digests before report extraction.

A separate unprivileged local Linux aarch64 run also passed seven scenarios
on Debian 12/glibc 2.36 in the local VZ VM. Its crate cohort is `de2c49e9` and
builder is `33ca8c5c`; it is separate from the Ubuntu CI results.

The cases cover original-format conversion, already-current retry, oversized
independent state, missing-store refusal, corrupt transaction slots at 64 and
192, and final current-format retry. These installed scenarios alone do not
establish every authenticated-input, injected-I/O, process-cut or power-loss
property. CAPTURES.zip retains raw command results, case reports, inventories,
and API source/job/artifact metadata with per-member hashes. Candidate package
archives remain locally retained; no release or registry publication occurred.
