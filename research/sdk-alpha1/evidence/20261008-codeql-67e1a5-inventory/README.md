# CodeQL inventory for 67e1a5b0

Rust job 113515487851 completed analysis, the database quality gate, SARIF upload
and diagnostic retention successfully. This is not a passing aggregate security
review: PR check 113516080666 reports 1,607 new alerts (178 critical, 1,383 high,
46 medium). The PR merge ref has 1,616 open alerts. These are different scopes;
neither count represents individually confirmed vulnerabilities.

The PR merge is `f4c28bad22afb06f61a0b5fdbb0068a9631265a2`; its recorded parents
include source head `67e1a5b03bf263ab175bc2261e4b70413ce8d79f`. The retained Rust
SARIF has 809 results. `INVENTORY.json` preserves counts by rule, and
`INVENTORY.zip` contains the exact SARIF, job/check metadata, complete open-PR
alert inventory, initial 100 annotations and the merge identity. The raw Rust
diagnostic ZIP was also downloaded and SHA-256 checked; its 472 MB payload is
retained locally, not duplicated into repository history.

This record completes no new alert dispositions. Initial source inspection found
command/path reports in qualification harnesses and hard-coded-value reports
whose source locations include `Ok(false)`/`Ok(true)` and an enum derive. Their
SARIF paths reach actual journal AEAD key sinks; the location alone is insufficient
to accept or reject those flows. Existing earlier-source dispositions are not
silently applied to this new inventory. Actual dataflow, trust boundaries and
sink coverage still require review. No remote dismissal, query suppression,
security-parameter change or release-readiness claim was made.
