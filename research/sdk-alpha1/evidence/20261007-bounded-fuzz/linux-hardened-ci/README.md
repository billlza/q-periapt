# Hardened Linux fuzz execution and workflow regression

[Run 37684982568](https://github.com/billlza/q-periapt/actions/runs/37684982568)
passed all three targets and the statistics check through the repository's
hardened Python runner. Its auxiliary commit `c3ed0ac9` has the exact non-workflow
source and fuzz job/environment of product `6ece94f2`. Executed callback counts:
1,637,557 (combine), 1,112,288 (ML-KEM decapsulation), 30,946,018 (transport).
These include early input rejections and are not cryptographic operation counts
or a throughput benchmark. The full artifact download matched the service's
SHA-256 and every ZIP CRC was verified; logs and all final corpus members remain
here with byte identities.

The product CI at `4fc8412a` additionally exposed stale toolchain expectations and
a direct-Python invocation in the new fuzz step. `6ece94f2` preserves the exact
checks, updates the closed setup count and dated nightly selector, and routes
statistics through the existing hardened launcher. Its 2,631 artifact tests
passed from a clean standalone checkout in 560.362 seconds. Real fuzz logs pass
the updated statistics invocation; missing, zero, duplicate and nonnumeric
counts fail. Full raw test logs are losslessly encoded as base64+gzip with hashes.

This qualifies the corrected isolated fuzz job and those local artifact tests;
it is not full product CI, later proof-gate source qualification, stateful
Continuity fuzz coverage, memory-safety proof, or release approval.
