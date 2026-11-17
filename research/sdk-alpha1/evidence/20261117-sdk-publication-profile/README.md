# SDK publication profile qualification — 17 November 2026

This packet retains read-only execution through the explicit SDK 0.2.0 GitHub
CLI profile. It is not a 0.2.0 publication receipt.

The installed macOS ARM64 CLI 2.103.3 binary was compared byte for byte with
`bin/gh` in its [official immutable release archive](https://github.com/cli/cli/releases/tag/v2.103.3).
The ZIP SHA-256 is
`d700207eae9ae98fe2b89535c2c087c07823d4628c56364695a5a07ef311c062`,
also present in the retained upstream checksum manifest. The executable's
38,931,264 bytes have SHA-256
`5f8d7527e2bdf584249b030cdd1550c91d75e8afb40aa3c11573d416817a1260`.
No installation was performed. The ZIP remains in the task's local evidence
cache; its public URL and checksum permit independent retrieval.

`sdk-github-tag-readback.json` records two complete samples of both exact new
tag refs. Both were absent. This read did not create a tag or alter rulesets.

The same pinned executable performed an actual `release view` and cryptographic
`release verify` against the already published `v0.1.5` release. The existing
maintenance contract independently supplied release ID `383170350`, annotated
tag object `47162c5cc4d5d64d2c6d1c6f178db0a176e419bf`, commit, asset names and
digests. The shared strict readers accepted all four original assets and the
GitHub release signature's exact subjects and timestamp. The raw public view
and verification output are retained with their hashes in `INPUTS.json`.
This establishes current CLI/reader compatibility, not new SDK qualification.

The [operator contract](../../../../docs/SDK_GITHUB_PUBLICATION.md) describes the
separate SDK admission and plan schemas, unchanged shared transaction engine,
private state namespace, source/evidence relationship and fresh postpublication
verification. Its fault-oriented unit fixtures use synthetic packages and a
deterministic remote model; those controls do not claim real publication.
