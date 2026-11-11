# Continuity 0.2.0 Linux service distribution execution

The published source produced the five Linux Release service executables, a
complete distributable archive, successful installed-process checks, and an
accepted 14-node SDK/engine/service candidate package graph. The retained
published-source regression log records **90 passing tests**.

## Exact source and result

- Execution source: [`e314717842328f6f706d081753b52eb887061d1a`](https://github.com/billlza/q-periapt/commit/e314717842328f6f706d081753b52eb887061d1a).
- Execution tree: `de95f4e1e9ac98345eab0b91664e15b78616548d`.
- Distribution: `q-periapt-continuity-services` **0.2.0**, `x86_64-unknown-linux-gnu`.
- Original Cargo package: `q-periapt-continuity-reference-app` **0.0.0**, `publish = false`.
- Service archive: **7,024,604 bytes**, SHA-256
  `7612477540409b5fe09495767451983fb949151861773603e70162d80e63de01`.
- Archive contents: **417 regular files and 218 directories**; five executable
  files, public documentation, and notices for **209 production dependency
  packages**, including six explicitly verified upstream supplements.

This evidence directory is added after that execution source was published.
Its later Git commit preserves results; it is not the source of the recorded
build. [SOURCE_BINDING.json](SOURCE_BINDING.json) verifies all 15 production
files against the original reviewed bytes and the actual published source.

The installed processes reopened the original SDK authority, protocol
publisher, witness, and directory signer; read back the original SDK policy
outputs byte for byte; rejected three wrong identities; and retained the
directory ledger after refusing reinitialization. The original empty lookup
also returned the expected refusal. The archive contains no generated private
service state. Runtime library and symbol-version requirements are recorded
for each actual executable in the package receipt.

The independent archive readback checked every content digest, permission and
allowed path. Reconstructing the archive from the extracted compiled inputs
produced the identical archive hash and size. That reconstruction uses the
same compiled binaries. The package graph readback used the 14 original Cargo
manifests and the actual typed service receipts and artifact.

## Retained evidence

[SUMMARY.json](SUMMARY.json) indexes the results. Original primary receipts
are also readable directly here:

- [CONTINUITY_SERVICE_PACKAGE.json](CONTINUITY_SERVICE_PACKAGE.json)
- [CONTINUITY_SERVICE_INSTALLATION.json](CONTINUITY_SERVICE_INSTALLATION.json)
- [CONTINUITY_SERVICE_PACKAGE_GRAPH_READBACK.json](CONTINUITY_SERVICE_PACKAGE_GRAPH_READBACK.json)
- [CONTINUITY_SERVICE_ARCHIVE_READBACK.json](CONTINUITY_SERVICE_ARCHIVE_READBACK.json)

[CAPTURE.tar.gz](CAPTURE.tar.gz) is the self-contained public execution capture.
Its checksum and complete preservation/readback result are in
[CAPTURE_READBACK.json](CAPTURE_READBACK.json). Extract it to obtain
`q-periapt-service-execution-20261110/`:

| Capture directory | Original retained material |
| --- | --- |
| `published/` | Actual service archive, six JSON receipts, 36 command records with original stdout/stderr, and 14 original manifests. |
| `initial-failure/` | Original failed producer receipt and build logs, traceback, and missing-license inventory. |
| `diagnostic/` | Earlier sparse-source build and copied-binary readback receipts with their original scope and command output. |
| `review/` | Independent implementation and license reviews, upstream-source controls, Cargo ancestor-configuration control, graph readback script/output, and archive reconstruction receipt. |
| `tests/` | The exact 90-test log from the published source. |
| `source/` | Original reviewed/published source payloads, byte-verified source binding, and the earlier local-source Git bundle. |

`CONTENTS.json` records each captured input's byte count and SHA-256. The
capture contains only the explicit public output list; generated private
runtime state remains outside the capture and the distributable archive.

The earlier full producer attempt used local commit
`3085e38565e354ef708e63148a4089015fcc3eec`, tree
`0cc98900c9c4afa056eef017bf39ba8d9ca85bad`. It built the binaries and stopped
with `dependency has no distributable license text: asn1-rs-impl 0.2.0`, before
emitting an archive or package row. The fix authenticates missing notices
against the selected registry archive checksums and exact upstream Git blobs.
The earlier diagnostic build and copied-binary checks retain their separate
diagnostic identity. Their source bundle requires the public prerequisite
`0e2ca2d79ab0000bed79130cec97b31181e936ea`; `git bundle verify` output is retained.

## Reproduction and admission scope

For a fresh build, use a complete clean checkout of the exact execution
commit, Rust 1.98.1, CPython 3.14.7 and the
[documented producer command](https://github.com/billlza/q-periapt/blob/e314717842328f6f706d081753b52eb887061d1a/docs/continuity/SERVICE_DISTRIBUTION_0_2.md#build-and-retained-evidence).
For independent graph replay, copy the original package, installation,
distribution and row receipts plus the service archive from `published/`
into a fresh output directory, then run the captured
`review/service_package_graph_readback.py --source CLEAN_SOURCE --output FRESH_OUTPUT`.
The script writes its receipt exclusively and checks the exact source identity.

This closes the service distribution producer and its actual Linux execution
and manifest-connection gap. Coordinated release admission and existing
account/cross-client qualification retain their separate receipts; the
recorded release-eligibility and formal-account flags remain false.
