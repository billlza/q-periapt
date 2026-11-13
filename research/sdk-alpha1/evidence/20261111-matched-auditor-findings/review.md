# Review of four matched-auditor path findings

## Reconstruction notice

The original scratch review files and test transcript became unavailable after an executor filesystem snapshot change. This record reconstructs only facts already observed in the completed investigation. It does not recreate raw test output, invent unavailable archive hashes, or claim another test execution. The companion controls-observation.json is explicitly an observation record.

## Decision and scope

Recommend false-positive disposition for **only these four py/path-injection findings** under the documented local CLI contract. Their source is the operator's positional compact_results file argument, and reading that independent input is the command's intended function. No retained-JSON path escape or wrong-input acceptance was demonstrated for the four reported flows. The auditor, historical evidence and manifests were left unchanged. No alert was dismissed.

## Evidence identity

The public [canonical check](https://github.com/billlza/q-periapt/runs/130189943527) exposes four high annotations on paper/continuity/artifacts/matched-comparison/audit_matched_traces.py: two on line 66, one on line 67 and one on line 71. The original CodeQL run 42855086715 had an empty downloadable artifact list.

Exact fingerprints, columns and source/sink paths were inspected in the retained SDK codeql-python.zip from run 42959257074, analyzed merge 834c67183c403fd10d65600252ecbcb950c1af11 and tree 0f281a963c2bd0e6f203c025a99d507ae73da9c2. Git object comparisons established identical auditor bytes at that merge, old canonical 11e113f2, updated canonical local f457712a and SDK 0e2b23dd:

- Blob: b31a29f4c78b28b8dd20a3e0dbb356bf0adea238
- SHA-256: 6157726a6aa22f2bf8727da0680fc8f73293e8b129403e9ded53d2297cae658f
- Length: 18,157 bytes

The current source identity is recorded in integration_record.json and the subsequent path-review-20261110/INDEPENDENT_REVIEW.json. The original artifact_manifest.json retains the earlier auditor identity 235e93ccab4e4491e97ca0c28dff586077cf0a61502a61240cc7f3930f0d1bd1; it was not rewritten.

## Four findings

All four use rule py/path-injection, security severity 7.5, and source parser.parse_args() at line 318 through read_bytes(args.compact_results) at line 327. The argument is declared at line 316.

| Location | Sink | primaryLocationLineHash | Start-column fingerprint |
| --- | --- | --- | --- |
| 66:13 | path.is_file() | 7b762e037ad48810:1 | 8 |
| 66:36 | path.is_symlink() | 7b762e037ad48810:1 | 31 |
| 67:14 | path.lstat() | 65683eeb168f5892:1 | 9 |
| 71:10 | path.open("rb") | 494b83a68acd89fc:1 | 5 |

Public check annotation IDs, in displayed order, are 103262164775, 103262164946, 103262165155 and 103262165396. These are **not Code Scanning alert numbers**. Both first IDs refer to line 66; their column assignment was not visible and is not asserted. Security alert IDs were not retrieved.

## Actual input boundary

The documented command selects compact_results independently of the extracted evidence directory, commonly using the repository's compact JSON and an externally unpacked evidence directory. Its profile/scenario fields index expected results; they do not construct filesystem paths.

Manifest JSON is a separate input. manifest_records admits exactly 126 code-generated names. Its path fields validate that fixed set and index expected size/hash metadata. Filesystem reads iterate EXPECTED_MANIFEST_PATHS. manifest_path rejects noncanonical and escaping forms, Windows drives and backslashes, checks every component for symlinks, and requires resolved containment in the selected evidence root. read_bytes checks regular-file type, pre-open versus opened descriptor identity, and post-read identity and consumed size.

Requiring compact_results to share the evidence root would reject the documented invocation rather than repair the reported flow. No new wrapper or source suppression was proposed.

## Observed verification

All ten existing input-boundary controls were actually run and passed before the filesystem reset, with process exit 0 and unittest result OK. They cover traversal, leaf/directory symlinks, unknown/duplicate/missing manifest members, stat/open replacement, mutation during reading, and parsed-byte/digest identity. Their names and exact command are in controls-observation.json.

The existing independent source review also records unchanged recount values for all 49 compact rows and 126 manifest hashes. That full corpus was not rerun during this investigation. No claim about other SARIF findings or the check's separate missing Rust/Swift configurations is made.
