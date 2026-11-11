# Fresh revalidation of the four matched-auditor path findings

This is a new, actual execution after the earlier scratch snapshot loss. The reconstructed review and controls-observation.json remain unchanged. input-controls.log is the complete combined output captured from this fresh subprocess; it is not a reconstructed transcript.

All ten existing AuditInputBoundaryTests pass with exit code 0. Only these existing controls ran. No CI or complete native corpus was rerun, and the paper subtree was not modified.

## Published input identity

- Published paper commit: `df411f3b304fbcef04601098ad90cd226617b9c1`
- Published SDK commit: `1b47a1931cab2a944902316619cdcf479bd64ab0`
- Auditor Git blob in both: `b31a29f4c78b28b8dd20a3e0dbb356bf0adea238`
- Auditor SHA-256 in both: `6157726a6aa22f2bf8727da0680fc8f73293e8b129403e9ded53d2297cae658f`

The test file and public-manifest fixture are also byte-identical between the two published commits. All three per-commit blob IDs, SHA-256 values and byte counts are recorded in revalidation.json.

## Execution

Each of the three exact files was read using git show from the published paper commit and written to an independent temporary directory. The test therefore used the committed auditor, test module and retained fixture, without shared worktree edits. All three input hashes are unchanged after execution. The temporary directory was removed after capture.

A preliminary ordinary-clone attempt failed before test execution because the shared partial object store could not supply one unrelated promisor object. The receipt records that setup failure and the successful exact-input extraction method. The raw log describes only the actual test execution.

Command:

```sh
python -B -m unittest discover -s paper/continuity/artifacts/matched-comparison -p test_audit_input_boundaries.py -v
```

The receipt records the actual executable, full command, execution times and raw log hash. The controls cover traversal, leaf and directory symlinks, fixed corpus inventory, rejected unknown/duplicate/missing manifest names, file replacement, mutation during reading and parsed-byte/hash identity.

The finding-specific rationale remains in the preceding review: these four flows originate in the operator's documented compact_results positional input. This revalidation does not classify any other SARIF findings or dismiss any remote alert.
