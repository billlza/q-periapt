# Canonical temporary paths for analysis-receipt tests

The macOS CodeQL preparation failure is fixed by canonicalizing the temporary
root in the analysis-receipt test fixture before deriving its query-pack and
evidence paths. The production entry point already canonicalizes its query pack.
The new regression uses a real `var -> private/var` directory symlink and checks
all three receipt cases: unchanged inputs, replaced `PROFILE.json`, and replaced
`results.sarif`. The existing assertions continue to require receipt hashes for
the bytes actually validated.

## Observed failure

- Repository: `billlza/q-periapt`.
- CodeQL run: `42608385539`, attempt `1`.
- Job: `129183821957`, `Prepare Rust (macos)`.
- Run head: `a4c089570c787522210d16226219c0cc8aa9b05e`.
- Checked-out merge: `4d271f208fabd59636573c24376ddef15dadf475`.
- Host: macOS `26.7.2`, runner image `macos-26-arm64`, image version
  `20261102.0473.1`.

The preflight ran 158 tests and reported three errors in the new analysis-receipt
snapshot tests. Each reached `ValueError: query outside pinned Rust pack`.
`analyze()` resolves each query before testing containment in the query pack;
the fixture passed its unresolved temporary path as the pack. A macOS temporary
directory reached through `/var` therefore differs from its physical
`/private/var` path. Resolving the fixture root matches the production call
contract and the existing older analysis fixture.

The CodeQL setup, target extraction, transfer export, and transfer binding steps
were skipped after the preflight failure. The two subsequent upload steps found
no transfer or extraction-evidence paths. Their missing-file errors are a
consequence of the preflight failure. The full decoded GitHub job log is retained
as `github-macos-job.log`; it is the UTF-8 encoding of the connector's decoded
log, not a claim about the original HTTP archive bytes.

## Source and patch

The local base is integration commit
`360aa8107aa7df502108627a4dcf89f30d106594`, tree
`05c75d9d5848814a8b6b988df5e0c1240bec081a`. Its
`artifact/test_codeql_rust_profile.py` is byte-identical to that file at the failed
merge checkout. Its previous Git blob is
`7250b4c7076a522fd6c4ec6807dffc35dc132bc4`. The patch changes only that test file;
production query containment, evidence access, publication, and upload guards are
unchanged. `patch.diff` records the complete code change.

## Local verification

The interpreter was `/usr/bin/python3.12`, Python 3.12.3, through the repository's
`artifact/python-run.sh` hardened launcher on Linux x86_64.

| Execution | Result |
| --- | --- |
| Baseline, normal temporary parent, eight CI preflight modules | 158 passed |
| Candidate, normal temporary parent, same modules plus new regression | 159 passed |
| Baseline, original three receipt tests under real symlinked temporary parent | 3 errors, expected red control |
| Candidate, same three tests and alias | 3 passed |

The Linux red control rejects the noncanonical evidence path at its no-symlink
opener before it reaches query containment. The recorded macOS failure instead
reaches query containment. Both executions expose the same unresolved fixture
root; the red control is not represented as a native macOS execution. CodeQL
query execution in these existing unit fixtures is mocked, while directory
creation, symlink traversal, path replacement, hashing, receipt production, and
the production guards invoked by the fixture run normally.

64 required source blobs were downloaded at the pinned commit and verified by
their Git blob hashes. The original workspace was unavailable, so the inventory
tests use Git index metadata replayed from the exact API tree. Reconstructing
that index with `git write-tree --missing-ok` yields the pinned tree above, and
the index contains 1,173 tracked Rust paths. This is source-list verification,
not a complete source checkout or a Rust compilation/extraction result. The
downloaded-file identities appear in `source-pins.json`. An initial sparse setup
attempt lacked the Git index, Cargo manifests, and policy-vector fixtures; its
six setup errors are retained in `sparse-setup-preflight.log`. After those exact
prerequisites were restored, the complete preflight executions above passed.

## Reproduction in a complete checkout

Run the following command at the base commit and again after applying the patch:

```sh
sh artifact/python-run.sh -m unittest -v \
  test_codeql_rust_quality test_codeql_consumer_context \
  test_codeql_target_coverage test_codeql_compiler_sources \
  test_codeql_cargo_metadata test_codeql_rust_profile \
  test_codeql_rust_publication test_codeql_rust_transfer
```

For the real alias control, redirect the checked-in reproduction script through
the hardened launcher's stdin mode:

```sh
sh artifact/python-run.sh - < research/sdk-alpha1/evidence/20261109-macos-receipt-fixture/receipt-alias-repro.py
```

The baseline is expected to exit 1 with all three errors under this alias. The
candidate is expected to exit 0. The new permanent test exercises the same alias
and all three receipt modes during ordinary CI. A successful macOS target
extraction remains a result of the next hosted workflow execution; this evidence
establishes the fixture repair and local regression coverage.
