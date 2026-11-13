# Reviewed manuscript integration: tree-merge receipt

This receipt records the read-only three-way merge preflight for the reviewed 90-page JoC manuscript and the current SDK integration candidate. It verifies the proposed tree merge and the specifically exercised Android and archive-lock invariants. Hosted CI must qualify the new published head separately.

## Exact inputs and merge result

| Role | Commit | Tree |
|---|---|---|
| Actual merge base from GitHub compare | `7c5e3db4b441b3aa2aee62c48242f71ff0b2643d` | `e18aa1fe389e6f76aea2f7a856928a3964f3e83a` |
| Integration first parent | `93a8ce264624d2c711c894d02c04c582b0d10c63` | `ac25145315161f102997233937a64002e5cea3d0` |
| Paper second parent | `9a9bb4bf3d5adea9a70e487e30cbe888fbb18f7a` | `828df85c299e21c0f57c8222d153f17c5a48729b` |
| Planned two-parent merge | Parents in the order above | `8c1f760a5455a8796af3d925b89118d866fdf0ae` |

The predicted tree identifies the manuscript merge before this evidence-only follow-up commit. All three complete input trees were reconstructed from path, mode, type and object identities, reproducing GitHub's exact tree SHAs.

## Merge accounting and targeted checks

- The result contains 6,975 leaves. Relative to integration, 140 manuscript paths and the JoC workflow change: 122 additions, 19 modifications and zero deletions.
- All 149 paper changes relative to the true merge base are accounted for. All 6,275 integration-only coordinate changes, including 37 deletions, remain intact. The complete `paper/continuity/` subtree equals the reviewed paper head; integration's separate `paper/q-periapt.tex` change remains intact.
- Two textual conflicts occur in `artifact/android_bounded_command.py` and `artifact/test_android_bounded_command.py`. The merge retains their integration blobs `ca650a19ed1817cab687094648d883da473198aa` and `0876531d48ac25182e14f7dd677c9cfb06cd8843`. Integration already retains the paper's hosted API 35 / 16 KiB 4 GiB behavior and regression case through its validated runtime-profile interface, together with later diagnostics. The RAM predicates agree for all three admitted AVD mappings; the existing macOS, hosted 16 KiB and minimum-API boundary tests all passed.
- The six Android memory evidence files added on the paper branch already have identical integration blobs. They remain present. The additive JoC workflow brings four theory/data validation commands; the other 18 workflow files retain their exact integration identities.
- All 1,173 `.rs` files and 30 `Cargo.toml` files retain their paths, modes and blobs. Runtime, formal-model and research-code subtrees preserve their integration identities.
- Eight existing `Cargo.lock` files remain exact. Two fixed paper archive locks are added with the already declared SHA256 pins and no adjacent `Cargo.toml`. The current integration `codeql_rust_profile.tracked_lockfiles` function accepted an isolated index of the ten planned locks and returned the unchanged eight fetch roots.

`preflight-proof.json` records input commits, ordered parents, reconstructed tree identities, full-tree accounting, retained subtree hashes and before/after inventory digests. `targeted-checks.json` records the three executed regression tests, RAM mapping equivalence, archive-lock admission and 24 loaded source-module identities verified against the integration tree. These checks resolve the specific merge conflicts and preserve the existing qualification inputs; the published merge and evidence head has its own hosted CI results.
