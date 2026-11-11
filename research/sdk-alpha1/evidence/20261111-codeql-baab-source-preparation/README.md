# BAAB complete source preparation: failure and repair

The source preparation repair is published at [95ba31c114fd9b0c3bc014ed9e37d416a577715f](https://github.com/billlza/q-periapt/commit/95ba31c114fd9b0c3bc014ed9e37d416a577715f), tree `b97bd462405228631f9d830dac290a8f87d4f0ef`, directly above the original diagnostic `5e4819004450a43423c19818c65fe89779899eb6`. The public comparison changes only `artifact/codeql_fixture_baab.py`. Both public identities and the complete helper bytes were independently read back.

## Three recorded outcomes

| Execution | Observed result |
| --- | --- |
| Original hosted run [43081947833](https://github.com/billlza/q-periapt/actions/runs/43081947833), job 130736488898 | Extraction succeeded in 29.060392852 s. Preparing source A reached its 180 s archive deadline after 180.002059876 s, with unambiguous cleanup. The retained artifact contains zero analysis invocations and zero BQRS results. |
| First local public partial clone | Explicit source prefetch succeeded, but a whole-commit archive initiated an additional promisor fetch before producing output. The archive reached the unchanged deadline after 180.003407722 s. Its original failure record and Git trace are preserved. |
| Fresh local subtree reproduction | All 610 required blobs were initially missing, and one 5.845420054 s prefetch made the complete set available. Complete A and B archives finished in 0.079373625 s and 0.129271929 s; both original traces have zero lazy fetch. |

The hosted record identifies the timed-out preparation command. The separate cold reproduction and Git source review identify the implicit whole-index dependency addressed by the repair. Each local preparation command retained the 180 s bound.

## Complete fixed source inputs

The helper obtains the full regular-file `artifact/` tree of each fixed commit, prefetches the union of their blob IDs, and archives `<commit>:artifact` with `--prefix=artifact/`. This preserves the same member names and the original complete member-set, per-file Git blob and plan-manifest checks.

| Input | Fixed production commit | Files | Bytes | Canonical SHA-256 inventory |
| --- | --- | ---: | ---: | --- |
| A | `b5185165283880527a54289b47397fde78ddf553` | 597 | 16,532,600 | `3e816a42292d275b6059c08b64d1636e766f9ddfe190fc651be796b4822775de` |
| B | `ed38e305552db2825d90622c130973df87e16d50` | 600 | 16,559,281 | `ac3335a92bd7b9080b41dd86340d5b7be0e1d97fb540232d8596b8c452dfee1d` |

The independent reader opened both original TARs and verified all 1,197 members against these Git trees, including SHA-256 identities and executable bits. The complete inventories are retained here. TAR identities and the locations of other retained auxiliary outputs are recorded in `EXTERNAL_ORIGINALS.json`, avoiding duplicate 17 MB archives.

Git 2.47.3 [archive.c](https://github.com/git/git/blob/v2.47.3/archive.c) prepares its temporary index before applying the archive pathspec. [unpack-trees.c](https://github.com/git/git/blob/v2.47.3/unpack-trees.c) updates that cache tree, and [cache-tree.c](https://github.com/git/git/blob/v2.47.3/cache-tree.c) may prefetch missing index objects in a promisor repository. The fixed subtree confines that implicit dependency set to the complete intended input.

## Executed and published source

The successful cold reproduction used helper SHA-256 `198dacfc1e5507b43ed29ab41f97e92e64d4e0ab8fe1da0a77a2309ff62cd439`. Its exact source is retained as `source/helper.executed.py`. The published helper is `c1efbcc72f75fddc60422841d049c312c7575ff7257767060d9f5df397fc1b24`, Git blob `82699d8b906390a49c3c87674bdd288ef972641d`. A two-line comment correction explains the observed mechanism; the entire executable AST is identical.

Only source preparation changed. Fixed source imports, B–A–A–B order, the 600 s analysis limit, 850/15/900 s termination bounds, samplers, guards and full-result comparison remain byte-identical. Hosted paired-query results belong to their subsequent execution record.

## Retained evidence

`hosted-initial-failure/artifact.zip` is the original 678,971-byte artifact (SHA-256 `e27d75b7e78ded924475e42a387377e5b225d192f24758f71a99515efba8f28b`). Every one of its 148 member hashes was independently recomputed. It retains the complete extraction log and initial database inventory without duplicating those large members. The packet also includes the original job log and API snapshots, both local drivers and command receipts, successful Git traces, fixed source inventories, public source binding and sealed independent review. The unused success-path readback draft is excluded.
