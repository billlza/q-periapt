# Independent review: complete BAAB source preparation

The final diagnostic helper preserves both complete, pinned `artifact/` snapshots and resolves the source-archive failure in a fresh public partial clone. The executable change is confined to `prepare_sources`; every other helper function remains byte-identical to the originally reviewed diagnostic.

## Qualification

The cold reproduction fetched all 610 required blob OIDs in one explicit operation (5.845420054 seconds). All 610 were missing before that operation and none remained missing afterwards. The full A and B subtree archives completed in 0.079373625 and 0.129271929 seconds. Their original Git traces contain no lazy fetch.

Independent readback directly opened both original TAR files and verified every member against the complete pinned Git tree:

| Snapshot | Production commit | Files | Source bytes |
| --- | --- | ---: | ---: |
| A | b5185165283880527a54289b47397fde78ddf553 | 597 | 16,532,600 |
| B | ed38e305552db2825d90622c130973df87e16d50 | 600 | 16,559,281 |

All paths, Git blob identities, SHA-256 inventories, plan manifest digests, and executable bits match. The independent reader checked all 12 recorded preparation commands, each successful within the original 180-second bound. The original TARs remain in `fixture-baab-subtree-validation`; `READBACK.json` records their exact identities.

## Source binding

The actual cold reproduction executed helper SHA-256 `198dacfc1e5507b43ed29ab41f97e92e64d4e0ab8fe1da0a77a2309ff62cd439`. The final publication helper is `c1efbcc72f75fddc60422841d049c312c7575ff7257767060d9f5df397fc1b24`. The two changed lines are comments explaining the observed archive mechanism; independent full-AST comparison confirms identical executable code. The executed helper is retained as `fixture-baab-subtree-validation/helper.executed.py`.

The source imports, B–A–A–B order, 600-second analysis limit, 850-second TERM deadline, 15-second grace, 900-second outer limit, samplers, guards, 39-result checks, and semantic comparison are unchanged. This record qualifies source preparation; the hosted BAAB comparison has its separate run and result receipts.

## Why the subtree is the complete input

`git archive --prefix=artifact/ <commit>:artifact` archives the complete fixed subtree and restores the same member names used by the original whole-tree census. The original member-set check, per-file Git blob check and fixed plan-manifest check remain in place.

Git 2.47.3 [archive.c](https://github.com/git/git/blob/v2.47.3/archive.c) prepares its temporary index from the tree argument before applying the archive pathspec. [unpack-trees.c](https://github.com/git/git/blob/v2.47.3/unpack-trees.c) then updates the cache tree, and [cache-tree.c](https://github.com/git/git/blob/v2.47.3/cache-tree.c) can prefetch missing objects needed by that index in a promisor repository. Selecting the exact artifact subtree restricts that implicit object domain to the intended complete source input.

The first local full-commit archive attempt is retained separately. Its declared 610-object set was present, but the whole-tree archive initiated an additional fetch before producing output and reached its existing deadline. The successful subtree reproduction addresses this observed mechanism without broadening the download scope.

The reviewer performed source comparison and original-file readback only; the owner performed the recorded public Git reproductions.

