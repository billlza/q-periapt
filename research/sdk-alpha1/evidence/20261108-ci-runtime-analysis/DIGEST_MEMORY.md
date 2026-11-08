# Canonical source digest memory

`canonical_tree_digest` previously materialized every admitted file in a byte
dictionary before hashing. The inspected repository inventory contains about
5.0 GB of tracked blobs, including historical evidence archives. The digest
format requires ordered bytes, not simultaneous ownership of all file bodies.

The implementation now hashes each admitted file before reading the next one.
Both the tree and materialized-map entry points use the same unchanged framing:
eight-byte big-endian path length, UTF-8 path bytes, eight-byte content length,
then the exact content bytes. Sorted deduplication, generated-file exclusions,
repository containment, required file existence and pinned snapshot semantics
are preserved. An empty-byte pin remains an authoritative empty input; the
legacy `None` value still reads the file. No historical evidence or manifest
was rewritten by this optimization.

## Measured control

`DIGEST_MEMORY_CHECKS.json` binds the baseline commit and current source hash.
Sixteen files of 16 MiB each were written before either measurement. Each file
contains `bytes(range(256))` repeated 65,536 times. The original function was
loaded from commit `4e4c1b6deac233600d0cabc617c013d1307abbe1` using its Python
AST; the comparison function came from the changed module. Both calls used the
same on-disk fixture and returned the same canonical SHA-256.

| Measurement | Original | Per-file implementation |
| --- | ---: | ---: |
| Input bytes | 268,435,456 | 268,435,456 |
| Peak traced Python allocation | 268,445,134 B | 16,785,410 B |
| Recorded elapsed time | 0.309 s | 0.216 s |

Peak traced allocation decreased by 93.747%. Memory now scales with one
current unpinned file, plus the inventory and caller-owned pinned bytes. The
timing values describe this local control; filesystem caches were not
controlled and no CI throughput or protocol cryptographic-speed claim follows.

## Validation

All ten claim-ledger tests pass. The fixed digest fixture covers binary and
empty data, UTF-8 paths, reordered/duplicated inventory, exclusions and pinned
bytes. The eight-file memory regression fails against the original function
at 8,395,084 traced bytes and passes the changed implementation's 3 MiB budget.

An independent review compared 22 old/new cases, including empty and `None`
pins, nonbytes and unused pins, missing pinned files, path traversal, escaping
symlinks and read failures. Valid outcomes and rejection behavior agree. The
new implementation can reject an early invalid pin before encountering a
later missing file; both versions reject without returning a digest.

Run the maintained regression suite from the repository root:

```sh
sh artifact/python-run.sh -m unittest -v test_claim_ledger
```
