# Prepared wrapper method recovery

This packet preserves a prepared local CodeQL `database analyze` fixture method.
The method was not executed before the local executor became unavailable.
Recovery creates no query result, SARIF result, runtime measurement, or passing
wrapper-validation claim.

The four recoverable original files and the original six-file manifest were
reconstructed from the recorded source edits and JSON output. Each recovered
file has the exact SHA-256 and byte length recorded before the interruption.
The complete wrapper script is 28,039 bytes with SHA-256
`10dd2e7b9ff2062d895bcffd3dfdc9386423c9e5e8278470373b92f21e656eda`.
Its reconstruction also matched both recorded intermediate source hashes before
matching that final identity.

## Packet contents

| Recovery file | Original file | Status |
| --- | --- | --- |
| `run_fixture.py.txt` | `run_fixture.py` | Exact original bytes; unexecuted |
| `inspect_classfile.py.txt` | `inspect_classfile.py` | Exact original source bytes |
| `METHOD.json` | `METHOD.json` | Exact prepared-method declaration |
| `ORIGINAL_README.md` | `README.md` | Exact original explanation and intended checks |
| `ORIGINAL_MANIFEST.json` | `MANIFEST.json` | Exact original inventory of six files |
| `sampler-state-receipt.patch.txt` | New proposed correction | Unapplied; no Python or runtime verification |
| `RECOVERY.json` | New recovery receipt | Current file mapping, identities, and unavailable originals |
| `README.md` | This explanation | New recovery description |

The original manifest describes the pre-interruption directory. Two files
listed there are not present in this recovery packet: the full original
`DATABASE_CONFIG_READBACK.json` and `MEMORY_ROUTING_READBACK.json`. Their complete
bytes were not accessible after the interruption, and the conversation did not
contain enough data to reconstruct those bytes faithfully. Their original byte
lengths and hashes remain in both manifests. No replacement raw readback has
been invented.

The recovered inspection script can regenerate these static readbacks from the
exact official CodeQL 2.27.2 JAR when that authenticated runtime is accessible.
That regeneration has not been performed during recovery. The script reads Java
class files directly and does not invoke a JVM. The original archive identity is
retained in `METHOD.json`.

## Prepared execution contract

The intended run uses a fresh copy of the already accepted nonempty official
Rust env fixture database, a private authenticated runtime, and the fixed
Stage3+Stage4 projection. It retains the complete 39-query suite and requires
39 admitted QLX loads, zero implicit compilation, 39 fresh BQRS files, valid
SARIF, and full SummaryStats JSON equality with the three previously completed
baselines. The existing 29-row baselines are inputs to this planned comparison;
they are not outputs of the unexecuted wrapper method.

The declared local analysis budget is one 600-second supervisor, one thread,
a 1,024 MiB JVM heap, and 4,096 MiB native evaluator allocation. The method
requires an actual memory-resolution check before analysis, preserves all JVM
flag observations and sampled process arguments, and records the actual
evaluator invocation. It uses an explicit private empty QL configuration and
ordinary progress logging. These local settings are separate from the hosted
production allocation.

The method depends on the production admission helpers and bounded command
wrapper in a separately committed, clean implementation checkout. Its archived
text is not an active implementation or an activation of the production plan.
The restored runtime extraction helper must retain its existing descriptor
ownership checks. The packet does not alter that helper.

## Pending sampler receipt correction

The original script records a surrounding `started` or `completed` status after
calling the process sampler. The sampler can record an internal unavailable
state without throwing an exception, so those surrounding status labels should
be taken from `sampler.state`. The proposed patch makes only that diagnostic
receipt correction. It leaves the original script bytes unchanged in this
packet and has not been applied, syntax-checked as a patched file, or executed.

The original script already retains the sampler's full underlying state in
`JVM_COMMANDS.json` when a sampler object exists. The correction is intended to
make the separate summary receipt describe that same state accurately.

This directory is retained on `recover/codeql-wrapper-method-20261111` from
`ff193302f207bb3f06a2941a7c6bf98a2eeb5a17`. Python sources use `.py.txt` extensions
and the correction uses `.patch.txt` so this evidence does not add active source
files to production scanning roots. No workflow is dispatched by the recovery.
