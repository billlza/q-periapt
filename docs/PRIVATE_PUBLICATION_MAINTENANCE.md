# Private publication maintenance, version 2

This is the candidate contract for explicit reclamation of an unpublished
`q-periapt-host-store` publication attempt. It is separate from operational
database recovery, Continuity history retention and policy-store format migration.
Its new source and installed/platform qualification must be recorded separately
from earlier SDK cohorts. It does not freeze the 0.2.0 release contract.

## Selecting and running maintenance

Retain the failed publication's original context and stop its publisher and all
payload owners. Select the exact private control directory named by that attempt;
do not pass the formal destination or select a database by scanning residues.
The control-name correlation in an error is only a locator. Maintenance independently
validates the original scope, version, identities and exclusive lease.

The Rust API is `filesystem::reclaim_private_publication(attempt, limits)`. The
CLI build feature is `publication-maintenance`; the native maintenance package
includes it alongside its existing policy-store migration feature:

```sh
qperiapt publication-reclaim /absolute/private/.private-attempt-v2-ORIGINAL_NONCE \
  --max-entries 1024 --max-depth 32 --max-bytes 268435456
```

`ORIGINAL_NONCE` denotes the actual 32 lowercase hexadecimal characters of the
selected control name. This command takes one attempt, never a wildcard or recursive
root. Run as the existing owning account without changing permissions to gain admission.
The precompiled package targets remain macOS Apple Silicon and the separately
qualified Linux architectures; an implemented Windows adapter alone is not
installed Windows maintenance qualification.

The caller supplies a whole-remaining-payload work budget. Rust defaults are
1,024 entries, depth 32 and 256 MiB of regular-file lengths. Accepted bounds are
1–4,096 entries, depth 1–64 and 0–4 GiB. Root depth is one; files count toward
depth and entries. These are traversal limits, not guaranteed storage capacity or
available file descriptors. The entire remaining tree is admitted and every
regular file exclusively locked before the first deletion. Budget refusal,
private-file admission failure or a live owner leaves the payload untouched.

The successful JSON `reclaimed` result identifies the original control name and
retained original entry/byte totals. Repeat the exact command after a lost result;
its committed intent and receipt return those same totals, even after partial
cleanup. `no-payload` means no payload and no cleanup intent were observed. It
does not establish successful publication, safe first use or authority to recreate
a missing formal store. Reconcile formal state through its normal authenticated
opening path and independently retained identity.

An I/O error can follow partial deletion or an unknown receipt commit. Keep the
same control directory and original records; correct the actual failure and retry
that attempt. `Busy` means an owner still exists, including inherited open
descriptions in another process. Closing one parent handle is not proof that all
owners have gone. There is no internal timed retry or lock bypass. Cancellation
by process interruption uses this same original-intent recovery path.

## Publication and authority boundary

File, database and directory publication create a private control directory
`.private-attempt-v2-<nonce>`. Before returning any payload to an initializer, they
hold an independent exclusive `lease`, create the original `payload`, persist
the bound `record`, and sync the control and target parent. Database data retains
its own original Database/backend lock; the control lease is a different file.

After the complete payload is synced, publication moves only `payload` to the
original destination with NOREPLACE, checks its identity, and syncs both rename
parents. The publisher holds the control lease throughout. A cleaner cannot
admit the attempt while publication is active, and after rename no `payload`
name exists inside the control. It never follows the recorded destination or
deletes a formal target through a retained directory descriptor.

On success the publisher retires only its own `record`, `lease` name and empty
control directory, while still holding the original lease through parent sync.
A failure in retirement may leave a complete published target with a partially
retired control, or no control at all. Such an error does not authorize replacement
of the target. Publication errors never remove an unpublished payload or formal
target. The explicit maintenance operation is the only payload-removal path.

Maintenance verifies owner/private permissions and ACL, non-reparse/no-follow
access, single-link files, original parent/control/lease/payload identities and
same filesystem volume. It pins all admitted entries and file locks through
removal, rechecks names against those pins, syncs removed directories and retains
the original control intent/receipt. A checksum detects damaged bookkeeping;
private scope plus the original exclusive lease provide authority. Checksums and
filename prefixes are not authentication. Hostile code with the same account's
privileges is outside this boundary, as it already is for these private stores.

## Exact auxiliary format

This format changes publication bookkeeping only. It does not change operational
redb tables, wrapped key images, Continuity messages or the C ABI.

| Field | Encoding and binding |
| --- | --- |
| `lease` | `QPSTGL02` plus the original 16-byte random nonce, 24 bytes total |
| `record` | `QPSTG002`, platform byte (1 Unix, 2 Windows), payload-kind byte (1 file, 2 directory), nonce, original parent/control/lease/payload identities (16 bytes each), destination digest (32 bytes), SHA-256 of preceding bytes (32 bytes); 154 bytes total |
| Identity | Unix device and inode as two little-endian u64 values; Windows volume serial u32, four zero bytes, file index u64, all little endian |
| Destination digest | SHA-256 of `Q-PERIAPT-PRIVATE-PUBLICATION-DESTINATION/v2\0`, platform byte, native leaf bytes (Unix bytes or Windows UTF-16LE); retained binding, never a path for cleanup |
| `cleanup.intent` | `QPSTGC02`, SHA-256 of the complete original record, original entry count and file-length sum as big-endian u64 values, SHA-256 of preceding bytes; 88 bytes total |
| `cleanup.done` | `QPSTGD02` plus SHA-256 of the complete canonical intent, 40 bytes total |

Each cleanup field is written to its fixed `.pending` sibling, file-synced,
renamed with NOREPLACE and directory-synced. A partial pending file can resume
only if its bytes are an exact prefix of the same canonical field. It is never
truncated or reset. A committed and pending copy of the same field, completion
without an intent, completion with a remaining payload, or conflicting bytes is
refused. Completion writing begins only after the whole payload removal is synced.

Completed cleanup controls remain retained to replay the original result. There
is no automatic garbage collection of those controls or recursive sweep of a
parent. Hosts must bound failed first-use attempts and account for retained
metadata. Old `.private-publication-*`/directory residues, the experimental
`QPSTG001` format, incomplete control creation, controls moved to a different
parent or copied to new filesystem identities, and missing or replaced leases
are refused. An original parent inode surviving a namespace rename remains the
same filesystem scope; this does not change operational stores' own path contracts.
Refused residues require a separately authorized
host disposition procedure; they are not adopted or silently upgraded.

Logical removal and successful file/directory sync are not physical erasure,
backup erasure or evidence of every power-loss behavior. Process-kill evidence,
native filesystem execution, installed command execution and platform qualification
must each retain their actual source and environment identities.
