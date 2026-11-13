# Persistent secret encoding — 2026-10-17

Growing a `Zeroizing<Vec<u8>>` can release an earlier allocation before the
wrapper's final-drop zeroization. The preceding
[moving-allocator counterexample](../20261017-secret-growth/README.md) observes
14 such releases of the live rekey field across seven actual session encodings;
all seven final allocations are cleared normally. This correction addresses
those avoidable copies and related persistent-secret construction paths.

The private encoder measures length through the same read-only serializer,
allocates once, and checks that the write pass has exactly that length. Its
bounded writer cannot grow the secret allocation. A length mismatch or either
pass's error returns an error; no partial encoding is returned as success.
Traffic epochs write directly into their parent session buffer.

The change covers session state, staged bootstrap plans and outer journal
plaintext. Signing-key persistence reserves its fixed format size. Fanout
reserves the complete 64-byte tail while its buffer still contains public
metadata. Closed-epoch resolution streams private commitments directly into
the existing HMAC in the original order. When a verified bootstrap reply is
appended to a private waiting checkpoint, a new complete buffer is constructed
and the old zeroizing owner is released, instead of growing that owner in place.

The review distinguishes actual secret-copy risks from other vector uses:
prekey and wrapping-key encodings append their only secret last; existing
`pack` and peer-retirement wrappers reserve the complete size. Public terminal
and roster metadata are not treated as traffic-key copies solely because they
use a vector. This is not a general allocator replacement or a new erasure API.

## Compatibility and failure behavior

Public ABI, protocol tags, storage tags and field ordering are unchanged.
Frozen pre-change State/Traffic and journal composition serializers compare
bytes on every relevant native library-test encoding. They share leaf encoders;
the separately retained source comparison verifies that all twelve referenced
leaf/tag function bodies and `STATE_TAG` are unchanged. Two negative controls
alter an encoded byte and require the respective comparison to fail. These
comparisons use fixed messages and do not print secret byte arrays.

The aggregate capacity check remains inside journal sealing/persistence.
`Capacity` therefore still closes the active journal. Reopening the original
owner retains the rejected operation as `Absent`; acknowledging an old-epoch
message frees capacity for that same message ID. The change does not add an
earlier public preflight that leaves a different lifecycle state.

## Verification

- **1015 native library tests pass**, including the new encoder boundaries and
  oracle controls. The enabled features are `connection-tls,control-tls`.
  The complete inventory is divided into 64 disjoint exact-name batches with
  two test threads each. Their verified union has no ignored or unexecuted
  cases. Each process retains its command, terminal result and output. Total
  elapsed time is about 40.8 minutes; this is test-suite execution time, not an
  SDK latency result.
- **Two fresh native allocator cohorts pass**, under local and required-witness
  policy. Each retains 64 epoch-zero and 60 epoch-one maximum-sized messages,
  completes a real authenticated rekey, observes aggregate refusal/closure,
  reopens twice, and recovers the original rejected ID through an old-epoch ACK.
  All 125 ciphertext replays and authenticated TLS consumptions per cohort
  succeed. Independent readback checks 250 durable business files and rejects
  260 substituted-result controls.
- Formatting, **all-target/all-feature Clippy with warnings denied**, and a
  **Rust 1.90.0 all-feature library check** pass. Normal builds/tests use Rust
  1.98.1 Release, thin LTO and overflow checks. No dependency version or public
  interface changes, diagnostic allocator or observation hook enter the engine.

The earlier single-process library run was stopped after 375 terminal records
when review found the additional private-checkpoint append path. Its raw output,
source patch and interruption reason are preserved and are not counted as a
passing suite. The corrected candidate executes all 1015 cases. The initial
library compile failure from test call-site adaptation is also retained.

## Process-memory observations

| Local/witness workload | Peak process RSS | Physical footprint after 15 seconds of post-close idle waits |
| --- | ---: | ---: |
| Prior local VM census | 212.56 MiB | 164.50 MiB |
| Corrected local cohort | 158.56 MiB | 70.83 MiB |
| Corrected required-witness cohort | 160.14 MiB | 75.97 MiB |

The prior local row comes from the
[unchanged-allocator VM census](../20261017-vm-footprint/README.md), not its
separate pressure-relief experiment. These are single fresh-process observations
on the same Apple Silicon/macOS host. Both peers and observer bookkeeping are
included, and other host applications/power settings are uncontrolled. No task
build or broad test overlaps the measured cohorts. They do not establish
statistical latency tails, isolated SDK memory, mobile energy, a universal
percentage improvement or a complete explanation of remaining VM retention.

## Evidence and remaining gates

[SUMMARY.json](SUMMARY.json) binds the tested source base
`d71c6fc126fa78b56ab1073a574b13e7a99168e1`, exact candidate patch and admitted
source-file hashes. All admitted engine bytes match that tested candidate.
[CAPTURE.zip](CAPTURE.zip) contains 685 public members, all read back against
[CAPTURE.json](CAPTURE.json). Every unit-batch census and both native business
censuses are revalidated directly from the archive. SHA-256:
`ae5318faaf1e9e78fc191687b23793d232cee3ad61b7595a0c456e0b367b56c4`.
Keys, private installation configuration, encrypted databases, executables and
compiler caches are excluded; the original private cohorts remain sealed.

The three added Rust files raise the tracked-source inventory from 695 to 698.
The separate explicit SDK proof-input mapping remains 256; its historical
249-input manifest is unchanged. Committed-source contract checks and hosted CI
follow this capture. Their completion must be checked separately.

This improves owned-buffer handling. It does not erase old database pages,
backups, host/provider/compiler copies or already disclosed material, and does
not establish post-compromise recovery. Complete protocol/SDK refinement,
independent implementation, broader resource qualification and the remaining
0.2.0 release gates remain open.
