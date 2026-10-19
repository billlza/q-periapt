# Local protocol-policy publication

Source: `85a18e75d7605d217e3bb0dcffcdb922b032b6e8`.

The reference publisher now creates a protected native protocol signing owner,
retains each original request before signing, and commits the exact result before
returning it. Exported public inputs are consumed by the installed independent
Python implementation using cryptography 48.0.1 / OpenSSL 4.0.1. SDK authority and
witness pins in these checks are explicitly generated test inputs.

Local checks passed:

- Rust Debug and Release: 34 entries each, comprising 32 behavioral tests and two
  child-process dispatchers. The publisher exercises eight SIGKILL cuts.
- Strict Clippy, formatting, workflow syntax, Python syntax and diff checks.
- Installed independent implementation: eight adapter and 16 client tests.
- Actual publisher CLI: 13 commands, including four expected refusals, and policy
  versions 1–3 verified by the independent implementation.
- Separate public readback reverified all three SDK signatures and hybrid protocol
  signatures, exact metadata and original export consistency. This is historical
  verification; it does not backdate policy activation.

A real pre-fix CLI accepted extra witness fields attached to `local_only` and
silently discarded those fields. Empty struct enum variants now enforce strict
field parsing. The fixed CLI rejected a new operation against the same original
database, while the previously issued version 4 remained readable with identical
public exports. The capture includes both CLI observations and the pre-fix source.
It does not claim that an explicitly required-witness request became local-only.

`RECEIPT.json` identifies the capture and source. `PUBLIC_MANIFEST.json` inside the
capture inventories the public outputs, commands and selected source snapshots.
Private database/key files and the original pre-fix binary remain local and are
not included. The wheel qualification used an ordinary Git checkout and an
installation outside that checkout; no provenance gate was bypassed.

This closes the bounded local publication/verification path. Operational SDK root
issuance, authenticated operator provisioning, consumer activation, real
host-authorized device enrollment and full lifecycle admission remain separate.
These results do not establish power-loss recovery, cryptographic erasure, PCS,
or 0.2.0 release readiness. The reference publisher retains at most 512 operations;
capacity exhaustion remains explicit and history is never silently discarded.
