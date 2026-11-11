# ContextBound source and adapter artifact

This artifact identifies the native ContextBound computation and its
original-operation adapter. `source_audit.md` contains the exact encoding,
component-challenge routing, complete-tuple cache rule and the source
induction for the next rekey of one established session.

## Self-contained manuscript check

From this directory:

```sh
python3 check_contextbound_adapter.py --output check_receipt.json
```

This command needs Python's standard library and the adjacent `fixtures.json`.
It performs 36 format and finite adapter-model checks, including explicit
negative controls. It does not run native Rust or a cryptographic security
game. It can run on the paper branch without a checkout of the separately
pinned native development code.

The table and reservation-model strings are entry, source and result handles.
Distinct handles do not assert that independent keys, ciphertexts, secrets or
random-table outputs have different bytes; numerical collisions remain possible.

## Explicit native source audit

```sh
python3 audit_source.py --repo /path/to/native-checkout --output source_map.json
```

The supplied checkout must contain the source revisions
`228c944fc476e3e57d6c08063cacb19bca5b360e` and
`1c68aa666db22d36ee136be1ec712545a9e74f03`, and its fourteen selected worktree
files must match those exact revisions. The command performs twelve static
assertions and binds the manual source map to Git blob and SHA-256 identities.
Unavailable objects, wrong files and changed assertions fail the command.
The retained `source_map.json` is the successful receipt of this audit; it is
not silently regenerated from another source when that checkout is absent.

## Reading the results

The six existing core SHA3 digests in `fixtures.json` come from the pinned
`crates/q-periapt-backends/src/contextbound_kat.rs`. The new native-width
fixture independently encodes the actual 2,639-byte hash-input format and
115-byte policy wrapper, using synthetic input values. The root-allocation
witness demonstrates that equality of the combined input alone does not
guarantee equality of a later root-use descriptor. The next-rekey source
induction supplies the descriptor equality for its declared native profile.

The native challenge component in this artifact is ML-KEM-768. X25519 is
computed using its actual raw-DH backend and contributory rejection. No
uniform-256-bit KEM challenge assumption is inferred for that raw-DH output.
