# Original protected registration qualification

This increment implements the independent reference
[registration contract](../../../continuity-openssl-peer/REGISTRATION.md): create
and retain the original signing owner, submit its real enrollment proof, accept
independently pinned authority, and open one original pairwise child session.
The child uses the existing traffic, rekey, renewal and pending-write recovery
implementations. It no longer needs a cleartext fixture signing-key file or the
issuer's public fixture directory after preparation.

Nineteen runtime entrypoints and eleven public readback scripts passed. The
registered-owner lane completed 42 local and 50 witnessed process operations,
including 21 real SIGKILL cuts. The native endpoint verified the actual enrollment
proof, issued the credential, received original and new traffic, completed rekey,
and acknowledged the correct epoch. The witnessed profile separately approved
the original expired pending write, confirmed it with fresh signed Query results,
renewed the credential, and recovered the same original messages.

The final source inventory contains 99 files, including 89 parsed Python files.
The Rust census is 726 files. The changed ARM64 counterpart was built with
`--offline --locked --release`; strict Clippy, final rustfmt, actionlint and
`git diff --check` passed. Its SHA-256 is
`b33c31977dd7d77988472699a627921a23fc1a69a0704046055e65ea82e87bfe`.
The unchanged native importer retains its earlier strict build qualification.

A fault probe found a real lifetime defect in the initial implementation: after
child cleanup threw, the parent could still open another child. The repair
revokes the parent first and attempts parent journal cleanup in `finally`, while
returning the error. Red and green probes used the same original private state
without changing either head. The fault is explicitly injected after real child
cleanup; it is not an observed operating-system failure. The final registration
lane was rerun after this repair. The other eighteen lanes ran before the two
registration-only files changed; their audited import closures do not use either
file. Both source cohorts and the earlier bytes are retained.

Development evidence also preserves the shared-target build mismatch, the
argument-count lint failure, a wrong prototype class import, a malformed helper
extraction caught by AST parsing, a test's incorrect current-epoch ACK expectation,
and a copied reader's incorrect numeric constant. Their causes and repairs are
recorded separately. Original-state continuation/readback accompanies the failed
runtime attempts; no failed private installation was reset or recreated.

The public assets are partitioned to keep each below 50 MiB:

| Asset | Bytes | Members | SHA-256 |
| --- | ---: | ---: | --- |
| `CAPTURE.zip` | 51,432,769 | 15,766 | `20164e68051b287777e8114ebb6b3d42ac7c201057cd3223db49ccd051e26930` |
| `DEVELOPMENT.zip` | 7,863,335 | 2,037 | `fdccf3f536a958e48fa862a0ff9a957bcf8bd78f5b75623db907d7e8bb023c53` |

Every original aggregate manifest entry is retained exactly once across these
assets. Both manifests and archives were read back and hashed. Private images,
configuration files and wrapping keys are excluded; original private states stay
locally preserved. Public readers check signatures, transcripts, sources and
process markers. Private encryption, unchanged heads, resource release and
absence assertions remain runtime observations.

This is one reference child installation, with local registration configuration
kept outside session backups. It does not establish whole-configuration rollback
protection, Python physical erasure, deployed account authentication, installed
independent lifecycle, multi-device coordination, identity/policy/witness/root
replacement, power-loss behavior, resource/energy results, retained-state PCS,
final ABI, external review or full 0.2.0 release admission. Native traffic in this
fixture retains time 170 while the independent owner crosses signed expiry.
