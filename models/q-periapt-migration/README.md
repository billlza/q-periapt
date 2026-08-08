# q-periapt-migration

Non-normative, `publish = false` authenticated-migration model above frozen
Q-Periapt ABI 2.

The original phase-one surface remains byte-for-byte unchanged:

- a fixed 12-field LP8 `MigrationContextV1` body of exactly 315 bytes;
- local/peer policy normalization into initiator/responder ownership;
- suite, profile, key format, endpoint digests, and effective floor derived from
  authenticated policy types;
- an ABI 2 adapter restricted to ML-KEM-768 + X25519 that carries the expected
  execution-policy state; and
- failure-atomic encoding, independent Python/Rust full-byte vectors, and a real
  signed-policy ABI 2 round-trip/key-separation test.

V1 cannot produce an accepted session. Its externally supplied M7/M10/M11 values
remain public commitment inputs and are retained only for its frozen research
vectors and compatibility tests.

Migration Contract V2 adds a distinct 324-byte, thirteen-field domain:

- canonical migration-state bodies and authority signatures;
- explicit signed genesis, exact same-lineage advances, and recovery-authority
  resets whose global generation never resets;
- private pending-commit tokens carrying exact predecessor/successor revisions;
- identity-signed, strictly decoded capability offers binding role, identities,
  nonces, endpoint policy state, committed migration state, complete suite set,
  security posture, and the sender-owned key share;
- role-normalized authenticated negotiation which resolves both real
  `AuthenticatedPolicy` values against the common execution decision;
- typed pre/post-KEM transcripts with key-share and negotiation graft checks;
- a closed `HybridRequired` / `PostQuantumOnly` component mode; frozen ABI2
  explicitly rejects `PostQuantumOnly`;
- role-separated mutual Finished typestates; a pending ABI2 secret is consumed
  on every failure, and an accepted key is derived only after constant-time peer
  verification plus an exact current-state revision recheck; and
- stable V2 state, negotiation, transcript, context, Finished, and accepted-key
  vectors, including a real ML-DSA-65 authentication test.

The crate emits application bodies only. ABI2 still applies
`Q-PERIAPT-POLICY-CONTEXT/v1` and its execution-policy digest; callers must not
pre-wrap or pre-hash either body.

Boundary: this crate contains the pure authenticated domain model and in-memory
commit owner. Durable CAS/receipt storage, external monotonic anchors, reset-nonce
and session replay databases, crash reconciliation, socket authorization, and
secret-owning process isolation are Policy Agent responsibilities. Constructing
another in-memory state owner is not rollback resistance. The Agent must durably
reserve a verified pending token before calling its consuming `commit`, and must
be the sole owner passed to acceptance-time state rechecks.

The signer helpers require caller-owned, algorithm-exact signature output buffers;
this follows `q-periapt-sig::Signer` and avoids guessing a backend signature size.
All untrusted wire decoders are length bounded and reject trailing bytes.

See:

- [`docs/migration/MIGRATION_CONTEXT_V1.md`](../../docs/migration/MIGRATION_CONTEXT_V1.md)
- [`docs/MIGRATION_CONTRACT_RESEARCH.md`](../../docs/MIGRATION_CONTRACT_RESEARCH.md)
