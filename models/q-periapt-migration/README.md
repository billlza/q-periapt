# q-periapt-migration

Non-normative, `publish = false` research model for a canonical migration
application context above frozen Q-Periapt ABI 2.

Implemented in phase 1:

- a fixed 12-field LP8 `MigrationContextV1` body of exactly 315 bytes;
- local/peer policy normalization into initiator/responder ownership;
- suite, profile, key format, endpoint digests, and effective floor derived from
  authenticated policy types;
- an ABI 2 adapter restricted to ML-KEM-768 + X25519 that carries the expected
  execution-policy state; and
- failure-atomic encoding, independent Python/Rust full-byte vectors, and a real
  signed-policy ABI 2 round-trip/key-separation test.

The crate emits only the application body. ABI 2 applies
`Q-PERIAPT-POLICY-CONTEXT/v1` and the execution-policy digest itself; callers must
not pre-wrap or hash the 315 bytes.

Not implemented: transition certificates, authenticated migration-state
preimages, durable monotonic state, reset/fork resistance, peer authentication,
capability authentication, key confirmation, session acceptance,
MIG-ROLLBACK/MIG-AGREE/MIG-FLOOR, or resistance to a hostile same-process caller.

See:

- [`docs/migration/MIGRATION_CONTEXT_V1.md`](../../docs/migration/MIGRATION_CONTEXT_V1.md)
- [`docs/MIGRATION_CONTRACT_RESEARCH.md`](../../docs/MIGRATION_CONTRACT_RESEARCH.md)
