# Continuity identity and prekey-manifest candidate

This unpublished, isolated implementation exercises the accountable identity
chain proposed for [Continuity in 0.2.0](../../docs/continuity/RELEASE_0_2_SCOPE.md).
An independently pinned account root verifies a device credential and an exact
signed roster; the verified device then authenticates a signed prekey manifest
and individual Merkle membership proofs. Both ML-DSA-65 and ECDSA P-256/SHA-256
must verify. This crate is outside the SDK workspace and publication graph.
The existing ABI major remains **2**.

The candidate supplies actual signatures and byte validation. The lifecycle model
remains a separate test artifact, and supplies no authority to this implementation.
Product admission still needs the complete protocol, policy/capability schema,
bootstrap confirmations, ratchet and durable transaction contracts. Candidate
identifiers and encodings are not frozen product wire formats.

## Authority and ownership

`RootSigningKey` and `DeviceSigningKey` have distinct public issuance APIs, no raw
secret export, no clone, and explicit idempotent close. Closing drops zeroizing
secret owners. ML-DSA expanded material returned by the low-level provider is
explicitly cleared after transfer to the heap owner. This owner-level guarantee
does not cover compiler/provider copies, registers, paging or process abort.

`AccountPin` requires the expected self-certifying account identifier, root public
keys, exact roster version **and** body digest, and policy family. Enrollment must
obtain those expectations independently of the messages being authenticated.
The host supplies trusted time, durable checkpoint advancement and revocation.
Constructing a pin from an incoming bundle does not authenticate its claimed peer.

`VerifiedDevice` binds the credential, account, generation and exact roster.
`VerifiedManifest` additionally binds a bundle epoch, policy/suite/directory
digests, expiry, count and root. These signed context digests require separate
semantic authorization. `AuthenticatedLeaf` authenticates public bytes and their
role; it is not a primitive-validated KEM key, a lease or a consumption receipt.
Retained objects do not discover later revocation. An eventual consumption
transaction must recheck the current authority/fence and atomically commit the
prekey, session, deduplication, inbox and outbox records.

Exact public-byte fingerprints exclude role, epoch and expiry, allowing the
issuer to reject repeated public bytes within a manifest. They do not establish
mathematical equivalence of differently encoded keys. Cross-manifest uniqueness,
provider canonical admission, one-time use and durable tombstones remain storage
and bootstrap obligations.

## Exact candidate encoding

All integers are unsigned, big-endian, with no implicit padding. No trailing
bytes, unknown leaf kinds or variable algorithm selection are accepted. Intervals
are half-open `[from:u64, until:u64)`, nonempty, with `until != u64::MAX`.
Generations, roster versions and bundle epochs are in `1..u64::MAX` (exclusive
upper bound). Device IDs and context digests must be nonzero.

The public key is `ML-DSA-65 public[1952] || compressed SEC1 P-256 public[33]`.
P-256 points are decoded and checked against their canonical compressed encoding.
The signature is `ML-DSA-65 signature[3309] || ECDSA r[32] || s[32]`.
ECDSA uses SHA-256 and fixed-width unsigned r/s; the verifier rejects high S.

Let `C = ASCII("Q-PERIAPT-CONTINUITY-IDENTITY-CANDIDATE/v1")`.
Both algorithms sign `C || purpose:u8 || body_length:u32 || body`.
ML-DSA additionally uses `C` as its external context, with the ordinary ML-DSA
message encoding. Purposes are credential=1, roster=2, manifest=3.
The envelope is `body_length:u32 || body || signature[3373]` and admits at most
16,384 body bytes. ECDSA and ML-DSA are both required; neither is a fallback.

For every digest below, define
`D(name, bytes) = SHA3-256(u64(len(domain)) || domain || u64(len(bytes)) || bytes)`,
where `domain = ASCII("Q-PERIAPT-CONTINUITY-" + name + "-CANDIDATE/v1")`.
Body digests exclude randomized signatures.

| Record | Body, in field order |
| --- | --- |
| Credential (2,097 bytes) | `QPCERT01[8]`, account[32], device[16], generation:u64, interval[16], family[32], public key[1985] |
| Roster (66 + 56*n bytes) | `QPROST01[8]`, account[32], version:u64, interval[16], count:u16, entries `(device[16], generation:u64, credential_digest[32])` |
| Manifest (290 bytes) | `QPMANF01[8]`, scope[248], count:u16, Merkle root[32] |
| Leaf (57 or 1,209 bytes) | `QPLEAF01[8]`, kind:u8, interval[16], exact public key[32 or 1184] |
| Membership proof | index:u16, leaf_length:u16, leaf, depth:u8, siblings[depth*32] |

Account ID is `D("ACCOUNT", root public key)`. Credential and roster digests are
`D("CREDENTIAL", credential body)` and `D("ROSTER", roster body)`.
The roster has at most 32 entries, strictly sorted by device ID, with no duplicate
device ID. An empty roster revokes all listed membership. The root rejects device
keys sharing either of its signing components.

Scope is the concatenation of account[32], device[16], generation:u64,
credential_digest[32], roster_version:u64, roster_digest[32], bundle_epoch:u64,
policy_digest[32], suite_digest[32], directory_checkpoint[32], interval[16].
The authority binding is `D("AUTHORITY", account || roster_version ||
roster_digest || family)`. The manifest digest is `D("MANIFEST", body)`.

Kinds 1 and 2 designate reusable signed and one-time X25519 keys; kinds 3 and 4
designate last-resort and one-time ML-KEM-768 keys. Leaf shape checks require the
exact public key length and reject all-zero bytes. They do not replace primitive
validation. Leaf ID is `D("PREKEY-LEAF", scope || leaf)`; exact-public-byte
fingerprint is `D("PREKEY-PUBLIC", algorithm:u8 || public)`, where algorithm=1
for X25519 and 2 for ML-KEM-768.

The issuer sorts 1..1024 leaves by leaf ID. A one-leaf tree root is its
leaf ID. Otherwise split at the largest power of two strictly smaller than the
count and compute `D("PREKEY-NODE", left_root || right_root)` recursively.
Proof siblings are ordered from leaf toward root; count and index determine all
left/right directions and the exact path length, at most 10. No padded leaves
are used. An individual proof establishes the selected leaf's membership, not
the uniqueness or ordering of undisclosed leaves chosen by a malicious signer.
Manifest intervals must be contained in both credential and roster
intervals; leaf intervals must be contained in the manifest interval. Time is
rechecked during device, manifest and leaf verification.

## Reproduce verification

Run from the repository root with the locked toolchain. Each output directory
below must be new; evidence is never overwritten.

```sh
cargo fmt --manifest-path research/continuity-identity-candidate/Cargo.toml --package q-periapt-continuity-identity-candidate -- --check
cargo clippy --manifest-path research/continuity-identity-candidate/Cargo.toml --locked --all-targets -- -D warnings
cargo test --manifest-path research/continuity-identity-candidate/Cargo.toml --locked
cargo test --manifest-path research/continuity-identity-candidate/Cargo.toml --locked --release
cargo audit --file research/continuity-identity-candidate/Cargo.lock --deny warnings
cargo run --manifest-path research/continuity-identity-candidate/Cargo.toml --locked --example public_vectors -- target/continuity-public-vectors
sh artifact/python-run.sh research/continuity-identity-candidate/scripts/verify_public_vectors.py --fixtures target/continuity-public-vectors --output target/continuity-public-verification --openssl /absolute/path/to/openssl
```

The last command requires OpenSSL with ML-DSA and external-context support
(OpenSSL 3.5 or later). It fails when the required provider is unavailable. The
example generates fresh signing and actual X25519/ML-KEM public keys, emits only
public records, and discards secret owners. Python independently reconstructs
canonical bodies, seven body/signature bindings and 28 membership proofs across
tree sizes 1, 2, 3, 5 and 17. OpenSSL verifies both signature components and rejects
35 altered-body, purpose or ML-DSA-context controls. The report records fixture
hashes, OpenSSL identity, command arguments and return codes; separate bounded
stdout/stderr logs preserve failures. This is component verification, not a
network protocol or session-recovery test.

Hosted CI builds/tests the locked candidate on Linux with Rust 1.96.1 and the
declared 1.85.0 floor, and on macOS with Rust 1.96.1. The macOS lane uses its
installed OpenSSL provider for the independent fixture check. A separate
dependency fence prevents the candidate from entering SDK package manifests.
