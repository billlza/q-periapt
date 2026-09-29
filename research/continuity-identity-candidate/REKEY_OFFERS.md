# Durable identity-authenticated rekey offers

This checkpoint implements the first control flight for a whole-hybrid KEM rekey
candidate in the actual encrypted device journal. `prepare_rekey_offer` commits a
fresh ML-KEM-768 + X25519 public key and an identity-signed offer. It does not
install an epoch or change application traffic keys. Response processing, mutual
confirmation, recurring epoch installation, old-epoch handling and an authenticated
PQ-progress budget remain implementation work for 0.2.0. The complete product
ratchet profile remains unfrozen. ABI major stays 2.

## Owned preparation and exact recovery

The API takes the admitted `BootstrapContext`, established message-session ID,
designated device signing owner and trusted time. It accepts no caller entropy,
raw private key or replacement operation ID. The journal checks the session,
owner, policy and installed account rosters before private work and release.
The first proposer is the original bootstrap initiator; the responder cannot
create an independent competing proposal for that target epoch.

Preparation uses three existing exact-intent journal transactions:

1. Reserve SDK key-generation randomness scoped to the journal identity, session,
   context, predecessor and target epoch, and commit the sealed operation token.
2. Generate that exact hybrid key, construct the complete public body, reserve
   purpose-bound signing randomness and commit both before signing.
3. Sign with both device-identity components and commit the exact public outbox.
   A required witness must confirm the committed image before bytes return.

The temporary `HybridKey` owner is dropped after public-key extraction. Its sealed
generation token remains for future response decapsulation; no private-key export
is introduced. A resumed unsigned offer reconstructs the same public key and checks
it against the retained body before signing. A committed offer replays exact bytes
without reopening a signer or regenerating a key. Both signatures and all bound
fields are checked on cached release. Policy close, expiry or committed revocation
still denies release; read-only `rekey_offer_status` remains available.

Unknown storage or witness outcomes close the journal. Reopening reconciles the
same retained write intent. Retries never replace a committed randomness
reservation. Corrupted tokens, bodies or signatures cannot yield an alternate
offer. The [recovery conditions](../../docs/continuity/RECOVERY_CONDITIONS_V1.md)
still apply: re-executing an exposed reservation is not new entropy relative to
that disclosure.

## Exact candidate public bytes

Let `H(label, body)` be the existing length-delimited SHA3-256 function, with domain
`ASCII("Q-PERIAPT-CONTINUITY-REKEY-CANDIDATE/v1/") || label`. Its preimage is
`domain_length:u64 || domain || body_length:u64 || body`; integers are big endian.

The 1,369-byte offer body is:

`"QPRKOF01"[8] || profile[32] || bootstrap_context[32] || session[32] || prior_epoch:u64 || target_epoch:u64 || proposer_role:u8 || predecessor[32] || hybrid_public_key[1216]`

The profile is `H("offer-profile", ASCII("ML-KEM-768+X25519/ContextBound;ML-DSA-65+P-256/SHA-256;accountable-epoch-offer/v1"))`.
The initial predecessor is `H("genesis", session || bootstrap_context)`. This
checkpoint accepts only prior epoch 0, target epoch 1 and proposer role 1. A
persisted nonzero confirmed epoch is rejected; preparation cannot manufacture
confirmation evidence. The public key is the SDK's full ML-KEM-768 key followed by
its X25519 key. ContextBound will apply to the actual two-leg KEM exchange;
preparation itself neither encapsulates nor establishes new shared entropy.

The candidate envelope adds `body_length:u32` and the fixed 3,373-byte ML-DSA-65 /
canonical P-256 signature pair. Total wire length is **4,746 bytes**. Signing
purpose is **9**, separate from bootstrap and witness purposes. Both signatures
cover the existing identity context, purpose, length and complete body. Unknown
tags, altered profiles/roles/session/epoch/predecessor bindings, wrong lengths and
trailing bytes fail. Retransmission preserves the original signatures. The
application-message decoder does not reinterpret this control packet as traffic.

## Sealed representation

Journal v11 uses `continuity_device_candidate_v11`, `QPVLT011` and `QPVIMG11`.
Earlier candidate journals are rejected without implicit migration or reset.
Message state is `QPMST003`; existing traffic-key, sequence, retention and
acknowledgement fields retain their meanings. Public application frames remain
`QPCMSG02`, epoch zero.

The payload appends `QPRKST01 || epoch:u64 || predecessor[32] || phase:u8`.
Phase 0 has no proposal. Other phases retain the 277-byte sealed key-generation
token; phase 1 adds nothing, phase 2 adds the exact body and 64-byte signing
reservation, and phase 3 adds the exact signed wire. Unknown phases, orphaned
bindings and invented completed epochs fail image admission. One offer can be
pending per session, within the existing 2 MiB aggregate bound.

## Validation boundary

Local validation passes 131 candidate release tests, strict all-target Clippy and
actual Rust 1.90 all-target checking. The offer transition measures 13 storage sync
barriers; 26 before/after-sync faults recover through the original exact intent.
Five actual process termination points cover key reservation/computation,
signature reservation/computation and committed outbox before return. The tests
compare the original computed public key and signature bytes after restart.
Required-witness tests reject both a lost final release query and a failed cached
offer release query. Wrong roles/signers, revocation, corrupted authenticated
fixtures and fictitious epoch advancement are rejected.

`public_vectors --with-rekey` completes both bootstrap roles through real private
journals, prepares the offer and checks restart replay. The independent
`verify_public_vectors.py --with-rekey` oracle verifies both signatures, the exact
profile/session/predecessor grammar and canonical public-key encodings. Together
with the existing fixtures it verifies 16 signed envelopes and 80 signature
negative controls. It reports offered epoch 1 and confirmed epoch 0; response,
confirmation and traffic-key transition verification remains required.
