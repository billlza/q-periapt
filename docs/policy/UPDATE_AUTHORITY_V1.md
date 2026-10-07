# Policy Update Authority — design RFC (V1 draft)

> **Status: DESIGN ONLY for dynamic threshold succession and complete product root migration.** Section 1
> distinguishes the existing fixed-root enforcement from those missing features.
> The proposed API and authority encoding do not exist in shipped crates. This
> document defines target semantics for authenticated policy *succession*, records the
> ABI constraints that bound any implementation, and states what is explicitly out
> of scope. Tags follow [`THREAT_MODEL.md`](../THREAT_MODEL.md): **ENFORCED** (a CI
> gate or type-level invariant fails the build on regression), **DESIGN** (agreed
> target, not built), **OPEN** (unresolved question).
>
> Cross-references: [`THREAT_MODEL.md`](../THREAT_MODEL.md) §4.3 (ADV-POLICY),
> [`MIGRATION_CONTRACT_RESEARCH.md`](../MIGRATION_CONTRACT_RESEARCH.md) (the
> session-acceptance layer above this one),
> [`crates/q-periapt-policy/src/lib.rs`](../../crates/q-periapt-policy/src/lib.rs).

## 1. Current contract and missing lifecycle

The current SDK pins one independently supplied ML-DSA-65 root when it creates a
runtime. `Runtime::prepare_policy_update` obtains the verification key from that
runtime, not from the candidate policy or a new caller argument. The host store
persists the root and rejects opening it with a different root. This fixed-root
design is an authorization rule; a candidate cannot authorize its own key.

`Policy::load_signed_monotonic` is a lower-level verifier with caller-supplied
root/algorithm and optional prior state. It does not implement a persistent
succession authority. Supplying `None` explicitly bootstraps verification; a host
must not use it as a recovery fallback for missing or rejected trusted state.
The owned SDK/store paths already retain the established root and state instead.

The candidate's `min_nist_level` checks its signer's strength. Business signature
allow-lists (`allowed_sigs` / `deprecated`) are a different role from authority to
update policy: an ML-DSA-65 policy signature can remain authorized even when that
algorithm is retired for business use. This separation is intentional. Reading
those lists as an update-authority list would prevent some algorithm migrations.
It is not an authentication bypass or evidence that the candidate chose its root.

The lifecycle gap is real for the default fixed-root/v1 path: that authority cannot rotate or recover. Policy
versions are `u32` and ordinary updates must strictly increase them. An authorized
policy at `u32::MAX` prevents every further update, including a disabled policy.
The host-store regression
`max_version_exhaustion_is_durable_and_not_a_bootstrap_fallback` verifies that the
condition survives reopening, that same-version/lower-version disable attempts
fail, and that a separately valid replacement root cannot select itself. Closing
the runtime revokes local aliases but does not persist an emergency-disable policy.

A larger counter, rejecting only the largest value, or rolling back/reinitializing
storage would not provide independent recovery from a compromised signing key.
The threshold-governed succession below and complete Continuity root migration
remain **DESIGN**. A limited opt-in Rust host-store v2 profile now implements a
fixed independently pinned recovery key, exact predecessor/history binding,
incoming-key possession proof and durable cutover. See its
[contract and limits](../SDK_HOST_STORE.md#independent-online-root-recovery-rust-development-profile).
It does not implement this RFC's N-of-M governance, recovery-key rotation or
transparent migration of existing v1 stores.

## 2. Target semantics (DESIGN)

Let `P_n` be the currently trusted policy and `S_n` its trusted state.

1. **Predecessor governs succession.** `P_n` alone decides who may sign `P_{n+1}`.
2. **No self-authorization.** `P_{n+1}` defines authority for `P_{n+2}` onward. It
   never contributes to the decision to accept itself.
3. **Update authority is a distinct role.** The set of keys/algorithms permitted to
   *sign policy updates* is separate from `allowed_sigs` / `deprecated`, which
   govern business/protocol signatures. Conflating them is what makes the naive
   "signer must be in `allowed_sigs`" guard break algorithm migration.
4. **Succession records are bound and atomic.** An accepted update binds
   predecessor identity (id/version), the new document digest, and the signer's
   key identity *and* algorithm; acceptance and the monotonic state advance commit
   together or not at all.
5. **Bootstrap and recovery are explicit.** The first policy is introduced from an
   external trust root through a dedicated entry point. Emergency recovery is a
   separate, explicit rule — never an implicit fallback reached by passing `None`.

Under these rules the migration case resolves cleanly: outgoing algorithm `X` may
sign the transition policy that retires `X`, because `P_n` (which still authorizes
`X` for updates) governs that transition. Once committed, `X` loses update
eligibility unless `P_{n+1}` explicitly re-grants it.

## 3. Binding constraint: preserve existing ABI 2 contracts (ENFORCED)

[`artifact/c_abi_contract.py`](../../artifact/c_abi_contract.py) checks a
version-specific closed export set: nine symbols for 0.1.5 and **43 for 0.2.0**.
The latter imports its additive owner declarations from
[`artifact/sdk_abi2_spec.py`](../../artifact/sdk_abi2_spec.py). All original nine
signatures/status values and the 36-byte trusted-policy-state encoding remain
unchanged. The current 43-symbol allow-list must not silently grow either.

This RFC previously mistook the historical nine-symbol snapshot for a permanent
ban on additive ABI 2 entry points. That was incorrect. Existing structures and
encodings cannot be widened in place, but a separate versioned authority state
and explicitly reviewed additive interface do not inherently require ABI major 3.
Any such implementation must update the SDK extension/package contract, generated
headers, language wrappers, and old/new installed-consumer validation together.
No new export or authority encoding is specified or approved by this RFC itself.

The 36-byte value identifies a policy version/digest. It must not be relabelled as
a complete authenticated authority/recovery state. Use a distinct versioned state
with an explicit connection-binding contract; preserve existing KATs and byte
contracts rather than overloading their fields.

## 4. Proposed shape (DESIGN)

### 4.1 Separate the authority from the algorithm allow-lists

```
UpdateAuthority {            // governance — who may sign the NEXT policy
    keys:      [{ key_id, algorithm, public_key_digest }],
    threshold: u8,           // N-of-M quorum for the NEXT update (see §4.3)
}
```

`UpdateAuthority` is carried *by the policy document* (governing its successor)
and committed into the trusted state. It is disjoint from `allowed_sigs` /
`deprecated`, which continue to govern protocol signatures only.

### 4.2 Entry points

```rust
// The only entry point without a predecessor. Explicit, separate, auditable.
Policy::bootstrap(root: &UpdateAuthority, toml, sigs) -> (Policy, TrustedState)

// The only state-changing entry point. S_n authorizes P_{n+1}.
Policy::advance(current: &TrustedState, toml, sigs) -> (Policy, TrustedState)

// Demoted: proves bytes carry a valid signature. Produces NO trusted policy.
policy::verify_detached(key, toml, sig) -> VerifiedBytes
```

This proposed API would supersede `load_signed` / `load_signed_monotonic` for
authority succession; no such deprecation or replacement is implemented yet.
Crucially, **the verification key must be taken from the trusted state, not from
a caller argument** — otherwise the caller, not `P_n`, still decides who may sign,
and the whole chain is decorative.

Atomicity is expressed by construction: `advance` returns the new policy and new
state as one value, with no intermediate "accepted but not yet advanced" state for
a caller to mishandle. Durability of the returned state remains the caller's
responsibility (the library does not own storage) and must be documented as such.

### 4.3 Anti-lockout

A rotation that names an unusable successor key must fail *before* commit, not
brick updates afterwards. Two **separate** quorums are involved, and conflating
them reintroduces the lockout:

- **Authorization quorum — the current authority.** Accepting `P_{n+1}` requires
  satisfying `S_n`'s recorded `UpdateAuthority.threshold`. This is the ordinary
  succession rule (§2 rule 1) and is unaffected by what the candidate declares.
- **Capability quorum — the candidate authority.** A transition that *changes*
  `UpdateAuthority` additionally requires proof of possession from **enough
  distinct candidate keys to satisfy the candidate's own declared threshold** —
  each signing the transition digest, which demonstrates control of the private
  key rather than merely naming a public one.

  The candidate's `threshold` is **not** rewritten (to `2` or anything else): by
  the no-self-authorization rule (§2 rule 2) it governs the *following* update, so
  overwriting it would silently change the post-rotation quorum. Requiring merely
  "outgoing plus one incoming signature" is also insufficient for a general
  N-of-M rotation: for a 2-of-3 candidate authority, one usable incoming key
  satisfies such a rule while a second key that was mistyped or lost leaves the
  committed authority permanently unable to reach its own quorum — precisely the
  lockout this section exists to prevent.
- **Explicit recovery rule.** A separately authorized recovery path, distinct from
  normal succession and never reached implicitly.

## 5. Staging

1. **(done, separate)** Role/strength separation in the allow-lists —
   [PR #74](https://github.com/billlza/q-periapt/pull/74). Independent of this RFC.
2. **This document** — pin the semantics and distinguish current fixed-root
   enforcement from the missing rotation/recovery lifecycle.
3. **Rust-only implementation.** `bootstrap` / `advance` / `verify_detached` in
   `q-periapt-policy`, consumed by rustls / the policy agent / the migration model.
   This is compatible with the freeze **because it adds no C export and does not
   change the 36-byte state**: the authority commitment lives in a Rust-side state
   type, and the 36-byte ABI 2 state remains the policy-identity value it is today.
4. **Product interface review.** Expose the completed lifecycle through a distinct
   versioned state and reviewed additive owner interface, or propose a new ABI
   major if existing layouts/signatures must change. Include durable host storage,
   language wrappers and installed consumers; a Rust-only verifier is not closure
   of the product lifecycle.

## 6. Open questions (OPEN)

- **State versioning.** The Rust-side authority state needs its own canonical,
  version-tagged encoding; it must not be conflated with the 36-byte ABI 2 state.
  Wire format is unspecified here.
- **Key identity.** Whether `key_id` is a raw public key, a digest, or an
  indirection to a caller-held keystore — this decides how much key material the
  state must carry.
- **Interaction with the migration contract.** Whether the succession record
  becomes an input to the session-acceptance predicate in
  [`MIGRATION_CONTRACT_RESEARCH.md`](../MIGRATION_CONTRACT_RESEARCH.md) or stays
  strictly below it.
- **Recovery authorization.** What authorizes recovery when the authority is lost
  entirely — necessarily an out-of-band trust root, whose handling is unspecified.

## 7. Non-goals

This RFC does not propose key transparency, a policy distribution transport, a
revocation service, multi-tenant policy scoping, or any change to the combiner,
suite negotiation, or ABI 2 byte contract.

## 8. Recovery requirements and unresolved integration (DESIGN)

Recovery authorization must be independently pinned before an online-root
compromise. Neither the candidate policy nor the compromised online signer may
replace that recovery authority. For an existing installation with no such pin,
adding one requires a separately authorized trust-configuration/migration ceremony;
opening with a newly supplied key is not that ceremony.

An authorization must bind the deployment/lineage, exact predecessor authority and
policy state, a distinct recovery generation, replacement authority, replacement
policy and original operation identity. The generation advances by exactly one;
normal policy versions remain monotonic within their authority epoch. Incoming
keys must prove possession over the full transition, at the incoming authority's
own threshold. A signature on a previously published policy alone is insufficient.

The store must compare the predecessor and commit the new authority, policy,
generation and original signed receipt together before exposing a runtime. An
uncertain outcome must be reconciled using that same operation; it must not create
a new operation, roll back a floor or fall through to first provisioning. Reopening
must authenticate the stored successor against the independent recovery trust
configuration. Old aliases remain revoked after successful cutover.

Authority epoch/lineage must also have an explicit protocol identity. Binding only
a per-device predecessor receipt would prevent peers that legitimately started
from different policy versions from agreeing on the same recovered deployment.
Binding only the policy bytes could reuse an old identity after rotation back to
a prior key. The common fleet-level authorization and per-store compare/commit
receipt therefore need distinct roles; their encoding and integration are **OPEN**.

This path must compose with Continuity's installation, credential, roster and
witness authority rules. The existing migration reset and device-replacement
flows are not automatically SDK policy-root recovery. Protected-file durability
also does not provide resistance to restoring an entire old disk image. Recovery
can report authorized cutover; it cannot observe whether the replacement private
keys are unknown to an attacker or assert restored message confidentiality merely
because a root/version changed.
