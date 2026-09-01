# Policy Update Authority — design RFC (V1 draft)

> **Status: DESIGN ONLY. Nothing in this document is implemented.** No API,
> encoding, or guarantee described here exists in the shipped crates today. It
> defines the target semantics for authenticated policy *succession*, records the
> ABI constraints that bound any implementation, and states what is explicitly out
> of scope. Tags follow [`THREAT_MODEL.md`](../THREAT_MODEL.md): **ENFORCED** (a CI
> gate or type-level invariant fails the build on regression), **DESIGN** (agreed
> target, not built), **OPEN** (unresolved question).
>
> Cross-references: [`THREAT_MODEL.md`](../THREAT_MODEL.md) §4.3 (ADV-POLICY),
> [`MIGRATION_CONTRACT_RESEARCH.md`](../MIGRATION_CONTRACT_RESEARCH.md) (the
> session-acceptance layer above this one),
> [`crates/q-periapt-policy/src/lib.rs`](../../crates/q-periapt-policy/src/lib.rs).

## 1. Problem

`Policy::load_signed` authenticates a policy document against a caller-supplied
key and returns an `AuthenticatedPolicy` — a value the caller may then treat as
trusted. Two properties of that design are wrong, independent of any
implementation bug:

**1.1 The document authorizes its own signer.** After parsing, the only
policy-derived gate on the signer is:

```rust
if verifier.algorithm().nist_level() < policy.min_nist_level() {
    return Err(PolicyError::WeakSigner);
}
```

`policy` here is the *newly parsed document*. The bar the signer must clear is
therefore set by the document being authorized. The stated intent ("an L1 root
must not sign an L5 policy") holds, but the converse — an L1 key signing a new
document that declares `min_nist_level = 1` — is self-consistent and accepted.
Authority must come from the predecessor, never from the candidate.

**1.2 Succession is not modelled.** `load_signed_monotonic` accepts
`last_trusted: Option<&TrustedPolicyState>`, but `TrustedPolicyState` carries only
`(version, digest)`. The predecessor therefore *cannot* express who may sign its
successor, so no authorization decision is possible even in principle. `None`
additionally means "no predecessor, accept anything" — an implicit bootstrap
fallback inside the same entry point as normal succession.

A consequence observed in review: a policy that explicitly deprecates `ML-DSA-65`
is accepted when signed by `ML-DSA-65`. `allowed_sigs`/`deprecated` have no
bearing on who may update the policy.

**Not a vulnerability.** The verification key and `Verifier` are supplied by the
caller per call, so an attacker cannot forge a signature; and the signature is
verified before the document is parsed, so document content never influences its
own signature check. These are *semantic* defects that make the trust chain
unable to express succession — not an authentication bypass.

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

## 3. Binding constraint: ABI 2 is frozen (ENFORCED)

Any implementation is bounded by two CI-gated freezes in
[`artifact/c_abi_contract.py`](../../artifact/c_abi_contract.py):

| Frozen item | Value | Consequence for this design |
|---|---|---|
| `Q_PERIAPT_TRUSTED_POLICY_STATE_LEN` | `36` (`c_abi_contract.py:76`, `:206`) | The trusted state **cannot grow** to carry an authority commitment. The FFI statically asserts it equals `TrustedPolicyState::ENCODED_LEN`. |
| `EXPECTED_EXPORTS` | exactly nine symbols, exact-match (`c_abi_contract.py:87`, checked at `:426`) | **No new C entry point** (`q_periapt_policy_advance`, …) may be added. |

Therefore **the authenticated succession state machine cannot be exposed through
ABI 2 at all.** This is the central constraint, and it rules out the obvious
implementations (extend the state; add an `advance` export). Any proposal that
requires either is an ABI 3 proposal.

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

`load_signed` / `load_signed_monotonic` are deprecated in favour of these.
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
2. **This document** — pin the semantics and record the ABI constraint.
3. **Rust-only implementation.** `bootstrap` / `advance` / `verify_detached` in
   `q-periapt-policy`, consumed by rustls / the policy agent / the migration model.
   This is compatible with the freeze **because it adds no C export and does not
   change the 36-byte state**: the authority commitment lives in a Rust-side state
   type, and the 36-byte ABI 2 state remains the policy-identity value it is today.
4. **ABI 3 (separate proposal).** Expose succession through the C ABI, which
   requires a new export and a wider state — both out of scope here.

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
