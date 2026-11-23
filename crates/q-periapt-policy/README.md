# q-periapt-policy

Signed algorithm policy, rollback/equivocation state and suite resolution for
Q-Periapt. Policy parsing and signature verification remain explicit operations.

```sh
cargo add 'q-periapt-policy@=0.2.0'
```

## API and host responsibilities

The [0.2.0 Rust API](https://docs.rs/q-periapt-policy/0.2.0/q_periapt_policy/)
includes `Policy`, `TrustedPolicyState`, and resolved suite decisions.
`load_signed` verifies the exact policy bytes against the supplied trusted key.
Monotonic admission compares the signed version and digest with independently
retained trusted state; equal versions with different bytes are conflicts.

The host pins the verification key and commits the accepted state durably
before using it. `Policy::from_toml` provides parsing without signature
authentication. Resolution selects from the concrete suites supported by the
caller; a policy declaration does not add a backend to a fixed product surface.

The [owned SDK](https://docs.rs/q-periapt-sdk/0.2.0/q_periapt_sdk/)
integrates policy verification with key ownership.
[q-periapt-host-store](https://docs.rs/q-periapt-host-store/0.2.0/q_periapt_host_store/)
supplies durable policy ownership. Read the
[prepare/persist/activate contract](https://github.com/billlza/q-periapt/blob/v0.2.0-verified-cohort/docs/SDK_POLICY_UPDATES.md)
for policy replacement.

## Release and evidence

- [Published 0.2.0 package and qualification record](https://github.com/billlza/q-periapt/tree/v0.2.0-verified-cohort/release/0.2.0)
- [Proofs, performance results and reproduction entry points](https://github.com/billlza/q-periapt/blob/main/docs/EVIDENCE_INDEX.md)
- [Changelog](https://github.com/billlza/q-periapt/blob/main/CHANGELOG.md)
