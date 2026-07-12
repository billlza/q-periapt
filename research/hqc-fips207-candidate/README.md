# HQC v5 / FIPS 207 draft-candidate shadow lane

This directory is an isolated, `publish = false`, `no_std` research workspace
for evaluating `hqc-kem = 0.1.0-rc.0`. It is intentionally outside the root
Cargo workspace and has its own `Cargo.lock`.

The upstream crate describes itself as implementing FIPS 207 and its v5
candidate. That wording is an upstream tracking claim, not official publication
evidence. As checked on 2026-07-12, NIST's
[`/pubs/fips/207/ipd`](https://csrc.nist.gov/pubs/fips/207/ipd) endpoint is
unavailable, while NIST's
[selected-algorithms page](https://csrc.nist.gov/projects/post-quantum-cryptography/selected-algorithms-2022)
still describes FIPS 207 as forthcoming. This lane therefore uses
`FIPS207-DRAFT-CANDIDATE` labels and makes no IPD/final-standard claim.

This is **not** a production Q-Periapt suite, an ABI 1/ABI 2 dependency, a FIPS
validation claim, or a claim that the eventual FIPS 207 bytes are final. It has
no numeric suite code and specifically does not reuse historical suite code
`3`. Any future promotion requires a new, explicitly versioned suite identifier,
fresh proof-to-byte evidence, interoperability vectors, timing evidence, and a
separate release decision after the standard and implementation stabilize.

## Candidate contract

| Adapter algorithm label | Public key | Secret key | Ciphertext | Shared secret | Deterministic encapsulation input |
|---|---:|---:|---:|---:|---:|
| `HQC-128-V5-FIPS207-DRAFT-CANDIDATE` | 2241 | 2321 | 4433 | 32 | 16-byte message + 16-byte salt |
| `HQC-192-V5-FIPS207-DRAFT-CANDIDATE` | 4514 | 4602 | 8978 | 32 | 24-byte message + 16-byte salt |
| `HQC-256-V5-FIPS207-DRAFT-CANDIDATE` | 7237 | 7333 | 14421 | 32 | 32-byte message + 16-byte salt |

Key generation consumes exactly 32 deterministic bytes. All adapter boundaries
reject wrong input or output lengths with `q_periapt_core::Error::InvalidLength`
before mutating outputs. Same-length corrupt ciphertexts continue to the
upstream Fujisaki-Okamoto implicit-rejection path and return a pseudorandom
32-byte secret rather than an oracle error.

Both `Kem::C2PRI` and `Kem::COMPAT_XWING_SAFE` are deliberately `false`. The
candidate can therefore be constructed under `Profile::ContextBound`, which
binds every component ciphertext and public key, while `Profile::CompatXWing`
is rejected with `Error::PolicyDenied`.

## Architecture boundary

The production workspace has no dependency on this crate. Dependency direction
is one way only:

```text
q-periapt-hqc-fips207-candidate
  -> q-periapt-core (production trait/error contract)
  -> hqc-kem 0.1.0-rc.0 (candidate primitive)
  -> q-periapt-kem (dev-only profile/combiner contract tests)
```

The root production package graph and root `Cargo.lock` are not modified or
resolved into this workspace. Cargo still reads the root workspace metadata
needed by the two explicit path dependencies because those production crates
inherit package fields from it; that one-way metadata dependency does not make
this candidate a root workspace member.

## Verification

Run the complete independent gate from this directory or any parent directory:

```sh
bash research/hqc-fips207-candidate/scripts/verify.sh
```

The script fails if formatting, Clippy, tests, documentation, dependency audit,
host build, or any installed cross-target build fails. It explicitly reports
cross targets that are not installed; a missing target is not reported as a
successful build. MSRV is pinned in `Cargo.toml` to Rust 1.85 and is checked when
the `1.85` toolchain is installed.
