#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # q-periapt-core
//!
//! Auditable, `no_std`, panic-light core for the PQ/T hybrid suite.
//!
//! This crate contains **no cryptographic primitive implementations**. Every
//! primitive (ML-KEM, X25519, HQC, SHA3/SHAKE) is injected through a trait.
//!
//! Rationale: keep the security-critical *composition* logic — the hybrid KEM
//! combiner and its transcript/context binding — tiny, primitive-agnostic and
//! reviewable in isolation, decoupled from any backend or platform. Vetted /
//! formally-verified backends (libcrux, RustCrypto, x25519-dalek, sha3) are
//! wired in by the `q-periapt-kem` / `q-periapt-sig` crates.
//!
//! ## Security notes
//! - Error values are deliberately coarse and **must never** encode
//!   secret-dependent information (e.g. *why* a decapsulation failed). The only
//!   errors are *public* conditions (buffer lengths, policy). Failure paths are
//!   designed to be indistinguishable — see `docs/COMBINER_SPEC.md`.
//! - The combiner constructions here are pinned by `docs/COMBINER_SPEC.md` and
//!   `docs/BINDING_SECURITY.md`, validated by KATs, which are authoritative.
//! - The constant-time helpers ([`ct_select32`], [`ct_eq`]) are best-effort in
//!   portable Rust; real constant-time assurance comes from the side-channel CI
//!   (dudect / binary-level checks) — see `docs/ROADMAP.md`.

/// Length in bytes of a combined hybrid shared secret (SHA3-256 / SHAKE-256-32).
pub const SHARED_SECRET_LEN: usize = 32;

/// Domain-separation tag for the context-bound combiner profile. Bumped on any
/// wire-incompatible change to the binding format.
pub const DOMAIN: &[u8] = b"Q-PERIAPT-HYBRID-KEM/v1";

/// The X-Wing combiner label `\.//^\` (6 bytes), per
/// `draft-connolly-cfrg-xwing-kem`. Used only by [`Profile::CompatXWing`].
pub const XWING_LABEL: [u8; 6] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

/// Coarse, side-channel-safe error type. Variants carry no secret information;
/// every variant corresponds to a *publicly observable* condition.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Error {
    /// A supplied buffer had an unexpected length (a public, attacker-known fact).
    InvalidLength,
    /// A backend primitive reported an opaque failure.
    Backend,
    /// The active algorithm policy / profile combination is forbidden
    /// (e.g. a non-C2PRI KEM requested with the fast `CompatXWing` profile).
    PolicyDenied,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Error::InvalidLength => "invalid length",
            Error::Backend => "backend failure",
            Error::PolicyDenied => "policy denied",
        };
        f.write_str(s)
    }
}

/// A 32-byte secret that is best-effort zeroized on drop.
///
/// NOTE: this is a dependency-free, best-effort wipe using [`core::hint::black_box`]
/// to discourage dead-store elimination. Production backends should prefer the
/// audited `zeroize` crate; tracked in `docs/ROADMAP.md`.
#[derive(Clone)]
pub struct Secret([u8; SHARED_SECRET_LEN]);

impl Secret {
    /// Wrap raw bytes as a secret.
    #[must_use]
    pub fn from_bytes(bytes: [u8; SHARED_SECRET_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrow the raw secret bytes. Treat the result as secret.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_LEN] {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        for b in self.0.iter_mut() {
            *b = 0;
        }
        // Prevent the compiler from eliding the wipe above.
        let _ = core::hint::black_box(&self.0);
    }
}

/// An incremental XOF / hash used to derive the combined secret (e.g. SHAKE-256
/// or SHA3-256). Implementations **must** be constant-time with respect to the
/// absorbed data.
pub trait Xof256 {
    /// Create a fresh, empty absorbing state.
    fn new() -> Self;
    /// Absorb a chunk of input.
    fn absorb(&mut self, data: &[u8]);
    /// Finalize and squeeze exactly 32 output bytes.
    fn squeeze32(self) -> [u8; SHARED_SECRET_LEN];
}

/// A key-encapsulation mechanism backend (ML-KEM, X25519-as-KEM, HQC, ...).
///
/// All methods **must** run in constant time with respect to secret inputs, and
/// `decapsulate` **must** use implicit rejection so its failure path is
/// indistinguishable from success — it must NOT return [`Error`] to signal an
/// invalid ciphertext (only public conditions like a length mismatch).
pub trait Kem {
    /// Stable algorithm identifier, e.g. `"ML-KEM-768"`.
    fn algorithm(&self) -> &'static str;

    /// Whether this KEM is **ciphertext second-preimage resistant** (C2PRI),
    /// i.e. provably binds its ciphertext (ML-KEM-768 via the FO transform +
    /// explicit rejection). This is the load-bearing property that lets
    /// [`Profile::CompatXWing`] safely *omit* the PQ ciphertext from the KDF.
    ///
    /// Defaults to `false` (the safe choice): a KEM that does not prove C2PRI
    /// must be combined with [`Profile::ContextBound`], which binds all
    /// ciphertexts. Backends that are proven C2PRI override this to `true`.
    const C2PRI: bool = false;

    /// Encapsulate to `pk`, writing the ciphertext to `ct` and shared secret to
    /// `ss`. `randomness` supplies the KEM's encapsulation coins (caller-provided
    /// so the operation is deterministic — required for KATs — and `no_std`, with
    /// no internal RNG). ML-KEM-768 and X25519 each consume 32 bytes.
    fn encapsulate(
        &self,
        pk: &[u8],
        randomness: &[u8],
        ct: &mut [u8],
        ss: &mut [u8],
    ) -> Result<(), Error>;
    /// Decapsulate `ct` with `sk`, writing the shared secret to `ss`.
    fn decapsulate(&self, sk: &[u8], ct: &[u8], ss: &mut [u8]) -> Result<(), Error>;
}

/// Which combiner construction to use.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Profile {
    /// Fast, byte-exact X-Wing-compatible combiner (parity with mainstream).
    /// Binds the traditional ciphertext+pubkey; relies on the PQ KEM being
    /// [`Kem::C2PRI`] to *not* hash the PQ ct/pk. Requires all four absorbed
    /// fields to be exactly 32 bytes. Does **not** bind external context.
    CompatXWing = 1,
    /// Stronger context-bound combiner: domain-separated, injective fixed-width
    /// length-prefixed, binds a first-class agility block (`suite_id`,
    /// `policy_version`), every component ct+pk, **and** a mandatory non-empty
    /// caller context (e.g. a handshake transcript hash). Target notion
    /// `MAL-BIND-K-CT`/`K-PK` reducing only to XOF collision-resistance — see
    /// `docs/BINDING_SECURITY.md`. Costs extra hashing vs [`Profile::CompatXWing`].
    ContextBound = 2,
}

/// The values fed to [`combine`]. Slices, so it works for any parameter set.
#[derive(Clone, Copy)]
pub struct CombineInput<'a> {
    /// Canonical suite identifier (e.g. `b"ML-KEM-768+X25519"`). Bound
    /// first-class by [`Profile::ContextBound`] for downgrade/substitution
    /// resistance; ignored by [`Profile::CompatXWing`].
    pub suite_id: &'a [u8],
    /// Algorithm-policy / agility version. Bound first-class by
    /// [`Profile::ContextBound`]; ignored by [`Profile::CompatXWing`].
    pub policy_version: u32,
    /// Post-quantum (ML-KEM) shared secret.
    pub ss_pq: &'a [u8],
    /// Traditional (X25519) shared secret.
    pub ss_trad: &'a [u8],
    /// Post-quantum ciphertext.
    pub ct_pq: &'a [u8],
    /// Post-quantum public key.
    pub pk_pq: &'a [u8],
    /// Traditional "ciphertext" (the X25519 ephemeral public key).
    pub ct_trad: &'a [u8],
    /// Traditional recipient public key.
    pub pk_trad: &'a [u8],
    /// Caller context to bind (transcript hash, etc.). Used only by
    /// [`Profile::ContextBound`]. Downgrade resistance does NOT rely on this
    /// field — it is bound *in addition to* the structured agility block.
    pub context: &'a [u8],
}

fn absorb_lp<X: Xof256>(x: &mut X, data: &[u8]) {
    // Fixed-width (8-byte) big-endian length prefix on every field, so the
    // encoding of the field tuple is injective: distinct tuples — including ones
    // differing only in field boundaries — can never map to the same byte
    // string. This injectivity is the load-bearing step of the
    // collision-resistance → binding reduction (docs/BINDING_SECURITY.md §3.2).
    x.absorb(&(data.len() as u64).to_be_bytes());
    x.absorb(data);
}

/// Derive the combined hybrid shared secret from both components.
///
/// See `docs/COMBINER_SPEC.md` and `docs/BINDING_SECURITY.md` for the
/// authoritative definitions and test vectors. Returns [`Error::InvalidLength`]
/// if a [`Profile::CompatXWing`] field is not exactly 32 bytes (required for
/// X-Wing byte-exactness and to avoid canonical-encoding ambiguity), or if a
/// [`Profile::ContextBound`] call has an empty `context` (required for the
/// `MAL-BIND-K-CTX` guarantee).
pub fn combine<X: Xof256>(profile: Profile, input: &CombineInput<'_>) -> Result<Secret, Error> {
    let mut x = X::new();
    match profile {
        // X-Wing: SHA3-256(ss_M || ss_X || ct_X || pk_X || label). All four
        // fields are fixed 32-byte values, concatenated with NO length prefixes
        // for byte-exactness. We HARD-CHECK the lengths first: without this,
        // arbitrary-length slices could collide across field boundaries
        // (e.g. 33+31 vs 32+32), collapsing domain separation.
        Profile::CompatXWing => {
            if input.ss_pq.len() != SHARED_SECRET_LEN
                || input.ss_trad.len() != SHARED_SECRET_LEN
                || input.ct_trad.len() != SHARED_SECRET_LEN
                || input.pk_trad.len() != SHARED_SECRET_LEN
            {
                return Err(Error::InvalidLength);
            }
            x.absorb(input.ss_pq);
            x.absorb(input.ss_trad);
            x.absorb(input.ct_trad);
            x.absorb(input.pk_trad);
            x.absorb(&XWING_LABEL);
        }
        // Context-bound: the GHP/Chempat "hash everything" shape under an
        // injective, fixed-width-BE-length-prefixed, domain-separated encoding.
        // Reduces MAL-BIND-K-CT / K-PK to collision-resistance of the XOF with
        // NO binding assumption on the component KEMs. Canonical field order
        // (docs/BINDING_SECURITY.md §3.2):
        //   0 LABEL, 1 suite_id, 2 policy_version, 3 ss_pq, 4 ss_trad,
        //   5 ct_pq, 6 pk_pq, 7 ct_trad, 8 pk_trad, 9 context.
        // `DOMAIN` is field 0 and is distinct from `XWING_LABEL`, giving
        // cross-profile separation; suite_id + policy_version are bound
        // first-class for downgrade/substitution resistance.
        Profile::ContextBound => {
            // Mandatory non-empty context, else the K-CTX guarantee degenerates
            // (docs/BINDING_SECURITY.md §3.3). Callers with no application
            // context pass a fixed protocol/role/version label.
            if input.context.is_empty() {
                return Err(Error::InvalidLength);
            }
            absorb_lp(&mut x, DOMAIN);
            absorb_lp(&mut x, input.suite_id);
            absorb_lp(&mut x, &input.policy_version.to_be_bytes());
            absorb_lp(&mut x, input.ss_pq);
            absorb_lp(&mut x, input.ss_trad);
            absorb_lp(&mut x, input.ct_pq);
            absorb_lp(&mut x, input.pk_pq);
            absorb_lp(&mut x, input.ct_trad);
            absorb_lp(&mut x, input.pk_trad);
            absorb_lp(&mut x, input.context);
        }
    }
    Ok(Secret::from_bytes(x.squeeze32()))
}

/// Returns `0xFF` if `x == 0`, else `0x00`, without branching on `x`.
fn ct_is_zero(x: u8) -> u8 {
    let q = ((u32::from(x).wrapping_sub(1)) >> 8) & 1; // 1 iff x == 0
    (q as u8).wrapping_neg()
}

/// Constant-time equality of two byte slices. Returns `0xFF` if equal, else
/// `0x00`. The slice *lengths* are treated as public (compared directly).
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> u8 {
    if a.len() != b.len() {
        return 0x00;
    }
    let mut acc = 0u8;
    for (&xa, &xb) in a.iter().zip(b.iter()) {
        acc |= xa ^ xb;
    }
    ct_is_zero(acc)
}

/// Branch-free select over 32-byte buffers: returns `a` if `mask == 0xFF`, `b`
/// if `mask == 0x00`. `mask` must be all-ones or all-zeros (use [`ct_eq`] /
/// [`ct_is_zero`] to produce it). This is the primitive for implicit rejection:
/// always run the real and rejection derivations, then select with a mask, so
/// the failure path is instruction-indistinguishable from success.
#[must_use]
pub fn ct_select32(mask: u8, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for ((o, &ai), &bi) in out.iter_mut().zip(a.iter()).zip(b.iter()) {
        *o = (ai & mask) | (bi & !mask);
    }
    out
}

#[cfg(test)]
mod tests {
    // Toy test helpers index slices / unwrap freely; the lints target library code.
    #![allow(clippy::indexing_slicing, clippy::unwrap_used)]
    use super::*;

    /// Toy, NON-cryptographic XOF used only to exercise the wiring/determinism
    /// of the combiner. Never use outside tests.
    struct ToyXof(u64);
    impl Xof256 for ToyXof {
        fn new() -> Self {
            ToyXof(0xcbf2_9ce4_8422_2325)
        }
        fn absorb(&mut self, data: &[u8]) {
            for &b in data {
                self.0 ^= u64::from(b);
                self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        fn squeeze32(mut self) -> [u8; 32] {
            let mut out = [0u8; 32];
            for chunk in out.chunks_mut(8) {
                self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3) ^ 0x9e37_79b9_7f4a_7c15;
                let bytes = self.0.to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
            out
        }
    }

    fn input_with(suite: &'static [u8], ver: u32, ctx: &'static [u8]) -> CombineInput<'static> {
        CombineInput {
            suite_id: suite,
            policy_version: ver,
            ss_pq: &[1u8; 32],
            ss_trad: &[2u8; 32],
            ct_pq: &[3u8; 8],
            pk_pq: &[4u8; 8],
            ct_trad: &[5u8; 32],
            pk_trad: &[6u8; 32],
            context: ctx,
        }
    }

    #[test]
    fn deterministic_and_profiles_differ() {
        let inp = input_with(b"suite-A", 1, b"ctx");
        let a = combine::<ToyXof>(Profile::CompatXWing, &inp).unwrap();
        let a2 = combine::<ToyXof>(Profile::CompatXWing, &inp).unwrap();
        let b = combine::<ToyXof>(Profile::ContextBound, &inp).unwrap();
        assert_eq!(
            a.as_bytes(),
            a2.as_bytes(),
            "combiner must be deterministic"
        );
        assert_ne!(
            a.as_bytes(),
            b.as_bytes(),
            "profiles must be domain-separated"
        );
    }

    #[test]
    fn compat_rejects_wrong_length() {
        // 33-byte ss_pq must be rejected (canonical-encoding guard).
        let mut inp = input_with(b"s", 1, b"");
        inp.ss_pq = &[1u8; 33];
        assert_eq!(
            combine::<ToyXof>(Profile::CompatXWing, &inp).err(),
            Some(Error::InvalidLength)
        );
    }

    #[test]
    fn context_bound_binds_suite_and_version_and_context() {
        let base =
            combine::<ToyXof>(Profile::ContextBound, &input_with(b"suite-A", 1, b"ctx")).unwrap();
        let diff_suite =
            combine::<ToyXof>(Profile::ContextBound, &input_with(b"suite-B", 1, b"ctx")).unwrap();
        let diff_ver =
            combine::<ToyXof>(Profile::ContextBound, &input_with(b"suite-A", 2, b"ctx")).unwrap();
        let diff_ctx =
            combine::<ToyXof>(Profile::ContextBound, &input_with(b"suite-A", 1, b"other")).unwrap();
        assert_ne!(base.as_bytes(), diff_suite.as_bytes(), "suite_id must bind");
        assert_ne!(
            base.as_bytes(),
            diff_ver.as_bytes(),
            "policy_version must bind"
        );
        assert_ne!(base.as_bytes(), diff_ctx.as_bytes(), "context must bind");
    }

    #[test]
    fn context_bound_requires_nonempty_context() {
        let inp = input_with(b"suite-A", 1, b"");
        assert_eq!(
            combine::<ToyXof>(Profile::ContextBound, &inp).err(),
            Some(Error::InvalidLength)
        );
    }

    #[test]
    fn injective_encoding_prevents_boundary_collision() {
        // Negative KAT (docs/BINDING_SECURITY.md §3.2): two tuples differing only
        // in where the suite_id/context boundary falls. Under naive concatenation
        // they could collide; fixed-width length prefixing must keep them distinct.
        let a = input_with(b"AB", 1, b"C");
        let b = input_with(b"A", 1, b"BC");
        let ka = combine::<ToyXof>(Profile::ContextBound, &a).unwrap();
        let kb = combine::<ToyXof>(Profile::ContextBound, &b).unwrap();
        assert_ne!(ka.as_bytes(), kb.as_bytes());
    }

    #[test]
    fn compat_profile_ignores_agility_and_context() {
        // X-Wing-compatible profile must NOT depend on suite/version/context.
        let x =
            combine::<ToyXof>(Profile::CompatXWing, &input_with(b"suite-A", 1, b"ctx-A")).unwrap();
        let y =
            combine::<ToyXof>(Profile::CompatXWing, &input_with(b"suite-B", 9, b"ctx-B")).unwrap();
        assert_eq!(x.as_bytes(), y.as_bytes());
    }

    #[test]
    fn ct_helpers() {
        assert_eq!(ct_eq(b"abc", b"abc"), 0xFF);
        assert_eq!(ct_eq(b"abc", b"abd"), 0x00);
        assert_eq!(ct_eq(b"abc", b"ab"), 0x00);
        let a = [0xAAu8; 32];
        let b = [0x55u8; 32];
        assert_eq!(ct_select32(0xFF, &a, &b), a);
        assert_eq!(ct_select32(0x00, &a, &b), b);
    }
}
