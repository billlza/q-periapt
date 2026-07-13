#![cfg_attr(not(test), no_std)]
// `deny` (not `forbid`) so the single, isolated secure-zeroization block in
// `Secret::drop` can opt in with a local `#[allow(unsafe_code)]`. That is the
// ONLY `unsafe` in the crate; everything else is forbidden by the deny.
#![deny(unsafe_code)]
#![warn(missing_docs)]

//! # q-periapt-core
//!
//! Auditable, `no_std`, panic-light core for the PQ/T hybrid suite.
//!
//! This crate contains **no cryptographic primitive implementations**. Every
//! primitive (for example ML-KEM, X25519, or SHA3/SHAKE) is injected through a trait.
//!
//! Rationale: keep the security-critical *composition* logic — the hybrid KEM
//! combiner and its transcript/context binding — tiny, primitive-agnostic and
//! reviewable in isolation, decoupled from any backend or platform. Third-party
//! backends (`mlkem-native`, `fips204`, `x25519-dalek`, `sha3`) are wired in by
//! `q-periapt-backends` behind the traits owned here and in the KEM/signature
//! composition crates.
//!
//! ## Security notes
//! - Error values are deliberately coarse and **must never** encode
//!   secret-dependent information (e.g. *why* a decapsulation failed). Variants
//!   represent either public conditions (length, policy, public-key validity) or
//!   an opaque internal backend failure. Correctly sized FO-KEM ciphertexts use
//!   implicit rejection rather than an error oracle — see `docs/COMBINER_SPEC.md`.
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

/// Domain separation for the high-level context that commits an authenticated
/// policy digest together with an application transcript/context.
pub const POLICY_CONTEXT_DOMAIN: &[u8] = b"Q-PERIAPT-POLICY-CONTEXT/v1";

/// The X-Wing combiner label `\.//^\` (6 bytes), per
/// `draft-connolly-cfrg-xwing-kem`. Used only by [`Profile::CompatXWing`].
pub const XWING_LABEL: [u8; 6] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

/// Coarse, side-channel-safe error type. Variants carry no secret information;
/// backend-internal failures remain opaque rather than exposing their cause.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum Error {
    /// A supplied buffer had an unexpected length (a public, attacker-known fact).
    InvalidLength,
    /// A backend primitive reported an opaque failure.
    Backend,
    /// A supplied **public** key share is invalid and was rejected before keying — e.g. a
    /// non-canonical ML-KEM encapsulation key or a low-order / non-contributory X25519 point (which
    /// would force an all-zero DH secret). This is a public-input validity failure, **not** a
    /// secret-dependent decapsulation oracle: an FO-KEM's ciphertext validity remains hidden by
    /// implicit rejection.
    InvalidKeyShare,
    /// The active algorithm policy / profile combination is forbidden
    /// (e.g. a first-slot KEM lacking either required `CompatXWing` capability).
    PolicyDenied,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            Error::InvalidLength => "invalid length",
            Error::Backend => "backend failure",
            Error::InvalidKeyShare => "invalid public key share",
            Error::PolicyDenied => "policy denied",
        };
        f.write_str(s)
    }
}

/// A 32-byte combined shared secret, securely zeroized on drop.
///
/// The wipe uses volatile byte writes (which the optimizer may not elide) followed
/// by a compiler fence — the same technique the audited `zeroize` crate uses,
/// inlined here to keep `q-periapt-core` dependency-free. `Secret` is intentionally
/// **not** `Clone`/`Copy`, preventing implicit duplication of the owner. Its
/// [`as_bytes`](Secret::as_bytes) borrow can still be copied explicitly; callers
/// own and must wipe any such copy. Drop wipes only this value's storage.
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
        secure_wipe(&mut self.0);
    }
}

/// Fixed-size byte storage that securely wipes its own storage on drop.
///
/// This is the shared RAII owner for seeds, component secrets, and randomness
/// that must survive fallible calls. It is intentionally not `Clone`/`Copy`.
/// Borrowers can still copy the bytes explicitly; such copies are outside this
/// value's ownership and must be wiped by their owners.
pub struct ZeroizingBytes<const N: usize>([u8; N]);

impl<const N: usize> ZeroizingBytes<N> {
    /// Allocate a zero-filled owned buffer.
    #[must_use]
    pub const fn zeroed() -> Self {
        Self([0u8; N])
    }

    /// Take ownership of an existing fixed-size array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Borrow the owned bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    /// Mutably borrow the owned bytes.
    pub fn as_mut_bytes(&mut self) -> &mut [u8; N] {
        &mut self.0
    }

    /// Wipe the owned storage immediately. Drop remains idempotent and wipes it again.
    pub fn clear(&mut self) {
        secure_wipe(&mut self.0);
    }
}

impl<const N: usize> Drop for ZeroizingBytes<N> {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Volatile-zero a buffer so the compiler may not elide the wipe, with a fence so the
/// zeroing is ordered before the storage is reused. This is exactly the `zeroize`
/// crate's technique, inlined to keep the crate dependency-free. Use it to clear
/// transient secret material that lives in borrowed scratch (component shared secrets,
/// sponge staging buffers) and so is not protected by [`Secret`]'s own `Drop`.
#[allow(unsafe_code)]
pub fn secure_wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // SAFETY: `b` points to one initialized, aligned, writable byte; a volatile
        // write of 0 is sound and the only `unsafe` operation in the crate.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// An incremental XOF / hash used to derive the combined secret (e.g. SHAKE-256
/// or SHA3-256). Implementations **must** be constant-time with respect to the
/// absorbed data, and **must** securely wipe any secret-bearing staging/sponge
/// storage that the implementation owns and can still reach when dropped (the
/// combiner absorbs raw component shared secrets) — e.g. via [`secure_wipe`] in a
/// `Drop` impl. Primitive/callee temporaries, registers, and OS copies outside the
/// implementation's ownership are a separate backend-assurance boundary.
pub trait Xof256 {
    /// Create a fresh, empty absorbing state.
    fn new() -> Self;
    /// Hint that `additional` bytes will be absorbed, so a staging implementation can allocate its
    /// buffer **once** up front and never reallocate mid-absorb. This matters for secret hygiene: a
    /// reallocation while absorbing secret material would free the old buffer without zeroizing it,
    /// leaving an unreachable copy. Default: no-op (for impls that never stage secrets).
    fn reserve(&mut self, _additional: usize) {}
    /// Absorb a chunk whose sensitivity is not classified by the caller.
    ///
    /// Implementations must conservatively treat this input as potentially secret.
    /// New code should prefer [`Xof256::absorb_public`] or
    /// [`Xof256::absorb_secret`] so a staging implementation can erase only bytes
    /// that actually held secret material. This method retains the conservative
    /// legacy contract for existing implementations and callers.
    fn absorb(&mut self, data: &[u8]);
    /// Absorb bytes known to be public and attacker-observable.
    ///
    /// The default delegates to [`Xof256::absorb`], preserving the conservative
    /// erase behavior of implementations that do not distinguish sensitivity.
    fn absorb_public(&mut self, data: &[u8]) {
        self.absorb(data);
    }
    /// Absorb bytes that contain secret material.
    ///
    /// The default delegates to [`Xof256::absorb`]. Implementations that stage
    /// input may override this method to track the exact ranges that require a
    /// secure erase, without changing the absorbed byte stream.
    fn absorb_secret(&mut self, data: &[u8]) {
        self.absorb(data);
    }
    /// Finalize and squeeze exactly 32 output bytes.
    fn squeeze32(self) -> [u8; SHARED_SECRET_LEN];
}

/// A key-encapsulation mechanism backend (for example ML-KEM or X25519-as-KEM).
///
/// Secret-bearing operations must avoid secret-dependent control flow and memory access.
/// Algorithm-mandated rejection sampling (for example, an ML-DSA signer) requires a
/// separately documented timing boundary and must not be represented as strict constant-time.
///
/// **Failure contract.** A backend must never expose a *secret-dependent* decapsulation oracle:
/// for an FO-KEM (ML-KEM), `decapsulate` **must** use implicit rejection — a cryptographically
/// invalid ciphertext yields a pseudorandom secret, never an [`Error`], so the failure path is
/// indistinguishable from success. Backends **may** return an [`Error`] only for **public** input
/// conditions that an attacker already knows (a length mismatch via [`Error::InvalidLength`]; for a
/// non-canonical KEM encapsulation key or, for a DH-style adapter such as X25519-as-KEM, a low-order
/// / non-contributory key share via [`Error::InvalidKeyShare`]). Importing a caller-supplied local
/// secret key may also return [`Error::Backend`] when its fixed-length encoding is malformed;
/// callers must treat that as a configuration/key-storage failure, not as a ciphertext-validity
/// signal. Such checks occur before output is written. They do not change the requirement that
/// every correctly sized ML-KEM ciphertext follows implicit rejection and returns a shared secret.
pub trait Kem {
    /// Stable algorithm identifier, e.g. `"ML-KEM-768"`.
    fn algorithm(&self) -> &'static str;

    /// Whether this KEM's primitive is **ciphertext second-preimage resistant** (C2PRI),
    /// i.e. provably binds its ciphertext (ML-KEM via its FO transform and implicit rejection).
    ///
    /// Defaults to `false` (the safe choice): a KEM placed in the first slot whose
    /// ciphertext/public key `CompatXWing` omits must prove C2PRI. Otherwise it must
    /// use [`Profile::ContextBound`], which binds all ciphertexts and public keys.
    const C2PRI: bool = false;

    /// Whether this **backend API and exposed key format** may be used with
    /// [`Profile::CompatXWing`].
    ///
    /// This is an additional requirement beyond [`C2PRI`](Self::C2PRI): the primitive can be C2PRI while a
    /// backend that accepts arbitrary expanded/imported decapsulation keys is still not a
    /// safe X-Wing-compatible API. Such backends must use [`Profile::ContextBound`], which
    /// binds `ct_pq` and `pk_pq` directly. Seed-derived X-Wing-style backends may opt in.
    const COMPAT_XWING_SAFE: bool = false;

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
    /// Binds the traditional ciphertext+pubkey; relies on the first-slot backend being
    /// both [`Kem::C2PRI`] and [`Kem::COMPAT_XWING_SAFE`] to *not* hash that slot's
    /// ct/pk. Requires all four absorbed fields to be exactly 32 bytes.
    ///
    /// **Footgun:** X-Wing has no `suite_id`/`policy_version`/`context` fields, so this profile
    /// **silently ignores** any you pass — it does **not** bind external context or the agility
    /// block. If you need that binding, you **must** use [`Profile::ContextBound`]; passing a
    /// context here is accepted and discarded with no error (a deliberate compatibility limitation,
    /// not context binding).
    CompatXWing = 1,
    /// Full-transcript context-bound profile: domain-separated, injective fixed-width
    /// length-prefixed, binds a first-class agility block (`suite_id`,
    /// `policy_version`), every component ct+pk, **and** a mandatory non-empty
    /// caller context (e.g. a handshake transcript hash). Standard target notions
    /// `MAL-BIND-K-CT`/`K-PK` reducing only to XOF collision-resistance — see
    /// `docs/BINDING_SECURITY.md`; the context field has a separate local wrapper
    /// collision bound and requires protocol authentication for semantic meaning.
    /// Costs extra hashing vs [`Profile::CompatXWing`].
    ContextBound = 2,
}

impl Profile {
    /// The stable 1-byte wire code (`1` = `CompatXWing`, `2` = `ContextBound`) used by
    /// the C ABI / WASM / transport faces. This is the single source of truth for the
    /// mapping, so the faces don't each hand-roll it.
    #[must_use]
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Inverse of [`to_u8`](Self::to_u8): decode a wire code, or `None` if unrecognized.
    #[must_use]
    pub fn from_u8(code: u8) -> Option<Self> {
        match code {
            1 => Some(Profile::CompatXWing),
            2 => Some(Profile::ContextBound),
            _ => None,
        }
    }
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
    /// field — it is bound *in addition to* the structured agility block. The
    /// staging XOF treats it conservatively as potentially sensitive because the
    /// public API does not require callers to supply only attacker-visible bytes.
    pub context: &'a [u8],
}

/// Parse exactly nine 8-byte big-endian length-prefixed fields from `buf` and reject
/// any trailing bytes — the canonical combiner transport decoder shared by the FFI and
/// WASM faces (so they cannot drift). The length is range-checked with `usize::try_from`
/// (not a truncating `as usize`), so an over-long prefix is rejected identically on
/// 32-bit (wasm32) and 64-bit targets.
fn parse_lp9(mut buf: &[u8]) -> Option<[&[u8]; 9]> {
    let mut out: [&[u8]; 9] = [&[]; 9];
    for slot in &mut out {
        if buf.len() < 8 {
            return None;
        }
        let (len_bytes, rest) = buf.split_at(8);
        let len_u64 = u64::from_be_bytes(len_bytes.try_into().ok()?);
        let len = usize::try_from(len_u64).ok()?;
        if rest.len() < len {
            return None;
        }
        let (field, tail) = rest.split_at(len);
        *slot = field;
        buf = tail;
    }
    buf.is_empty().then_some(out)
}

impl<'a> CombineInput<'a> {
    /// Decode the canonical length-prefixed combiner transport into a [`CombineInput`]:
    /// nine fields, each an 8-byte big-endian length followed by its bytes, in the order
    /// `suite_id`, `policy_version` (4-byte big-endian), `ss_pq`, `ss_trad`, `ct_pq`,
    /// `pk_pq`, `ct_trad`, `pk_trad`, `context`. Returns `None` on any malformed or
    /// over-long prefix, a `policy_version` field that is not 4 bytes, or trailing bytes.
    /// This is the single decoder both the C ABI and WASM faces use.
    #[must_use]
    pub fn from_transport(buf: &'a [u8]) -> Option<Self> {
        let [suite, ver, ss_pq, ss_trad, ct_pq, pk_pq, ct_trad, pk_trad, context] = parse_lp9(buf)?;
        let ver: [u8; 4] = ver.try_into().ok()?;
        Some(CombineInput {
            suite_id: suite,
            policy_version: u32::from_be_bytes(ver),
            ss_pq,
            ss_trad,
            ct_pq,
            pk_pq,
            ct_trad,
            pk_trad,
            context,
        })
    }
}

fn absorb_public_lp<X: Xof256>(x: &mut X, data: &[u8]) {
    // Fixed-width (8-byte) big-endian length prefix on every field, so the
    // encoding of the field tuple is injective: distinct tuples — including ones
    // differing only in field boundaries — can never map to the same byte
    // string. This injectivity is the load-bearing step of the
    // collision-resistance → binding reduction (docs/BINDING_SECURITY.md §3.2).
    x.absorb_public(&(data.len() as u64).to_be_bytes());
    x.absorb_public(data);
}

fn absorb_secret_lp<X: Xof256>(x: &mut X, data: &[u8]) {
    // Field lengths are public framing metadata; only the potentially sensitive
    // field body is marked secret. Both helpers produce the exact same LP byte encoding.
    x.absorb_public(&(data.len() as u64).to_be_bytes());
    x.absorb_secret(data);
}

/// Maximum application-context size accepted by policy-bound operations.
///
/// Current protocol labels and transcript hashes are tiny; this bound prevents
/// unauthenticated callers from requesting an unbounded wrapper allocation.
pub const MAX_APPLICATION_CONTEXT_BYTES: usize = 64 * 1024;

/// Exact byte length required by [`encode_policy_bound_context`].
#[must_use]
pub fn policy_bound_context_len(application_context_len: usize) -> Option<usize> {
    if application_context_len > MAX_APPLICATION_CONTEXT_BYTES {
        return None;
    }
    (8 + POLICY_CONTEXT_DOMAIN.len())
        .checked_add(8 + SHARED_SECRET_LEN)
        .and_then(|size| size.checked_add(8 + application_context_len))
}

fn write_lp<'a>(out: &'a mut [u8], field: &[u8]) -> Result<&'a mut [u8], Error> {
    let field_len = u64::try_from(field.len()).map_err(|_| Error::InvalidLength)?;
    let needed = 8usize
        .checked_add(field.len())
        .ok_or(Error::InvalidLength)?;
    if out.len() < needed {
        return Err(Error::InvalidLength);
    }
    let (length_out, rest) = out.split_at_mut(8);
    length_out.copy_from_slice(&field_len.to_be_bytes());
    let (field_out, tail) = rest.split_at_mut(field.len());
    field_out.copy_from_slice(field);
    Ok(tail)
}

/// Encode the canonical context used by signed-policy-controlled execution.
///
/// The result is `LP(domain) || LP(policy_digest) || LP(application_context)`
/// with 8-byte big-endian lengths. The caller supplies the exact SHA3-256 digest
/// of the authenticated policy and an output buffer at least
/// [`policy_bound_context_len`] bytes long. This helper is shared by native and
/// WASM faces so their context-wrapper bytes cannot drift.
pub fn encode_policy_bound_context(
    policy_digest: &[u8; SHARED_SECRET_LEN],
    application_context: &[u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let expected =
        policy_bound_context_len(application_context.len()).ok_or(Error::InvalidLength)?;
    if out.len() < expected {
        return Err(Error::InvalidLength);
    }
    let expected_tail = out.len() - expected;
    let tail = write_lp(out, POLICY_CONTEXT_DOMAIN)?;
    let tail = write_lp(tail, policy_digest)?;
    let tail = write_lp(tail, application_context)?;
    debug_assert_eq!(tail.len(), expected_tail);
    Ok(expected)
}

/// Derive the combined hybrid shared secret from both components.
///
/// See `docs/COMBINER_SPEC.md` and `docs/BINDING_SECURITY.md` for the
/// authoritative definitions and test vectors. Returns [`Error::InvalidLength`]
/// if a [`Profile::CompatXWing`] field is not exactly 32 bytes (required for
/// X-Wing byte-exactness and to avoid canonical-encoding ambiguity), or if a
/// [`Profile::ContextBound`] call has an empty `context` (the profile requires an
/// explicit protocol/application label; this is not an encoding-injectivity precondition).
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
            x.absorb_secret(input.ss_pq);
            x.absorb_secret(input.ss_trad);
            x.absorb_public(input.ct_trad);
            x.absorb_public(input.pk_trad);
            x.absorb_public(&XWING_LABEL);
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
            // Mandatory non-empty context as a semantic profile guard
            // (docs/BINDING_SECURITY.md §3.3). Fixed-width length prefixes would
            // encode an empty field injectively, but callers must make protocol /
            // role / version intent explicit through a fixed or application label.
            if input.context.is_empty() {
                return Err(Error::InvalidLength);
            }
            // Pre-reserve the whole length-prefixed transcript so a staging XOF allocates once and
            // never reallocates mid-absorb (no un-zeroizable secret residue). Each field costs its
            // 8-byte BE length prefix plus its body.
            let total = [
                DOMAIN.len(),
                input.suite_id.len(),
                core::mem::size_of::<u32>(),
                input.ss_pq.len(),
                input.ss_trad.len(),
                input.ct_pq.len(),
                input.pk_pq.len(),
                input.ct_trad.len(),
                input.pk_trad.len(),
                input.context.len(),
            ]
            .into_iter()
            .try_fold(0usize, |size, field_len| {
                size.checked_add(8)?.checked_add(field_len)
            })
            .ok_or(Error::InvalidLength)?;
            x.reserve(total);
            absorb_public_lp(&mut x, DOMAIN);
            absorb_public_lp(&mut x, input.suite_id);
            absorb_public_lp(&mut x, &input.policy_version.to_be_bytes());
            absorb_secret_lp(&mut x, input.ss_pq);
            absorb_secret_lp(&mut x, input.ss_trad);
            absorb_public_lp(&mut x, input.ct_pq);
            absorb_public_lp(&mut x, input.pk_pq);
            absorb_public_lp(&mut x, input.ct_trad);
            absorb_public_lp(&mut x, input.pk_trad);
            absorb_secret_lp(&mut x, input.context);
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

    struct ClassifyingXof {
        transcript: Vec<u8>,
        legacy_calls: u8,
        public_calls: u8,
        secret_calls: u8,
    }

    impl Xof256 for ClassifyingXof {
        fn new() -> Self {
            Self {
                transcript: Vec::new(),
                legacy_calls: 0,
                public_calls: 0,
                secret_calls: 0,
            }
        }

        fn absorb(&mut self, data: &[u8]) {
            self.legacy_calls = self.legacy_calls.saturating_add(1);
            self.transcript.extend_from_slice(data);
        }

        fn absorb_public(&mut self, data: &[u8]) {
            self.public_calls = self.public_calls.saturating_add(1);
            self.transcript.extend_from_slice(data);
        }

        fn absorb_secret(&mut self, data: &[u8]) {
            self.secret_calls = self.secret_calls.saturating_add(1);
            self.transcript.extend_from_slice(data);
        }

        fn squeeze32(self) -> [u8; SHARED_SECRET_LEN] {
            let mut out = [0u8; SHARED_SECRET_LEN];
            out[0] = self.legacy_calls;
            out[1] = self.public_calls;
            out[2] = self.secret_calls;
            out[3..11].copy_from_slice(&(self.transcript.len() as u64).to_be_bytes());
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
    fn combiner_classifies_component_secrets_and_caller_context_as_sensitive() {
        let input = input_with(b"suite-A", 1, b"ctx");
        let compat = combine::<ClassifyingXof>(Profile::CompatXWing, &input).unwrap();
        assert_eq!(compat.as_bytes()[0], 0, "legacy absorb must not be used");
        assert_eq!(compat.as_bytes()[1], 3, "ct, pk, and label are public");
        assert_eq!(compat.as_bytes()[2], 2, "both component secrets are secret");

        let context = combine::<ClassifyingXof>(Profile::ContextBound, &input).unwrap();
        assert_eq!(context.as_bytes()[0], 0, "legacy absorb must not be used");
        assert_eq!(
            context.as_bytes()[1],
            17,
            "seven public LP fields plus three sensitive length prefixes are public"
        );
        assert_eq!(
            context.as_bytes()[2],
            3,
            "both component-secret bodies and caller context are conservatively sensitive"
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
    fn compat_xwing_silently_discards_context_use_contextbound_to_bind() {
        // DELIBERATE COMPATIBILITY LIMITATION, *not* a security feature: CompatXWing is byte-exact
        // X-Wing, which has no suite_id/policy_version/context, so it SILENTLY IGNORES them. A caller
        // that needs to bind context or the agility block MUST select `Profile::ContextBound`;
        // choosing CompatXWing and passing a context yields NO context binding (the footgun the
        // `Profile::CompatXWing` doc warns about). We pin the discard so a regression cannot start
        // binding here, which would break X-Wing byte-compatibility.
        let x =
            combine::<ToyXof>(Profile::CompatXWing, &input_with(b"suite-A", 1, b"ctx-A")).unwrap();
        let y =
            combine::<ToyXof>(Profile::CompatXWing, &input_with(b"suite-B", 9, b"ctx-B")).unwrap();
        assert_eq!(x.as_bytes(), y.as_bytes()); // identical despite different ctx => discarded
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

    fn lp(out: &mut Vec<u8>, field: &[u8]) {
        out.extend_from_slice(&(field.len() as u64).to_be_bytes());
        out.extend_from_slice(field);
    }

    #[test]
    fn from_transport_round_trips_and_rejects_malformed() {
        let mut buf = Vec::new();
        for f in [
            &b"ML-KEM-768+X25519"[..],
            &7u32.to_be_bytes()[..],
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 4],
            &[4u8; 5],
            &[5u8; 6],
            &[6u8; 7],
            b"ctx",
        ] {
            lp(&mut buf, f);
        }
        let ci = CombineInput::from_transport(&buf).expect("valid transport");
        assert_eq!(ci.suite_id, b"ML-KEM-768+X25519");
        assert_eq!(ci.policy_version, 7);
        assert_eq!(ci.context, b"ctx");

        // Trailing bytes, a truncated buffer, and a too-short prefix are all rejected.
        let mut trailing = buf.clone();
        trailing.push(0);
        assert!(CombineInput::from_transport(&trailing).is_none());
        assert!(CombineInput::from_transport(&buf[..buf.len() - 1]).is_none());
        assert!(CombineInput::from_transport(&[0u8; 4]).is_none());
    }

    #[test]
    fn profile_u8_round_trips() {
        for p in [Profile::CompatXWing, Profile::ContextBound] {
            assert_eq!(Profile::from_u8(p.to_u8()), Some(p));
        }
        assert_eq!(Profile::CompatXWing.to_u8(), 1);
        assert_eq!(Profile::ContextBound.to_u8(), 2);
        assert_eq!(Profile::from_u8(0), None);
        assert_eq!(Profile::from_u8(3), None);
    }

    #[test]
    fn from_transport_rejects_overlong_length_prefix() {
        // An 8-byte prefix with the high 32 bits set must be rejected as out-of-range
        // (a checked `usize::try_from`), NOT truncated to a small length — this keeps
        // accept/reject identical on 32-bit (wasm32) and 64-bit targets.
        let mut buf = (1u64 << 40).to_be_bytes().to_vec(); // length far past any buffer
        buf.extend_from_slice(&[0u8; 8]);
        assert!(CombineInput::from_transport(&buf).is_none());
    }

    #[test]
    fn from_transport_rejects_non_four_byte_policy_version() {
        // `policy_version` is the only intra-field length constraint in the shared
        // C-ABI/WASM decoder: a field that is not exactly 4 bytes must be rejected.
        for ver_len in [0usize, 3, 5, 8] {
            let ver = vec![0u8; ver_len];
            let mut buf = Vec::new();
            for f in [
                &b"S"[..],
                &ver[..],
                &[1u8; 32],
                &[2u8; 32],
                &[3u8; 4],
                &[4u8; 5],
                &[5u8; 6],
                &[6u8; 7],
                b"ctx",
            ] {
                lp(&mut buf, f);
            }
            assert!(
                CombineInput::from_transport(&buf).is_none(),
                "policy_version of {ver_len} bytes must be rejected"
            );
        }
    }

    #[test]
    fn secure_wipe_zeroes_the_buffer() {
        let mut buf = [0xABu8; 64];
        secure_wipe(&mut buf);
        assert_eq!(buf, [0u8; 64], "secure_wipe must zero every byte");
        secure_wipe(&mut []); // empty slice must not panic
    }

    #[test]
    fn zeroizing_bytes_explicit_clear_zeroes_owned_storage() {
        let mut bytes = ZeroizingBytes::from_bytes([0xABu8; 64]);
        bytes.clear();
        assert_eq!(bytes.as_bytes(), &[0u8; 64]);
    }

    #[test]
    fn policy_bound_context_is_canonical_and_commits_every_field() {
        let digest_a = [0x11u8; SHARED_SECRET_LEN];
        let digest_b = [0x12u8; SHARED_SECRET_LEN];
        let app_a = b"transcript-a";
        let app_b = b"transcript-b";
        let len = policy_bound_context_len(app_a.len()).unwrap();
        let mut encoded_a = vec![0u8; len];
        let mut encoded_digest = vec![0u8; len];
        let mut encoded_app = vec![0u8; len];
        assert_eq!(
            encode_policy_bound_context(&digest_a, app_a, &mut encoded_a).unwrap(),
            len
        );
        encode_policy_bound_context(&digest_b, app_a, &mut encoded_digest).unwrap();
        encode_policy_bound_context(&digest_a, app_b, &mut encoded_app).unwrap();
        assert_ne!(encoded_a, encoded_digest, "policy digest must commit");
        assert_ne!(encoded_a, encoded_app, "application context must commit");

        let mut short = vec![0u8; len - 1];
        assert_eq!(
            encode_policy_bound_context(&digest_a, app_a, &mut short).unwrap_err(),
            Error::InvalidLength
        );
    }

    #[test]
    fn policy_bound_context_rejects_unbounded_allocation_requests() {
        assert!(policy_bound_context_len(MAX_APPLICATION_CONTEXT_BYTES).is_some());
        assert_eq!(
            policy_bound_context_len(MAX_APPLICATION_CONTEXT_BYTES + 1),
            None
        );
    }
}
