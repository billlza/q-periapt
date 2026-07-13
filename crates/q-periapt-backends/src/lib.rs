#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! # q-periapt-backends
//!
//! Third-party primitive backends wired into the `q-periapt-core` traits:
//! - **ML-KEM** (FIPS 203) via `fips203`:
//!   [`MlKem512`], [`MlKem768`], [`MlKem1024`] expose the FIPS-expanded decapsulation
//!   key format and are therefore confined to `ContextBound`; [`MlKem768XWingSeed`]
//!   exposes the X-Wing seed-derived key format and is the only ML-KEM backend here
//!   marked `COMPAT_XWING_SAFE` for the byte-exact `CompatXWing` profile.
//! - **ML-DSA** (FIPS 204) via `fips204`: [`MlDsa44`], [`MlDsa65`], [`MlDsa87`]
//!   with context/hedged and SHAKE-128 pre-hash support.
//! - [`X25519`] — X25519 ECDH-as-KEM via `x25519-dalek`, deterministic from a 32-byte
//!   scalar. It is the absorbed traditional slot in canonical X-Wing. If a caller
//!   instead places it in the first slot whose ct/pk `CompatXWing` omits, the
//!   default-false capabilities make `q-periapt-kem` reject that construction.
//! - [`Sha3_256Xof`] — the combiner XOF (SHA3-256).
//! - Off by default (cargo feature): `slh-dsa` ⇒
//!   `SlhDsaSha2_128s`/`_192s`/`_256s` (FIPS 205, via `fips205`).
//!
//! This is the only crate that touches real cryptographic primitives; the
//! security-critical composition stays in the dependency-free `q-periapt-core`.

use fips203::{
    ml_kem_1024 as mlkem1024, ml_kem_512 as mlkem512, ml_kem_768 as mlkem768,
    traits::{
        Decaps as Fips203Decaps, Encaps as Fips203Encaps, KeyGen as Fips203KeyGen,
        SerDes as Fips203SerDes,
    },
};
use q_periapt_core::{Error, Kem, Xof256, ZeroizingBytes, SHARED_SECRET_LEN};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Digest, Sha3_256, Shake256,
};
use x25519_dalek::{PublicKey, StaticSecret};

#[cfg(test)]
mod xwing_kat;

// Multi-backend differential: fips203 vs the independent RustCrypto `ml-kem`
// implementation (byte-identical keygen/encaps/decaps under FIPS 203).
#[cfg(test)]
mod differential;

// NIST ACVP (FIPS 203) ground-truth conformance vectors for ML-KEM-768.
#[cfg(test)]
mod acvp;

// Generative property-based tests of combiner / hybrid-KEM invariants.
#[cfg(test)]
mod proptests;

// ContextBound combiner reference vectors (positive KAT, independently cross-checked).
#[cfg(test)]
mod contextbound_kat;

// Enhanced-mode suite (ML-KEM-1024 + X25519) end-to-end pinned KAT.
#[cfg(test)]
mod enhanced_kat;

// Optional, off-by-default backends (see Cargo.toml [features]).
#[cfg(feature = "slh-dsa")]
mod slhdsa;
#[cfg(feature = "slh-dsa")]
pub use slhdsa::{SlhDsaSha2_128s, SlhDsaSha2_192s, SlhDsaSha2_256s};

mod mldsa;
pub use mldsa::{
    MlDsa44, MlDsa65, MlDsa87, ML_DSA_44_KEYGEN_SEED_LEN, ML_DSA_44_SIGN_RAND_LEN,
    ML_DSA_44_SIG_LEN, ML_DSA_44_SK_LEN, ML_DSA_44_VK_LEN, ML_DSA_65_KEYGEN_SEED_LEN,
    ML_DSA_65_SIGN_RAND_LEN, ML_DSA_65_SIG_LEN, ML_DSA_65_SK_LEN, ML_DSA_65_VK_LEN,
    ML_DSA_87_KEYGEN_SEED_LEN, ML_DSA_87_SIGN_RAND_LEN, ML_DSA_87_SIG_LEN, ML_DSA_87_SK_LEN,
    ML_DSA_87_VK_LEN,
};

// NIST ACVP (FIPS 205) ground-truth conformance vectors for SLH-DSA-SHA2-{128,192,256}s.
#[cfg(all(test, feature = "slh-dsa"))]
mod acvp_slhdsa;

/// X25519 public-key / secret-key / ciphertext length, bytes.
pub const X25519_LEN: usize = 32;

/// Default concrete hybrid suite exposed by the fixed FFI/WASM product surfaces.
pub const DEFAULT_SUITE_ID: &[u8] = b"ML-KEM-768+X25519";

/// Default concrete hybrid suite as a NUL-terminated C string.
pub const DEFAULT_SUITE_ID_CSTR: &[u8] = b"ML-KEM-768+X25519\0";

#[inline]
fn to_arr<const N: usize>(s: &[u8]) -> Result<[u8; N], Error> {
    <[u8; N]>::try_from(s).map_err(|_| Error::InvalidLength)
}

#[inline]
fn to_zeroizing<const N: usize>(s: &[u8]) -> Result<ZeroizingBytes<N>, Error> {
    if s.len() != N {
        return Err(Error::InvalidLength);
    }
    let mut owned = ZeroizingBytes::zeroed();
    owned.as_mut_bytes().copy_from_slice(s);
    Ok(owned)
}

#[inline]
fn write_exact(dst: &mut [u8], src: &[u8]) -> Result<(), Error> {
    if dst.len() != src.len() {
        return Err(Error::InvalidLength);
    }
    dst.copy_from_slice(src);
    Ok(())
}

#[inline]
fn sha3_256(data: &[u8]) -> [u8; SHARED_SECRET_LEN] {
    Sha3_256::digest(data).into()
}

#[inline]
fn shake256<const N: usize>(data: &[u8]) -> [u8; N] {
    let mut state = Shake256::default();
    Update::update(&mut state, data);
    let mut reader = state.finalize_xof();
    let mut output = [0u8; N];
    XofReader::read(&mut reader, &mut output);
    output
}

/// Declares an ML-KEM (FIPS 203) backend over a `fips203` parameter module: the
/// public length constants, the unit struct, its seed-deterministic
/// `generate` associated fn, and the [`Kem`] impl. All parameter sets share this
/// boilerplate (validated expanded-key import, C2PRI ⇒ ciphertext-binding),
/// differing only in module and byte lengths — so they are
/// generated from one definition rather than hand-copied.
macro_rules! mlkem_backend {
    (
        $name:ident, $m:ident, $alg:literal,
        $pk_len:ident = $pk:literal,
        $sk_len:ident = $sk:literal,
        $ct_len:ident = $ct:literal,
        $seed_len:ident = $seed:literal,
        $rand_len:ident = $rand:literal,
        $struct_doc:literal
    ) => {
        #[doc = concat!($alg, " encapsulation-key (public key) length, bytes.")]
        pub const $pk_len: usize = $pk;
        #[doc = concat!($alg, " decapsulation-key (secret key) length, bytes.")]
        pub const $sk_len: usize = $sk;
        #[doc = concat!($alg, " ciphertext length, bytes.")]
        pub const $ct_len: usize = $ct;
        #[doc = concat!($alg, " key-generation seed length, bytes (FIPS 203 d‖z).")]
        pub const $seed_len: usize = $seed;
        #[doc = concat!($alg, " encapsulation randomness length, bytes.")]
        pub const $rand_len: usize = $rand;

        #[doc = $struct_doc]
        #[derive(Clone, Copy, Debug, Default)]
        pub struct $name;

        impl $name {
            /// Deterministically generate a key pair from a 64-byte seed.
            /// Returns `(decapsulation_key, encapsulation_key)`.
            #[must_use]
            pub fn generate(seed: [u8; $seed_len]) -> ([u8; $sk_len], [u8; $pk_len]) {
                let seed = ZeroizingBytes::from_bytes(seed);
                let (d_bytes, z_bytes) = seed.as_bytes().split_at($seed_len / 2);
                let mut d = ZeroizingBytes::<32>::zeroed();
                let mut z = ZeroizingBytes::<32>::zeroed();
                d.as_mut_bytes().copy_from_slice(d_bytes);
                z.as_mut_bytes().copy_from_slice(z_bytes);
                let (encapsulation_key, decapsulation_key) =
                    $m::KG::keygen_from_seed(*d.as_bytes(), *z.as_bytes());
                (
                    decapsulation_key.into_bytes(),
                    encapsulation_key.into_bytes(),
                )
            }
        }

        impl Kem for $name {
            const C2PRI: bool = true; // ML-KEM's primitive has FO ciphertext self-binding.
                                      // This backend accepts arbitrary FIPS-expanded decapsulation keys. The expanded key
                                      // format exposes rejection-seed material that can be adversarially imported/cached
                                      // outside the seed-derived X-Wing key schedule. Use ContextBound for this raw-key
                                      // backend; use MlKem768XWingSeed for byte-exact X-Wing compatibility.
            const COMPAT_XWING_SAFE: bool = false;

            fn algorithm(&self) -> &'static str {
                $alg
            }

            fn encapsulate(
                &self,
                pk: &[u8],
                randomness: &[u8],
                ct: &mut [u8],
                ss: &mut [u8],
            ) -> Result<(), Error> {
                if ct.len() != $ct_len || ss.len() != SHARED_SECRET_LEN {
                    return Err(Error::InvalidLength);
                }
                let pk_arr = to_arr::<$pk_len>(pk)?;
                let public = $m::EncapsKey::try_from_bytes(pk_arr).map_err(|_| Error::Backend)?;
                let randomness = to_zeroizing::<$rand_len>(randomness)?;
                let (shared, ciphertext) = public.encaps_from_seed(randomness.as_bytes());
                let shared = ZeroizingBytes::from_bytes(shared.into_bytes());
                write_exact(ct, &ciphertext.into_bytes())?;
                write_exact(ss, shared.as_bytes())
            }

            fn decapsulate(&self, sk: &[u8], ct: &[u8], ss: &mut [u8]) -> Result<(), Error> {
                if ss.len() != SHARED_SECRET_LEN {
                    return Err(Error::InvalidLength);
                }
                let sk_arr = to_zeroizing::<$sk_len>(sk)?;
                let ct_arr = to_arr::<$ct_len>(ct)?;
                let private = $m::DecapsKey::try_from_bytes(*sk_arr.as_bytes())
                    .map_err(|_| Error::Backend)?;
                let ciphertext =
                    $m::CipherText::try_from_bytes(ct_arr).map_err(|_| Error::Backend)?;
                let shared = private
                    .try_decaps(&ciphertext)
                    .map_err(|_| Error::Backend)?;
                let shared = ZeroizingBytes::from_bytes(shared.into_bytes());
                write_exact(ss, shared.as_bytes())
            }
        }
    };
}

mlkem_backend!(
    MlKem768,
    mlkem768,
    "ML-KEM-768",
    ML_KEM_768_PK_LEN = 1184,
    ML_KEM_768_SK_LEN = 2400,
    ML_KEM_768_CT_LEN = 1088,
    ML_KEM_768_KEYGEN_SEED_LEN = 64,
    ML_KEM_768_ENCAPS_RAND_LEN = 32,
    "ML-KEM-768 backend (FIPS 203) via fips203."
);

mlkem_backend!(
    MlKem1024,
    mlkem1024,
    "ML-KEM-1024",
    ML_KEM_1024_PK_LEN = 1568,
    ML_KEM_1024_SK_LEN = 3168,
    ML_KEM_1024_CT_LEN = 1568,
    ML_KEM_1024_KEYGEN_SEED_LEN = 64,
    ML_KEM_1024_ENCAPS_RAND_LEN = 32,
    "ML-KEM-1024 backend (FIPS 203, NIST level 5) via fips203 — the enhanced-mode KEM."
);

mlkem_backend!(
    MlKem512,
    mlkem512,
    "ML-KEM-512",
    ML_KEM_512_PK_LEN = 800,
    ML_KEM_512_SK_LEN = 1632,
    ML_KEM_512_CT_LEN = 768,
    ML_KEM_512_KEYGEN_SEED_LEN = 64,
    ML_KEM_512_ENCAPS_RAND_LEN = 32,
    "ML-KEM-512 backend (FIPS 203, NIST level 1) via fips203 — the smallest parameter set."
);

/// X-Wing seed decapsulation key length, bytes.
pub const ML_KEM_768_XWING_SEED_LEN: usize = 32;

/// ML-KEM-768 backend whose decapsulation key is the 32-byte X-Wing seed format.
///
/// `CompatXWing` is sound only when the omitted PQ fields are self-bound by the key
/// schedule. This backend derives the FIPS 203 `(d || z)` seed from a single 32-byte
/// seed with SHAKE-256, matching X-Wing's seed-derived key format; it never accepts an
/// arbitrary expanded ML-KEM decapsulation key from the caller.
#[derive(Clone, Copy, Debug, Default)]
pub struct MlKem768XWingSeed;

#[inline]
fn mlkem768_xwing_dz(seed: [u8; ML_KEM_768_XWING_SEED_LEN]) -> [u8; ML_KEM_768_KEYGEN_SEED_LEN] {
    shake256::<ML_KEM_768_KEYGEN_SEED_LEN>(&seed)
}

impl MlKem768XWingSeed {
    /// Deterministically generate a key pair from a 32-byte X-Wing seed.
    /// Returns `(seed_decapsulation_key, encapsulation_key)`.
    #[must_use]
    pub fn generate(
        seed: [u8; ML_KEM_768_XWING_SEED_LEN],
    ) -> ([u8; ML_KEM_768_XWING_SEED_LEN], [u8; ML_KEM_768_PK_LEN]) {
        let (expanded_sk, pk) = MlKem768::generate(mlkem768_xwing_dz(seed));
        let _expanded_sk = ZeroizingBytes::from_bytes(expanded_sk);
        (seed, pk)
    }
}

impl Kem for MlKem768XWingSeed {
    const C2PRI: bool = true;
    const COMPAT_XWING_SAFE: bool = true;

    fn algorithm(&self) -> &'static str {
        "ML-KEM-768(seed-dk)"
    }

    fn encapsulate(
        &self,
        pk: &[u8],
        randomness: &[u8],
        ct: &mut [u8],
        ss: &mut [u8],
    ) -> Result<(), Error> {
        MlKem768.encapsulate(pk, randomness, ct, ss)
    }

    fn decapsulate(&self, sk: &[u8], ct: &[u8], ss: &mut [u8]) -> Result<(), Error> {
        let seed = to_arr::<ML_KEM_768_XWING_SEED_LEN>(sk)?;
        let (expanded_sk, _pk) = MlKem768::generate(mlkem768_xwing_dz(seed));
        let expanded_sk = ZeroizingBytes::from_bytes(expanded_sk);
        MlKem768.decapsulate(expanded_sk.as_bytes(), ct, ss)
    }
}

/// X25519 ECDH-as-KEM backend (deterministic from a 32-byte scalar).
#[derive(Clone, Copy, Debug, Default)]
pub struct X25519;

impl X25519 {
    /// Deterministically derive a key pair from a 32-byte secret scalar.
    /// Returns `(secret_key, public_key)`.
    #[must_use]
    pub fn generate(secret: [u8; X25519_LEN]) -> ([u8; X25519_LEN], [u8; X25519_LEN]) {
        let s = StaticSecret::from(secret);
        let p = PublicKey::from(&s);
        (s.to_bytes(), p.to_bytes())
    }
}

impl Kem for X25519 {
    // Both capabilities default to false. X25519 is valid as the traditional
    // slot whose ct/pk CompatXWing absorbs, but cannot occupy the omitted first slot.

    fn algorithm(&self) -> &'static str {
        "X25519"
    }

    fn encapsulate(
        &self,
        pk: &[u8],
        randomness: &[u8],
        ct: &mut [u8],
        ss: &mut [u8],
    ) -> Result<(), Error> {
        // The ephemeral scalar is the caller-supplied randomness; the ciphertext
        // is the ephemeral public key.
        let eph = StaticSecret::from(to_arr::<X25519_LEN>(randomness)?);
        let peer = PublicKey::from(to_arr::<X25519_LEN>(pk)?);
        let eph_pub = PublicKey::from(&eph);
        let shared = eph.diffie_hellman(&peer);
        // Reject a low-order / non-contributory peer key (all-zero shared secret). The hybrid would
        // still be safe via ML-KEM, but a zero classical leg must never key — defense-in-depth.
        if !shared.was_contributory() {
            return Err(Error::InvalidKeyShare);
        }
        write_exact(ct, eph_pub.as_bytes())?;
        write_exact(ss, shared.as_bytes())
    }

    fn decapsulate(&self, sk: &[u8], ct: &[u8], ss: &mut [u8]) -> Result<(), Error> {
        let secret = StaticSecret::from(to_arr::<X25519_LEN>(sk)?);
        let eph_pub = PublicKey::from(to_arr::<X25519_LEN>(ct)?);
        let shared = secret.diffie_hellman(&eph_pub);
        if !shared.was_contributory() {
            return Err(Error::InvalidKeyShare);
        }
        write_exact(ss, shared.as_bytes())
    }
}

/// Inline staging capacity for [`Sha3_256Xof`]. The CompatXWing / X-Wing combiner
/// input is a single 134-byte SHA3-256 block, so this keeps that path — the only
/// performance-sensitive one — entirely on the stack (no heap allocation).
const SHA3_XOF_INLINE_CAP: usize = 200;

/// Maximum number of disjoint secret transcript ranges tracked without falling
/// back to erasing the entire staging buffer. The combiner's two component
/// secrets plus conservatively sensitive caller context require three entries;
/// the extra entry keeps the generic XOF surface useful without making the
/// hot-path state dynamically allocated.
const SHA3_XOF_SECRET_RANGE_CAP: usize = 4;

/// SHA3-256-based [`Xof256`] for the combiner (fixed 32-byte output), via RustCrypto.
///
/// The digest backend exposes one-shot SHA3-256, so absorbed chunks are staged
/// contiguously and hashed at finalize; SHA3-256 over the concatenation equals the
/// incremental hash, so the digest is byte-identical to X-Wing. The hot path — the
/// 134-byte single-block CompatXWing combiner — stages into a fixed inline buffer
/// and **never allocates**; only the larger multi-KB ContextBound transcript spills
/// to the heap. This makes the X-Wing-compatible combiner allocation-free: it does
/// the minimal single-block Keccak work with no per-`update` sponge bookkeeping and
/// no heap traffic, while producing identical bytes.
pub struct Sha3_256Xof {
    inline: [u8; SHA3_XOF_INLINE_CAP],
    inline_len: usize,
    spill: Vec<u8>,
    secret_ranges: [(usize, usize); SHA3_XOF_SECRET_RANGE_CAP],
    secret_range_count: usize,
    wipe_all: bool,
}

impl Sha3_256Xof {
    fn staged_len(&self) -> usize {
        if self.spill.is_empty() {
            self.inline_len
        } else {
            self.spill.len()
        }
    }

    fn record_secret_range(&mut self, len: usize) {
        if len == 0 || self.wipe_all {
            return;
        }
        let start = self.staged_len();
        let Some(end) = start.checked_add(len) else {
            self.wipe_all = true;
            return;
        };
        let Some(slot) = self.secret_ranges.get_mut(self.secret_range_count) else {
            self.wipe_all = true;
            return;
        };
        *slot = (start, end);
        self.secret_range_count += 1;
    }

    fn ranges_are_valid(&self, transcript_len: usize) -> bool {
        self.inline_len <= self.inline.len()
            && self.secret_range_count <= self.secret_ranges.len()
            && self
                .secret_ranges
                .iter()
                .take(self.secret_range_count)
                .all(|&(start, end)| start <= end && end <= transcript_len)
    }

    fn wipe_range_intersections(
        storage: &mut [u8],
        initialized_len: usize,
        ranges: &[(usize, usize); SHA3_XOF_SECRET_RANGE_CAP],
        range_count: usize,
    ) -> bool {
        if initialized_len > storage.len() || range_count > ranges.len() {
            return false;
        }
        for &(start, end) in ranges.iter().take(range_count) {
            let intersection_start = start.min(initialized_len);
            let intersection_end = end.min(initialized_len);
            if intersection_start < intersection_end {
                let Some(secret) = storage.get_mut(intersection_start..intersection_end) else {
                    return false;
                };
                q_periapt_core::secure_wipe(secret);
            }
        }
        true
    }

    fn wipe_live_spill_before_reallocation(&mut self) {
        if self.spill.is_empty() {
            return;
        }
        let spill_len = self.spill.len();
        let metadata_valid = self.secret_range_count <= self.secret_ranges.len()
            && self
                .secret_ranges
                .iter()
                .take(self.secret_range_count)
                .all(|&(start, end)| start <= end && end <= spill_len);
        if self.wipe_all
            || !metadata_valid
            || !Self::wipe_range_intersections(
                self.spill.as_mut_slice(),
                spill_len,
                &self.secret_ranges,
                self.secret_range_count,
            )
        {
            q_periapt_core::secure_wipe(self.spill.as_mut_slice());
        }
    }

    fn ensure_spill_capacity(&mut self, required: usize) {
        if self.spill.capacity() >= required {
            return;
        }
        let target_capacity = self
            .spill
            .capacity()
            .checked_mul(2)
            .map_or(required, |doubled| doubled.max(required));
        // Copy first, then volatile-wipe the secret-bearing ranges in the old
        // allocation before replacing it. This preserves secret hygiene even
        // for generic callers that did not pre-reserve the complete transcript.
        // Geometric growth retains Vec's amortized behavior for that generic
        // incremental path; an explicit initial reserve remains exact.
        let mut replacement = Vec::new();
        if replacement.try_reserve_exact(target_capacity).is_err() {
            self.wipe_and_abort();
        }
        replacement.extend_from_slice(&self.spill);
        self.wipe_live_spill_before_reallocation();
        self.spill = replacement;
    }

    fn wipe_and_abort(&mut self) -> ! {
        // A live slice and initialized Vec cannot legitimately exceed usize, so
        // callers use this for corrupted private state, impossible address-space
        // requests, and allocation failure. `abort` skips Drop, so wipe the live
        // staging copies synchronously before terminating.
        self.wipe_all = true;
        self.wipe_staged_secrets();
        std::process::abort()
    }

    fn append_bytes(&mut self, data: &[u8]) {
        // Once the input has outgrown the inline buffer, everything goes to heap.
        if !self.spill.is_empty() {
            let Some(required) = self.spill.len().checked_add(data.len()) else {
                self.wipe_and_abort();
            };
            self.ensure_spill_capacity(required);
            self.spill.extend_from_slice(data);
            return;
        }

        let Some(end) = self.inline_len.checked_add(data.len()) else {
            self.wipe_and_abort();
        };
        match self.inline.get_mut(self.inline_len..end) {
            Some(dst) => {
                dst.copy_from_slice(data);
                self.inline_len = end;
            }
            None => {
                // Inline capacity exceeded: migrate the initialized prefix. Keep
                // inline_len because the inline copy remains live until Drop and
                // may contain an earlier secret range that must also be erased.
                self.ensure_spill_capacity(end);
                let Some(staged) = self.inline.get(..self.inline_len) else {
                    self.wipe_and_abort();
                };
                self.spill.extend_from_slice(staged);
                self.spill.extend_from_slice(data);
            }
        }
    }

    fn wipe_staged_secrets(&mut self) {
        let transcript_len = self.staged_len();
        let spill_len = self.spill.len();
        let metadata_valid = self.ranges_are_valid(transcript_len);
        let selective_ok = metadata_valid
            && Self::wipe_range_intersections(
                &mut self.inline,
                self.inline_len,
                &self.secret_ranges,
                self.secret_range_count,
            )
            && Self::wipe_range_intersections(
                self.spill.as_mut_slice(),
                spill_len,
                &self.secret_ranges,
                self.secret_range_count,
            );

        if self.wipe_all || !selective_ok {
            // Metadata corruption, range overflow, or legacy/unclassified input
            // always falls back to the original whole-buffer erase behavior.
            q_periapt_core::secure_wipe(&mut self.inline);
            q_periapt_core::secure_wipe(self.spill.as_mut_slice());
        }
        self.inline_len = 0;
        self.secret_ranges = [(0, 0); SHA3_XOF_SECRET_RANGE_CAP];
        self.secret_range_count = 0;
        self.wipe_all = false;
    }
}

impl Drop for Sha3_256Xof {
    fn drop(&mut self) {
        // Erase every staging copy of explicitly secret or legacy/unclassified
        // input before releasing storage. Public transcript bytes need no volatile
        // erase; malformed range metadata fails closed to a whole-buffer wipe.
        self.wipe_staged_secrets();
    }
}

impl Default for Sha3_256Xof {
    fn default() -> Self {
        <Self as Xof256>::new()
    }
}

impl Xof256 for Sha3_256Xof {
    fn new() -> Self {
        Self {
            inline: [0u8; SHA3_XOF_INLINE_CAP],
            inline_len: 0,
            spill: Vec::new(),
            secret_ranges: [(0, 0); SHA3_XOF_SECRET_RANGE_CAP],
            secret_range_count: 0,
            wipe_all: false,
        }
    }

    fn reserve(&mut self, additional: usize) {
        // Allocate the heap spill once for the whole transcript so later `absorb`s never reallocate
        // and leak a secret-bearing buffer (the migration path moves the inline-staged bytes into
        // the spill, so its final length is the full transcript). Reserving over the inline
        // capacity is harmless; ContextBound transcripts always exceed it.
        let Some(required) = self.staged_len().checked_add(additional) else {
            self.wipe_and_abort();
        };
        if required > SHA3_XOF_INLINE_CAP {
            self.ensure_spill_capacity(required);
        }
    }

    fn absorb(&mut self, data: &[u8]) {
        // Preserve the legacy contract conservatively: unclassified input may
        // contain secrets, so erase the complete staging buffer on Drop.
        self.wipe_all = true;
        self.append_bytes(data);
    }

    fn absorb_public(&mut self, data: &[u8]) {
        self.append_bytes(data);
    }

    fn absorb_secret(&mut self, data: &[u8]) {
        self.record_secret_range(data.len());
        self.append_bytes(data);
    }

    fn squeeze32(mut self) -> [u8; SHARED_SECRET_LEN] {
        if self.spill.is_empty() {
            let Some(staged) = self.inline.get(..self.inline_len) else {
                self.wipe_and_abort();
            };
            sha3_256(staged)
        } else {
            sha3_256(&self.spill)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use q_periapt_sig::{Signer, Verifier};

    #[test]
    fn sha3_256_known_answer() {
        // SHA3-256("") = a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a
        let mut x = Sha3_256Xof::new();
        x.absorb_public(b"");
        let d = x.squeeze32();
        let expected = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
        let got: String = d.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(got, expected);
    }

    #[test]
    fn sha3_staging_wipes_only_inline_secret_ranges() {
        let prefix = b"public-prefix";
        let secret = [0xA5u8; 32];
        let suffix = b"public-suffix";
        let mut x = Sha3_256Xof::new();
        x.absorb_public(prefix);
        x.absorb_secret(&secret);
        x.absorb_public(suffix);
        assert!(x.spill.is_empty());

        let secret_start = prefix.len();
        let secret_end = secret_start + secret.len();
        let suffix_end = secret_end + suffix.len();
        x.wipe_staged_secrets();

        assert_eq!(&x.inline[..secret_start], prefix);
        assert_eq!(&x.inline[secret_start..secret_end], &[0u8; 32]);
        assert_eq!(&x.inline[secret_end..suffix_end], suffix);
    }

    #[test]
    fn sha3_staging_wipes_inline_and_spill_secret_copies() {
        let prefix = b"public-prefix";
        let secret = [0x5Au8; 32];
        let suffix = vec![0xC3u8; SHA3_XOF_INLINE_CAP];
        let mut x = Sha3_256Xof::new();
        x.absorb_public(prefix);
        x.absorb_secret(&secret);
        x.absorb_public(&suffix);
        assert!(
            !x.spill.is_empty(),
            "large public suffix must trigger spill"
        );

        let secret_start = prefix.len();
        let secret_end = secret_start + secret.len();
        let suffix_end = secret_end + suffix.len();
        x.wipe_staged_secrets();

        assert_eq!(&x.inline[..secret_start], prefix);
        assert_eq!(&x.inline[secret_start..secret_end], &[0u8; 32]);
        assert_eq!(&x.spill[..secret_start], prefix);
        assert_eq!(&x.spill[secret_start..secret_end], &[0u8; 32]);
        assert_eq!(&x.spill[secret_end..suffix_end], suffix.as_slice());
    }

    #[test]
    fn sha3_staging_tracks_secret_that_triggers_and_follows_spill() {
        let prefix = vec![0x11u8; SHA3_XOF_INLINE_CAP - 4];
        let first_secret = [0x22u8; 16];
        let public_middle = b"middle";
        let second_secret = [0x33u8; 8];
        let mut x = Sha3_256Xof::new();
        x.absorb_public(&prefix);
        x.absorb_secret(&first_secret);
        x.absorb_public(public_middle);
        x.absorb_secret(&second_secret);
        assert!(!x.spill.is_empty());

        let first_start = prefix.len();
        let first_end = first_start + first_secret.len();
        let middle_end = first_end + public_middle.len();
        let second_end = middle_end + second_secret.len();
        x.wipe_staged_secrets();

        assert_eq!(&x.inline[..first_start], prefix.as_slice());
        assert_eq!(&x.inline[first_start..SHA3_XOF_INLINE_CAP], &[0u8; 4]);
        assert_eq!(&x.spill[..first_start], prefix.as_slice());
        assert_eq!(&x.spill[first_start..first_end], &[0u8; 16]);
        assert_eq!(&x.spill[first_end..middle_end], public_middle);
        assert_eq!(&x.spill[middle_end..second_end], &[0u8; 8]);
    }

    #[test]
    fn sha3_staging_range_overflow_and_invalid_metadata_wipe_all() {
        let mut x = Sha3_256Xof::new();
        for value in 0..=SHA3_XOF_SECRET_RANGE_CAP {
            x.absorb_public(&[0x40 + value as u8]);
            x.absorb_secret(&[0x80 + value as u8]);
        }
        assert!(x.wipe_all, "range-capacity exhaustion must fail closed");
        let initialized = x.inline_len;
        x.wipe_staged_secrets();
        assert_eq!(&x.inline[..initialized], vec![0u8; initialized]);

        let mut invalid = Sha3_256Xof::new();
        invalid.absorb_public(b"public");
        invalid.secret_ranges[0] = (1, usize::MAX);
        invalid.secret_range_count = 1;
        invalid.wipe_staged_secrets();
        assert_eq!(&invalid.inline[..b"public".len()], &[0u8; 6]);

        let mut arithmetic_overflow = Sha3_256Xof::new();
        arithmetic_overflow.absorb_public(b"public");
        arithmetic_overflow.record_secret_range(usize::MAX);
        assert!(
            arithmetic_overflow.wipe_all,
            "range arithmetic overflow must fail closed"
        );
        arithmetic_overflow.wipe_staged_secrets();
        assert_eq!(&arithmetic_overflow.inline[..b"public".len()], &[0u8; 6]);
    }

    #[test]
    fn sha3_staging_empty_secret_is_free_and_classification_preserves_digest() {
        let mut public_secret = Sha3_256Xof::new();
        public_secret.absorb_public(b"prefix");
        public_secret.absorb_secret(&[]);
        assert_eq!(public_secret.secret_range_count, 0);
        public_secret.absorb_secret(b"secret");
        public_secret.absorb_public(b"suffix");

        let mut legacy = Sha3_256Xof::new();
        legacy.absorb(b"prefix");
        legacy.absorb(b"secret");
        legacy.absorb(b"suffix");
        assert_eq!(public_secret.squeeze32(), legacy.squeeze32());
    }

    #[test]
    fn sha3_legacy_absorb_and_spill_range_overflow_wipe_every_live_byte() {
        let mut legacy = Sha3_256Xof::new();
        legacy.absorb(b"public-but-unclassified");
        legacy.absorb(b"secret");
        let inline_len = legacy.inline_len;
        assert!(legacy.wipe_all);
        legacy.wipe_staged_secrets();
        assert_eq!(&legacy.inline[..inline_len], vec![0u8; inline_len]);

        let mut overflow = Sha3_256Xof::new();
        overflow.absorb_public(&vec![0x71u8; SHA3_XOF_INLINE_CAP + 1]);
        for value in 0..=SHA3_XOF_SECRET_RANGE_CAP {
            overflow.absorb_secret(&[0x90 + value as u8]);
            overflow.absorb_public(&[0x30 + value as u8]);
        }
        assert!(overflow.wipe_all);
        let spill_len = overflow.spill.len();
        overflow.wipe_staged_secrets();
        assert_eq!(&overflow.spill[..spill_len], vec![0u8; spill_len]);
    }

    #[test]
    fn sha3_spill_reallocation_wipes_old_secret_ranges_and_grows_geometrically() {
        let prefix = vec![0x41u8; SHA3_XOF_INLINE_CAP + 1];
        let secret = [0x52u8; 16];
        let suffix = b"suffix";
        let mut x = Sha3_256Xof::new();
        x.absorb_public(&prefix);
        x.absorb_secret(&secret);
        x.absorb_public(suffix);

        let secret_start = prefix.len();
        let secret_end = secret_start + secret.len();
        let suffix_end = secret_end + suffix.len();
        x.wipe_live_spill_before_reallocation();
        assert_eq!(&x.spill[..secret_start], prefix.as_slice());
        assert_eq!(&x.spill[secret_start..secret_end], &[0u8; 16]);
        assert_eq!(&x.spill[secret_end..suffix_end], suffix);

        let mut growth = Sha3_256Xof::new();
        growth.absorb_public(&prefix);
        let old_capacity = growth.spill.capacity();
        let additional = old_capacity + 1 - growth.spill.len();
        growth.absorb_public(&vec![0x63u8; additional]);
        assert!(
            growth.spill.capacity() >= old_capacity * 2,
            "unreserved incremental spill growth must remain amortized"
        );
    }

    #[test]
    fn mlkem768_roundtrip() {
        let (sk, pk) = MlKem768::generate([7u8; 64]);
        let kem = MlKem768;
        let mut ct = [0u8; ML_KEM_768_CT_LEN];
        let mut ss_e = [0u8; 32];
        kem.encapsulate(&pk, &[3u8; 32], &mut ct, &mut ss_e)
            .unwrap();
        let mut ss_d = [0u8; 32];
        kem.decapsulate(&sk, &ct, &mut ss_d).unwrap();
        assert_eq!(ss_e, ss_d, "ML-KEM-768 encaps/decaps must agree");
        assert_ne!(ss_e, [0u8; 32], "shared secret must be non-trivial");
    }

    #[test]
    fn mlkem_algorithm_strings() {
        // `algorithm()` is generated from the `mlkem_backend!` `$alg` literal — pin the
        // three strings so a future macro edit can't silently relabel a backend.
        assert_eq!(MlKem512.algorithm(), "ML-KEM-512");
        assert_eq!(MlKem768.algorithm(), "ML-KEM-768");
        assert_eq!(MlKem1024.algorithm(), "ML-KEM-1024");
    }

    #[test]
    fn x25519_roundtrip() {
        let (sk, pk) = X25519::generate([9u8; 32]);
        let kem = X25519;
        let mut ct = [0u8; 32];
        let mut ss_e = [0u8; 32];
        kem.encapsulate(&pk, &[5u8; 32], &mut ct, &mut ss_e)
            .unwrap();
        let mut ss_d = [0u8; 32];
        kem.decapsulate(&sk, &ct, &mut ss_d).unwrap();
        assert_eq!(ss_e, ss_d, "X25519 encaps/decaps must agree");
    }

    #[test]
    fn x25519_rejects_low_order_point() {
        // The all-zero public key is a low-order point: the DH yields an all-zero (non-contributory)
        // shared secret, which must be rejected rather than keyed.
        let low_order = [0u8; 32];
        let (mut ct, mut ss) = ([0u8; 32], [0u8; 32]);
        assert!(
            X25519
                .encapsulate(&low_order, &[5u8; 32], &mut ct, &mut ss)
                .is_err(),
            "encaps to a low-order pk must fail"
        );
        let (sk, _) = X25519::generate([9u8; 32]);
        assert!(
            X25519.decapsulate(&sk, &low_order, &mut ss).is_err(),
            "decaps of a low-order ct must fail"
        );
    }

    #[test]
    fn hybrid_real_roundtrip_context_bound_expanded_and_compat_seed_dk() {
        use q_periapt_core::Profile;
        use q_periapt_kem::HybridKem;

        let (sk_pq, pk_pq) = MlKem768::generate([7u8; 64]);
        let (sk_trad, pk_trad) = X25519::generate([9u8; 32]);
        let ctx = b"q-periapt/v1/test-transcript";

        {
            let (pq, trad) = (MlKem768, X25519);
            let kem = HybridKem::<_, _, Sha3_256Xof>::new(
                &pq,
                &trad,
                Profile::ContextBound,
                b"ML-KEM-768+X25519",
                1,
            )
            .unwrap();

            let mut ct_pq = [0u8; ML_KEM_768_CT_LEN];
            let mut ct_trad = [0u8; X25519_LEN];
            let enc = kem
                .encapsulate(
                    &pk_pq,
                    &pk_trad,
                    ctx,
                    &[11u8; 32],
                    &[22u8; 32],
                    &mut ct_pq,
                    &mut ct_trad,
                )
                .unwrap();

            let dec = kem
                .decapsulate(&sk_pq, &ct_pq, &pk_pq, &sk_trad, &ct_trad, &pk_trad, ctx)
                .unwrap();

            assert_eq!(
                enc.as_bytes(),
                dec.as_bytes(),
                "ContextBound expanded-key hybrid encap/decap must agree"
            );
        }

        {
            let (sk_pq, pk_pq) = MlKem768XWingSeed::generate([7u8; 32]);
            let (pq, trad) = (MlKem768XWingSeed, X25519);
            let kem = HybridKem::<_, _, Sha3_256Xof>::new(
                &pq,
                &trad,
                Profile::CompatXWing,
                b"ML-KEM-768+X25519",
                1,
            )
            .unwrap();
            let mut ct_pq = [0u8; ML_KEM_768_CT_LEN];
            let mut ct_trad = [0u8; X25519_LEN];
            let enc = kem
                .encapsulate(
                    &pk_pq,
                    &pk_trad,
                    b"",
                    &[11u8; 32],
                    &[22u8; 32],
                    &mut ct_pq,
                    &mut ct_trad,
                )
                .unwrap();
            let dec = kem
                .decapsulate(&sk_pq, &ct_pq, &pk_pq, &sk_trad, &ct_trad, &pk_trad, b"")
                .unwrap();
            assert_eq!(
                enc.as_bytes(),
                dec.as_bytes(),
                "CompatXWing seed-dk hybrid encap/decap must agree"
            );
        }
    }

    #[test]
    fn compat_rejects_x25519_in_the_omitted_first_slot() {
        use q_periapt_core::{Error, Profile};
        use q_periapt_kem::HybridKem;

        let result = HybridKem::<_, _, Sha3_256Xof>::new(
            &X25519,
            &MlKem768XWingSeed,
            Profile::CompatXWing,
            b"reversed-slots",
            1,
        );
        assert!(matches!(result.err(), Some(Error::PolicyDenied)));
    }

    #[test]
    fn enhanced_hybrid_real_roundtrip_context_bound_and_rejects_compat() {
        // The enhanced suite: ML-KEM-1024 + X25519. The raw expanded-key backend is
        // confined to ContextBound; the buffers are sized to the 1024 ciphertext
        // (1568, NOT the 768 length). Proves the enhanced HybridKem actually round-trips.
        use q_periapt_core::Profile;
        use q_periapt_kem::HybridKem;

        let (sk_pq, pk_pq) = MlKem1024::generate([7u8; 64]);
        let (sk_trad, pk_trad) = X25519::generate([9u8; 32]);
        let ctx = b"q-periapt/v1/enhanced-transcript";

        {
            let (pq, trad) = (MlKem1024, X25519);
            let kem = HybridKem::<_, _, Sha3_256Xof>::new(
                &pq,
                &trad,
                Profile::ContextBound,
                b"ML-KEM-1024+X25519",
                1,
            )
            .unwrap();

            let mut ct_pq = [0u8; ML_KEM_1024_CT_LEN];
            let mut ct_trad = [0u8; X25519_LEN];
            let enc = kem
                .encapsulate(
                    &pk_pq,
                    &pk_trad,
                    ctx,
                    &[11u8; 32],
                    &[22u8; 32],
                    &mut ct_pq,
                    &mut ct_trad,
                )
                .unwrap();

            let dec = kem
                .decapsulate(&sk_pq, &ct_pq, &pk_pq, &sk_trad, &ct_trad, &pk_trad, ctx)
                .unwrap();

            assert_eq!(
                enc.as_bytes(),
                dec.as_bytes(),
                "enhanced ContextBound hybrid encap/decap must agree"
            );
        }
        assert!(HybridKem::<_, _, Sha3_256Xof>::new(
            &MlKem1024,
            &X25519,
            Profile::CompatXWing,
            b"ML-KEM-1024+X25519",
            1
        )
        .is_err());
    }

    #[test]
    fn deterministic_encaps() {
        // Same randomness ⇒ identical ciphertext+secret (KAT precondition).
        let (_sk, pk) = MlKem768::generate([1u8; 64]);
        let kem = MlKem768;
        let (mut ct1, mut ss1) = ([0u8; ML_KEM_768_CT_LEN], [0u8; 32]);
        let (mut ct2, mut ss2) = ([0u8; ML_KEM_768_CT_LEN], [0u8; 32]);
        kem.encapsulate(&pk, &[42u8; 32], &mut ct1, &mut ss1)
            .unwrap();
        kem.encapsulate(&pk, &[42u8; 32], &mut ct2, &mut ss2)
            .unwrap();
        assert_eq!(ct1, ct2);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn mlkem768_rejects_malformed_expanded_keys_without_partial_output() {
        const EMBEDDED_EK_OFFSET: usize =
            ML_KEM_768_SK_LEN - ML_KEM_768_PK_LEN - (2 * SHARED_SECRET_LEN);
        const EMBEDDED_EK_HASH_OFFSET: usize = ML_KEM_768_SK_LEN - (2 * SHARED_SECRET_LEN);

        let (sk, pk) = MlKem768::generate([0x31; ML_KEM_768_KEYGEN_SEED_LEN]);
        let mut ct = [0u8; ML_KEM_768_CT_LEN];
        let mut expected_secret = [0u8; SHARED_SECRET_LEN];
        MlKem768
            .encapsulate(
                &pk,
                &[0x42; ML_KEM_768_ENCAPS_RAND_LEN],
                &mut ct,
                &mut expected_secret,
            )
            .unwrap();

        let mut bad_hash = sk;
        bad_hash[EMBEDDED_EK_HASH_OFFSET] ^= 1;
        let mut output = [0xA5; SHARED_SECRET_LEN];
        assert_eq!(
            MlKem768.decapsulate(&bad_hash, &ct, &mut output),
            Err(Error::Backend),
            "expanded key import must validate H(ek)"
        );
        assert_eq!(
            output, [0xA5; SHARED_SECRET_LEN],
            "failed key import must not partially overwrite the output"
        );

        let mut noncanonical_ek = sk;
        noncanonical_ek[EMBEDDED_EK_OFFSET] = 0xFF;
        noncanonical_ek[EMBEDDED_EK_OFFSET + 1] = 0x0F;
        assert_eq!(
            MlKem768.decapsulate(&noncanonical_ek, &ct, &mut output),
            Err(Error::Backend),
            "embedded ek coefficients outside the ML-KEM modulus must be rejected"
        );
        assert_eq!(output, [0xA5; SHARED_SECRET_LEN]);

        let malformed = [0xFF; ML_KEM_768_SK_LEN];
        let no_panic = std::panic::catch_unwind(|| {
            let mut scratch = [0x5A; SHARED_SECRET_LEN];
            let result = MlKem768.decapsulate(&malformed, &ct, &mut scratch);
            (result, scratch)
        });
        let (result, scratch) = no_panic.expect("malformed fixed-length dk must not panic");
        assert_eq!(result, Err(Error::Backend));
        assert_eq!(scratch, [0x5A; SHARED_SECRET_LEN]);
    }

    #[test]
    fn mlkem768_malformed_ciphertext_uses_deterministic_implicit_rejection() {
        let (sk, pk) = MlKem768::generate([0x17; ML_KEM_768_KEYGEN_SEED_LEN]);
        let mut valid_ct = [0u8; ML_KEM_768_CT_LEN];
        let mut valid_secret = [0u8; SHARED_SECRET_LEN];
        MlKem768
            .encapsulate(
                &pk,
                &[0x29; ML_KEM_768_ENCAPS_RAND_LEN],
                &mut valid_ct,
                &mut valid_secret,
            )
            .unwrap();

        let mut malformed_ct = valid_ct;
        malformed_ct[0] ^= 1;
        let mut rejected_secret_a = [0u8; SHARED_SECRET_LEN];
        let mut rejected_secret_b = [0u8; SHARED_SECRET_LEN];
        MlKem768
            .decapsulate(&sk, &malformed_ct, &mut rejected_secret_a)
            .unwrap();
        MlKem768
            .decapsulate(&sk, &malformed_ct, &mut rejected_secret_b)
            .unwrap();

        assert_eq!(rejected_secret_a, rejected_secret_b);
        assert_ne!(rejected_secret_a, valid_secret);
    }

    #[test]
    fn mlkem768_rejects_malformed_public_key_atomically() {
        let malformed_pk = [0xFF; ML_KEM_768_PK_LEN];
        let mut ct = [0xA5; ML_KEM_768_CT_LEN];
        let mut secret = [0x5A; SHARED_SECRET_LEN];
        assert_eq!(
            MlKem768.encapsulate(
                &malformed_pk,
                &[0x11; ML_KEM_768_ENCAPS_RAND_LEN],
                &mut ct,
                &mut secret,
            ),
            Err(Error::Backend)
        );
        assert_eq!(ct, [0xA5; ML_KEM_768_CT_LEN]);
        assert_eq!(secret, [0x5A; SHARED_SECRET_LEN]);
    }

    #[test]
    fn mldsa65_sign_verify_and_reject() {
        let (sk, vk) = MlDsa65::generate([4u8; 32]);
        let signer = MlDsa65;
        let msg = b"authenticated handshake transcript";
        let mut sig = [0u8; ML_DSA_65_SIG_LEN];
        let n = signer.sign(&sk, msg, &[9u8; 32], &mut sig).unwrap();
        assert_eq!(n, ML_DSA_65_SIG_LEN);

        let verifier = MlDsa65;
        verifier.verify(&vk, msg, &sig).unwrap();
        assert!(verifier.verify(&vk, b"tampered message", &sig).is_err());
        let mut bad = sig;
        bad[0] ^= 0xFF;
        assert!(verifier.verify(&vk, msg, &bad).is_err());
    }

    #[test]
    fn mldsa65_context_boundary_is_explicit_and_atomic() {
        let (sk, vk) = MlDsa65::generate([0x36; ML_DSA_65_KEYGEN_SEED_LEN]);
        let randomness = [0x47; ML_DSA_65_SIGN_RAND_LEN];
        let context_255 = [0x58; 255];
        let context_256 = [0x69; 256];
        let mut signature = [0u8; ML_DSA_65_SIG_LEN];

        MlDsa65
            .sign_ctx(
                &sk,
                b"context boundary",
                &context_255,
                &randomness,
                &mut signature,
            )
            .unwrap();
        MlDsa65
            .verify_ctx(&vk, b"context boundary", &context_255, &signature)
            .unwrap();

        let mut untouched = [0xA5; ML_DSA_65_SIG_LEN];
        assert_eq!(
            MlDsa65.sign_ctx(
                &sk,
                b"context boundary",
                &context_256,
                &randomness,
                &mut untouched,
            ),
            Err(Error::InvalidLength)
        );
        assert_eq!(untouched, [0xA5; ML_DSA_65_SIG_LEN]);
        assert_eq!(
            MlDsa65.verify_ctx(&vk, b"context boundary", &context_256, &signature),
            Err(Error::InvalidLength)
        );
    }

    #[test]
    fn mldsa65_malformed_keys_fail_without_panics_or_partial_output() {
        let (_valid_sk, valid_vk) = MlDsa65::generate([0x62; ML_DSA_65_KEYGEN_SEED_LEN]);
        let malformed_sk = [0xFF; ML_DSA_65_SK_LEN];
        let arbitrary_vk = [0xFF; ML_DSA_65_VK_LEN];
        let randomness = [0x73; ML_DSA_65_SIGN_RAND_LEN];
        let no_panic = std::panic::catch_unwind(|| {
            let mut signature = [0xA5; ML_DSA_65_SIG_LEN];
            let result = MlDsa65.sign(&malformed_sk, b"malformed key", &randomness, &mut signature);
            (result, signature)
        });
        let (result, signature) = no_panic.expect("malformed fixed-length sk must not panic");
        assert_eq!(result, Err(Error::Backend));
        assert_eq!(signature, [0xA5; ML_DSA_65_SIG_LEN]);

        let malformed_signature = [0xFF; ML_DSA_65_SIG_LEN];
        let no_panic = std::panic::catch_unwind(|| {
            MlDsa65.verify(&valid_vk, b"malformed signature", &malformed_signature)
        });
        assert_eq!(
            no_panic.expect("malformed fixed-length signature must not panic"),
            Err(Error::Backend)
        );

        // Every fixed-length ML-DSA public-key bit pattern is a canonical packed t1 value.
        // It is therefore importable, but cannot validate an unrelated malformed signature.
        assert_eq!(
            MlDsa65.verify(&arbitrary_vk, b"arbitrary public key", &malformed_signature),
            Err(Error::Backend)
        );
    }

    #[test]
    fn mldsa44_and_87_reject_noncanonical_small_secret_coefficients_atomically() {
        let mut signature_44 = [0xA5; ML_DSA_44_SIG_LEN];
        assert_eq!(
            MlDsa44.sign(
                &[0xFF; ML_DSA_44_SK_LEN],
                b"non-canonical eta=2 key",
                &[0x11; ML_DSA_44_SIGN_RAND_LEN],
                &mut signature_44,
            ),
            Err(Error::Backend)
        );
        assert_eq!(signature_44, [0xA5; ML_DSA_44_SIG_LEN]);

        let mut signature_87 = [0x5A; ML_DSA_87_SIG_LEN];
        assert_eq!(
            MlDsa87.sign(
                &[0xFF; ML_DSA_87_SK_LEN],
                b"non-canonical eta=2 key",
                &[0x22; ML_DSA_87_SIGN_RAND_LEN],
                &mut signature_87,
            ),
            Err(Error::Backend)
        );
        assert_eq!(signature_87, [0x5A; ML_DSA_87_SIG_LEN]);
    }

    #[test]
    fn mldsa65_wrong_output_length_does_not_write() {
        let (sk, _) = MlDsa65::generate([0x84; ML_DSA_65_KEYGEN_SEED_LEN]);
        let mut short = [0xA5; ML_DSA_65_SIG_LEN - 1];
        assert_eq!(
            MlDsa65.sign(
                &sk,
                b"wrong output length",
                &[0x95; ML_DSA_65_SIGN_RAND_LEN],
                &mut short,
            ),
            Err(Error::InvalidLength)
        );
        assert_eq!(short, [0xA5; ML_DSA_65_SIG_LEN - 1]);
    }
}
