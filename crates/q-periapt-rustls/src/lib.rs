//! Production-stack integration demo: Q-Periapt's PQ/T hybrid KEM wired into rustls
//! as a TLS 1.3 key-exchange group, exposed via a [`CryptoProvider`].
//!
//! Unlike the IANA-standard `X25519MLKEM768` group (which rustls ships, using the simple
//! *concatenation* combiner of draft-ietf-tls-ecdhe-mlkem), this group runs Q-Periapt's own
//! combiner — `ContextBound` (assumption-minimal injective binding) or `CompatXWing`
//! (X-Wing byte-exact). It reuses [`q_periapt_kem::HybridKem`] verbatim, so the same
//! composition covered by the suite's conformance and formal-model evidence runs on the wire.
//!
//! Group codes are in the TLS "private use" range (RFC 8446 §11), so this interoperates with
//! another Q-Periapt endpoint, not with the standard group — it is a research deployment of
//! the suite's own design, and a baseline-comparable target for evaluation.

use std::fmt;

use rustls::crypto::{
    ActiveKeyExchange, CompletedKeyExchange, CryptoProvider, SecureRandom, SharedSecret,
    SupportedKxGroup,
};
use rustls::{Error, NamedGroup, PeerMisbehaved};

use q_periapt_backends::{
    MlKem768, MlKem768XWingSeed, Sha3_256Xof, ML_KEM_768_CT_LEN, ML_KEM_768_ENCAPS_RAND_LEN,
    ML_KEM_768_KEYGEN_SEED_LEN, ML_KEM_768_PK_LEN, ML_KEM_768_XWING_SEED_LEN, X25519, X25519_LEN,
};
use q_periapt_core::{Profile, ZeroizingBytes, SHARED_SECRET_LEN};
use q_periapt_kem::HybridKem;
use q_periapt_policy::{HybridSuite, PolicyResolutionError};

const PQ_CLIENT_SHARE: usize = ML_KEM_768_PK_LEN; // 1184: ML-KEM encapsulation key
const PQ_SERVER_SHARE: usize = ML_KEM_768_CT_LEN; // 1088: ML-KEM ciphertext
const CLASSICAL_SHARE: usize = X25519_LEN; //          32: X25519 public / ephemeral
const CLIENT_SHARE: usize = PQ_CLIENT_SHARE + CLASSICAL_SHARE; // pk_pq || pk_trad
const SERVER_SHARE: usize = PQ_SERVER_SHARE + CLASSICAL_SHARE; // ct_pq || ct_trad

/// TLS private-use group code for the `ContextBound` profile (RFC 8446 §11 range).
pub const Q_PERIAPT_CONTEXTBOUND: NamedGroup = NamedGroup::Unknown(0xFE01);
/// TLS private-use group code for the `CompatXWing` profile.
pub const Q_PERIAPT_COMPATXWING: NamedGroup = NamedGroup::Unknown(0xFE02);

const SUITE_ID: &[u8] = b"Q-PERIAPT-TLS/ML-KEM-768+X25519";
const SUPPORTED_POLICY_VERSION: u32 = 1;
// `SupportedKxGroup` cannot access the TLS transcript. This is a protocol-domain
// label, not a per-session transcript commitment; the rustls key schedule binds
// the transcript separately.
const TLS_CONTEXT: &[u8] = b"q-periapt-tls/v1";

/// A Q-Periapt hybrid key-exchange group (one combiner profile).
pub struct QPeriaptKxGroup {
    profile: Profile,
    group: NamedGroup,
    rng: &'static dyn SecureRandom,
}

impl fmt::Debug for QPeriaptKxGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "QPeriaptKxGroup({:?}, {:?})", self.profile, self.group)
    }
}

impl QPeriaptKxGroup {
    fn context(&self) -> &'static [u8] {
        match self.profile {
            Profile::ContextBound => TLS_CONTEXT,
            Profile::CompatXWing => &[],
        }
    }

    fn invalid_pairing() -> Error {
        Error::General("q-periapt: invalid profile/backend pairing".into())
    }
}

impl SupportedKxGroup for QPeriaptKxGroup {
    fn name(&self) -> NamedGroup {
        self.group
    }

    /// Client side: generate the ML-KEM + X25519 key pairs and stage the combined key share.
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut seed = ZeroizingBytes::<ML_KEM_768_KEYGEN_SEED_LEN>::zeroed();
        let mut scalar = ZeroizingBytes::<X25519_LEN>::zeroed();
        self.rng
            .fill(seed.as_mut_bytes())
            .and_then(|()| self.rng.fill(scalar.as_mut_bytes()))?;
        let (sk_pq, pk_pq) = match self.profile {
            Profile::ContextBound => {
                let (sk, pk) = MlKem768::generate(*seed.as_bytes());
                (sk.to_vec(), pk)
            }
            Profile::CompatXWing => {
                let mut seed32 = ZeroizingBytes::<ML_KEM_768_XWING_SEED_LEN>::zeroed();
                seed32
                    .as_mut_bytes()
                    .copy_from_slice(&seed.as_bytes()[..ML_KEM_768_XWING_SEED_LEN]);
                let (sk, pk) = MlKem768XWingSeed::generate(*seed32.as_bytes());
                (sk.to_vec(), pk)
            }
        };
        let (sk_trad, pk_trad) = X25519::generate(*scalar.as_bytes());

        let mut pub_key = Vec::with_capacity(CLIENT_SHARE);
        pub_key.extend_from_slice(&pk_pq);
        pub_key.extend_from_slice(&pk_trad);

        Ok(Box::new(QPeriaptActiveKx {
            profile: self.profile,
            group: self.group,
            sk_pq,
            pk_pq,
            sk_trad,
            pk_trad,
            pub_key,
        }))
    }

    /// Server side: encapsulate to the client's share, returning the ciphertext share + secret.
    fn start_and_complete(&self, client_share: &[u8]) -> Result<CompletedKeyExchange, Error> {
        if client_share.len() != CLIENT_SHARE {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        let (pk_pq, pk_trad) = client_share.split_at(PQ_CLIENT_SHARE);

        let mut rand_pq = ZeroizingBytes::<ML_KEM_768_ENCAPS_RAND_LEN>::zeroed();
        let mut rand_trad = ZeroizingBytes::<X25519_LEN>::zeroed();
        self.rng
            .fill(rand_pq.as_mut_bytes())
            .and_then(|()| self.rng.fill(rand_trad.as_mut_bytes()))?;

        let mut ct_pq = [0u8; ML_KEM_768_CT_LEN];
        let mut ct_trad = [0u8; X25519_LEN];
        // Compute, then wipe the encapsulation coins on EVERY path — a peer InvalidKeyShare
        // (e.g. a low-order X25519 share) must not leave rand_pq/rand_trad in the frame.
        let result = match self.profile {
            Profile::ContextBound => HybridKem::<MlKem768, X25519, Sha3_256Xof>::new(
                &MlKem768,
                &X25519,
                self.profile,
                SUITE_ID,
                SUPPORTED_POLICY_VERSION,
            )
            .map_err(|_| Self::invalid_pairing())
            .and_then(|kem| {
                kem.encapsulate(
                    pk_pq,
                    pk_trad,
                    self.context(),
                    rand_pq.as_bytes(),
                    rand_trad.as_bytes(),
                    &mut ct_pq,
                    &mut ct_trad,
                )
                .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))
            }),
            Profile::CompatXWing => HybridKem::<MlKem768XWingSeed, X25519, Sha3_256Xof>::new(
                &MlKem768XWingSeed,
                &X25519,
                self.profile,
                SUITE_ID,
                SUPPORTED_POLICY_VERSION,
            )
            .map_err(|_| Self::invalid_pairing())
            .and_then(|kem| {
                kem.encapsulate(
                    pk_pq,
                    pk_trad,
                    self.context(),
                    rand_pq.as_bytes(),
                    rand_trad.as_bytes(),
                    &mut ct_pq,
                    &mut ct_trad,
                )
                .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))
            }),
        };
        let secret = result?;

        let mut pub_key = Vec::with_capacity(SERVER_SHARE);
        pub_key.extend_from_slice(&ct_pq);
        pub_key.extend_from_slice(&ct_trad);

        Ok(CompletedKeyExchange {
            group: self.group,
            pub_key,
            secret: SharedSecret::from(&secret.as_bytes()[..]),
        })
    }
}

/// In-flight client key exchange: holds the local key pairs until the server share arrives.
struct QPeriaptActiveKx {
    profile: Profile,
    group: NamedGroup,
    sk_pq: Vec<u8>,
    pk_pq: [u8; ML_KEM_768_PK_LEN],
    sk_trad: [u8; X25519_LEN],
    pk_trad: [u8; X25519_LEN],
    pub_key: Vec<u8>,
}

impl Drop for QPeriaptActiveKx {
    fn drop(&mut self) {
        // Wipe the secret keys if this kx is dropped without completing the exchange
        // (HelloRetryRequest, a connection abort) — the zeroize-on-drop property the API
        // documents. `pk_*`/`pub_key` are public and need no wipe.
        q_periapt_core::secure_wipe(self.sk_pq.as_mut_slice());
        q_periapt_core::secure_wipe(&mut self.sk_trad);
    }
}

impl ActiveKeyExchange for QPeriaptActiveKx {
    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        self.group
    }

    /// Client side: decapsulate the server's ciphertext share to the combined secret.
    fn complete(self: Box<Self>, server_share: &[u8]) -> Result<SharedSecret, Error> {
        if server_share.len() != SERVER_SHARE {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        let (ct_pq, ct_trad) = server_share.split_at(PQ_SERVER_SHARE);

        let context: &[u8] = match self.profile {
            Profile::ContextBound => TLS_CONTEXT,
            Profile::CompatXWing => &[],
        };
        let secret = match self.profile {
            Profile::ContextBound => {
                let kem = HybridKem::<MlKem768, X25519, Sha3_256Xof>::new(
                    &MlKem768,
                    &X25519,
                    self.profile,
                    SUITE_ID,
                    SUPPORTED_POLICY_VERSION,
                )
                .map_err(|_| QPeriaptKxGroup::invalid_pairing())?;
                kem.decapsulate(
                    &self.sk_pq,
                    ct_pq,
                    &self.pk_pq,
                    &self.sk_trad,
                    ct_trad,
                    &self.pk_trad,
                    context,
                )
            }
            Profile::CompatXWing => {
                let kem = HybridKem::<MlKem768XWingSeed, X25519, Sha3_256Xof>::new(
                    &MlKem768XWingSeed,
                    &X25519,
                    self.profile,
                    SUITE_ID,
                    SUPPORTED_POLICY_VERSION,
                )
                .map_err(|_| QPeriaptKxGroup::invalid_pairing())?;
                kem.decapsulate(
                    &self.sk_pq,
                    ct_pq,
                    &self.pk_pq,
                    &self.sk_trad,
                    ct_trad,
                    &self.pk_trad,
                    context,
                )
            }
        }
        .map_err(|_| PeerMisbehaved::InvalidKeyShare)?;
        debug_assert_eq!(secret.as_bytes().len(), SHARED_SECRET_LEN);
        Ok(SharedSecret::from(&secret.as_bytes()[..]))
    }
}

/// Build the two Q-Periapt hybrid key-exchange groups (ContextBound, CompatXWing), bound to
/// `rng` for keypair/encapsulation randomness. The two `'static` groups are leaked exactly ONCE
/// and cached, so repeated `provider()` calls do not leak (the `rng` is ring's process-static).
fn kx_groups(rng: &'static dyn SecureRandom) -> Vec<&'static dyn SupportedKxGroup> {
    static KX: std::sync::OnceLock<[&'static dyn SupportedKxGroup; 2]> = std::sync::OnceLock::new();
    KX.get_or_init(|| {
        let context_bound: &'static dyn SupportedKxGroup = Box::leak(Box::new(QPeriaptKxGroup {
            profile: Profile::ContextBound,
            group: Q_PERIAPT_CONTEXTBOUND,
            rng,
        }));
        let compat_xwing: &'static dyn SupportedKxGroup = Box::leak(Box::new(QPeriaptKxGroup {
            profile: Profile::CompatXWing,
            group: Q_PERIAPT_COMPATXWING,
            rng,
        }));
        [context_bound, compat_xwing]
    })
    .to_vec()
}

/// A rustls [`CryptoProvider`] = the `ring` base provider (cipher suites, signatures, RNG)
/// with Q-Periapt's hybrid groups as the **only** key-exchange groups. TLS 1.3 only.
#[must_use]
pub fn provider() -> CryptoProvider {
    let base = rustls::crypto::ring::default_provider();
    let kx = kx_groups(base.secure_random);
    CryptoProvider {
        kx_groups: kx,
        ..base
    }
}

/// Error resolving a runtime policy onto this rustls provider's fixed wire groups.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProviderPolicyError {
    /// No suite implemented by this provider meets the policy floor/allow-list.
    NoSupportedSuite,
    /// This provider has only a statically defined v1 wire group. It refuses a
    /// different policy content version instead of binding false agility metadata.
    UnsupportedPolicyVersion,
}

impl fmt::Display for ProviderPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSupportedSuite => {
                f.write_str("policy cannot be satisfied by the rustls ML-KEM-768 suite")
            }
            Self::UnsupportedPolicyVersion => {
                f.write_str("policy version is not represented by this static rustls group")
            }
        }
    }
}

impl std::error::Error for ProviderPolicyError {}

impl From<PolicyResolutionError> for ProviderPolicyError {
    fn from(_: PolicyResolutionError) -> Self {
        Self::NoSupportedSuite
    }
}

/// Build a provider only when `policy` resolves atomically to the exact suite,
/// profile, key representation, and policy version this static wire group runs.
///
/// This version implements ML-KEM-768 + X25519 only. L5/enhanced policies and
/// newer policy versions fail closed; they are never silently mapped onto L3 or
/// version 1. The rustls KX API supplies only a fixed protocol-domain context,
/// so this path must not be described as per-session transcript K-CTX binding.
/// `policy` is already parsed but is not cryptographically authenticated by this
/// function; no signed-policy digest or monotonic state crosses this API. A caller
/// making an authorization claim must authenticate the policy and own rollback
/// state at a trusted boundary before invoking this parsed-policy selector.
pub fn provider_with_policy(
    policy: &q_periapt_policy::Policy,
) -> Result<CryptoProvider, ProviderPolicyError> {
    let decision = policy.resolve_suite(&[HybridSuite::MlKem768X25519])?;
    if decision.policy_version() != SUPPORTED_POLICY_VERSION {
        return Err(ProviderPolicyError::UnsupportedPolicyVersion);
    }
    let base = rustls::crypto::ring::default_provider();
    let want = match decision.profile() {
        Profile::ContextBound => Q_PERIAPT_CONTEXTBOUND,
        Profile::CompatXWing => Q_PERIAPT_COMPATXWING,
    };
    let kx: Vec<&'static dyn SupportedKxGroup> = kx_groups(base.secure_random)
        .into_iter()
        .filter(|g| g.name() == want)
        .collect();
    Ok(CryptoProvider {
        kx_groups: kx,
        ..base
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used)]
    use super::*;
    use q_periapt_policy::Policy;

    #[test]
    fn provider_with_policy_resolves_exact_suite_and_fails_closed() {
        let default = provider_with_policy(&Policy::default()).unwrap();
        assert_eq!(default.kx_groups.len(), 1);
        assert_eq!(default.kx_groups[0].name(), Q_PERIAPT_CONTEXTBOUND);

        let compat = Policy::from_toml(
            "schema_version = 1\n\
             policy_version = 1\n\
             min_nist_level = 3\n\
             default_profile = \"CompatXWing\"\n\
             allowed_kems = [\"ML-KEM-768\", \"X25519\"]\n\
             allowed_sigs = [\"ML-DSA-65\"]\n\
             deprecated = []\n",
        )
        .unwrap();
        let compat_provider = provider_with_policy(&compat).unwrap();
        assert_eq!(compat_provider.kx_groups.len(), 1);
        assert_eq!(compat_provider.kx_groups[0].name(), Q_PERIAPT_COMPATXWING);

        assert_eq!(
            provider_with_policy(&Policy::enhanced()).unwrap_err(),
            ProviderPolicyError::NoSupportedSuite,
            "an L5 policy must never run the fixed L3 group"
        );

        let version_two = Policy::from_toml(
            "schema_version = 1\n\
             policy_version = 2\n\
             min_nist_level = 3\n\
             default_profile = \"ContextBound\"\n\
             allowed_kems = [\"ML-KEM-768\", \"X25519\"]\n\
             allowed_sigs = [\"ML-DSA-65\"]\n\
             deprecated = []\n",
        )
        .unwrap();
        assert_eq!(
            provider_with_policy(&version_two).unwrap_err(),
            ProviderPolicyError::UnsupportedPolicyVersion
        );
    }
}
