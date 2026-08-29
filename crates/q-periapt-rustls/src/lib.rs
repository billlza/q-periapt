//! Research integration demo: Q-Periapt's PQ/T hybrid KEM wired into rustls
//! as private-use TLS 1.3 key-exchange groups, exposed via a [`CryptoProvider`].
//!
//! Unlike the RFC 10024 `X25519MLKEM768` group (which rustls ships, using the RFC 9954
//! *concatenation* construction), these groups run Q-Periapt's own
//! combiner — `ContextBound` (assumption-minimal injective binding) or `CompatXWing`
//! (X-Wing byte-exact). It reuses [`q_periapt_kem::HybridKem`] verbatim, so the same
//! composition covered by the suite's conformance and formal-model evidence runs on the wire.
//!
//! Group codes are in IANA's TLS Supported Groups private-use range, so this interoperates
//! only with another endpoint configured for the same Q-Periapt profile. It is not the
//! RFC 10024 group (`0x11EC`): that group has a 64-byte concatenated key-exchange secret,
//! whereas these private groups expose Q-Periapt's 32-byte combiner output to the TLS key
//! schedule. This crate is a research deployment of the suite's own design and a
//! baseline-comparable evaluation target, not a standardized TLS group.

use std::fmt;

use rustls::crypto::{
    ActiveKeyExchange, CompletedKeyExchange, CryptoProvider, SecureRandom, SharedSecret,
    SupportedKxGroup,
};
use rustls::{Error, NamedGroup, PeerMisbehaved};

use q_periapt_backends::{
    MlKem768, MlKem768XWingSeed, PreparedMlKem768XWingKey, Sha3_256Xof, ML_KEM_768_CT_LEN,
    ML_KEM_768_ENCAPS_RAND_LEN, ML_KEM_768_KEYGEN_SEED_LEN, ML_KEM_768_PK_LEN, ML_KEM_768_SK_LEN,
    ML_KEM_768_XWING_SEED_LEN, X25519, X25519_LEN,
};
use q_periapt_core::{Error as KemError, Profile, ZeroizingBytes, SHARED_SECRET_LEN};
use q_periapt_kem::{
    HybridKem, PqCiphertext, PqPublicKey, PqSecretKey, TradCiphertext, TradPublicKey, TradSecretKey,
};
use q_periapt_policy::{HybridSuite, PolicyResolutionError};

const PQ_CLIENT_SHARE: usize = ML_KEM_768_PK_LEN; // 1184: ML-KEM encapsulation key
const PQ_SERVER_SHARE: usize = ML_KEM_768_CT_LEN; // 1088: ML-KEM ciphertext
const CLASSICAL_SHARE: usize = X25519_LEN; //          32: X25519 public / ephemeral
const CLIENT_SHARE: usize = PQ_CLIENT_SHARE + CLASSICAL_SHARE; // pk_pq || pk_trad
const SERVER_SHARE: usize = PQ_SERVER_SHARE + CLASSICAL_SHARE; // ct_pq || ct_trad

/// TLS Supported Groups private-use code for the `ContextBound` profile.
pub const Q_PERIAPT_CONTEXTBOUND: NamedGroup = NamedGroup::Unknown(0xFE01);
/// TLS private-use group code for the `CompatXWing` profile.
pub const Q_PERIAPT_COMPATXWING: NamedGroup = NamedGroup::Unknown(0xFE02);

const SUITE_ID: &[u8] = b"Q-PERIAPT-TLS/ML-KEM-768+X25519";
const SUPPORTED_POLICY_VERSION: u32 = 1;
// `SupportedKxGroup` cannot access the TLS transcript. This is a protocol-domain
// label, not a per-session transcript commitment; the rustls key schedule binds
// the transcript separately.
const TLS_CONTEXT: &[u8] = b"q-periapt-tls/v1";

/// Project a trusted, statically configured TLS group onto the metadata
/// contract of its combiner profile. CompatXWing has no metadata slots; the
/// TLS transcript remains bound by the TLS 1.3 key schedule.
fn kem_metadata(profile: Profile) -> (&'static [u8], u32, &'static [u8]) {
    match profile {
        Profile::ContextBound => (SUITE_ID, SUPPORTED_POLICY_VERSION, TLS_CONTEXT),
        Profile::CompatXWing => (&[], 0, &[]),
    }
}

/// A Q-Periapt hybrid key-exchange group (one combiner profile).
pub struct QPeriaptKxGroup {
    profile: Profile,
    group: NamedGroup,
    rng: &'static dyn SecureRandom,
    compat_key_preparer: &'static dyn CompatKeyPreparer,
}

/// Internal injection boundary used to verify that a Compat handshake invokes
/// the production preparation path exactly once. It carries no cache or key
/// state; production uses the stateless implementation below.
trait CompatKeyPreparer: Sync {
    fn prepare(
        &self,
        seed: ZeroizingBytes<ML_KEM_768_XWING_SEED_LEN>,
    ) -> Result<PreparedMlKem768XWingKey, KemError>;
}

struct BackendCompatKeyPreparer;

impl CompatKeyPreparer for BackendCompatKeyPreparer {
    fn prepare(
        &self,
        seed: ZeroizingBytes<ML_KEM_768_XWING_SEED_LEN>,
    ) -> Result<PreparedMlKem768XWingKey, KemError> {
        MlKem768XWingSeed::prepare(seed)
    }
}

static BACKEND_COMPAT_KEY_PREPARER: BackendCompatKeyPreparer = BackendCompatKeyPreparer;

impl fmt::Debug for QPeriaptKxGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "QPeriaptKxGroup({:?}, {:?})", self.profile, self.group)
    }
}

impl QPeriaptKxGroup {
    fn invalid_pairing() -> Error {
        Error::General("q-periapt: invalid profile/backend pairing".into())
    }

    fn kem_error(error: KemError) -> Error {
        match error {
            KemError::InvalidKeyShare => PeerMisbehaved::InvalidKeyShare.into(),
            KemError::InvalidLength => {
                Error::General("q-periapt: hybrid KEM length invariant failed".into())
            }
            KemError::Backend => Error::General("q-periapt: hybrid KEM backend failure".into()),
            KemError::PolicyDenied => Self::invalid_pairing(),
            _ => Error::General("q-periapt: hybrid KEM failed".into()),
        }
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
        let pq_key = match self.profile {
            Profile::ContextBound => {
                // `generate_zeroizing` borrows the seed and writes the expanded
                // decapsulation key straight into its boxed zeroizing owner, so
                // neither secret crosses this boundary as an unwiped by-value
                // stack copy.
                let (decapsulation_key, encapsulation_key) =
                    MlKem768::generate_zeroizing(seed.as_bytes()).map_err(|_| {
                        Error::General("q-periapt: ML-KEM key generation failed".into())
                    })?;
                QPeriaptClientPqKey::ContextBound {
                    decapsulation_key,
                    encapsulation_key,
                }
            }
            Profile::CompatXWing => {
                let mut seed32 = ZeroizingBytes::<ML_KEM_768_XWING_SEED_LEN>::zeroed();
                seed32
                    .as_mut_bytes()
                    .copy_from_slice(&seed.as_bytes()[..ML_KEM_768_XWING_SEED_LEN]);
                let prepared = self.compat_key_preparer.prepare(seed32).map_err(|_| {
                    Error::General("q-periapt: ML-KEM key generation failed".into())
                })?;
                QPeriaptClientPqKey::CompatXWing(prepared)
            }
        };
        let (sk_trad, pk_trad) = X25519::generate(*scalar.as_bytes());

        let mut pub_key = Vec::with_capacity(CLIENT_SHARE);
        pub_key.extend_from_slice(pq_key.encapsulation_key());
        pub_key.extend_from_slice(&pk_trad);

        Ok(Box::new(QPeriaptActiveKx {
            group: self.group,
            pq_key,
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
        let (suite_id, policy_version, context) = kem_metadata(self.profile);
        // Compute, then wipe the encapsulation coins on EVERY path — a peer InvalidKeyShare
        // (e.g. a low-order X25519 share) must not leave rand_pq/rand_trad in the frame.
        let result = match self.profile {
            Profile::ContextBound => HybridKem::<MlKem768, X25519, Sha3_256Xof>::new(
                &MlKem768,
                &X25519,
                self.profile,
                suite_id,
                policy_version,
            )
            .map_err(|_| Self::invalid_pairing())
            .and_then(|kem| {
                kem.encapsulate(
                    pk_pq,
                    pk_trad,
                    context,
                    rand_pq.as_bytes(),
                    rand_trad.as_bytes(),
                    &mut ct_pq,
                    &mut ct_trad,
                )
                .map_err(Self::kem_error)
            }),
            Profile::CompatXWing => HybridKem::<MlKem768XWingSeed, X25519, Sha3_256Xof>::new(
                &MlKem768XWingSeed,
                &X25519,
                self.profile,
                suite_id,
                policy_version,
            )
            .map_err(|_| Self::invalid_pairing())
            .and_then(|kem| {
                kem.encapsulate(
                    pk_pq,
                    pk_trad,
                    context,
                    rand_pq.as_bytes(),
                    rand_trad.as_bytes(),
                    &mut ct_pq,
                    &mut ct_trad,
                )
                .map_err(Self::kem_error)
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

/// Profile-specific PQ key owner for an in-flight client exchange.
enum QPeriaptClientPqKey {
    ContextBound {
        decapsulation_key: Box<ZeroizingBytes<ML_KEM_768_SK_LEN>>,
        encapsulation_key: [u8; ML_KEM_768_PK_LEN],
    },
    CompatXWing(PreparedMlKem768XWingKey),
}

impl QPeriaptClientPqKey {
    fn encapsulation_key(&self) -> &[u8; ML_KEM_768_PK_LEN] {
        match self {
            Self::ContextBound {
                encapsulation_key, ..
            } => encapsulation_key,
            Self::CompatXWing(prepared) => prepared.encapsulation_key(),
        }
    }
}

/// In-flight client key exchange: holds the local key pairs until the server share arrives.
struct QPeriaptActiveKx {
    group: NamedGroup,
    pq_key: QPeriaptClientPqKey,
    sk_trad: [u8; X25519_LEN],
    pk_trad: [u8; X25519_LEN],
    pub_key: Vec<u8>,
}

impl Drop for QPeriaptActiveKx {
    fn drop(&mut self) {
        // Both PQ variants own their secret material through ZeroizingBytes (the
        // Compat variant transitively through PreparedMlKem768XWingKey). Wipe the
        // traditional key explicitly if this exchange is abandoned or completed.
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

        let secret = match &self.pq_key {
            QPeriaptClientPqKey::ContextBound {
                decapsulation_key,
                encapsulation_key,
            } => {
                let (suite_id, policy_version, context) = kem_metadata(Profile::ContextBound);
                let kem = HybridKem::<MlKem768, X25519, Sha3_256Xof>::new(
                    &MlKem768,
                    &X25519,
                    Profile::ContextBound,
                    suite_id,
                    policy_version,
                )
                .map_err(|_| QPeriaptKxGroup::invalid_pairing())?;
                kem.decapsulate(
                    PqSecretKey::new(decapsulation_key.as_bytes()),
                    PqCiphertext::new(ct_pq),
                    PqPublicKey::new(encapsulation_key),
                    TradSecretKey::new(&self.sk_trad),
                    TradCiphertext::new(ct_trad),
                    TradPublicKey::new(&self.pk_trad),
                    context,
                )
            }
            QPeriaptClientPqKey::CompatXWing(prepared) => {
                let (suite_id, policy_version, context) = kem_metadata(Profile::CompatXWing);
                let kem = HybridKem::<MlKem768XWingSeed, X25519, Sha3_256Xof>::new(
                    &MlKem768XWingSeed,
                    &X25519,
                    Profile::CompatXWing,
                    suite_id,
                    policy_version,
                )
                .map_err(|_| QPeriaptKxGroup::invalid_pairing())?;
                kem.decapsulate_prepared(
                    prepared,
                    PqCiphertext::new(ct_pq),
                    TradSecretKey::new(&self.sk_trad),
                    TradCiphertext::new(ct_trad),
                    TradPublicKey::new(&self.pk_trad),
                    context,
                )
            }
        }
        .map_err(QPeriaptKxGroup::kem_error)?;
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
            compat_key_preparer: &BACKEND_COMPAT_KEY_PREPARER,
        }));
        let compat_xwing: &'static dyn SupportedKxGroup = Box::leak(Box::new(QPeriaptKxGroup {
            profile: Profile::CompatXWing,
            group: Q_PERIAPT_COMPATXWING,
            rng,
            compat_key_preparer: &BACKEND_COMPAT_KEY_PREPARER,
        }));
        [context_bound, compat_xwing]
    })
    .to_vec()
}

/// The `ring` base provider restricted to its TLS 1.3 cipher suites.
///
/// The Q-Periapt groups are TLS 1.3 key-share groups; a TLS 1.2 suite in the
/// provider would advertise a protocol version these groups never serve. The
/// documented TLS 1.3-only contract is therefore enforced mechanically here —
/// by filtering ring's suite list — rather than left to the feature set the
/// final binary happens to unify (`tls12` is additive across a workspace).
fn tls13_only_base() -> CryptoProvider {
    let mut base = rustls::crypto::ring::default_provider();
    base.cipher_suites.retain(|suite| suite.tls13().is_some());
    base
}

/// A rustls [`CryptoProvider`] = the `ring` base provider (cipher suites, signatures, RNG)
/// with Q-Periapt's hybrid groups as the **only** key-exchange groups. TLS 1.3 only:
/// the cipher-suite list is filtered to ring's TLS 1.3 suites, so a TLS 1.2-pinned
/// configuration against this provider fails to build.
#[must_use]
pub fn provider() -> CryptoProvider {
    let base = tls13_only_base();
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
/// profile, key representation, and policy version represented by this static
/// wire-group selection.
///
/// This version implements ML-KEM-768 + X25519 only. L5/enhanced policies and
/// newer policy versions fail closed; they are never silently mapped onto L3 or
/// version 1. For `ContextBound`, the rustls KX API supplies only a fixed
/// protocol-domain context, so this path must not be described as per-session
/// transcript K-CTX binding. For `CompatXWing`, the policy selects the private
/// wire group but the KEM receives canonical absent metadata (`[]`, `0`, `[]`);
/// the TLS 1.3 key schedule independently binds the handshake transcript.
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
    let base = tls13_only_base();
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
    use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

    use super::*;
    use q_periapt_policy::Policy;

    #[derive(Debug)]
    struct DistinctTestRandom(AtomicU8);

    impl SecureRandom for DistinctTestRandom {
        fn fill(&self, output: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
            let domain = self.0.fetch_add(1, Ordering::Relaxed);
            for (index, byte) in output.iter_mut().enumerate() {
                *byte = domain.wrapping_add(index as u8);
            }
            Ok(())
        }
    }

    struct CountingCompatKeyPreparer(AtomicUsize);

    impl CompatKeyPreparer for CountingCompatKeyPreparer {
        fn prepare(
            &self,
            seed: ZeroizingBytes<ML_KEM_768_XWING_SEED_LEN>,
        ) -> Result<PreparedMlKem768XWingKey, KemError> {
            self.0.fetch_add(1, Ordering::Relaxed);
            MlKem768XWingSeed::prepare(seed)
        }
    }

    struct FailingCompatKeyPreparer(AtomicUsize);

    impl CompatKeyPreparer for FailingCompatKeyPreparer {
        fn prepare(
            &self,
            _seed: ZeroizingBytes<ML_KEM_768_XWING_SEED_LEN>,
        ) -> Result<PreparedMlKem768XWingKey, KemError> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Err(KemError::Backend)
        }
    }

    #[test]
    fn kem_error_only_attributes_public_key_share_failures_to_the_peer() {
        assert_eq!(
            QPeriaptKxGroup::kem_error(KemError::InvalidKeyShare),
            Error::PeerMisbehaved(PeerMisbehaved::InvalidKeyShare)
        );
        assert_eq!(
            QPeriaptKxGroup::kem_error(KemError::InvalidLength),
            Error::General("q-periapt: hybrid KEM length invariant failed".into())
        );
        assert_eq!(
            QPeriaptKxGroup::kem_error(KemError::Backend),
            Error::General("q-periapt: hybrid KEM backend failure".into())
        );
        assert_eq!(
            QPeriaptKxGroup::kem_error(KemError::PolicyDenied),
            Error::General("q-periapt: invalid profile/backend pairing".into())
        );
    }

    #[test]
    fn provider_ships_no_tls12_cipher_suite_and_rejects_a_tls12_pinned_config() {
        use rustls::{ClientConfig, ProtocolVersion, SupportedProtocolVersion, ALL_VERSIONS};

        for candidate in [
            provider(),
            provider_with_policy(&Policy::default()).unwrap(),
        ] {
            assert!(
                !candidate.cipher_suites.is_empty(),
                "the TLS 1.3 filter must not empty the suite list"
            );
            assert!(
                candidate
                    .cipher_suites
                    .iter()
                    .all(|suite| suite.version().version == ProtocolVersion::TLSv1_3),
                "provider must carry only TLS 1.3 cipher suites: {:?}",
                candidate.cipher_suites
            );
        }

        // A TLS 1.2-pinned client configuration against this provider must fail. When
        // the `tls12` rustls feature is compiled out entirely (this crate's default
        // build), `ALL_VERSIONS` has no TLS 1.2 entry and such a pin cannot even be
        // expressed; when the feature is unified in by another dependency, the pinned
        // builder must refuse the provider ("no usable cipher suites").
        let tls12_pin: Vec<&'static SupportedProtocolVersion> = ALL_VERSIONS
            .iter()
            .copied()
            .filter(|candidate| candidate.version == ProtocolVersion::TLSv1_2)
            .collect();
        if tls12_pin.is_empty() {
            return;
        }
        assert!(
            ClientConfig::builder_with_provider(provider().into())
                .with_protocol_versions(&tls12_pin)
                .is_err(),
            "a TLS 1.2-pinned client config must fail to build against this provider"
        );
    }

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

    #[test]
    fn each_private_group_start_uses_fresh_key_material() {
        static RANDOM: DistinctTestRandom = DistinctTestRandom(AtomicU8::new(0));
        let group = QPeriaptKxGroup {
            profile: Profile::ContextBound,
            group: Q_PERIAPT_CONTEXTBOUND,
            rng: &RANDOM,
            compat_key_preparer: &BACKEND_COMPAT_KEY_PREPARER,
        };
        let first = group.start().unwrap();
        let second = group.start().unwrap();
        assert_eq!(first.pub_key().len(), CLIENT_SHARE);
        assert_eq!(second.pub_key().len(), CLIENT_SHARE);
        assert_ne!(first.pub_key(), second.pub_key());
        assert_eq!(u16::from(Q_PERIAPT_CONTEXTBOUND), 0xFE01);
        assert_eq!(u16::from(Q_PERIAPT_COMPATXWING), 0xFE02);
        assert_ne!(u16::from(Q_PERIAPT_CONTEXTBOUND), 0x11EC);
        assert_ne!(u16::from(Q_PERIAPT_COMPATXWING), 0x11EC);
    }

    #[test]
    fn compat_handshake_prepares_the_backend_key_exactly_once() {
        static RANDOM: DistinctTestRandom = DistinctTestRandom(AtomicU8::new(0x40));
        static PREPARER: CountingCompatKeyPreparer = CountingCompatKeyPreparer(AtomicUsize::new(0));
        PREPARER.0.store(0, Ordering::Relaxed);
        let group = QPeriaptKxGroup {
            profile: Profile::CompatXWing,
            group: Q_PERIAPT_COMPATXWING,
            rng: &RANDOM,
            compat_key_preparer: &PREPARER,
        };

        let client = group.start().unwrap();
        assert_eq!(PREPARER.0.load(Ordering::Relaxed), 1);
        let server = group.start_and_complete(client.pub_key()).unwrap();
        assert_eq!(
            PREPARER.0.load(Ordering::Relaxed),
            1,
            "server encapsulation must not generate a recipient key"
        );
        let client_secret = client.complete(&server.pub_key).unwrap();
        assert_eq!(client_secret.secret_bytes(), server.secret.secret_bytes());
        assert_eq!(
            PREPARER.0.load(Ordering::Relaxed),
            1,
            "client completion must reuse the prepared expanded key"
        );
    }

    #[test]
    fn compat_preparation_failure_creates_no_active_exchange() {
        static RANDOM: DistinctTestRandom = DistinctTestRandom(AtomicU8::new(0x50));
        static PREPARER: FailingCompatKeyPreparer = FailingCompatKeyPreparer(AtomicUsize::new(0));
        PREPARER.0.store(0, Ordering::Relaxed);
        let group = QPeriaptKxGroup {
            profile: Profile::CompatXWing,
            group: Q_PERIAPT_COMPATXWING,
            rng: &RANDOM,
            compat_key_preparer: &PREPARER,
        };

        let result = group.start();
        assert!(result.is_err());
        assert_eq!(PREPARER.0.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn failed_completion_neither_reprepares_nor_reuses_the_next_key() {
        static RANDOM: DistinctTestRandom = DistinctTestRandom(AtomicU8::new(0x60));
        static PREPARER: CountingCompatKeyPreparer = CountingCompatKeyPreparer(AtomicUsize::new(0));
        PREPARER.0.store(0, Ordering::Relaxed);
        let group = QPeriaptKxGroup {
            profile: Profile::CompatXWing,
            group: Q_PERIAPT_COMPATXWING,
            rng: &RANDOM,
            compat_key_preparer: &PREPARER,
        };

        let first = group.start().unwrap();
        let first_public = first.pub_key().to_vec();
        assert!(first.complete(&[0u8; 1]).is_err());
        assert_eq!(
            PREPARER.0.load(Ordering::Relaxed),
            1,
            "failed completion must not re-run key preparation"
        );

        let second = group.start().unwrap();
        assert_eq!(PREPARER.0.load(Ordering::Relaxed), 2);
        assert_ne!(first_public, second.pub_key());
    }

    #[test]
    fn concurrent_compat_active_exchanges_keep_independent_keys() {
        let provider = provider();
        let group = provider
            .kx_groups
            .iter()
            .copied()
            .find(|candidate| candidate.name() == Q_PERIAPT_COMPATXWING)
            .unwrap();

        let results = std::thread::scope(|scope| {
            let workers = (0..4)
                .map(|_| {
                    scope.spawn(move || {
                        let client = group.start().unwrap();
                        let client_share = client.pub_key().to_vec();
                        let server = group.start_and_complete(&client_share).unwrap();
                        let client_secret = client.complete(&server.pub_key).unwrap();
                        assert_eq!(client_secret.secret_bytes(), server.secret.secret_bytes());
                        (client_share, client_secret.secret_bytes().to_vec())
                    })
                })
                .collect::<Vec<_>>();
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap())
                .collect::<Vec<_>>()
        });

        for left in 0..results.len() {
            for right in (left + 1)..results.len() {
                assert_ne!(results[left].0, results[right].0);
                assert_ne!(results[left].1, results[right].1);
            }
        }
    }

    #[test]
    fn private_groups_project_canonical_profile_metadata() {
        static RANDOM: DistinctTestRandom = DistinctTestRandom(AtomicU8::new(0));
        let context_bound = QPeriaptKxGroup {
            profile: Profile::ContextBound,
            group: Q_PERIAPT_CONTEXTBOUND,
            rng: &RANDOM,
            compat_key_preparer: &BACKEND_COMPAT_KEY_PREPARER,
        };
        let compat = QPeriaptKxGroup {
            profile: Profile::CompatXWing,
            group: Q_PERIAPT_COMPATXWING,
            rng: &RANDOM,
            compat_key_preparer: &BACKEND_COMPAT_KEY_PREPARER,
        };

        assert_eq!(
            kem_metadata(context_bound.profile),
            (SUITE_ID, SUPPORTED_POLICY_VERSION, TLS_CONTEXT)
        );
        assert_eq!(kem_metadata(compat.profile), (&[][..], 0, &[][..]));
    }
}
