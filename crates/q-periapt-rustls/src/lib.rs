//! Production path: Q-Periapt's PQ/T hybrid KEM wired into rustls as a TLS 1.3
//! key-exchange group, exposed via a [`CryptoProvider`].
//!
//! Unlike the IANA-standard `X25519MLKEM768` group (which rustls ships, using the simple
//! *concatenation* combiner of draft-ietf-tls-ecdhe-mlkem), this group runs Q-Periapt's own
//! combiner — `ContextBound` (assumption-minimal injective binding) or `CompatXWing`
//! (X-Wing byte-exact). It reuses [`q_periapt_kem::HybridKem`] verbatim, so the same audited,
//! formally-analysed composition that the rest of the suite uses is what runs on the wire.
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
    MlKem768, Sha3_256Xof, ML_KEM_768_CT_LEN, ML_KEM_768_ENCAPS_RAND_LEN,
    ML_KEM_768_KEYGEN_SEED_LEN, ML_KEM_768_PK_LEN, ML_KEM_768_SK_LEN, X25519, X25519_LEN,
};
use q_periapt_core::{Profile, SHARED_SECRET_LEN};
use q_periapt_kem::HybridKem;

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
const POLICY_VERSION: u32 = 1;
// ContextBound requires a non-empty context; bind a fixed protocol label.
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

    fn kem(&self) -> Result<HybridKem<'static, MlKem768, X25519, Sha3_256Xof>, Error> {
        HybridKem::new(&MlKem768, &X25519, self.profile, SUITE_ID, POLICY_VERSION)
            .map_err(|_| Error::General("q-periapt: invalid profile/backend pairing".into()))
    }
}

impl SupportedKxGroup for QPeriaptKxGroup {
    fn name(&self) -> NamedGroup {
        self.group
    }

    /// Client side: generate the ML-KEM + X25519 key pairs and stage the combined key share.
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut seed = [0u8; ML_KEM_768_KEYGEN_SEED_LEN];
        let mut scalar = [0u8; X25519_LEN];
        self.rng.fill(&mut seed)?;
        self.rng.fill(&mut scalar)?;
        let (sk_pq, pk_pq) = MlKem768::generate(seed);
        let (sk_trad, pk_trad) = X25519::generate(scalar);
        seed.fill(0);
        scalar.fill(0);

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

        let mut rand_pq = [0u8; ML_KEM_768_ENCAPS_RAND_LEN];
        let mut rand_trad = [0u8; X25519_LEN];
        self.rng.fill(&mut rand_pq)?;
        self.rng.fill(&mut rand_trad)?;

        let mut ct_pq = [0u8; ML_KEM_768_CT_LEN];
        let mut ct_trad = [0u8; X25519_LEN];
        let secret = self
            .kem()?
            .encapsulate(
                pk_pq,
                pk_trad,
                self.context(),
                &rand_pq,
                &rand_trad,
                &mut ct_pq,
                &mut ct_trad,
            )
            .map_err(|_| PeerMisbehaved::InvalidKeyShare)?;
        rand_pq.fill(0);
        rand_trad.fill(0);

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
    sk_pq: [u8; ML_KEM_768_SK_LEN],
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
        q_periapt_core::secure_wipe(&mut self.sk_pq);
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

        let kem = HybridKem::<MlKem768, X25519, Sha3_256Xof>::new(
            &MlKem768,
            &X25519,
            self.profile,
            SUITE_ID,
            POLICY_VERSION,
        )
        .map_err(|_| Error::General("q-periapt: invalid profile/backend pairing".into()))?;
        let context: &[u8] = match self.profile {
            Profile::ContextBound => TLS_CONTEXT,
            Profile::CompatXWing => &[],
        };
        let secret = kem
            .decapsulate(
                &self.sk_pq,
                ct_pq,
                &self.pk_pq,
                &self.sk_trad,
                ct_trad,
                &self.pk_trad,
                context,
            )
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

/// A [`CryptoProvider`] whose offered hybrid group is **chosen by `policy`** rather than a hard-coded
/// constant: [`q_periapt_policy::Policy::select_profile`] picks ContextBound (when the policy requires
/// it — e.g. an L5 / non-C2PRI posture) or the policy's default profile. This is the shipping path
/// that lets the agility policy actually drive key-exchange selection (vs. a raw profile argument).
#[must_use]
pub fn provider_with_policy(policy: &q_periapt_policy::Policy) -> CryptoProvider {
    let base = rustls::crypto::ring::default_provider();
    let want = match policy.select_profile() {
        Profile::ContextBound => Q_PERIAPT_CONTEXTBOUND,
        Profile::CompatXWing => Q_PERIAPT_COMPATXWING,
    };
    let kx: Vec<&'static dyn SupportedKxGroup> = kx_groups(base.secure_random)
        .into_iter()
        .filter(|g| g.name() == want)
        .collect();
    CryptoProvider {
        kx_groups: kx,
        ..base
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::unwrap_used)]
    use super::*;
    use q_periapt_policy::Policy;

    #[test]
    fn provider_with_policy_lets_the_policy_pick_the_kx_group() {
        // The agility policy actually drives the offered group: enhanced (L5/HQC) -> ContextBound,
        // default -> CompatXWing. This is the shipping-path use of Policy::select_profile().
        let enhanced = provider_with_policy(&Policy::enhanced());
        assert_eq!(enhanced.kx_groups.len(), 1);
        assert_eq!(enhanced.kx_groups[0].name(), Q_PERIAPT_CONTEXTBOUND);

        let default = provider_with_policy(&Policy::default());
        assert_eq!(default.kx_groups.len(), 1);
        assert_eq!(default.kx_groups[0].name(), Q_PERIAPT_COMPATXWING);
    }
}
