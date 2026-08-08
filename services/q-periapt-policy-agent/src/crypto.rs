//! Narrow frozen-ABI-2 adapter. No other module is permitted to use unsafe code.

#![allow(unsafe_code)]

use core::fmt;

use q_periapt_backends::{MlDsa65, ML_DSA_65_SIG_LEN, ML_DSA_65_VK_LEN};
use q_periapt_core::{Secret, ZeroizingBytes};
use q_periapt_ffi_abi2::{
    q_periapt_abi_version, q_periapt_decapsulate, q_periapt_decision_from_signed_policy,
    q_periapt_encapsulate, q_periapt_generate_keypair, Q_PERIAPT_ABI_VERSION,
    Q_PERIAPT_MAX_SIGNED_POLICY_BYTES, Q_PERIAPT_MLKEM768_CT_LEN, Q_PERIAPT_MLKEM768_PK_LEN,
    Q_PERIAPT_MLKEM768_SK_LEN, Q_PERIAPT_OK, Q_PERIAPT_POLICY_DECISION_LEN, Q_PERIAPT_SECRET_LEN,
    Q_PERIAPT_X25519_LEN,
};
use q_periapt_migration::Abi2MigrationApplicationContextV2;
use q_periapt_policy::{AuthenticatedResolvedSuite, HybridSuite, Policy, TrustedPolicyState};

/// Exact public key pair exposed by the isolated service.
#[derive(Clone, Eq, PartialEq)]
pub struct EncapsulationPublicKeys {
    pq: [u8; Q_PERIAPT_MLKEM768_PK_LEN],
    traditional: [u8; Q_PERIAPT_X25519_LEN],
}

impl fmt::Debug for EncapsulationPublicKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EncapsulationPublicKeys([redacted])")
    }
}

impl EncapsulationPublicKeys {
    /// Borrow the ML-KEM-768 public key.
    #[must_use]
    pub const fn pq(&self) -> &[u8; Q_PERIAPT_MLKEM768_PK_LEN] {
        &self.pq
    }

    /// Borrow the X25519 public key.
    #[must_use]
    pub const fn traditional(&self) -> &[u8; Q_PERIAPT_X25519_LEN] {
        &self.traditional
    }

    pub(crate) fn from_slices(pq: &[u8], traditional: &[u8]) -> Result<Self, Abi2EngineError> {
        Ok(Self {
            pq: pq
                .try_into()
                .map_err(|_| Abi2EngineError::InvalidPublicInput)?,
            traditional: traditional
                .try_into()
                .map_err(|_| Abi2EngineError::InvalidPublicInput)?,
        })
    }
}

/// Exact component ciphertext pair. It never contains the shared secret.
#[derive(Clone, Eq, PartialEq)]
pub struct EncapsulationCiphertexts {
    pq: [u8; Q_PERIAPT_MLKEM768_CT_LEN],
    traditional: [u8; Q_PERIAPT_X25519_LEN],
}

impl fmt::Debug for EncapsulationCiphertexts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EncapsulationCiphertexts([public ciphertexts])")
    }
}

impl EncapsulationCiphertexts {
    /// Borrow the ML-KEM-768 ciphertext.
    #[must_use]
    pub const fn pq(&self) -> &[u8; Q_PERIAPT_MLKEM768_CT_LEN] {
        &self.pq
    }

    /// Borrow the X25519 ciphertext.
    #[must_use]
    pub const fn traditional(&self) -> &[u8; Q_PERIAPT_X25519_LEN] {
        &self.traditional
    }

    pub(crate) fn from_slices(pq: &[u8], traditional: &[u8]) -> Result<Self, Abi2EngineError> {
        Ok(Self {
            pq: pq
                .try_into()
                .map_err(|_| Abi2EngineError::InvalidPublicInput)?,
            traditional: traditional
                .try_into()
                .map_err(|_| Abi2EngineError::InvalidPublicInput)?,
        })
    }
}

/// Frozen ABI authentication, contract, public-input, or local-provider failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Abi2EngineError {
    /// The linked ABI is not frozen ABI version 2.
    AbiVersionMismatch,
    /// The signed execution policy failed authentication or exact-state checks.
    PolicyRejected,
    /// A peer key/ciphertext had the wrong exact public extent or was invalid.
    InvalidPublicInput,
    /// The V2 context did not bind the engine's authenticated execution policy.
    ContextMismatch,
    /// Entropy or a local cryptographic provider failed.
    LocalCryptoFailure,
}

impl fmt::Display for Abi2EngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::AbiVersionMismatch => "frozen ABI 2 version mismatch",
            Self::PolicyRejected => "signed execution policy rejected",
            Self::InvalidPublicInput => "peer cryptographic input invalid",
            Self::ContextMismatch => "migration context and execution decision mismatch",
            Self::LocalCryptoFailure => "local cryptographic operation failed",
        })
    }
}

impl std::error::Error for Abi2EngineError {}

pub(crate) struct Abi2Engine {
    decision: [u8; Q_PERIAPT_POLICY_DECISION_LEN],
    execution: AuthenticatedResolvedSuite,
    secret_pq: ZeroizingBytes<{ Q_PERIAPT_MLKEM768_SK_LEN }>,
    public_keys: EncapsulationPublicKeys,
    secret_traditional: ZeroizingBytes<{ Q_PERIAPT_X25519_LEN }>,
}

impl fmt::Debug for Abi2Engine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Abi2Engine([redacted])")
    }
}

impl Abi2Engine {
    pub(crate) fn provision(
        signed_policy: &[u8],
        signature: &[u8],
        verification_key: &[u8; ML_DSA_65_VK_LEN],
        expected_state: TrustedPolicyState,
    ) -> Result<Self, Abi2EngineError> {
        if q_periapt_abi_version() != Q_PERIAPT_ABI_VERSION {
            return Err(Abi2EngineError::AbiVersionMismatch);
        }
        if signed_policy.is_empty()
            || signed_policy.len() > Q_PERIAPT_MAX_SIGNED_POLICY_BYTES
            || signature.len() != ML_DSA_65_SIG_LEN
        {
            return Err(Abi2EngineError::PolicyRejected);
        }
        let policy = Policy::load_signed_monotonic(
            &MlDsa65,
            verification_key,
            signed_policy,
            signature,
            Some(&expected_state),
        )
        .map_err(|_| Abi2EngineError::PolicyRejected)?;
        if policy.trusted_state() != expected_state {
            return Err(Abi2EngineError::PolicyRejected);
        }
        let execution = policy
            .resolve_suite(&[HybridSuite::MlKem768X25519])
            .map_err(|_| Abi2EngineError::PolicyRejected)?;
        let mut decision = [0u8; Q_PERIAPT_POLICY_DECISION_LEN];
        let trusted = expected_state.encode();
        // SAFETY: every pointer comes from a live, disjoint Rust slice/array and
        // every length is its exact extent. `decision` is the sole mutable output.
        let decision_status = unsafe {
            q_periapt_decision_from_signed_policy(
                signed_policy.as_ptr(),
                signed_policy.len(),
                signature.as_ptr(),
                signature.len(),
                verification_key.as_ptr(),
                verification_key.len(),
                trusted.as_ptr(),
                trusted.len(),
                decision.as_mut_ptr(),
                decision.len(),
            )
        };
        if decision_status != Q_PERIAPT_OK || decision.get(4..) != Some(trusted.as_slice()) {
            return Err(Abi2EngineError::PolicyRejected);
        }

        let mut secret_pq = ZeroizingBytes::<{ Q_PERIAPT_MLKEM768_SK_LEN }>::zeroed();
        let mut public_pq = [0u8; Q_PERIAPT_MLKEM768_PK_LEN];
        let mut secret_traditional = ZeroizingBytes::<{ Q_PERIAPT_X25519_LEN }>::zeroed();
        let mut public_traditional = [0u8; Q_PERIAPT_X25519_LEN];
        // SAFETY: the immutable decision and four pairwise-disjoint exact-size
        // output allocations remain live for the duration of the call.
        let keypair_status = unsafe {
            q_periapt_generate_keypair(
                decision.as_ptr(),
                decision.len(),
                secret_pq.as_mut_bytes().as_mut_ptr(),
                secret_pq.as_bytes().len(),
                public_pq.as_mut_ptr(),
                public_pq.len(),
                secret_traditional.as_mut_bytes().as_mut_ptr(),
                secret_traditional.as_bytes().len(),
                public_traditional.as_mut_ptr(),
                public_traditional.len(),
            )
        };
        if keypair_status != Q_PERIAPT_OK {
            return Err(Abi2EngineError::LocalCryptoFailure);
        }
        Ok(Self {
            decision,
            execution,
            secret_pq,
            public_keys: EncapsulationPublicKeys {
                pq: public_pq,
                traditional: public_traditional,
            },
            secret_traditional,
        })
    }

    pub(crate) const fn public_keys(&self) -> &EncapsulationPublicKeys {
        &self.public_keys
    }

    pub(crate) const fn execution(&self) -> AuthenticatedResolvedSuite {
        self.execution
    }

    pub(crate) fn encapsulate(
        &self,
        peer: &EncapsulationPublicKeys,
        context: &Abi2MigrationApplicationContextV2,
    ) -> Result<(EncapsulationCiphertexts, Secret), Abi2EngineError> {
        self.validate_context(context)?;
        let mut pq = [0u8; Q_PERIAPT_MLKEM768_CT_LEN];
        let mut traditional = [0u8; Q_PERIAPT_X25519_LEN];
        let mut secret = ZeroizingBytes::<{ Q_PERIAPT_SECRET_LEN }>::zeroed();
        // SAFETY: all immutable inputs and disjoint exact-size outputs are backed
        // by live Rust allocations. The frozen ABI validates the public keys.
        let status = unsafe {
            q_periapt_encapsulate(
                self.decision.as_ptr(),
                self.decision.len(),
                peer.pq.as_ptr(),
                peer.pq.len(),
                peer.traditional.as_ptr(),
                peer.traditional.len(),
                context.as_bytes().as_ptr(),
                context.as_bytes().len(),
                pq.as_mut_ptr(),
                pq.len(),
                traditional.as_mut_ptr(),
                traditional.len(),
                secret.as_mut_bytes().as_mut_ptr(),
                secret.as_bytes().len(),
            )
        };
        if status != Q_PERIAPT_OK {
            return Err(classify_operation_status(status));
        }
        Ok((
            EncapsulationCiphertexts { pq, traditional },
            Secret::from_bytes(*secret.as_bytes()),
        ))
    }

    pub(crate) fn decapsulate(
        &self,
        ciphertexts: &EncapsulationCiphertexts,
        context: &Abi2MigrationApplicationContextV2,
    ) -> Result<Secret, Abi2EngineError> {
        self.validate_context(context)?;
        let mut secret = ZeroizingBytes::<{ Q_PERIAPT_SECRET_LEN }>::zeroed();
        // SAFETY: all immutable inputs and the exact-size, disjoint secret output
        // are backed by live Rust allocations for the complete call.
        let status = unsafe {
            q_periapt_decapsulate(
                self.decision.as_ptr(),
                self.decision.len(),
                self.secret_pq.as_bytes().as_ptr(),
                self.secret_pq.as_bytes().len(),
                ciphertexts.pq.as_ptr(),
                ciphertexts.pq.len(),
                self.public_keys.pq.as_ptr(),
                self.public_keys.pq.len(),
                self.secret_traditional.as_bytes().as_ptr(),
                self.secret_traditional.as_bytes().len(),
                ciphertexts.traditional.as_ptr(),
                ciphertexts.traditional.len(),
                self.public_keys.traditional.as_ptr(),
                self.public_keys.traditional.len(),
                context.as_bytes().as_ptr(),
                context.as_bytes().len(),
                secret.as_mut_bytes().as_mut_ptr(),
                secret.as_bytes().len(),
            )
        };
        if status != Q_PERIAPT_OK {
            return Err(classify_operation_status(status));
        }
        Ok(Secret::from_bytes(*secret.as_bytes()))
    }

    fn validate_context(
        &self,
        context: &Abi2MigrationApplicationContextV2,
    ) -> Result<(), Abi2EngineError> {
        if context.expected_execution_state() != self.execution.trusted_state()
            || self.decision.get(4..)
                != Some(context.expected_execution_state().encode().as_slice())
        {
            Err(Abi2EngineError::ContextMismatch)
        } else {
            Ok(())
        }
    }
}

fn classify_operation_status(status: i32) -> Abi2EngineError {
    match status {
        q_periapt_ffi_abi2::Q_PERIAPT_ERR_LENGTH
        | q_periapt_ffi_abi2::Q_PERIAPT_ERR_INVALID_KEYSHARE => Abi2EngineError::InvalidPublicInput,
        q_periapt_ffi_abi2::Q_PERIAPT_ERR_POLICY => Abi2EngineError::ContextMismatch,
        _ => Abi2EngineError::LocalCryptoFailure,
    }
}
