//! Typed, non-circular pre- and post-KEM transcript projections.

use core::fmt;

use q_periapt_policy::AuthenticatedResolvedSuite;
use sha3::{Digest, Sha3_256};

use crate::capability::{
    AuthenticatedNegotiationDigest, AuthenticatedNegotiationV1, EndpointKeyShareV1,
    MAX_PQ_PUBLIC_KEY_BYTES, MAX_TRADITIONAL_PUBLIC_KEY_BYTES,
};
use crate::codec::{encode_lp8_fields, CodecError};
use crate::context_v2::MigrationContextV2;
use crate::state::{
    validate_committed_execution, CommittedMigrationStateV1, MigrationStateError, StateRevisionV1,
};
use crate::EndpointRole;

/// Domain for the canonical pre-KEM transcript.
pub const PRE_KEM_TRANSCRIPT_DOMAIN: &[u8] = b"Q-PERIAPT-MIGRATION-PRE-KEM-TRANSCRIPT/v1";
/// Domain for the canonical post-KEM transcript.
pub const POST_KEM_TRANSCRIPT_DOMAIN: &[u8] = b"Q-PERIAPT-MIGRATION-POST-KEM-TRANSCRIPT/v1";
/// Transcript schema version.
pub const MIGRATION_TRANSCRIPT_SCHEMA_VERSION: u16 = 1;
/// Maximum PQ ciphertext extent accepted by the generic contract model.
pub const MAX_PQ_CIPHERTEXT_BYTES: usize = 4 * 1024;
/// Maximum traditional ciphertext extent accepted by the generic contract model.
pub const MAX_TRADITIONAL_CIPHERTEXT_BYTES: usize = 256;

macro_rules! transcript_digest {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Eq, Hash, PartialEq)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Borrow the exact digest bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

transcript_digest!(
    PreKemTranscriptDigest,
    "Digest of the typed non-circular pre-KEM transcript."
);
transcript_digest!(
    PostKemTranscriptDigest,
    "Digest of the typed full post-KEM transcript."
);

/// Exact pre-KEM transcript derived from authenticated negotiation and committed state.
#[derive(Clone, Eq, PartialEq)]
pub struct PreKemTranscriptV1 {
    encoded: Vec<u8>,
    digest: PreKemTranscriptDigest,
    state_revision: StateRevisionV1,
    encapsulator_role: EndpointRole,
    negotiation_digest: AuthenticatedNegotiationDigest,
    receiver_key_share: EndpointKeyShareV1,
}

impl fmt::Debug for PreKemTranscriptV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreKemTranscriptV1([redacted])")
    }
}

impl PreKemTranscriptV1 {
    /// Derive the pre-KEM transcript and retain the exact receiver keys for KEM use.
    pub fn from_authenticated_contract(
        negotiation: AuthenticatedNegotiationV1,
        committed_state: CommittedMigrationStateV1,
        execution: AuthenticatedResolvedSuite,
        encapsulator_role: EndpointRole,
        receiver_key_share: EndpointKeyShareV1,
    ) -> Result<Self, TranscriptError> {
        validate_committed_execution(committed_state, execution).map_err(TranscriptError::State)?;
        if negotiation.execution() != execution
            || negotiation.state_revision() != committed_state.revision()
        {
            return Err(TranscriptError::ContractMismatch);
        }
        let receiver_role = opposite(encapsulator_role);
        if receiver_key_share.commitment() != negotiation.key_share_commitment(receiver_role) {
            return Err(TranscriptError::KeyShareMismatch);
        }
        let schema = MIGRATION_TRANSCRIPT_SCHEMA_VERSION.to_be_bytes();
        let revision = committed_state.revision();
        let generation = revision.global_generation().to_be_bytes();
        let epoch = revision.epoch().to_be_bytes();
        let execution_state = execution.trusted_state().encode();
        let suite = [execution.resolved().suite().to_u8()];
        let floor = [negotiation.effective_floor().to_u8()];
        let mode = [negotiation.component_mode().to_u8()];
        let role = [encapsulator_role as u8];
        let encoded = encode_lp8_fields(&[
            PRE_KEM_TRANSCRIPT_DOMAIN,
            &schema,
            negotiation.protocol_id().as_bytes(),
            negotiation.session_id().as_bytes(),
            negotiation.digest().as_bytes(),
            revision.digest().as_bytes(),
            &generation,
            &epoch,
            &execution_state,
            &suite,
            &floor,
            &mode,
            &role,
            receiver_key_share.pq_public_key(),
            receiver_key_share.traditional_public_key(),
        ])
        .map_err(TranscriptError::from_codec)?;
        let digest = PreKemTranscriptDigest(Sha3_256::digest(&encoded).into());
        Ok(Self {
            encoded,
            digest,
            state_revision: revision,
            encapsulator_role,
            negotiation_digest: negotiation.digest(),
            receiver_key_share,
        })
    }

    /// Borrow the exact public transcript bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    /// Return the internally derived transcript digest.
    #[must_use]
    pub const fn digest(&self) -> PreKemTranscriptDigest {
        self.digest
    }

    /// Return the exact committed state revision.
    #[must_use]
    pub const fn state_revision(&self) -> StateRevisionV1 {
        self.state_revision
    }

    /// Return the agreed KEM direction.
    #[must_use]
    pub const fn encapsulator_role(&self) -> EndpointRole {
        self.encapsulator_role
    }

    /// Return the exact authenticated negotiation from which this transcript was derived.
    #[must_use]
    pub const fn negotiation_digest(&self) -> AuthenticatedNegotiationDigest {
        self.negotiation_digest
    }

    /// Borrow the exact receiver keys that the KEM operation must use.
    #[must_use]
    pub const fn receiver_key_share(&self) -> &EndpointKeyShareV1 {
        &self.receiver_key_share
    }
}

/// Exact post-KEM transcript used by mutual confirmation.
#[derive(Clone, Eq, PartialEq)]
pub struct PostKemTranscriptV1 {
    encoded: Vec<u8>,
    digest: PostKemTranscriptDigest,
    state_revision: StateRevisionV1,
    encapsulator_role: EndpointRole,
    context_digest: crate::context_v2::MigrationContextV2Digest,
}

impl fmt::Debug for PostKemTranscriptV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PostKemTranscriptV1([redacted])")
    }
}

impl PostKemTranscriptV1 {
    /// Bind the exact V2 context and both component ciphertexts.
    pub fn from_context(
        context: &MigrationContextV2,
        pq_ciphertext: &[u8],
        traditional_ciphertext: &[u8],
    ) -> Result<Self, TranscriptError> {
        if pq_ciphertext.is_empty()
            || pq_ciphertext.len() > MAX_PQ_CIPHERTEXT_BYTES
            || traditional_ciphertext.is_empty()
            || traditional_ciphertext.len() > MAX_TRADITIONAL_CIPHERTEXT_BYTES
        {
            return Err(TranscriptError::InvalidCiphertextLength);
        }
        let schema = MIGRATION_TRANSCRIPT_SCHEMA_VERSION.to_be_bytes();
        let context_bytes = context
            .encode()
            .map_err(|_| TranscriptError::InvalidEncoding)?;
        let context_digest = context
            .digest()
            .map_err(|_| TranscriptError::InvalidEncoding)?;
        let encoded = encode_lp8_fields(&[
            POST_KEM_TRANSCRIPT_DOMAIN,
            &schema,
            &context_bytes,
            pq_ciphertext,
            traditional_ciphertext,
        ])
        .map_err(TranscriptError::from_codec)?;
        let digest = PostKemTranscriptDigest(Sha3_256::digest(&encoded).into());
        Ok(Self {
            encoded,
            digest,
            state_revision: context.state_revision(),
            encapsulator_role: context.encapsulator_role(),
            context_digest,
        })
    }

    /// Borrow the exact post-KEM transcript bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    /// Return the post-KEM transcript digest.
    #[must_use]
    pub const fn digest(&self) -> PostKemTranscriptDigest {
        self.digest
    }

    /// Return the committed state revision pinned by the transcript.
    #[must_use]
    pub const fn state_revision(&self) -> StateRevisionV1 {
        self.state_revision
    }

    /// Return the agreed encapsulator role.
    #[must_use]
    pub const fn encapsulator_role(&self) -> EndpointRole {
        self.encapsulator_role
    }

    /// Return the exact V2 context digest from which this post-KEM transcript was derived.
    #[must_use]
    pub const fn context_digest(&self) -> crate::context_v2::MigrationContextV2Digest {
        self.context_digest
    }
}

/// Typed transcript construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TranscriptError {
    /// A canonical LP8 length overflowed or encoding failed.
    InvalidEncoding,
    /// State, negotiation, and execution did not describe one contract snapshot.
    ContractMismatch,
    /// Exact receiver keys differed from the signed offer commitment.
    KeyShareMismatch,
    /// Component ciphertexts were empty or exceeded their fixed bounds.
    InvalidCiphertextLength,
    /// The committed state rejected the execution decision.
    State(MigrationStateError),
}

impl TranscriptError {
    fn from_codec(_error: CodecError) -> Self {
        Self::InvalidEncoding
    }
}

impl fmt::Display for TranscriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "migration transcript rejected: {self:?}")
    }
}

impl std::error::Error for TranscriptError {}

fn opposite(role: EndpointRole) -> EndpointRole {
    match role {
        EndpointRole::Initiator => EndpointRole::Responder,
        EndpointRole::Responder => EndpointRole::Initiator,
    }
}

const _: () = {
    assert!(MAX_PQ_CIPHERTEXT_BYTES >= MAX_PQ_PUBLIC_KEY_BYTES);
    assert!(MAX_TRADITIONAL_CIPHERTEXT_BYTES >= MAX_TRADITIONAL_PUBLIC_KEY_BYTES);
};
