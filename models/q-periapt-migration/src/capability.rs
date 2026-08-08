//! Signed, role-ordered capability negotiation for Migration Contract V2.

use core::fmt;

use q_periapt_policy::{AuthenticatedPolicy, AuthenticatedResolvedSuite, TrustedPolicyState};
use q_periapt_sig::{Signer, Verifier};
use sha3::{Digest, Sha3_256};

use crate::codec::{encode_lp8_fields, CodecError, Lp8Reader};
use crate::state::{
    validate_committed_execution, CommittedMigrationStateV1, ComponentMode, MigrationChainId,
    MigrationSecurityPosture, MigrationStateDigest, MigrationStateError, MigrationSuiteSet,
    StateRevisionV1, MAX_MIGRATION_SIGNATURE_BYTES,
};
use crate::{AuthenticatedEndpointPolicy, EndpointRole, MigrationProtocolId, SecurityFloor};

/// Domain for signed capability-offer bodies.
pub const CAPABILITY_OFFER_DOMAIN: &[u8] = b"Q-PERIAPT-MIGRATION-CAPABILITY-OFFER/v1";
/// Domain for capability-offer signatures.
pub const CAPABILITY_OFFER_SIGNATURE_DOMAIN: &[u8] = b"Q-PERIAPT-MIGRATION-CAPABILITY-SIGNATURE/v1";
/// Domain for the role-ordered joint-negotiation digest.
pub const AUTHENTICATED_NEGOTIATION_DOMAIN: &[u8] =
    b"Q-PERIAPT-MIGRATION-AUTHENTICATED-NEGOTIATION/v1";
/// Domain for commitments to exact hybrid KEM public keys.
pub const KEY_SHARE_COMMITMENT_DOMAIN: &[u8] = b"Q-PERIAPT-MIGRATION-KEY-SHARE/v1";
/// Capability schema version.
pub const CAPABILITY_SCHEMA_VERSION: u16 = 1;
/// Maximum canonical offer body accepted before signature verification.
pub const MAX_CAPABILITY_OFFER_BODY_BYTES: usize = 2 * 1024;
/// Maximum PQ public-key extent accepted by the generic transcript model.
pub const MAX_PQ_PUBLIC_KEY_BYTES: usize = 4 * 1024;
/// Maximum traditional public-key extent accepted by the generic transcript model.
pub const MAX_TRADITIONAL_PUBLIC_KEY_BYTES: usize = 256;

macro_rules! public_bytes {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, Eq, Hash, PartialEq)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Construct the public value from exact bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Borrow the exact bytes.
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

public_bytes!(
    MigrationSessionId,
    "A fresh pairwise migration-session identifier."
);
public_bytes!(
    MigrationIdentityKeyId,
    "A pinned endpoint identity-key identifier."
);
public_bytes!(
    MigrationNonce,
    "A fresh endpoint nonce authenticated by an offer signature."
);
public_bytes!(
    KeyShareCommitment,
    "A commitment to exact PQ and traditional public keys."
);
public_bytes!(
    AuthenticatedNegotiationDigest,
    "A digest of both authenticated role-ordered offers."
);

/// Exact public keys owned by the capability offer and reused by the KEM operation.
#[derive(Clone, Eq, PartialEq)]
pub struct EndpointKeyShareV1 {
    pq_public_key: Vec<u8>,
    traditional_public_key: Vec<u8>,
    commitment: KeyShareCommitment,
}

impl fmt::Debug for EndpointKeyShareV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EndpointKeyShareV1([redacted])")
    }
}

impl EndpointKeyShareV1 {
    /// Validate, own, and commit exact receiver public-key bytes.
    pub fn new(
        pq_public_key: &[u8],
        traditional_public_key: &[u8],
    ) -> Result<Self, CapabilityError> {
        if pq_public_key.is_empty()
            || pq_public_key.len() > MAX_PQ_PUBLIC_KEY_BYTES
            || traditional_public_key.is_empty()
            || traditional_public_key.len() > MAX_TRADITIONAL_PUBLIC_KEY_BYTES
        {
            return Err(CapabilityError::InvalidKeyShareLength);
        }
        let commitment = KeyShareCommitment(hash_lp8(&[
            KEY_SHARE_COMMITMENT_DOMAIN,
            pq_public_key,
            traditional_public_key,
        ])?);
        Ok(Self {
            pq_public_key: pq_public_key.to_vec(),
            traditional_public_key: traditional_public_key.to_vec(),
            commitment,
        })
    }

    /// Borrow the exact PQ public key.
    #[must_use]
    pub fn pq_public_key(&self) -> &[u8] {
        &self.pq_public_key
    }

    /// Borrow the exact traditional public key.
    #[must_use]
    pub fn traditional_public_key(&self) -> &[u8] {
        &self.traditional_public_key
    }

    /// Return the commitment authenticated by an offer.
    #[must_use]
    pub const fn commitment(&self) -> KeyShareCommitment {
        self.commitment
    }
}

/// Canonical endpoint capability offer; it is not authenticated until signature verification.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CapabilityOfferV1 {
    protocol_id: MigrationProtocolId,
    chain_id: MigrationChainId,
    session_id: MigrationSessionId,
    sender_role: EndpointRole,
    sender_identity: MigrationIdentityKeyId,
    receiver_identity: MigrationIdentityKeyId,
    sender_nonce: MigrationNonce,
    sender_policy_state: TrustedPolicyState,
    migration_state_digest: MigrationStateDigest,
    global_generation: u64,
    offered_suites: MigrationSuiteSet,
    posture: MigrationSecurityPosture,
    sender_key_share: KeyShareCommitment,
}

/// Authenticated inputs used to derive one canonical endpoint capability offer.
///
/// The record deliberately retains authenticated policy and committed-state
/// types instead of accepting caller-supplied policy or state commitments.
#[derive(Clone, Copy)]
pub struct CapabilityOfferInputV1<'a> {
    /// Protocol namespace governed by the committed state.
    pub protocol_id: MigrationProtocolId,
    /// Fresh common capability-session identifier.
    pub session_id: MigrationSessionId,
    /// Role of the endpoint signing this offer.
    pub sender_role: EndpointRole,
    /// Pinned identity of the signing endpoint.
    pub sender_identity: MigrationIdentityKeyId,
    /// Pinned identity of the intended peer.
    pub receiver_identity: MigrationIdentityKeyId,
    /// Fresh nonce contributed by the signing endpoint.
    pub sender_nonce: MigrationNonce,
    /// Authenticated endpoint policy whose state is committed by the offer.
    pub sender_policy: &'a AuthenticatedPolicy,
    /// Exact committed migration state bound by the offer.
    pub committed_state: CommittedMigrationStateV1,
    /// Closed set of suites offered by this endpoint.
    pub offered_suites: MigrationSuiteSet,
    /// Exact public key share owned by the signing endpoint.
    pub sender_key_share: &'a EndpointKeyShareV1,
}

impl fmt::Debug for CapabilityOfferV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CapabilityOfferV1([redacted])")
    }
}

impl CapabilityOfferV1 {
    /// Construct an offer from authenticated policy and committed migration state.
    pub fn from_authenticated_state(
        input: CapabilityOfferInputV1<'_>,
    ) -> Result<Self, CapabilityError> {
        let CapabilityOfferInputV1 {
            protocol_id,
            session_id,
            sender_role,
            sender_identity,
            receiver_identity,
            sender_nonce,
            sender_policy,
            committed_state,
            offered_suites,
            sender_key_share,
        } = input;
        if all_zero(protocol_id.as_bytes())
            || all_zero(session_id.as_bytes())
            || all_zero(sender_identity.as_bytes())
            || all_zero(receiver_identity.as_bytes())
            || all_zero(sender_nonce.as_bytes())
        {
            return Err(CapabilityError::ZeroIdentifier);
        }
        let state = committed_state.state();
        if protocol_id != state.protocol_id() {
            return Err(CapabilityError::StateMismatch);
        }
        let sender_floor = SecurityFloor::from_nist_level(sender_policy.policy().min_nist_level())
            .map_err(|_| CapabilityError::InvalidSecurityFloor)?;
        let minimum = core::cmp::max(sender_floor, state.posture().minimum_pq_level());
        Ok(Self {
            protocol_id,
            chain_id: state.chain_id(),
            session_id,
            sender_role,
            sender_identity,
            receiver_identity,
            sender_nonce,
            sender_policy_state: sender_policy.trusted_state(),
            migration_state_digest: committed_state.revision().digest(),
            global_generation: state.global_generation(),
            offered_suites,
            posture: MigrationSecurityPosture::new(minimum, state.posture().component_mode()),
            sender_key_share: sender_key_share.commitment(),
        })
    }

    /// Encode the exact signed body.
    pub fn encode(&self) -> Result<Vec<u8>, CapabilityError> {
        let schema = CAPABILITY_SCHEMA_VERSION.to_be_bytes();
        let role = [self.sender_role as u8];
        let policy = self.sender_policy_state.encode();
        let generation = self.global_generation.to_be_bytes();
        let suites = [self.offered_suites.bits()];
        let floor = [self.posture.minimum_pq_level().to_u8()];
        let mode = [self.posture.component_mode().to_u8()];
        let encoded = encode_lp8_fields(&[
            CAPABILITY_OFFER_DOMAIN,
            &schema,
            self.protocol_id.as_bytes(),
            self.chain_id.as_bytes(),
            self.session_id.as_bytes(),
            &role,
            self.sender_identity.as_bytes(),
            self.receiver_identity.as_bytes(),
            self.sender_nonce.as_bytes(),
            &policy,
            self.migration_state_digest.as_bytes(),
            &generation,
            &suites,
            &floor,
            &mode,
            self.sender_key_share.as_bytes(),
        ])
        .map_err(CapabilityError::from_codec)?;
        if encoded.len() > MAX_CAPABILITY_OFFER_BODY_BYTES {
            return Err(CapabilityError::OfferTooLarge);
        }
        Ok(encoded)
    }

    /// Strictly decode one untrusted canonical offer body.
    pub fn decode(encoded: &[u8]) -> Result<Self, CapabilityError> {
        if encoded.len() > MAX_CAPABILITY_OFFER_BODY_BYTES {
            return Err(CapabilityError::OfferTooLarge);
        }
        let mut reader = Lp8Reader::new(encoded);
        require_field(&mut reader, CAPABILITY_OFFER_DOMAIN)?;
        if read_u16(reader.field().map_err(CapabilityError::from_codec)?)?
            != CAPABILITY_SCHEMA_VERSION
        {
            return Err(CapabilityError::UnsupportedSchema);
        }
        let protocol_id = MigrationProtocolId::from_bytes(read_array(
            reader.field().map_err(CapabilityError::from_codec)?,
        )?);
        let chain_id = MigrationChainId::from_bytes(read_array(
            reader.field().map_err(CapabilityError::from_codec)?,
        )?);
        let session_id = MigrationSessionId(read_array(
            reader.field().map_err(CapabilityError::from_codec)?,
        )?);
        let sender_role = match read_byte(reader.field().map_err(CapabilityError::from_codec)?)? {
            1 => EndpointRole::Initiator,
            2 => EndpointRole::Responder,
            _ => return Err(CapabilityError::UnknownRole),
        };
        let sender_identity = MigrationIdentityKeyId(read_array(
            reader.field().map_err(CapabilityError::from_codec)?,
        )?);
        let receiver_identity = MigrationIdentityKeyId(read_array(
            reader.field().map_err(CapabilityError::from_codec)?,
        )?);
        let sender_nonce = MigrationNonce(read_array(
            reader.field().map_err(CapabilityError::from_codec)?,
        )?);
        let sender_policy_state =
            TrustedPolicyState::decode(reader.field().map_err(CapabilityError::from_codec)?)
                .map_err(|_| CapabilityError::InvalidPolicyState)?;
        let migration_state_digest = MigrationStateDigest::from_bytes(read_array(
            reader.field().map_err(CapabilityError::from_codec)?,
        )?);
        let global_generation = read_u64(reader.field().map_err(CapabilityError::from_codec)?)?;
        let offered_suites = MigrationSuiteSet::from_suites(&decode_suites(read_byte(
            reader.field().map_err(CapabilityError::from_codec)?,
        )?)?)
        .map_err(CapabilityError::State)?;
        let floor = SecurityFloor::from_nist_level(read_byte(
            reader.field().map_err(CapabilityError::from_codec)?,
        )?)
        .map_err(|_| CapabilityError::InvalidSecurityFloor)?;
        let mode = match read_byte(reader.field().map_err(CapabilityError::from_codec)?)? {
            1 => ComponentMode::HybridRequired,
            2 => ComponentMode::PostQuantumOnly,
            _ => return Err(CapabilityError::UnknownComponentMode),
        };
        let sender_key_share = KeyShareCommitment(read_array(
            reader.field().map_err(CapabilityError::from_codec)?,
        )?);
        reader.finish().map_err(CapabilityError::from_codec)?;
        if all_zero(protocol_id.as_bytes())
            || all_zero(chain_id.as_bytes())
            || all_zero(session_id.as_bytes())
            || all_zero(sender_identity.as_bytes())
            || all_zero(receiver_identity.as_bytes())
            || all_zero(sender_nonce.as_bytes())
            || all_zero(migration_state_digest.as_bytes())
            || all_zero(sender_key_share.as_bytes())
            || global_generation == 0
            || global_generation == u64::MAX
        {
            return Err(CapabilityError::ZeroIdentifier);
        }
        Ok(Self {
            protocol_id,
            chain_id,
            session_id,
            sender_role,
            sender_identity,
            receiver_identity,
            sender_nonce,
            sender_policy_state,
            migration_state_digest,
            global_generation,
            offered_suites,
            posture: MigrationSecurityPosture::new(floor, mode),
            sender_key_share,
        })
    }
}

/// Signed capability envelope received from one endpoint.
#[derive(Clone, Eq, PartialEq)]
pub struct SignedCapabilityOfferV1 {
    offer: CapabilityOfferV1,
    signature: Vec<u8>,
}

impl fmt::Debug for SignedCapabilityOfferV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignedCapabilityOfferV1([redacted])")
    }
}

impl SignedCapabilityOfferV1 {
    /// Sign an exact capability offer.
    ///
    /// `signature_output` must be exactly the selected backend's signature
    /// length. Success requires the backend to write the complete slice.
    pub fn sign<S: Signer>(
        offer: CapabilityOfferV1,
        signer: &S,
        signing_key: &[u8],
        randomness: &[u8],
        signature_output: &mut [u8],
    ) -> Result<Self, CapabilityError> {
        if signature_output.is_empty() || signature_output.len() > MAX_MIGRATION_SIGNATURE_BYTES {
            return Err(CapabilityError::InvalidSignatureLength);
        }
        let message = offer_signature_message(&offer)?;
        let written = signer
            .sign(signing_key, &message, randomness, signature_output)
            .map_err(|_| CapabilityError::SignatureFailure)?;
        if written != signature_output.len() {
            return Err(CapabilityError::InvalidSignatureLength);
        }
        let signature = signature_output
            .get(..written)
            .ok_or(CapabilityError::InvalidSignatureLength)?
            .to_vec();
        Ok(Self { offer, signature })
    }

    /// Encode body and signature as a strict LP8 envelope.
    pub fn encode(&self) -> Result<Vec<u8>, CapabilityError> {
        let body = self.offer.encode()?;
        encode_lp8_fields(&[&body, &self.signature]).map_err(CapabilityError::from_codec)
    }

    /// Strictly decode an untrusted signed-offer envelope.
    pub fn decode(encoded: &[u8]) -> Result<Self, CapabilityError> {
        let maximum = MAX_CAPABILITY_OFFER_BODY_BYTES
            .checked_add(MAX_MIGRATION_SIGNATURE_BYTES)
            .and_then(|value| value.checked_add(16))
            .ok_or(CapabilityError::OfferTooLarge)?;
        if encoded.len() > maximum {
            return Err(CapabilityError::OfferTooLarge);
        }
        let mut reader = Lp8Reader::new(encoded);
        let offer =
            CapabilityOfferV1::decode(reader.field().map_err(CapabilityError::from_codec)?)?;
        let signature = reader.field().map_err(CapabilityError::from_codec)?;
        if signature.is_empty() || signature.len() > MAX_MIGRATION_SIGNATURE_BYTES {
            return Err(CapabilityError::InvalidSignatureLength);
        }
        reader.finish().map_err(CapabilityError::from_codec)?;
        Ok(Self {
            offer,
            signature: signature.to_vec(),
        })
    }

    /// Verify the signature against one pinned sender identity.
    pub fn authenticate<V: Verifier>(
        &self,
        verifier: &V,
        verification_key: &[u8],
        expected_sender_identity: MigrationIdentityKeyId,
    ) -> Result<AuthenticatedCapabilityOfferV1, CapabilityError> {
        if self.offer.sender_identity != expected_sender_identity {
            return Err(CapabilityError::IdentityMismatch);
        }
        if verifier.algorithm().nist_level() < self.offer.posture.minimum_pq_level().to_u8() {
            return Err(CapabilityError::WeakSigner);
        }
        verifier
            .verify(
                verification_key,
                &offer_signature_message(&self.offer)?,
                &self.signature,
            )
            .map_err(|_| CapabilityError::SignatureFailure)?;
        Ok(AuthenticatedCapabilityOfferV1 { offer: self.offer })
    }
}

/// Capability offer whose exact bytes verified under a pinned identity key.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AuthenticatedCapabilityOfferV1 {
    offer: CapabilityOfferV1,
}

impl fmt::Debug for AuthenticatedCapabilityOfferV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthenticatedCapabilityOfferV1([redacted])")
    }
}

impl AuthenticatedCapabilityOfferV1 {
    /// Re-encode the exact canonical body whose signature was verified.
    pub fn canonical_body(&self) -> Result<Vec<u8>, CapabilityError> {
        self.offer.encode()
    }
}

/// Authenticated, role-ordered joint negotiation with a closed selected suite and floor.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AuthenticatedNegotiationV1 {
    initiator: CapabilityOfferV1,
    responder: CapabilityOfferV1,
    digest: AuthenticatedNegotiationDigest,
    execution: AuthenticatedResolvedSuite,
    effective_floor: SecurityFloor,
    component_mode: ComponentMode,
    state_revision: StateRevisionV1,
}

/// Exact local/peer inputs for one authenticated, role-ordered negotiation.
#[derive(Clone, Copy)]
pub struct AuthenticatedNegotiationInputV1<'a> {
    /// Role of the local endpoint invoking normalization.
    pub local_role: EndpointRole,
    /// Authenticated offer signed by the local endpoint.
    pub local_offer: AuthenticatedCapabilityOfferV1,
    /// Authenticated offer signed by the peer endpoint.
    pub peer_offer: AuthenticatedCapabilityOfferV1,
    /// Authenticated local endpoint policy.
    pub local_policy: &'a AuthenticatedPolicy,
    /// Authenticated peer endpoint policy.
    pub peer_policy: &'a AuthenticatedPolicy,
    /// Exact committed state named by both offers.
    pub committed_state: CommittedMigrationStateV1,
    /// Common authenticated execution decision resolved by both endpoint policies.
    pub execution: AuthenticatedResolvedSuite,
}

impl fmt::Debug for AuthenticatedNegotiationV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthenticatedNegotiationV1([redacted])")
    }
}

impl AuthenticatedNegotiationV1 {
    /// Normalize local/peer authenticated offers and bind them to policies, state, and execution.
    pub fn from_local_peer(
        input: AuthenticatedNegotiationInputV1<'_>,
    ) -> Result<Self, CapabilityError> {
        let AuthenticatedNegotiationInputV1 {
            local_role,
            local_offer: local,
            peer_offer: peer,
            local_policy,
            peer_policy,
            committed_state,
            execution,
        } = input;
        validate_committed_execution(committed_state, execution).map_err(CapabilityError::State)?;
        let (initiator, responder, initiator_policy, responder_policy) = match local_role {
            EndpointRole::Initiator => (local.offer, peer.offer, local_policy, peer_policy),
            EndpointRole::Responder => (peer.offer, local.offer, peer_policy, local_policy),
        };
        let initiator_projection =
            AuthenticatedEndpointPolicy::from_authenticated_policy(initiator_policy, execution)
                .map_err(|_| CapabilityError::EndpointPolicyRejected)?;
        let responder_projection =
            AuthenticatedEndpointPolicy::from_authenticated_policy(responder_policy, execution)
                .map_err(|_| CapabilityError::EndpointPolicyRejected)?;
        if initiator.sender_role != EndpointRole::Initiator
            || responder.sender_role != EndpointRole::Responder
        {
            return Err(CapabilityError::RoleMismatch);
        }
        if initiator.protocol_id != responder.protocol_id
            || initiator.chain_id != responder.chain_id
            || initiator.session_id != responder.session_id
            || initiator.receiver_identity != responder.sender_identity
            || responder.receiver_identity != initiator.sender_identity
        {
            return Err(CapabilityError::OfferMismatch);
        }
        if initiator.sender_identity == responder.sender_identity
            || initiator.sender_nonce == responder.sender_nonce
        {
            return Err(CapabilityError::ReflectionRisk);
        }
        let state = committed_state.state();
        let revision = committed_state.revision();
        for offer in [initiator, responder] {
            if offer.chain_id != state.chain_id()
                || offer.protocol_id != state.protocol_id()
                || offer.migration_state_digest != revision.digest()
                || offer.global_generation != revision.global_generation()
                || offer.posture.component_mode() != state.posture().component_mode()
            {
                return Err(CapabilityError::StateMismatch);
            }
        }
        let expected_initiator_posture = MigrationSecurityPosture::new(
            core::cmp::max(
                initiator_projection.security_floor(),
                state.posture().minimum_pq_level(),
            ),
            state.posture().component_mode(),
        );
        let expected_responder_posture = MigrationSecurityPosture::new(
            core::cmp::max(
                responder_projection.security_floor(),
                state.posture().minimum_pq_level(),
            ),
            state.posture().component_mode(),
        );
        if initiator.posture != expected_initiator_posture
            || responder.posture != expected_responder_posture
        {
            return Err(CapabilityError::PolicyMismatch);
        }
        if initiator.sender_policy_state != initiator_policy.trusted_state()
            || responder.sender_policy_state != responder_policy.trusted_state()
        {
            return Err(CapabilityError::PolicyMismatch);
        }
        let suite = execution.resolved().suite();
        if !initiator.offered_suites.contains(suite) || !responder.offered_suites.contains(suite) {
            return Err(CapabilityError::SuiteNotOffered);
        }
        let effective_floor = core::cmp::max(
            core::cmp::max(
                initiator_projection.security_floor(),
                responder_projection.security_floor(),
            ),
            state.posture().minimum_pq_level(),
        );
        if suite.nist_level() < effective_floor.to_u8() {
            return Err(CapabilityError::SuiteBelowFloor);
        }
        let digest = negotiation_digest(
            initiator,
            responder,
            execution,
            effective_floor,
            state.posture().component_mode(),
        )?;
        Ok(Self {
            initiator,
            responder,
            digest,
            execution,
            effective_floor,
            component_mode: state.posture().component_mode(),
            state_revision: revision,
        })
    }

    /// Return the joint authenticated negotiation digest.
    #[must_use]
    pub const fn digest(self) -> AuthenticatedNegotiationDigest {
        self.digest
    }

    /// Return the common selected execution decision.
    #[must_use]
    pub const fn execution(self) -> AuthenticatedResolvedSuite {
        self.execution
    }

    /// Return the effective state-and-endpoint floor.
    #[must_use]
    pub const fn effective_floor(self) -> SecurityFloor {
        self.effective_floor
    }

    /// Return the committed component mode.
    #[must_use]
    pub const fn component_mode(self) -> ComponentMode {
        self.component_mode
    }

    /// Return the exact committed state revision authenticated by both offers.
    #[must_use]
    pub const fn state_revision(self) -> StateRevisionV1 {
        self.state_revision
    }

    /// Return the common protocol identifier.
    #[must_use]
    pub const fn protocol_id(self) -> MigrationProtocolId {
        self.initiator.protocol_id
    }

    /// Return the common fresh session identifier.
    #[must_use]
    pub const fn session_id(self) -> MigrationSessionId {
        self.initiator.session_id
    }

    /// Return the commitment to the exact key share owned by `role`.
    #[must_use]
    pub const fn key_share_commitment(self, role: EndpointRole) -> KeyShareCommitment {
        match role {
            EndpointRole::Initiator => self.initiator.sender_key_share,
            EndpointRole::Responder => self.responder.sender_key_share,
        }
    }

    /// Return the initiator policy state.
    #[must_use]
    pub const fn initiator_policy_state(self) -> TrustedPolicyState {
        self.initiator.sender_policy_state
    }

    /// Return the responder policy state.
    #[must_use]
    pub const fn responder_policy_state(self) -> TrustedPolicyState {
        self.responder.sender_policy_state
    }
}

/// Capability decoding, authentication, or agreement failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CapabilityError {
    /// Canonical LP8 or fixed-width encoding was malformed.
    InvalidEncoding,
    /// An unsupported schema was supplied.
    UnsupportedSchema,
    /// A body exceeded its fixed resource bound.
    OfferTooLarge,
    /// A signature was empty or exceeded its bound.
    InvalidSignatureLength,
    /// A key share was empty or exceeded its bound.
    InvalidKeyShareLength,
    /// A required public identifier was all zero.
    ZeroIdentifier,
    /// An endpoint role code was unknown.
    UnknownRole,
    /// A component-mode code was unknown.
    UnknownComponentMode,
    /// A policy state was malformed.
    InvalidPolicyState,
    /// A security floor was not a closed NIST category.
    InvalidSecurityFloor,
    /// Signature creation or verification failed.
    SignatureFailure,
    /// The identity signer was below the offer floor.
    WeakSigner,
    /// The signed sender identity did not match the pinned key.
    IdentityMismatch,
    /// Offers did not normalize to initiator/responder roles.
    RoleMismatch,
    /// Common offer fields or reciprocal identities disagreed.
    OfferMismatch,
    /// Distinct endpoint roles reused an identity or fresh nonce.
    ReflectionRisk,
    /// An offer did not bind the committed state.
    StateMismatch,
    /// An offer did not bind its authenticated endpoint policy.
    PolicyMismatch,
    /// One endpoint did not offer the common selected suite.
    SuiteNotOffered,
    /// One authenticated endpoint policy rejected the common execution decision.
    EndpointPolicyRejected,
    /// The selected suite was below the effective floor.
    SuiteBelowFloor,
    /// The committed state rejected the execution decision.
    State(MigrationStateError),
}

impl CapabilityError {
    fn from_codec(_error: CodecError) -> Self {
        Self::InvalidEncoding
    }
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "migration capability rejected: {self:?}")
    }
}

impl std::error::Error for CapabilityError {}

fn offer_signature_message(offer: &CapabilityOfferV1) -> Result<Vec<u8>, CapabilityError> {
    let body = offer.encode()?;
    encode_lp8_fields(&[CAPABILITY_OFFER_SIGNATURE_DOMAIN, &body])
        .map_err(CapabilityError::from_codec)
}

fn negotiation_digest(
    initiator: CapabilityOfferV1,
    responder: CapabilityOfferV1,
    execution: AuthenticatedResolvedSuite,
    floor: SecurityFloor,
    mode: ComponentMode,
) -> Result<AuthenticatedNegotiationDigest, CapabilityError> {
    let initiator = initiator.encode()?;
    let responder = responder.encode()?;
    let execution_state = execution.trusted_state().encode();
    let suite = [execution.resolved().suite().to_u8()];
    let floor = [floor.to_u8()];
    let mode = [mode.to_u8()];
    Ok(AuthenticatedNegotiationDigest(hash_lp8(&[
        AUTHENTICATED_NEGOTIATION_DOMAIN,
        &initiator,
        &responder,
        &execution_state,
        &suite,
        &floor,
        &mode,
    ])?))
}

fn hash_lp8(fields: &[&[u8]]) -> Result<[u8; 32], CapabilityError> {
    let encoded = encode_lp8_fields(fields).map_err(CapabilityError::from_codec)?;
    Ok(Sha3_256::digest(encoded).into())
}

fn decode_suites(bits: u8) -> Result<Vec<q_periapt_policy::HybridSuite>, CapabilityError> {
    if bits == 0 || bits & !0b11 != 0 {
        return Err(CapabilityError::InvalidEncoding);
    }
    let mut suites = Vec::with_capacity(2);
    if bits & 1 != 0 {
        suites.push(q_periapt_policy::HybridSuite::MlKem768X25519);
    }
    if bits & 2 != 0 {
        suites.push(q_periapt_policy::HybridSuite::MlKem1024X25519);
    }
    Ok(suites)
}

fn require_field(reader: &mut Lp8Reader<'_>, expected: &[u8]) -> Result<(), CapabilityError> {
    if reader.field().map_err(CapabilityError::from_codec)? == expected {
        Ok(())
    } else {
        Err(CapabilityError::InvalidEncoding)
    }
}

fn read_array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], CapabilityError> {
    bytes
        .try_into()
        .map_err(|_| CapabilityError::InvalidEncoding)
}

fn read_u16(bytes: &[u8]) -> Result<u16, CapabilityError> {
    Ok(u16::from_be_bytes(read_array(bytes)?))
}

fn read_u64(bytes: &[u8]) -> Result<u64, CapabilityError> {
    Ok(u64::from_be_bytes(read_array(bytes)?))
}

fn read_byte(bytes: &[u8]) -> Result<u8, CapabilityError> {
    bytes
        .first()
        .copied()
        .filter(|_| bytes.len() == 1)
        .ok_or(CapabilityError::InvalidEncoding)
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
