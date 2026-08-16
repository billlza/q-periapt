//! Role-ordered mutual key confirmation and accepted-key derivation.

use core::{fmt, marker::PhantomData};

use q_periapt_core::{ct_eq, Secret, Xof256};

use crate::context_v2::{MigrationContextV2, MigrationContractError};
use crate::state::{ComponentMode, MigrationStateMachineV1, StateRevisionV1};
use crate::transcript::{PostKemTranscriptDigest, PostKemTranscriptV1};
use crate::EndpointRole;

/// Domain for role-separated Finished values.
pub const MIGRATION_FINISHED_DOMAIN: &[u8] = b"Q-PERIAPT-MIGRATION-FINISHED/v1";
/// Domain for the key released only after peer confirmation and state recheck.
pub const MIGRATION_ACCEPTED_KEY_DOMAIN: &[u8] = b"Q-PERIAPT-MIGRATION-ACCEPTED-KEY/v1";

/// Public Finished value issued only by the protocol initiator.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct InitiatorFinishedV1([u8; 32]);

impl InitiatorFinishedV1 {
    /// Decode an exact 32-byte initiator Finished value.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the exact initiator Finished bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for InitiatorFinishedV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InitiatorFinishedV1([redacted])")
    }
}

/// Public Finished value issued by the responder only after accepting the initiator Finished.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ResponderFinishedV1([u8; 32]);

impl ResponderFinishedV1 {
    /// Decode an exact 32-byte responder Finished value.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the exact responder Finished bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ResponderFinishedV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResponderFinishedV1([redacted])")
    }
}

struct ConfirmationMaterialV1<X: Xof256> {
    secret: Secret,
    post_kem_digest: PostKemTranscriptDigest,
    state_revision: StateRevisionV1,
    _xof: PhantomData<X>,
}

impl<X: Xof256> ConfirmationMaterialV1<X> {
    fn new(
        secret: Secret,
        context: &MigrationContextV2,
        post_kem: &PostKemTranscriptV1,
        expected_role: EndpointRole,
    ) -> Result<Self, ConfirmationError> {
        if context.local_role() != expected_role {
            return Err(ConfirmationError::RoleMismatch);
        }
        if context.component_mode() == ComponentMode::PostQuantumOnly {
            return Err(ConfirmationError::TraditionalComponentForbidden);
        }
        if context.state_revision() != post_kem.state_revision()
            || context.encapsulator_role() != post_kem.encapsulator_role()
            || context.digest().map_err(ConfirmationError::Contract)? != post_kem.context_digest()
        {
            return Err(ConfirmationError::TranscriptMismatch);
        }
        Ok(Self {
            secret,
            post_kem_digest: post_kem.digest(),
            state_revision: post_kem.state_revision(),
            _xof: PhantomData,
        })
    }

    fn ensure_current(
        &self,
        state_owner: &MigrationStateMachineV1,
    ) -> Result<(), ConfirmationError> {
        if state_owner.current_revision() == self.state_revision {
            Ok(())
        } else {
            Err(ConfirmationError::StaleState)
        }
    }

    fn derive_initiator_finished(&self) -> InitiatorFinishedV1 {
        InitiatorFinishedV1(derive_finished::<X>(
            &self.secret,
            EndpointRole::Initiator,
            self.post_kem_digest,
        ))
    }

    fn derive_responder_finished(&self) -> ResponderFinishedV1 {
        ResponderFinishedV1(derive_finished::<X>(
            &self.secret,
            EndpointRole::Responder,
            self.post_kem_digest,
        ))
    }

    fn derive_accepted_key(
        &self,
        initiator_finished: InitiatorFinishedV1,
        responder_finished: ResponderFinishedV1,
    ) -> AcceptedSessionKeyV1 {
        let accepted = derive_accepted_key::<X>(
            &self.secret,
            self.post_kem_digest,
            initiator_finished,
            responder_finished,
        );
        AcceptedSessionKeyV1 {
            secret: Secret::from_bytes(accepted),
            state_revision: self.state_revision,
        }
    }
}

impl<X: Xof256> fmt::Debug for ConfirmationMaterialV1<X> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConfirmationMaterialV1([redacted])")
    }
}

/// Initiator confirmation state before the initiator Finished has been issued.
pub struct InitiatorConfirmationV1<X: Xof256> {
    material: ConfirmationMaterialV1<X>,
}

impl<X: Xof256> fmt::Debug for InitiatorConfirmationV1<X> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InitiatorConfirmationV1([redacted])")
    }
}

impl<X: Xof256> InitiatorConfirmationV1<X> {
    /// Take ownership of an initiator ABI2 secret without exposing an accepted key.
    pub fn new(
        secret: Secret,
        context: &MigrationContextV2,
        post_kem: &PostKemTranscriptV1,
    ) -> Result<Self, ConfirmationError> {
        Ok(Self {
            material: ConfirmationMaterialV1::new(
                secret,
                context,
                post_kem,
                EndpointRole::Initiator,
            )?,
        })
    }

    /// Issue the initiator Finished and advance to the responder-waiting typestate.
    #[must_use]
    pub fn issue_finished(self) -> (InitiatorAwaitingResponderFinishedV1<X>, InitiatorFinishedV1) {
        let initiator_finished = self.material.derive_initiator_finished();
        (
            InitiatorAwaitingResponderFinishedV1 {
                material: self.material,
                initiator_finished,
            },
            initiator_finished,
        )
    }
}

/// Initiator state after issuing its Finished and before accepting the responder Finished.
pub struct InitiatorAwaitingResponderFinishedV1<X: Xof256> {
    material: ConfirmationMaterialV1<X>,
    initiator_finished: InitiatorFinishedV1,
}

impl<X: Xof256> fmt::Debug for InitiatorAwaitingResponderFinishedV1<X> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InitiatorAwaitingResponderFinishedV1([redacted])")
    }
}

impl<X: Xof256> InitiatorAwaitingResponderFinishedV1<X> {
    /// Recheck state, verify the responder Finished, and derive the accepted key.
    ///
    /// Every failure consumes this value, so the pending `Secret` is wiped on return.
    pub fn verify_and_accept(
        self,
        state_owner: &MigrationStateMachineV1,
        received_responder_finished: &ResponderFinishedV1,
    ) -> Result<AcceptedSessionKeyV1, ConfirmationError> {
        self.material.ensure_current(state_owner)?;
        let expected_responder_finished = self.material.derive_responder_finished();
        if ct_eq(
            expected_responder_finished.as_bytes(),
            received_responder_finished.as_bytes(),
        ) != 0xFF
        {
            return Err(ConfirmationError::PeerFinishedMismatch);
        }
        Ok(self
            .material
            .derive_accepted_key(self.initiator_finished, expected_responder_finished))
    }
}

/// Responder state waiting for the initiator Finished; no responder Finished exists yet.
pub struct ResponderAwaitingInitiatorFinishedV1<X: Xof256> {
    material: ConfirmationMaterialV1<X>,
}

impl<X: Xof256> fmt::Debug for ResponderAwaitingInitiatorFinishedV1<X> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResponderAwaitingInitiatorFinishedV1([redacted])")
    }
}

impl<X: Xof256> ResponderAwaitingInitiatorFinishedV1<X> {
    /// Take ownership of a responder ABI2 secret without issuing a Finished value.
    pub fn new(
        secret: Secret,
        context: &MigrationContextV2,
        post_kem: &PostKemTranscriptV1,
    ) -> Result<Self, ConfirmationError> {
        Ok(Self {
            material: ConfirmationMaterialV1::new(
                secret,
                context,
                post_kem,
                EndpointRole::Responder,
            )?,
        })
    }

    /// Recheck state, accept the initiator Finished, and only then issue the responder Finished.
    ///
    /// Every failure consumes this value, so neither a responder Finished nor an accepted key is
    /// returned and the pending `Secret` is wiped on return.
    pub fn verify_accept_and_issue_finished(
        self,
        state_owner: &MigrationStateMachineV1,
        received_initiator_finished: &InitiatorFinishedV1,
    ) -> Result<(AcceptedSessionKeyV1, ResponderFinishedV1), ConfirmationError> {
        self.material.ensure_current(state_owner)?;
        let expected_initiator_finished = self.material.derive_initiator_finished();
        if ct_eq(
            expected_initiator_finished.as_bytes(),
            received_initiator_finished.as_bytes(),
        ) != 0xFF
        {
            return Err(ConfirmationError::PeerFinishedMismatch);
        }
        let responder_finished = self.material.derive_responder_finished();
        let accepted = self
            .material
            .derive_accepted_key(expected_initiator_finished, responder_finished);
        Ok((accepted, responder_finished))
    }
}

/// Application secret released only after the accepted-session predicate succeeds.
pub struct AcceptedSessionKeyV1 {
    secret: Secret,
    state_revision: StateRevisionV1,
}

impl fmt::Debug for AcceptedSessionKeyV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AcceptedSessionKeyV1([redacted])")
    }
}

impl AcceptedSessionKeyV1 {
    /// Borrow the accepted secret.
    #[must_use]
    pub const fn secret(&self) -> &Secret {
        &self.secret
    }

    /// Return the exact committed state revision bound to this accepted key.
    #[must_use]
    pub const fn state_revision(&self) -> StateRevisionV1 {
        self.state_revision
    }

    /// Transfer ownership of the accepted zeroizing secret.
    #[must_use]
    pub fn into_secret(self) -> Secret {
        self.secret
    }
}

/// Key-confirmation or acceptance failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ConfirmationError {
    /// A role-specific constructor received the opposite endpoint's context.
    RoleMismatch,
    /// Context and post-KEM transcript did not belong to one snapshot.
    TranscriptMismatch,
    /// Frozen hybrid execution is forbidden by a PQ-only state.
    TraditionalComponentForbidden,
    /// The state advanced after KEM and before acceptance.
    StaleState,
    /// The role-separated peer Finished did not verify.
    PeerFinishedMismatch,
    /// Contract construction failed before confirmation.
    Contract(MigrationContractError),
}

impl fmt::Display for ConfirmationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "migration confirmation rejected: {self:?}")
    }
}

impl std::error::Error for ConfirmationError {}

fn derive_finished<X: Xof256>(
    secret: &Secret,
    sender_role: EndpointRole,
    post_kem_digest: PostKemTranscriptDigest,
) -> [u8; 32] {
    let role = [sender_role as u8];
    let mut xof = X::new();
    let reserve = lp8_extent(MIGRATION_FINISHED_DOMAIN.len())
        + lp8_extent(secret.as_bytes().len())
        + lp8_extent(role.len())
        + lp8_extent(post_kem_digest.as_bytes().len());
    xof.reserve(reserve);
    absorb_public_lp8(&mut xof, MIGRATION_FINISHED_DOMAIN);
    absorb_secret_lp8(&mut xof, secret.as_bytes());
    absorb_public_lp8(&mut xof, &role);
    absorb_public_lp8(&mut xof, post_kem_digest.as_bytes());
    xof.squeeze32()
}

fn derive_accepted_key<X: Xof256>(
    secret: &Secret,
    post_kem_digest: PostKemTranscriptDigest,
    initiator_finished: InitiatorFinishedV1,
    responder_finished: ResponderFinishedV1,
) -> [u8; 32] {
    let mut xof = X::new();
    let reserve = lp8_extent(MIGRATION_ACCEPTED_KEY_DOMAIN.len())
        + lp8_extent(secret.as_bytes().len())
        + lp8_extent(post_kem_digest.as_bytes().len())
        + lp8_extent(initiator_finished.as_bytes().len())
        + lp8_extent(responder_finished.as_bytes().len());
    xof.reserve(reserve);
    absorb_public_lp8(&mut xof, MIGRATION_ACCEPTED_KEY_DOMAIN);
    absorb_secret_lp8(&mut xof, secret.as_bytes());
    absorb_public_lp8(&mut xof, post_kem_digest.as_bytes());
    absorb_public_lp8(&mut xof, initiator_finished.as_bytes());
    absorb_public_lp8(&mut xof, responder_finished.as_bytes());
    xof.squeeze32()
}

fn absorb_public_lp8<X: Xof256>(xof: &mut X, value: &[u8]) {
    xof.absorb_public(&(value.len() as u64).to_be_bytes());
    xof.absorb_public(value);
}

fn absorb_secret_lp8<X: Xof256>(xof: &mut X, value: &[u8]) {
    xof.absorb_public(&(value.len() as u64).to_be_bytes());
    xof.absorb_secret(value);
}

const fn lp8_extent(length: usize) -> usize {
    8 + length
}
