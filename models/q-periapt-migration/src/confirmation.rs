//! Role-separated mutual key confirmation and accepted-key derivation.

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

/// Public role-separated key-confirmation value.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct MigrationFinishedV1([u8; 32]);

impl MigrationFinishedV1 {
    /// Decode an exact 32-byte peer Finished value.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the exact Finished bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for MigrationFinishedV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MigrationFinishedV1([redacted])")
    }
}

/// A KEM secret that has not yet emitted a local Finished or authenticated its peer.
pub struct PendingMutualConfirmationV1<X: Xof256> {
    secret: Secret,
    local_role: EndpointRole,
    post_kem_digest: PostKemTranscriptDigest,
    state_revision: StateRevisionV1,
    _xof: PhantomData<X>,
}

impl<X: Xof256> fmt::Debug for PendingMutualConfirmationV1<X> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PendingMutualConfirmationV1([redacted])")
    }
}

impl<X: Xof256> PendingMutualConfirmationV1<X> {
    /// Take ownership of an ABI2 secret without exposing an accepted application key.
    pub fn new(
        secret: Secret,
        context: &MigrationContextV2,
        post_kem: &PostKemTranscriptV1,
    ) -> Result<Self, ConfirmationError> {
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
            local_role: context.local_role(),
            post_kem_digest: post_kem.digest(),
            state_revision: post_kem.state_revision(),
            _xof: PhantomData,
        })
    }

    /// Emit the local role-separated Finished and advance the typestate.
    #[must_use]
    pub fn issue_local_finished(self) -> (IssuedLocalFinishedV1<X>, MigrationFinishedV1) {
        let finished = derive_finished::<X>(&self.secret, self.local_role, self.post_kem_digest);
        (
            IssuedLocalFinishedV1 {
                secret: self.secret,
                local_role: self.local_role,
                post_kem_digest: self.post_kem_digest,
                state_revision: self.state_revision,
                local_finished: finished,
                _xof: PhantomData,
            },
            finished,
        )
    }
}

/// Pending secret after the local Finished has been fixed but before peer confirmation.
pub struct IssuedLocalFinishedV1<X: Xof256> {
    secret: Secret,
    local_role: EndpointRole,
    post_kem_digest: PostKemTranscriptDigest,
    state_revision: StateRevisionV1,
    local_finished: MigrationFinishedV1,
    _xof: PhantomData<X>,
}

impl<X: Xof256> fmt::Debug for IssuedLocalFinishedV1<X> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IssuedLocalFinishedV1([redacted])")
    }
}

impl<X: Xof256> IssuedLocalFinishedV1<X> {
    /// Verify the peer Finished in constant time, recheck the exact current state, and derive K.
    ///
    /// Every failure consumes this value, so the pending `Secret` is wiped on return.
    pub fn verify_peer_and_accept(
        self,
        state_owner: &MigrationStateMachineV1,
        received_peer_finished: &MigrationFinishedV1,
    ) -> Result<AcceptedSessionKeyV1, ConfirmationError> {
        if state_owner.current_revision() != self.state_revision {
            return Err(ConfirmationError::StaleState);
        }
        let peer_role = opposite(self.local_role);
        let expected = derive_finished::<X>(&self.secret, peer_role, self.post_kem_digest);
        if ct_eq(expected.as_bytes(), received_peer_finished.as_bytes()) != 0xFF {
            return Err(ConfirmationError::PeerFinishedMismatch);
        }
        let (initiator_finished, responder_finished) = match self.local_role {
            EndpointRole::Initiator => (self.local_finished, expected),
            EndpointRole::Responder => (expected, self.local_finished),
        };
        let accepted = derive_accepted_key::<X>(
            &self.secret,
            self.post_kem_digest,
            initiator_finished,
            responder_finished,
        );
        Ok(AcceptedSessionKeyV1 {
            secret: Secret::from_bytes(accepted),
            state_revision: self.state_revision,
        })
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
) -> MigrationFinishedV1 {
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
    MigrationFinishedV1(xof.squeeze32())
}

fn derive_accepted_key<X: Xof256>(
    secret: &Secret,
    post_kem_digest: PostKemTranscriptDigest,
    initiator_finished: MigrationFinishedV1,
    responder_finished: MigrationFinishedV1,
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

const fn opposite(role: EndpointRole) -> EndpointRole {
    match role {
        EndpointRole::Initiator => EndpointRole::Responder,
        EndpointRole::Responder => EndpointRole::Initiator,
    }
}
