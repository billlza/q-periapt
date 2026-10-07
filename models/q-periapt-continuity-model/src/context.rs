//! Candidate canonical bytes for authenticated Continuity lifecycle context.
//!
//! This module is intentionally dependency-free and non-normative. It fixes one
//! candidate byte projection for the test-only lifecycle model; it does not
//! authenticate credentials, directory checkpoints, prekeys, or transcripts.

use crate::codec::{CodecError, LpWriter};
use crate::commitments::{
    AccountId, ContextDigest, DeviceEpoch, DeviceId, DirectoryCheckpointDigest,
    IdentityCredentialDigest, PolicyDigest, ProtocolId, RatchetEpoch, RosterDigest, RosterVersion,
    SessionId, SuiteDigest, TranscriptDigest, WireVersion,
};
use crate::prekey::{CanonicalPrekeySelection, PrekeyContext};

/// Domain used by the existing signed-policy context wrapper.
pub const POLICY_CONTEXT_DOMAIN: &[u8] = b"Q-PERIAPT-POLICY-CONTEXT/v1";
/// Domain for the candidate lifecycle body.
pub const LIFECYCLE_CONTEXT_DOMAIN: &[u8] = b"Q-PERIAPT-CONTINUITY-LIFECYCLE/v1";
/// Domain for the durable fixed-width context digest preimage.
pub const CONTEXT_DIGEST_DOMAIN: &[u8] = b"Q-PERIAPT-CONTINUITY-CONTEXT-DIGEST/v1";
/// Candidate lifecycle-context schema version.
pub const LIFECYCLE_CONTEXT_SCHEMA_VERSION: u16 = 1;
/// Exact encoded bootstrap lifecycle-body length.
pub const BOOTSTRAP_BODY_LEN: usize = 666;
/// Exact encoded root-transition lifecycle-body length.
pub const ROOT_TRANSITION_BODY_LEN: usize = 626;
/// Exact policy-bound bootstrap K-CTX length.
pub const BOOTSTRAP_POLICY_BOUND_KCTX_LEN: usize = 749;
/// Exact policy-bound root-transition K-CTX length.
pub const ROOT_TRANSITION_POLICY_BOUND_KCTX_LEN: usize = 709;
/// Exact bootstrap context-digest preimage length.
pub const BOOTSTRAP_DIGEST_PREIMAGE_LEN: usize = 803;
/// Exact root-transition context-digest preimage length.
pub const ROOT_TRANSITION_DIGEST_PREIMAGE_LEN: usize = 763;

const MAX_BODY_LEN: usize = BOOTSTRAP_BODY_LEN;
const MAX_POLICY_BOUND_KCTX_LEN: usize = BOOTSTRAP_POLICY_BOUND_KCTX_LEN;
const MAX_DIGEST_PREIMAGE_LEN: usize = BOOTSTRAP_DIGEST_PREIMAGE_LEN;

/// Accountable-versus-deniable identity semantics selected by closed policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum IdentityMode {
    /// Transferable, accountable device identity semantics.
    Accountable = 1,
    /// A separately specified deniable identity profile.
    Deniable = 2,
}

/// Canonical traffic direction relative to fixed initiator/responder roles.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Direction {
    /// The session initiator is the sender for this context.
    InitiatorToResponder = 1,
    /// The session responder is the sender for this context.
    ResponderToInitiator = 2,
}

/// Peer-agreed authentication stage; local delivery state is deliberately absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AuthenticationStage {
    /// Offline credentials and the selected prekey bundle are authenticated.
    PrekeyAuthenticated = 1,
    /// The peer supplied a fresh confirmation for the transcript.
    PeerConfirmed = 2,
    /// Both roles supplied the profile-required fresh confirmation.
    MutuallyConfirmed = 3,
}

/// Root-transition components that advance in one context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RootTransitionKind {
    /// Root and classical DH epochs advance; the PQ epoch is unchanged.
    Dh = 1,
    /// Root and PQ epochs advance; the classical DH epoch is unchanged.
    Pq = 2,
    /// Root, classical DH, and PQ epochs all advance.
    Hybrid = 3,
}

/// Stable protocol and pairwise-session identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextProtocol {
    protocol_id: ProtocolId,
    wire_version: WireVersion,
    suite_digest: SuiteDigest,
    session_id: SessionId,
}

impl ContextProtocol {
    /// Construct the stable protocol projection.
    #[must_use]
    pub const fn new(
        protocol_id: ProtocolId,
        wire_version: WireVersion,
        suite_digest: SuiteDigest,
        session_id: SessionId,
    ) -> Self {
        Self {
            protocol_id,
            wire_version,
            suite_digest,
            session_id,
        }
    }
}

/// One role-ordered authenticated account/device identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextParty {
    account_id: AccountId,
    device_id: DeviceId,
    device_epoch: DeviceEpoch,
    identity_credential_digest: IdentityCredentialDigest,
}

impl ContextParty {
    /// Construct one role-ordered identity projection.
    #[must_use]
    pub const fn new(
        account_id: AccountId,
        device_id: DeviceId,
        device_epoch: DeviceEpoch,
        identity_credential_digest: IdentityCredentialDigest,
    ) -> Self {
        Self {
            account_id,
            device_id,
            device_epoch,
            identity_credential_digest,
        }
    }
}

/// Fixed initiator/responder identities and peer-agreed semantic stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextRoles {
    initiator: ContextParty,
    responder: ContextParty,
    identity_mode: IdentityMode,
    direction: Direction,
    authentication_stage: AuthenticationStage,
}

impl ContextRoles {
    /// Construct the role-ordered semantic projection.
    #[must_use]
    pub const fn new(
        initiator: ContextParty,
        responder: ContextParty,
        identity_mode: IdentityMode,
        direction: Direction,
        authentication_stage: AuthenticationStage,
    ) -> Self {
        Self {
            initiator,
            responder,
            identity_mode,
            direction,
            authentication_stage,
        }
    }

    /// Return the peer-agreed authentication stage.
    #[must_use]
    pub const fn authentication_stage(self) -> AuthenticationStage {
        self.authentication_stage
    }
}

/// Fields shared by bootstrap and root-transition contexts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommonContext {
    protocol: ContextProtocol,
    roles: ContextRoles,
}

impl CommonContext {
    /// Construct the common projection.
    #[must_use]
    pub const fn new(protocol: ContextProtocol, roles: ContextRoles) -> Self {
        Self { protocol, roles }
    }

    /// Return the peer-agreed authentication stage.
    #[must_use]
    pub const fn authentication_stage(self) -> AuthenticationStage {
        self.roles.authentication_stage()
    }
}

/// Verified roster and directory commitments used at bootstrap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryContext {
    roster_version: RosterVersion,
    roster_digest: RosterDigest,
    directory_checkpoint_digest: DirectoryCheckpointDigest,
}

impl DirectoryContext {
    /// Construct the directory projection.
    #[must_use]
    pub const fn new(
        roster_version: RosterVersion,
        roster_digest: RosterDigest,
        directory_checkpoint_digest: DirectoryCheckpointDigest,
    ) -> Self {
        Self {
            roster_version,
            roster_digest,
            directory_checkpoint_digest,
        }
    }
}

/// Candidate bootstrap context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapContext {
    common: CommonContext,
    directory: DirectoryContext,
    prekey: PrekeyContext,
    key_schedule_transcript_digest: TranscriptDigest,
}

impl BootstrapContext {
    /// Construct a bootstrap context from one indivisible canonical selection.
    ///
    /// Suite, responder identity, directory checkpoint, and bootstrap direction
    /// are cross-checked before the full selection record is reduced to B21-B23.
    pub fn new(
        common: CommonContext,
        directory: DirectoryContext,
        canonical_prekey: CanonicalPrekeySelection,
        key_schedule_transcript_digest: TranscriptDigest,
    ) -> Result<Self, ContextEncodingError> {
        let record = canonical_prekey.record();
        if common.roles.direction != Direction::InitiatorToResponder {
            return Err(ContextEncodingError::InvalidBootstrapDirection);
        }
        if common.protocol.suite_digest != record.suite_digest() {
            return Err(ContextEncodingError::PrekeySuiteMismatch);
        }
        let responder = record.responder();
        if common.roles.responder.account_id != responder.account_id()
            || common.roles.responder.device_id != responder.device_id()
            || common.roles.responder.device_epoch != responder.device_epoch()
            || common.roles.responder.identity_credential_digest
                != responder.identity_credential_digest()
        {
            return Err(ContextEncodingError::PrekeyResponderMismatch);
        }
        if directory.directory_checkpoint_digest != record.directory_checkpoint_digest() {
            return Err(ContextEncodingError::PrekeyDirectoryMismatch);
        }
        Ok(Self {
            common,
            directory,
            prekey: PrekeyContext::from_canonical(canonical_prekey),
            key_schedule_transcript_digest,
        })
    }
}

/// Prior and next values for root, classical-DH, and PQ ratchets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootEpochs {
    prior_root: RatchetEpoch,
    next_root: RatchetEpoch,
    prior_dh: RatchetEpoch,
    next_dh: RatchetEpoch,
    prior_pq: RatchetEpoch,
    next_pq: RatchetEpoch,
}

impl RootEpochs {
    /// Construct the complete epoch transition.
    #[must_use]
    pub const fn new(
        root: (RatchetEpoch, RatchetEpoch),
        dh: (RatchetEpoch, RatchetEpoch),
        pq: (RatchetEpoch, RatchetEpoch),
    ) -> Self {
        Self {
            prior_root: root.0,
            next_root: root.1,
            prior_dh: dh.0,
            next_dh: dh.1,
            prior_pq: pq.0,
            next_pq: pq.1,
        }
    }
}

/// Candidate root-transition context.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RootTransitionContext {
    common: CommonContext,
    kind: RootTransitionKind,
    prior_context_digest: ContextDigest,
    epochs: RootEpochs,
    transition_transcript_digest: TranscriptDigest,
}

impl RootTransitionContext {
    /// Construct a root-transition context. Validation occurs before encoding.
    #[must_use]
    pub const fn new(
        common: CommonContext,
        kind: RootTransitionKind,
        prior_context_digest: ContextDigest,
        epochs: RootEpochs,
        transition_transcript_digest: TranscriptDigest,
    ) -> Self {
        Self {
            common,
            kind,
            prior_context_digest,
            epochs,
            transition_transcript_digest,
        }
    }
}

/// Closed candidate context variants for bootstrap and root transitions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleContextV1 {
    /// Initial asynchronous bootstrap context.
    Bootstrap(BootstrapContext),
    /// A post-confirmation root-transition context.
    RootTransition(RootTransitionContext),
}

/// Canonical lifecycle preimage, its signed-policy identity, and derived digest.
///
/// Construction is available only through
/// [`LifecycleContextV1::derive_authenticated_context_with`], so callers cannot
/// independently select a lifecycle body and digest. The digest adapter and every
/// commitment inside the lifecycle body remain explicit trusted inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthenticatedContext {
    lifecycle_context: LifecycleContextV1,
    policy_digest: PolicyDigest,
    digest: ContextDigest,
}

impl AuthenticatedContext {
    /// Return the canonical candidate lifecycle context.
    #[must_use]
    pub const fn lifecycle_context(self) -> LifecycleContextV1 {
        self.lifecycle_context
    }

    /// Return the exact authenticated signed-policy commitment used by K-CTX.
    #[must_use]
    pub const fn policy_digest(self) -> PolicyDigest {
        self.policy_digest
    }

    /// Return the peer-agreed authentication stage derived from the context.
    #[must_use]
    pub const fn stage(self) -> AuthenticationStage {
        self.lifecycle_context.authentication_stage()
    }

    /// Return the adapter-derived durable context digest.
    #[must_use]
    pub const fn digest(self) -> ContextDigest {
        self.digest
    }
}

/// Typed failure from candidate context validation or encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextEncodingError {
    /// An output buffer was not exactly the canonical length.
    InvalidOutputLength,
    /// A required identifier or commitment used the all-zero unset sentinel.
    ZeroField,
    /// Protocol wire version zero is reserved.
    InvalidWireVersion,
    /// A device or roster epoch is outside the candidate valid range.
    InvalidMonotonicValue,
    /// Initiator and responder resolve to the same logical account/device.
    SameParty,
    /// The authentication stage is invalid for the selected context variant.
    InvalidAuthenticationStage,
    /// Bootstrap always projects an initiator selection of responder prekeys.
    InvalidBootstrapDirection,
    /// The canonical selection names a different closed protocol suite.
    PrekeySuiteMismatch,
    /// The canonical selection names a different responder identity scope.
    PrekeyResponderMismatch,
    /// The canonical selection names a different verified directory checkpoint.
    PrekeyDirectoryMismatch,
    /// Root/DH/PQ epoch movement does not match the closed transition kind.
    InvalidEpochAdvance,
}

impl From<CodecError> for ContextEncodingError {
    fn from(_: CodecError) -> Self {
        Self::InvalidOutputLength
    }
}

/// Failure while deriving a fixed-width digest through a trusted adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ContextDigestError<E> {
    /// Canonical context validation or encoding failed.
    Encoding(ContextEncodingError),
    /// The explicit digest adapter failed.
    Backend(E),
    /// The adapter returned the all-zero unset sentinel.
    ZeroDigest,
}

impl LifecycleContextV1 {
    /// Return the exact lifecycle-body length for this variant.
    #[must_use]
    pub const fn body_len(self) -> usize {
        match self {
            Self::Bootstrap(_) => BOOTSTRAP_BODY_LEN,
            Self::RootTransition(_) => ROOT_TRANSITION_BODY_LEN,
        }
    }

    /// Return the exact policy-bound K-CTX length for this variant.
    #[must_use]
    pub const fn policy_bound_kctx_len(self) -> usize {
        match self {
            Self::Bootstrap(_) => BOOTSTRAP_POLICY_BOUND_KCTX_LEN,
            Self::RootTransition(_) => ROOT_TRANSITION_POLICY_BOUND_KCTX_LEN,
        }
    }

    /// Return the exact context-digest preimage length for this variant.
    #[must_use]
    pub const fn digest_preimage_len(self) -> usize {
        match self {
            Self::Bootstrap(_) => BOOTSTRAP_DIGEST_PREIMAGE_LEN,
            Self::RootTransition(_) => ROOT_TRANSITION_DIGEST_PREIMAGE_LEN,
        }
    }

    /// Return the peer-agreed authentication stage.
    #[must_use]
    pub const fn authentication_stage(self) -> AuthenticationStage {
        match self {
            Self::Bootstrap(context) => context.common.authentication_stage(),
            Self::RootTransition(context) => context.common.authentication_stage(),
        }
    }

    /// Return the protocol identifier committed by this context.
    #[must_use]
    pub const fn protocol_id(self) -> ProtocolId {
        self.common().protocol.protocol_id
    }

    /// Return the protocol wire version committed by this context.
    #[must_use]
    pub const fn wire_version(self) -> WireVersion {
        self.common().protocol.wire_version
    }

    /// Return the pairwise session identifier committed by this context.
    #[must_use]
    pub const fn session_id(self) -> SessionId {
        self.common().protocol.session_id
    }

    /// Return the fixed initiator device identifier.
    #[must_use]
    pub const fn initiator_device_id(self) -> DeviceId {
        self.common().roles.initiator.device_id
    }

    /// Return the fixed responder device identifier.
    #[must_use]
    pub const fn responder_device_id(self) -> DeviceId {
        self.common().roles.responder.device_id
    }

    /// Return whether an unordered local/peer device pair matches the fixed roles.
    #[must_use]
    pub fn contains_device_pair(self, first: DeviceId, second: DeviceId) -> bool {
        (self.initiator_device_id() == first && self.responder_device_id() == second)
            || (self.initiator_device_id() == second && self.responder_device_id() == first)
    }

    /// Validate the candidate semantic invariants.
    pub fn validate(self) -> Result<(), ContextEncodingError> {
        match self {
            Self::Bootstrap(context) => {
                validate_common(context.common)?;
                if context.common.authentication_stage() != AuthenticationStage::PrekeyAuthenticated
                {
                    return Err(ContextEncodingError::InvalidAuthenticationStage);
                }
                validate_monotonic(context.directory.roster_version.get())?;
                for value in [
                    context.directory.roster_digest.as_bytes().as_slice(),
                    context
                        .directory
                        .directory_checkpoint_digest
                        .as_bytes()
                        .as_slice(),
                    context
                        .prekey
                        .signed_manifest_digest()
                        .as_bytes()
                        .as_slice(),
                    context.prekey.selection_digest().as_bytes().as_slice(),
                    context.key_schedule_transcript_digest.as_bytes().as_slice(),
                ] {
                    require_nonzero(value)?;
                }
                Ok(())
            }
            Self::RootTransition(context) => {
                validate_common(context.common)?;
                if context.common.authentication_stage() == AuthenticationStage::PrekeyAuthenticated
                {
                    return Err(ContextEncodingError::InvalidAuthenticationStage);
                }
                require_nonzero(context.prior_context_digest.as_bytes())?;
                require_nonzero(context.transition_transcript_digest.as_bytes())?;
                validate_root_epochs(context.kind, context.epochs)
            }
        }
    }

    /// Encode only the candidate lifecycle body.
    pub fn encode_body(self, out: &mut [u8]) -> Result<usize, ContextEncodingError> {
        self.validate()?;
        if out.len() != self.body_len() {
            return Err(ContextEncodingError::InvalidOutputLength);
        }
        let mut writer = LpWriter::new(out);
        match self {
            Self::Bootstrap(context) => {
                write_common(&mut writer, 1, context.common)?;
                writer.field(&context.directory.roster_version.get().to_be_bytes())?;
                writer.field(context.directory.roster_digest.as_bytes())?;
                writer.field(context.directory.directory_checkpoint_digest.as_bytes())?;
                writer.field(&[context.prekey.quality() as u8])?;
                writer.field(context.prekey.signed_manifest_digest().as_bytes())?;
                writer.field(context.prekey.selection_digest().as_bytes())?;
                writer.field(context.key_schedule_transcript_digest.as_bytes())?;
            }
            Self::RootTransition(context) => {
                write_common(&mut writer, 2, context.common)?;
                writer.field(&[context.kind as u8])?;
                writer.field(context.prior_context_digest.as_bytes())?;
                writer.field(&context.epochs.prior_root.get().to_be_bytes())?;
                writer.field(&context.epochs.next_root.get().to_be_bytes())?;
                writer.field(&context.epochs.prior_dh.get().to_be_bytes())?;
                writer.field(&context.epochs.next_dh.get().to_be_bytes())?;
                writer.field(&context.epochs.prior_pq.get().to_be_bytes())?;
                writer.field(&context.epochs.next_pq.get().to_be_bytes())?;
                writer.field(context.transition_transcript_digest.as_bytes())?;
            }
        }
        if !writer.is_empty() {
            return Err(ContextEncodingError::InvalidOutputLength);
        }
        Ok(out.len())
    }

    /// Encode the exact signed-policy wrapper consumed as KEM application context.
    pub fn encode_policy_bound_kctx(
        self,
        policy_digest: PolicyDigest,
        out: &mut [u8],
    ) -> Result<usize, ContextEncodingError> {
        self.validate()?;
        require_nonzero(policy_digest.as_bytes())?;
        if out.len() != self.policy_bound_kctx_len() {
            return Err(ContextEncodingError::InvalidOutputLength);
        }
        let mut body = [0u8; MAX_BODY_LEN];
        let body_len = self.body_len();
        self.encode_body(
            body.get_mut(..body_len)
                .ok_or(ContextEncodingError::InvalidOutputLength)?,
        )?;
        let mut writer = LpWriter::new(out);
        writer.field(POLICY_CONTEXT_DOMAIN)?;
        writer.field(policy_digest.as_bytes())?;
        writer.field(
            body.get(..body_len)
                .ok_or(ContextEncodingError::InvalidOutputLength)?,
        )?;
        if !writer.is_empty() {
            return Err(ContextEncodingError::InvalidOutputLength);
        }
        Ok(out.len())
    }

    /// Encode the exact domain-separated preimage used for the durable context digest.
    pub fn encode_digest_preimage(
        self,
        policy_digest: PolicyDigest,
        out: &mut [u8],
    ) -> Result<usize, ContextEncodingError> {
        if out.len() != self.digest_preimage_len() {
            return Err(ContextEncodingError::InvalidOutputLength);
        }
        let mut full = [0u8; MAX_POLICY_BOUND_KCTX_LEN];
        let full_len = self.policy_bound_kctx_len();
        self.encode_policy_bound_kctx(
            policy_digest,
            full.get_mut(..full_len)
                .ok_or(ContextEncodingError::InvalidOutputLength)?,
        )?;
        let mut writer = LpWriter::new(out);
        writer.field(CONTEXT_DIGEST_DOMAIN)?;
        writer.field(
            full.get(..full_len)
                .ok_or(ContextEncodingError::InvalidOutputLength)?,
        )?;
        if !writer.is_empty() {
            return Err(ContextEncodingError::InvalidOutputLength);
        }
        Ok(out.len())
    }

    /// Derive the durable digest through an explicit trusted, fallible adapter.
    ///
    /// The callback must implement the approved digest algorithm over the complete
    /// bytes supplied here. This model cannot authenticate that adapter or prove
    /// that the input commitments were produced by valid credentials.
    pub fn derive_digest_with<E, F>(
        self,
        policy_digest: PolicyDigest,
        derive: F,
    ) -> Result<ContextDigest, ContextDigestError<E>>
    where
        F: FnOnce(&[u8]) -> Result<[u8; 32], E>,
    {
        let mut preimage = [0u8; MAX_DIGEST_PREIMAGE_LEN];
        let preimage_len = self.digest_preimage_len();
        self.encode_digest_preimage(
            policy_digest,
            preimage
                .get_mut(..preimage_len)
                .ok_or(ContextDigestError::Encoding(
                    ContextEncodingError::InvalidOutputLength,
                ))?,
        )
        .map_err(ContextDigestError::Encoding)?;
        let digest = derive(
            preimage
                .get(..preimage_len)
                .ok_or(ContextDigestError::Encoding(
                    ContextEncodingError::InvalidOutputLength,
                ))?,
        )
        .map_err(ContextDigestError::Backend)?;
        if all_zero(&digest) {
            return Err(ContextDigestError::ZeroDigest);
        }
        Ok(ContextDigest::from_bytes(digest))
    }

    /// Construct one indivisible authenticated-context candidate through the
    /// canonical preimage and an explicit trusted digest adapter.
    pub fn derive_authenticated_context_with<E, F>(
        self,
        policy_digest: PolicyDigest,
        derive: F,
    ) -> Result<AuthenticatedContext, ContextDigestError<E>>
    where
        F: FnOnce(&[u8]) -> Result<[u8; 32], E>,
    {
        let digest = self.derive_digest_with(policy_digest, derive)?;
        Ok(AuthenticatedContext {
            lifecycle_context: self,
            policy_digest,
            digest,
        })
    }

    const fn common(self) -> CommonContext {
        match self {
            Self::Bootstrap(context) => context.common,
            Self::RootTransition(context) => context.common,
        }
    }
}

fn validate_common(common: CommonContext) -> Result<(), ContextEncodingError> {
    require_nonzero(common.protocol.protocol_id.as_bytes())?;
    if common.protocol.wire_version.get() == 0 {
        return Err(ContextEncodingError::InvalidWireVersion);
    }
    require_nonzero(common.protocol.suite_digest.as_bytes())?;
    require_nonzero(common.protocol.session_id.as_bytes())?;
    validate_party(common.roles.initiator)?;
    validate_party(common.roles.responder)?;
    if common.roles.initiator.account_id == common.roles.responder.account_id
        && common.roles.initiator.device_id == common.roles.responder.device_id
    {
        return Err(ContextEncodingError::SameParty);
    }
    Ok(())
}

fn validate_party(party: ContextParty) -> Result<(), ContextEncodingError> {
    require_nonzero(party.account_id.as_bytes())?;
    require_nonzero(party.device_id.as_bytes())?;
    validate_monotonic(party.device_epoch.get())?;
    require_nonzero(party.identity_credential_digest.as_bytes())
}

fn validate_monotonic(value: u64) -> Result<(), ContextEncodingError> {
    if value == 0 || value == u64::MAX {
        Err(ContextEncodingError::InvalidMonotonicValue)
    } else {
        Ok(())
    }
}

fn validate_root_epochs(
    kind: RootTransitionKind,
    epochs: RootEpochs,
) -> Result<(), ContextEncodingError> {
    let root_next = epochs
        .prior_root
        .get()
        .checked_add(1)
        .ok_or(ContextEncodingError::InvalidEpochAdvance)?;
    if epochs.next_root.get() != root_next {
        return Err(ContextEncodingError::InvalidEpochAdvance);
    }
    let dh_advances = matches!(kind, RootTransitionKind::Dh | RootTransitionKind::Hybrid);
    let pq_advances = matches!(kind, RootTransitionKind::Pq | RootTransitionKind::Hybrid);
    validate_component_epoch(epochs.prior_dh, epochs.next_dh, dh_advances)?;
    validate_component_epoch(epochs.prior_pq, epochs.next_pq, pq_advances)
}

fn validate_component_epoch(
    prior: RatchetEpoch,
    next: RatchetEpoch,
    advances: bool,
) -> Result<(), ContextEncodingError> {
    let expected = if advances {
        prior
            .get()
            .checked_add(1)
            .ok_or(ContextEncodingError::InvalidEpochAdvance)?
    } else {
        prior.get()
    };
    if next.get() == expected {
        Ok(())
    } else {
        Err(ContextEncodingError::InvalidEpochAdvance)
    }
}

fn require_nonzero(bytes: &[u8]) -> Result<(), ContextEncodingError> {
    if all_zero(bytes) {
        Err(ContextEncodingError::ZeroField)
    } else {
        Ok(())
    }
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn write_common(
    writer: &mut LpWriter<'_>,
    kind: u8,
    common: CommonContext,
) -> Result<(), ContextEncodingError> {
    writer.field(LIFECYCLE_CONTEXT_DOMAIN)?;
    writer.field(&LIFECYCLE_CONTEXT_SCHEMA_VERSION.to_be_bytes())?;
    writer.field(&[kind])?;
    writer.field(common.protocol.protocol_id.as_bytes())?;
    writer.field(&common.protocol.wire_version.get().to_be_bytes())?;
    writer.field(common.protocol.suite_digest.as_bytes())?;
    writer.field(common.protocol.session_id.as_bytes())?;
    write_party(writer, common.roles.initiator)?;
    write_party(writer, common.roles.responder)?;
    writer.field(&[common.roles.identity_mode as u8])?;
    writer.field(&[common.roles.direction as u8])?;
    writer.field(&[common.roles.authentication_stage as u8])?;
    Ok(())
}

fn write_party(writer: &mut LpWriter<'_>, party: ContextParty) -> Result<(), ContextEncodingError> {
    writer.field(party.account_id.as_bytes())?;
    writer.field(party.device_id.as_bytes())?;
    writer.field(&party.device_epoch.get().to_be_bytes())?;
    writer.field(party.identity_credential_digest.as_bytes())?;
    Ok(())
}
