// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Authenticated monotonic witness candidate. Its storage is an independent trust boundary.
use crate::{
    bootstrap::storage_owner,
    codec::{generation, nonzero, Decoder},
    crypto::{digest, envelope, open_envelope, Purpose},
    AnchorSigningKey, DeviceSigningKey, Error, JournalIdentity, PublicKey, VerifiedDevice,
    VerifiedSessionPolicy,
};
use std::sync::atomic::{AtomicBool, Ordering};

mod roster_refresh;
pub use roster_refresh::{
    AnchorRosterRefreshProposal, AnchorRosterRefreshState, RosterRefreshId, RosterRefreshScope,
};
mod policy_renewal;
pub use policy_renewal::{AnchorPolicyRenewalProposal, AnchorPolicyRenewalState};
mod store;
pub use store::{
    AnchorDeviceReplacementProposal, AnchorDeviceReplacementState, AnchorRetiredCleanup,
    AnchorRetiredCleanupProposal, AnchorRetiredCleanupState, AnchorRetiredReport,
    AnchorRetiredReportAcknowledgement, AnchorRetiredReportAcknowledgementState,
    AnchorRetiredReportProposal, AnchorRetiredReportState, AnchorRetiredSubject, AnchorStore,
};
mod transport;
pub use transport::{AnchorClient, AnchorClientError, AnchorTcpTransport, AnchorTransport};
#[cfg(feature = "anchor-tls")]
pub mod tls;

/// Independently provisioned identity of one witness instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchorIdentity([u8; 32]);
impl AnchorIdentity {
    /// Create public provisioning metadata before creating witness storage.
    pub fn generate() -> Result<Self, Error> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| Error::Entropy)?;
        Self::from_trusted_state(bytes)
    }
    /// Restore trusted configuration, never a value selected by an incoming response.
    pub fn from_trusted_state(bytes: [u8; 32]) -> Result<Self, Error> {
        nonzero(&bytes)?;
        Ok(Self(bytes))
    }
    /// Public configuration bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Public journal/device/policy scope. This metadata alone grants no authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchorSubject {
    journal: [u8; 32],
    owner: [u8; 32],
    policy: [u8; 32],
}
impl AnchorSubject {
    pub(crate) fn journal_parts(self) -> ([u8; 32], [u8; 32], [u8; 32]) {
        (self.journal, self.owner, self.policy)
    }
    /// Canonical public metadata for retention in an authenticated local intent.
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(96);
        self.encode(&mut bytes);
        bytes
    }
    /// Restore retained local metadata, not an authority selected by a peer.
    pub fn from_trusted_state(bytes: &[u8]) -> Result<Self, Error> {
        let mut d = Decoder::new(bytes);
        let subject = Self::decode(&mut d)?;
        d.finish()?;
        Ok(subject)
    }
    /// Derive a stable scope from retained verified inputs. Fresh admission is
    /// checked separately by enrollment and the consuming journal service.
    pub fn for_device(
        journal: JournalIdentity,
        device: &VerifiedDevice,
        policy: &impl AsRef<crate::HistoricalSessionPolicy>,
    ) -> Result<Self, Error> {
        let policy = policy.as_ref();
        if device.description.family != policy.family() {
            return Err(Error::Scope);
        }
        Ok(Self {
            journal: *journal.as_bytes(),
            owner: storage_owner(device),
            policy: policy.checkpoint().digest(),
        })
    }
    fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.journal);
        out.extend_from_slice(&self.owner);
        out.extend_from_slice(&self.policy);
    }
    fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        let result = Self {
            journal: d.array()?,
            owner: d.array()?,
            policy: d.array()?,
        };
        nonzero(&result.journal)?;
        nonzero(&result.owner)?;
        nonzero(&result.policy)?;
        Ok(result)
    }
    fn id(self, authority: &[u8; 32]) -> [u8; 32] {
        let mut bytes = authority.to_vec();
        self.encode(&mut bytes);
        digest(b"Q-PERIAPT-CONTINUITY-ANCHOR-SUBJECT/v1", &bytes)
    }
}

/// Public enrollment input obtained from an authenticated empty journal at revision 1,
/// or independently authenticated and approved by the witness control-plane operator.
/// It is not an anchor receipt or permission to use that journal without a live witness.
pub struct AnchorGenesis {
    subject: AnchorSubject,
    digest: [u8; 32],
}
impl AnchorGenesis {
    /// Restore an independently approved remote genesis for trusted control-plane use.
    ///
    /// This checks shape only. The operator must authenticate the exporting device
    /// and independently approve this exact initial image, account/roster and policy
    /// pins. Untrusted request bytes must not select these inputs. `AnchorStore::enroll`
    /// still checks current authority and rejects attempts to reset an existing lineage.
    /// This value is neither a witness receipt nor journal/session permission.
    pub fn from_trusted_state(
        subject: AnchorSubject,
        image_digest: [u8; 32],
    ) -> Result<Self, Error> {
        nonzero(&image_digest)?;
        Ok(Self {
            subject,
            digest: image_digest,
        })
    }

    pub(crate) fn from_journal(
        journal: JournalIdentity,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        digest: [u8; 32],
    ) -> Result<Self, Error> {
        Self::from_trusted_state(AnchorSubject::for_device(journal, device, policy)?, digest)
    }
    /// Exact journal/device/policy subject derived from the authenticated image.
    pub fn subject(&self) -> AnchorSubject {
        self.subject
    }
    /// Initial encrypted-image commitment; witness enrollment begins at fence/revision 1.
    pub fn image_digest(&self) -> [u8; 32] {
        self.digest
    }
}

/// Exact witness state. A constructed head is an expectation, never a signed receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchorHead {
    fence: u64,
    revision: u64,
    digest: [u8; 32],
}
impl AnchorHead {
    /// Restore an independently retained expectation or propose a public state.
    pub fn from_trusted_state(fence: u64, revision: u64, digest: [u8; 32]) -> Result<Self, Error> {
        generation(fence)?;
        generation(revision)?;
        nonzero(&digest)?;
        Ok(Self {
            fence,
            revision,
            digest,
        })
    }
    /// Current writer epoch.
    pub fn fence(self) -> u64 {
        self.fence
    }
    /// Current journal revision.
    pub fn revision(self) -> u64 {
        self.revision
    }
    /// Commitment to the complete encrypted journal image.
    pub fn digest(self) -> [u8; 32] {
        self.digest
    }
    fn encode(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.fence.to_be_bytes());
        out.extend_from_slice(&self.revision.to_be_bytes());
        out.extend_from_slice(&self.digest);
    }
    fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        Self::from_trusted_state(d.u64()?, d.u64()?, d.array()?)
    }
}

/// Public proposal read back from an authenticated original journal intent.
/// These bytes describe expected states; they are neither a witness receipt nor
/// authority to commit or release an operational device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchorCredentialRenewalProposal {
    witness: [u8; 32],
    subject: AnchorSubject,
    operation: crate::CredentialRenewalId,
    statement: [u8; 32],
    expected: AnchorHead,
    target: AnchorHead,
    continuation: Option<[u8; 32]>,
    adopts_policy: bool,
}
impl AnchorCredentialRenewalProposal {
    pub(crate) fn from_journal(
        witness: [u8; 32],
        subject: AnchorSubject,
        operation: crate::CredentialRenewalId,
        statement: [u8; 32],
        expected: AnchorHead,
        target: AnchorHead,
    ) -> Result<Self, Error> {
        let value = Self {
            witness,
            subject,
            operation,
            statement,
            expected,
            target,
            continuation: None,
            adopts_policy: false,
        };
        Self::from_trusted_state(&value.to_bytes())
    }
    /// Canonical public metadata for authenticated retention and explicit approval.
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = if self.continuation.is_some() {
            b"QPCRNP02".to_vec()
        } else {
            b"QPCRNP01".to_vec()
        };
        bytes.extend_from_slice(&self.witness);
        self.subject.encode(&mut bytes);
        bytes.extend_from_slice(self.operation.as_bytes());
        bytes.extend_from_slice(&self.statement);
        self.expected.encode(&mut bytes);
        self.target.encode(&mut bytes);
        if let Some(statement) = self.continuation {
            bytes.push(u8::from(self.adopts_policy));
            bytes.extend_from_slice(&statement);
        }
        bytes
    }
    /// Restore exact expected metadata, never a remote-selected authorization.
    /// The witness must independently compare its actual state and root grant.
    pub fn from_trusted_state(bytes: &[u8]) -> Result<Self, Error> {
        let mut d = Decoder::new(bytes);
        let version = d.array::<8>()?;
        if version != *b"QPCRNP01" && version != *b"QPCRNP02" {
            return Err(Error::Encoding);
        }
        let witness = d.array()?;
        nonzero(&witness)?;
        let subject = AnchorSubject::decode(&mut d)?;
        let operation = crate::CredentialRenewalId::from_trusted_state(d.array()?)?;
        let statement = d.array()?;
        nonzero(&statement)?;
        let expected = AnchorHead::decode(&mut d)?;
        let target = AnchorHead::decode(&mut d)?;
        let (continuation, adopts_policy) = if version == *b"QPCRNP02" {
            let adopts = match d.array::<1>()? {
                [0] => false,
                [1] => true,
                _ => return Err(Error::Encoding),
            };
            let statement = d.array()?;
            nonzero(&statement)?;
            (Some(statement), adopts)
        } else {
            (None, false)
        };
        d.finish()?;
        let Command::Advance(_, next) = AnchorOperation::advance(expected, target.digest)?.0 else {
            return Err(Error::State);
        };
        if target != next {
            return Err(Error::Encoding);
        }
        Ok(Self {
            witness,
            subject,
            operation,
            statement,
            expected,
            target,
            continuation,
            adopts_policy,
        })
    }
    /// Bind an independently approved policy continuation to this exact G and
    /// original journal subject. This constructs public expectations only; it
    /// neither changes the sealed target nor proves that a witness adopted T.
    pub fn with_policy_continuation(
        self,
        continuation: &crate::VerifiedPolicyContinuation,
    ) -> Result<Self, Error> {
        let scope = continuation.scope();
        if self.operation != scope.operation
            || self.statement != continuation.credential_statement()
            || self.subject.journal != *scope.journal.as_bytes()
            || self.subject.owner != scope.original_owner
            || self.subject.policy != scope.original_policy.digest()
            || self
                .continuation
                .is_some_and(|s| s != continuation.statement_digest() || !self.adopts_policy)
        {
            return Err(Error::Scope);
        }
        self.bind_policy_expectation(continuation.statement_digest(), true)
    }
    /// Independently bound target policy authorization, separate from G's
    /// statement. Absence explicitly denotes the original credential-only wire.
    pub fn policy_continuation(self) -> Option<[u8; 32]> {
        self.continuation
    }
    /// Whether this transaction adopts a new T or only carries the existing T.
    pub fn adopts_policy(self) -> bool {
        self.adopts_policy
    }
    /// Exact enrollment completion statement: T for adoption, G for G-only
    /// renewal. The complete proposal always binds both relevant authorities.
    pub fn transaction_statement(self) -> [u8; 32] {
        match self.continuation {
            Some(statement) if self.adopts_policy => statement,
            _ => self.statement,
        }
    }
    /// Carry the expected already-adopted T through a later G-only transaction.
    /// This history is not adoption or current permission; the witness must
    /// match its independently retained T and require the actual current P1.
    pub fn with_retained_policy_continuation(
        self,
        continuation: &crate::HistoricalPolicyContinuation,
    ) -> Result<Self, Error> {
        let scope = continuation.scope();
        let statement = continuation.statement_digest();
        if self.subject.journal != *scope.journal.as_bytes()
            || self.subject.owner != scope.original_owner
            || self.subject.policy != scope.original_policy.digest()
            || self
                .continuation
                .is_some_and(|s| s != statement || self.adopts_policy)
        {
            return Err(Error::Scope);
        }
        self.bind_policy_expectation(statement, false)
    }
    // Reconstruct only public expected metadata from an authenticated journal
    // intent whose exact sealed target has already verified the complete G/T.
    // Like from_trusted_state, this does not supply witness/current authority.
    pub(crate) fn bind_policy_expectation(
        mut self,
        statement: [u8; 32],
        adopts: bool,
    ) -> Result<Self, Error> {
        nonzero(&statement)?;
        if self
            .continuation
            .is_some_and(|s| s != statement || self.adopts_policy != adopts)
        {
            return Err(Error::Scope);
        }
        self.continuation = Some(statement);
        self.adopts_policy = adopts;
        Ok(self)
    }
    /// Pinned witness instance/key binding from the protected journal policy.
    pub fn witness_binding(self) -> [u8; 32] {
        self.witness
    }
    /// Original immutable journal/device/policy subject.
    pub fn subject(self) -> AnchorSubject {
        self.subject
    }
    /// Original root-authorized operation identity.
    pub fn operation(self) -> crate::CredentialRenewalId {
        self.operation
    }
    /// Exact root authorization statement commitment.
    pub fn statement(self) -> [u8; 32] {
        self.statement
    }
    /// Expected original head; this is not a signed currentness claim.
    pub fn expected_head(self) -> AnchorHead {
        self.expected
    }
    /// Head of the exact retained sealed target, not a freshly resealed copy.
    pub fn target_head(self) -> AnchorHead {
        self.target
    }
    /// Domain-separated identity of this complete public proposal.
    pub fn binding(self) -> [u8; 32] {
        digest(b"Q-PERIAPT-ANCHOR-CREDENTIAL-PROPOSAL/v1", &self.to_bytes())
    }
}

/// Exact independent cancellation request for a grant without a local proposal.
/// No target image is invented or sealed. These public bytes are an expectation,
/// not proof of absence, a witness receipt or permission to erase local state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchorCredentialRenewalCancellation {
    witness: [u8; 32],
    subject: AnchorSubject,
    operation: crate::CredentialRenewalId,
    statement: [u8; 32],
    expected: AnchorHead,
    continuation: Option<[u8; 32]>,
    adopts_policy: bool,
}
impl AnchorCredentialRenewalCancellation {
    /// Restore independently retained metadata, never a remote-selected authority.
    /// The control plane must compare the exact authenticated grant and real slot.
    pub fn from_trusted_state(bytes: &[u8]) -> Result<Self, Error> {
        let mut d = Decoder::new(bytes);
        let tag = d.array::<8>()?;
        if tag != *b"QPCRNC01" && tag != *b"QPCRNC02" {
            return Err(Error::Encoding);
        }
        let witness = d.array()?;
        nonzero(&witness)?;
        let subject = AnchorSubject::decode(&mut d)?;
        let operation = crate::CredentialRenewalId::from_trusted_state(d.array()?)?;
        let statement = d.array()?;
        nonzero(&statement)?;
        let expected = AnchorHead::decode(&mut d)?;
        let (continuation, adopts_policy) = if tag == *b"QPCRNC02" {
            let [mode] = d.array()?;
            if mode > 1 {
                return Err(Error::Encoding);
            }
            let statement = d.array()?;
            nonzero(&statement)?;
            (Some(statement), mode == 1)
        } else {
            (None, false)
        };
        d.finish()?;
        Ok(Self {
            witness,
            subject,
            operation,
            statement,
            expected,
            continuation,
            adopts_policy,
        })
    }
    /// Canonical metadata without a target head/image: 248 bytes for G alone,
    /// 281 bytes when independently binding T and adopt/carry mode.
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = if self.continuation.is_some() {
            b"QPCRNC02"
        } else {
            b"QPCRNC01"
        }
        .to_vec();
        bytes.extend_from_slice(&self.witness);
        self.subject.encode(&mut bytes);
        bytes.extend_from_slice(self.operation.as_bytes());
        bytes.extend_from_slice(&self.statement);
        self.expected.encode(&mut bytes);
        if let Some(statement) = self.continuation {
            bytes.push(u8::from(self.adopts_policy));
            bytes.extend_from_slice(&statement);
        }
        bytes
    }
    /// Bind a signed historical T to a request to close its exact G/T operation.
    /// This is public metadata, not a witness Closed receipt or current authority.
    pub fn with_policy_continuation(
        self,
        continuation: &crate::HistoricalPolicyContinuation,
    ) -> Result<Self, Error> {
        if self.operation != continuation.scope().operation
            || self.statement != continuation.credential_statement()
        {
            return Err(Error::Scope);
        }
        self.with_policy_expectation(continuation, true)
    }
    /// Explicitly retain the already-adopted T while cancelling a later G.
    pub fn with_retained_policy_continuation(
        self,
        continuation: &crate::HistoricalPolicyContinuation,
    ) -> Result<Self, Error> {
        if self.operation == continuation.scope().operation {
            return Err(Error::Scope);
        }
        self.with_policy_expectation(continuation, false)
    }
    fn with_policy_expectation(
        mut self,
        continuation: &crate::HistoricalPolicyContinuation,
        adopts: bool,
    ) -> Result<Self, Error> {
        let scope = continuation.scope();
        let statement = continuation.statement_digest();
        if self.subject.journal != *scope.journal.as_bytes()
            || self.subject.owner != scope.original_owner
            || self.subject.policy != scope.original_policy.digest()
            || self
                .continuation
                .is_some_and(|s| s != statement || self.adopts_policy != adopts)
        {
            return Err(Error::Scope);
        }
        self.continuation = Some(statement);
        self.adopts_policy = adopts;
        Ok(self)
    }
    /// Independently bound policy authorization, absent on the original grammar.
    pub fn policy_continuation(self) -> Option<[u8; 32]> {
        self.continuation
    }
    /// Whether the cancelled target would adopt a new T.
    pub fn adopts_policy(self) -> bool {
        self.adopts_policy
    }
    /// Original enrollment operation statement: T for adoption, G for carry.
    pub fn transaction_statement(self) -> [u8; 32] {
        match self.continuation {
            Some(t) if self.adopts_policy => t,
            _ => self.statement,
        }
    }
    /// Independently pinned witness identity/key binding.
    pub fn witness_binding(self) -> [u8; 32] {
        self.witness
    }
    /// Original immutable journal/device/policy subject.
    pub fn subject(self) -> AnchorSubject {
        self.subject
    }
    /// Exact root-authorized operation being independently closed.
    pub fn operation(self) -> crate::CredentialRenewalId {
        self.operation
    }
    /// Root statement commitment, excluding randomized signatures.
    pub fn statement(self) -> [u8; 32] {
        self.statement
    }
    /// Original head expectation which the witness must compare atomically.
    pub fn expected_head(self) -> AnchorHead {
        self.expected
    }
    /// Separate commitment domain; never interchangeable with a sealed proposal.
    pub fn binding(self) -> [u8; 32] {
        digest(
            b"Q-PERIAPT-ANCHOR-CREDENTIAL-CANCELLATION/v1",
            &self.to_bytes(),
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Command {
    RosterCommit([u8; 32]),
    RosterStatus([u8; 32]),
    RosterClose([u8; 32]),
    RosterAcknowledge([u8; 32]),
    Query,
    PolicyCommit([u8; 32]),
    PolicyStatus([u8; 32]),
    PolicyClose([u8; 32]),
    PolicyAcknowledge([u8; 32]),
    AdmitPolicy([u8; 32], [u8; 32]),
    AdmitAuthority([u8; 32]),
    AdmitContinuation([u8; 32], [u8; 32], [u8; 32]),
    CredentialCommit([u8; 32]),
    CredentialStatus([u8; 32]),
    CredentialClose([u8; 32]),
    CredentialAcknowledge([u8; 32]),
    Advance(AnchorHead, AnchorHead),
    Fence(AnchorHead, AnchorHead),
}
/// One immutable compare-and-advance command, separate from per-attempt freshness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchorOperation(Command);
impl AnchorOperation {
    /// Canonical immutable command for persistence before external dispatch.
    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(97);
        self.encode(&mut bytes);
        bytes
    }
    /// Restore the exact authenticated local intent. Parsing grants no claim
    /// that its expected head is current; the witness still compares it.
    pub fn from_trusted_state(bytes: &[u8]) -> Result<Self, Error> {
        let mut d = Decoder::new(bytes);
        let operation = Self::decode(&mut d)?;
        d.finish()?;
        Ok(operation)
    }
    /// Query one enrolled subject without advancing or creating it.
    pub fn query() -> Self {
        Self(Command::Query)
    }
    /// Read-only confirmation of an independently expected device authority.
    /// Use the binding from a current independently verified device. Unlike an
    /// ordinary head query, this requires the witness's exact current authority
    /// and live enrollment validity. It never updates or enrolls that authority.
    pub fn admit_authority(expected: [u8; 32]) -> Result<Self, Error> {
        nonzero(&expected)?;
        Ok(Self(Command::AdmitAuthority(expected)))
    }
    /// Fresh observation of exact account authority, current G and independent T.
    /// Callers must also compare the signed head and admit their current P1.
    pub fn admit_continuation(
        authority: [u8; 32],
        credential: [u8; 32],
        continuation: [u8; 32],
    ) -> Result<Self, Error> {
        for value in [authority, credential, continuation] {
            nonzero(&value)?;
        }
        Ok(Self(Command::AdmitContinuation(
            authority,
            credential,
            continuation,
        )))
    }
    /// Apply only the independently prepared exact joint head/credential target.
    pub fn commit_credential_renewal(proposal: &AnchorCredentialRenewalProposal) -> Self {
        Self(Command::CredentialCommit(proposal.binding()))
    }
    /// Read an exact renewal slot. Unavailable never proves non-commit.
    pub fn credential_renewal_status(proposal: &AnchorCredentialRenewalProposal) -> Self {
        Self(Command::CredentialStatus(proposal.binding()))
    }
    /// Close an existing exact preparation, mutually exclusively with apply.
    /// Closing before preparation requires the independent root control plane.
    pub fn close_credential_renewal(proposal: &AnchorCredentialRenewalProposal) -> Self {
        Self(Command::CredentialClose(proposal.binding()))
    }
    /// Retire an exact terminal only after retaining its disposition durably.
    /// The permanent floor still rejects old targets after the slot is removed.
    pub fn acknowledge_credential_renewal(proposal: &AnchorCredentialRenewalProposal) -> Self {
        Self(Command::CredentialAcknowledge(proposal.binding()))
    }
    /// Read the exact independently retained grant-only cancellation. A device
    /// cannot create it through this request; Unavailable never proves Closed.
    pub fn credential_cancellation_status(
        cancellation: &AnchorCredentialRenewalCancellation,
    ) -> Self {
        Self(Command::CredentialStatus(cancellation.binding()))
    }
    /// Retire only after the original enrollment durably retains its Closed state.
    pub fn acknowledge_credential_cancellation(
        cancellation: &AnchorCredentialRenewalCancellation,
    ) -> Self {
        Self(Command::CredentialAcknowledge(cancellation.binding()))
    }
    fn credential_binding(self) -> Option<[u8; 32]> {
        match self.0 {
            Command::CredentialCommit(binding)
            | Command::CredentialStatus(binding)
            | Command::CredentialClose(binding)
            | Command::CredentialAcknowledge(binding) => Some(binding),
            _ => None,
        }
    }
    /// Advance exactly one journal revision under the current writer fence.
    pub fn advance(expected: AnchorHead, next_digest: [u8; 32]) -> Result<Self, Error> {
        nonzero(&next_digest)?;
        if next_digest == expected.digest {
            return Err(Error::Conflict);
        }
        let revision = increment(expected.revision)?;
        Ok(Self(Command::Advance(
            expected,
            AnchorHead {
                revision,
                digest: next_digest,
                ..expected
            },
        )))
    }
    /// Explicitly advance the writer epoch while preserving the exact journal head.
    pub fn fence_writer(expected: AnchorHead) -> Result<Self, Error> {
        let fence = increment(expected.fence)?;
        Ok(Self(Command::Fence(
            expected,
            AnchorHead { fence, ..expected },
        )))
    }
    fn encode(self, out: &mut Vec<u8>) {
        match self.0 {
            Command::RosterCommit(binding) => {
                out.push(16);
                out.extend_from_slice(&binding);
                out.extend_from_slice(&[0; 64]);
            }
            Command::RosterStatus(binding) => {
                out.push(17);
                out.extend_from_slice(&binding);
                out.extend_from_slice(&[0; 64]);
            }
            Command::RosterClose(binding) => {
                out.push(18);
                out.extend_from_slice(&binding);
                out.extend_from_slice(&[0; 64]);
            }
            Command::RosterAcknowledge(binding) => {
                out.push(19);
                out.extend_from_slice(&binding);
                out.extend_from_slice(&[0; 64]);
            }
            Command::AdmitPolicy(authority, statement) => {
                out.push(15);
                out.extend_from_slice(&authority);
                out.extend_from_slice(&statement);
                out.extend_from_slice(&[0; 32]);
            }
            Command::PolicyCommit(binding) => {
                out.push(11);
                out.extend_from_slice(&binding);
                out.extend_from_slice(&[0; 64]);
            }
            Command::PolicyStatus(binding) => {
                out.push(12);
                out.extend_from_slice(&binding);
                out.extend_from_slice(&[0; 64]);
            }
            Command::PolicyClose(binding) => {
                out.push(13);
                out.extend_from_slice(&binding);
                out.extend_from_slice(&[0; 64]);
            }
            Command::PolicyAcknowledge(binding) => {
                out.push(14);
                out.extend_from_slice(&binding);
                out.extend_from_slice(&[0; 64]);
            }
            Command::AdmitContinuation(authority, credential, continuation) => {
                out.push(10);
                out.extend_from_slice(&authority);
                out.extend_from_slice(&credential);
                out.extend_from_slice(&continuation);
            }
            Command::Query => {
                out.push(1);
                out.extend_from_slice(&[0; 96]);
            }
            Command::AdmitAuthority(expected)
            | Command::CredentialCommit(expected)
            | Command::CredentialStatus(expected)
            | Command::CredentialClose(expected)
            | Command::CredentialAcknowledge(expected) => {
                out.push(match self.0 {
                    Command::CredentialCommit(_) => 5,
                    Command::CredentialStatus(_) => 6,
                    Command::CredentialClose(_) => 7,
                    Command::CredentialAcknowledge(_) => 8,
                    _ => 4,
                });
                out.extend_from_slice(&expected);
                out.extend_from_slice(&[0; 64]);
            }
            Command::Advance(before, after) | Command::Fence(before, after) => {
                out.push(if matches!(self.0, Command::Advance(..)) {
                    2
                } else {
                    3
                });
                before.encode(out);
                after.encode(out);
            }
        }
    }
    fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        let [kind] = d.array()?;
        if (16..=19).contains(&kind) {
            let binding = d.array()?;
            nonzero(&binding)?;
            if d.array::<64>()? != [0; 64] {
                return Err(Error::Encoding);
            }
            return match kind {
                16 => Ok(Self(Command::RosterCommit(binding))),
                17 => Ok(Self(Command::RosterStatus(binding))),
                18 => Ok(Self(Command::RosterClose(binding))),
                19 => Ok(Self(Command::RosterAcknowledge(binding))),
                _ => Err(Error::Encoding),
            };
        }
        if kind == 15 {
            let authority = d.array()?;
            let statement = d.array()?;
            if d.array::<32>()? != [0; 32] {
                return Err(Error::Encoding);
            }
            return Self::admit_policy_renewal(authority, statement);
        }
        if (11..=14).contains(&kind) {
            let binding = d.array()?;
            nonzero(&binding)?;
            if d.array::<64>()? != [0; 64] {
                return Err(Error::Encoding);
            }
            return match kind {
                11 => Ok(Self(Command::PolicyCommit(binding))),
                12 => Ok(Self(Command::PolicyStatus(binding))),
                13 => Ok(Self(Command::PolicyClose(binding))),
                14 => Ok(Self(Command::PolicyAcknowledge(binding))),
                _ => Err(Error::Encoding),
            };
        }
        if kind == 10 {
            return Self::admit_continuation(d.array()?, d.array()?, d.array()?);
        }
        if kind == 1 {
            if d.take(96)?.iter().any(|byte| *byte != 0) {
                return Err(Error::Encoding);
            }
            return Ok(Self::query());
        }
        if (4..=8).contains(&kind) {
            let expected = d.array()?;
            nonzero(&expected)?;
            if d.take(64)?.iter().any(|byte| *byte != 0) {
                return Err(Error::Encoding);
            }
            return match kind {
                4 => Self::admit_authority(expected),
                5 => Ok(Self(Command::CredentialCommit(expected))),
                6 => Ok(Self(Command::CredentialStatus(expected))),
                7 => Ok(Self(Command::CredentialClose(expected))),
                8 => Ok(Self(Command::CredentialAcknowledge(expected))),
                _ => Err(Error::Encoding),
            };
        }
        let before = AnchorHead::decode(d)?;
        let after = AnchorHead::decode(d)?;
        let operation = match kind {
            2 => Self::advance(before, after.digest)?,
            3 => Self::fence_writer(before)?,
            _ => return Err(Error::Encoding),
        };
        if operation.next() != Some(after) {
            return Err(Error::Encoding);
        }
        Ok(operation)
    }
    fn next(self) -> Option<AnchorHead> {
        match self.0 {
            Command::Query
            | Command::RosterCommit(_)
            | Command::RosterStatus(_)
            | Command::RosterClose(_)
            | Command::RosterAcknowledge(_)
            | Command::PolicyCommit(_)
            | Command::PolicyStatus(_)
            | Command::PolicyClose(_)
            | Command::PolicyAcknowledge(_)
            | Command::AdmitPolicy(..)
            | Command::AdmitAuthority(_)
            | Command::AdmitContinuation(..)
            | Command::CredentialCommit(_)
            | Command::CredentialStatus(_)
            | Command::CredentialClose(_)
            | Command::CredentialAcknowledge(_) => None,
            Command::Advance(_, next) | Command::Fence(_, next) => Some(next),
        }
    }
}
fn increment(value: u64) -> Result<u64, Error> {
    value
        .checked_add(1)
        .filter(|next| *next != u64::MAX)
        .ok_or(Error::Capacity)
}

/// Independently provisioned witness identity and exact dual-signature public key.
#[derive(Clone)]
pub struct AnchorPin {
    identity: AnchorIdentity,
    key: PublicKey,
    binding: [u8; 32],
}
impl AnchorPin {
    /// Pin trusted configuration independently of requests and replies.
    pub fn new(identity: AnchorIdentity, key: PublicKey) -> Self {
        let mut bytes = identity.0.to_vec();
        bytes.extend_from_slice(&key.encode());
        let binding = digest(b"Q-PERIAPT-CONTINUITY-ANCHOR-AUTHORITY/v1", &bytes);
        Self {
            identity,
            key,
            binding,
        }
    }
    /// Public witness-instance and key commitment.
    pub fn binding(&self) -> [u8; 32] {
        self.binding
    }
    /// Independently retained instance identity.
    pub fn identity(&self) -> AnchorIdentity {
        self.identity
    }
    /// Pinned public verification key; this does not expose signing material.
    pub fn public_key(&self) -> &PublicKey {
        &self.key
    }
    /// Authenticate an exact attempt, its full command and the closed outcome.
    pub fn verify_reply(&self, request: &AnchorRequest, wire: &[u8]) -> Result<AnchorReply, Error> {
        if request.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        if request.authority != self.binding {
            return Err(Error::Scope);
        }
        let (body, signature) = open_envelope(wire)?;
        self.key.verify(Purpose::AnchorReply, body, signature)?;
        let mut d = Decoder::new(body);
        if d.array::<8>()? != *b"QPANRS01"
            || d.array::<32>()? != self.binding
            || AnchorSubject::decode(&mut d)? != request.subject
            || d.array::<32>()? != request.attempt
            || d.array::<32>()? != request.command
        {
            return Err(Error::Scope);
        }
        let [outcome] = d.array()?;
        let outcome = match outcome {
            1 => AnchorOutcome::Current,
            2 => AnchorOutcome::Advanced,
            3 => AnchorOutcome::AlreadyAppliedExact,
            4 => AnchorOutcome::Conflict,
            5 => AnchorOutcome::AuthorityCurrent,
            6 => AnchorOutcome::AuthorityDenied,
            7 => AnchorOutcome::CredentialPrepared,
            8 => AnchorOutcome::CredentialApplied,
            9 => AnchorOutcome::CredentialClosed,
            10 => AnchorOutcome::CredentialUnavailable,
            11 => AnchorOutcome::CredentialAcknowledged,
            12 => AnchorOutcome::PolicyPrepared,
            13 => AnchorOutcome::PolicyApplied,
            14 => AnchorOutcome::PolicyClosed,
            15 => AnchorOutcome::PolicyUnavailable,
            16 => AnchorOutcome::PolicyAcknowledged,
            17 => AnchorOutcome::RosterPrepared,
            18 => AnchorOutcome::RosterApplied,
            19 => AnchorOutcome::RosterClosed,
            20 => AnchorOutcome::RosterUnavailable,
            21 => AnchorOutcome::RosterAcknowledged,
            _ => return Err(Error::Encoding),
        };
        let head = AnchorHead::decode(&mut d)?;
        let last = decode_last(&mut d, head)?;
        d.finish()?;
        match (request.operation.0, outcome) {
            (Command::Query, AnchorOutcome::Current) => {}
            (
                Command::RosterStatus(_),
                AnchorOutcome::RosterPrepared
                | AnchorOutcome::RosterApplied
                | AnchorOutcome::RosterClosed
                | AnchorOutcome::RosterUnavailable,
            ) => {}
            (
                Command::RosterCommit(_) | Command::RosterClose(_),
                AnchorOutcome::RosterApplied
                | AnchorOutcome::RosterClosed
                | AnchorOutcome::RosterUnavailable,
            ) => {}
            (
                Command::RosterAcknowledge(_),
                AnchorOutcome::RosterAcknowledged | AnchorOutcome::RosterUnavailable,
            ) => {}
            (
                Command::PolicyStatus(_),
                AnchorOutcome::PolicyPrepared
                | AnchorOutcome::PolicyApplied
                | AnchorOutcome::PolicyClosed
                | AnchorOutcome::PolicyUnavailable,
            ) => {}
            (
                Command::PolicyCommit(_) | Command::PolicyClose(_),
                AnchorOutcome::PolicyApplied
                | AnchorOutcome::PolicyClosed
                | AnchorOutcome::PolicyUnavailable,
            ) => {}
            (
                Command::PolicyAcknowledge(_),
                AnchorOutcome::PolicyAcknowledged | AnchorOutcome::PolicyUnavailable,
            ) => {}
            (
                Command::AdmitAuthority(_)
                | Command::AdmitContinuation(..)
                | Command::AdmitPolicy(..),
                AnchorOutcome::AuthorityCurrent | AnchorOutcome::AuthorityDenied,
            ) => {}
            (
                Command::CredentialStatus(_),
                AnchorOutcome::CredentialPrepared
                | AnchorOutcome::CredentialApplied
                | AnchorOutcome::CredentialClosed
                | AnchorOutcome::CredentialUnavailable,
            ) => {}
            (
                Command::CredentialCommit(_) | Command::CredentialClose(_),
                AnchorOutcome::CredentialApplied
                | AnchorOutcome::CredentialClosed
                | AnchorOutcome::CredentialUnavailable,
            ) => {}
            (
                Command::CredentialAcknowledge(_),
                AnchorOutcome::CredentialAcknowledged | AnchorOutcome::CredentialUnavailable,
            ) => {}
            (
                Command::Advance(_, next) | Command::Fence(_, next),
                AnchorOutcome::Advanced | AnchorOutcome::AlreadyAppliedExact,
            ) if head == next && last == Some(request.command) => {}
            (
                Command::Advance(expected, _) | Command::Fence(expected, _),
                AnchorOutcome::Conflict,
            ) if head != expected
                && !(Some(head) == request.operation.next() && last == Some(request.command)) => {}
            _ => return Err(Error::State),
        }
        request
            .closed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::Closed)?;
        Ok(AnchorReply {
            authority: self.binding,
            subject: request.subject,
            operation: request.operation,
            outcome,
            head,
            command: request.command,
            last,
        })
    }
}

/// Witness request failure, with absent acknowledgement distinct from rejection.
#[derive(Debug)]
pub enum AnchorError {
    /// The request was not admitted; no mutation was performed for it.
    Rejected(Error),
    /// Storage failed; a commit may require exact-operation reconciliation.
    Storage(crate::DurableError),
    /// State was already observed or committed, but no signed reply could be released.
    ReplyUnavailable(Error),
}
impl std::fmt::Display for AnchorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Rejected(_) => "witness request rejected",
            Self::Storage(_) => "witness storage failed",
            Self::ReplyUnavailable(_) => {
                "witness acknowledgement unavailable; reconcile exact command"
            }
        })
    }
}
impl std::error::Error for AnchorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rejected(e) | Self::ReplyUnavailable(e) => Some(e),
            Self::Storage(e) => Some(e),
        }
    }
}
impl From<Error> for AnchorError {
    fn from(e: Error) -> Self {
        Self::Rejected(e)
    }
}
impl From<crate::DurableError> for AnchorError {
    fn from(e: crate::DurableError) -> Self {
        Self::Storage(e)
    }
}

/// Signed request with a platform-generated fresh challenge for this attempt.
pub struct AnchorRequest {
    authority: [u8; 32],
    subject: AnchorSubject,
    operation: AnchorOperation,
    command: [u8; 32],
    attempt: [u8; 32],
    wire: Vec<u8>,
    closed: AtomicBool,
}
impl AnchorRequest {
    /// Sign a fresh attempt. Persist the immutable operation before dispatching
    /// a mutation; retries use that operation with a new challenge.
    pub fn new(
        pin: &AnchorPin,
        subject: AnchorSubject,
        operation: AnchorOperation,
        signer: &DeviceSigningKey,
    ) -> Result<Self, Error> {
        if signer.public_key()?.shares_component(&pin.key) {
            return Err(Error::Scope);
        }
        let command = command_id(&pin.binding, subject, operation);
        let mut challenge = [0; 32];
        getrandom::fill(&mut challenge).map_err(|_| Error::Entropy)?;
        nonzero(&challenge)?;
        let mut body = b"QPANRQ01".to_vec();
        body.extend_from_slice(&pin.binding);
        subject.encode(&mut body);
        body.extend_from_slice(&command);
        body.extend_from_slice(&challenge);
        operation.encode(&mut body);
        let wire = envelope(&body, &signer.sign(Purpose::AnchorRequest, &body)?)?;
        Ok(Self {
            authority: pin.binding,
            subject,
            operation,
            command,
            attempt: request_id(&body),
            wire,
            closed: AtomicBool::new(false),
        })
    }
    /// Public signed transport bytes; their signature is checked by the witness.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }
    /// Stable operation identity; freshness/signature bytes are deliberately excluded.
    pub fn command_id(&self) -> [u8; 32] {
        self.command
    }
    /// Stop accepting replies to this attempt. This does not undo a dispatched
    /// mutation; retain/reconcile its exact operation with a fresh request.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }
}

/// Authenticated, closed witness outcome. Conflict never authorizes local installation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorOutcome {
    /// A fresh read of an enrolled subject.
    Current = 1,
    /// The exact requested mutation committed before the reply was signed.
    Advanced = 2,
    /// The same complete command is the last applied transition; no second advance occurred.
    AlreadyAppliedExact = 3,
    /// The authoritative head/fence differs from the requested advance.
    Conflict = 4,
    /// Exact requested authority is current and valid at this fresh witness check.
    /// This is a read-only snapshot, not a future lease or mutation acknowledgement.
    AuthorityCurrent = 5,
    /// Authenticated refusal: the requested authority is not current or not valid.
    /// This never authorizes traffic or an unanchored fallback.
    AuthorityDenied = 6,
    /// Exact joint renewal is durably prepared, not committed.
    CredentialPrepared = 7,
    /// Exact joint head and credential transition is durably applied.
    CredentialApplied = 8,
    /// Exact preparation is durably closed without that joint transition.
    CredentialClosed = 9,
    /// No exact retained disposition is available; never infer NoCommit.
    CredentialUnavailable = 10,
    /// Exact terminal was retired, or its last acknowledgement was retried.
    CredentialAcknowledged = 11,
    /// Independently approved policy-only target is prepared, not committed.
    PolicyPrepared = 12,
    /// Exact journal head and independent policy authority committed atomically.
    PolicyApplied = 13,
    /// Exact policy-only target is permanently closed without application.
    PolicyClosed = 14,
    /// No exact policy-only history is retained; never infer no-commit.
    PolicyUnavailable = 15,
    /// Exact policy-only terminal was retired or its last ACK was retried.
    PolicyAcknowledged = 16,
    /// Exact roster/head target retained, not applied.
    RosterPrepared = 17,
    /// Exact head and roster authority applied together.
    RosterApplied = 18,
    /// Exact roster/head target permanently closed.
    RosterClosed = 19,
    /// No exact retained roster/head disposition; never infer no-commit.
    RosterUnavailable = 20,
    /// Exact roster/head terminal retired or its last ACK retried.
    RosterAcknowledged = 21,
}

/// Exact joint-renewal disposition. Historical states confer no traffic authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorCredentialRenewalState {
    /// Prepared target retained; no joint transition committed.
    Prepared,
    /// Joint transition committed; local recovery may still be pending.
    Applied,
    /// Joint transition is closed and cannot later be applied.
    Closed,
    /// Exact terminal acknowledgement was observed; retain its local outcome.
    Acknowledged,
    /// Absent, conflicting or retired exact history; not proof of non-commit.
    Unavailable,
}
/// Exact grant-only cancellation history; none of these grants runtime authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorCredentialCancellationState {
    /// Independent control plane closed the original unprepared grant durably.
    Closed,
    /// Its exact acknowledgement was observed; rely on the retained local terminal.
    Acknowledged,
    /// No exact retained cancellation; never infer non-commit from this result.
    Unavailable,
}
/// A reply authenticated against the caller's fresh attempt and pinned witness.
pub struct AnchorReply {
    authority: [u8; 32],
    subject: AnchorSubject,
    operation: AnchorOperation,
    outcome: AnchorOutcome,
    head: AnchorHead,
    command: [u8; 32],
    last: Option<[u8; 32]>,
}
impl AnchorReply {
    /// Exact outcome; this is not a caller-supplied adapter flag.
    pub fn outcome(&self) -> AnchorOutcome {
        self.outcome
    }
    /// The signed observation; callers must match it to their own local state.
    pub fn observed_head(&self) -> AnchorHead {
        self.head
    }
    /// Only a verified exact-applied outcome yields mutation acknowledgement.
    pub fn applied_head(&self) -> Result<AnchorHead, Error> {
        match self.outcome {
            AnchorOutcome::Advanced | AnchorOutcome::AlreadyAppliedExact => Ok(self.head),
            AnchorOutcome::Conflict => Err(Error::Conflict),
            _ => Err(Error::State),
        }
    }
    /// Interpret only an exact fresh reply under the independently retained
    /// proposal. Generic head or authority observations cannot stand in for it.
    pub fn credential_renewal_state(
        &self,
        proposal: &AnchorCredentialRenewalProposal,
    ) -> Result<AnchorCredentialRenewalState, Error> {
        if self.authority != proposal.witness
            || self.subject != proposal.subject
            || self.operation.credential_binding() != Some(proposal.binding())
        {
            return Err(Error::Scope);
        }
        match self.outcome {
            AnchorOutcome::CredentialPrepared if self.head == proposal.expected => {
                Ok(AnchorCredentialRenewalState::Prepared)
            }
            AnchorOutcome::CredentialClosed if self.head == proposal.expected => {
                Ok(AnchorCredentialRenewalState::Closed)
            }
            AnchorOutcome::CredentialApplied
                if self.head == proposal.target
                    && self.last
                        == Some(command_id(
                            &proposal.witness,
                            proposal.subject,
                            AnchorOperation::commit_credential_renewal(proposal),
                        )) =>
            {
                Ok(AnchorCredentialRenewalState::Applied)
            }
            AnchorOutcome::CredentialAcknowledged => Ok(AnchorCredentialRenewalState::Acknowledged),
            AnchorOutcome::CredentialUnavailable => Ok(AnchorCredentialRenewalState::Unavailable),
            _ => Err(Error::State),
        }
    }
    /// Interpret a fresh signed response under the exact original cancellation.
    /// Ordinary queries, another cancellation or a sealed proposal cannot replace it.
    pub fn credential_cancellation_state(
        &self,
        cancellation: &AnchorCredentialRenewalCancellation,
    ) -> Result<AnchorCredentialCancellationState, Error> {
        if self.authority != cancellation.witness
            || self.subject != cancellation.subject
            || self.operation.credential_binding() != Some(cancellation.binding())
        {
            return Err(Error::Scope);
        }
        match (self.operation.0, self.outcome) {
            (Command::CredentialStatus(_), AnchorOutcome::CredentialClosed)
                if self.head == cancellation.expected =>
            {
                Ok(AnchorCredentialCancellationState::Closed)
            }
            (Command::CredentialStatus(_), AnchorOutcome::CredentialUnavailable) => {
                Ok(AnchorCredentialCancellationState::Unavailable)
            }
            (Command::CredentialAcknowledge(_), AnchorOutcome::CredentialAcknowledged) => {
                Ok(AnchorCredentialCancellationState::Acknowledged)
            }
            (Command::CredentialAcknowledge(_), AnchorOutcome::CredentialUnavailable) => {
                Ok(AnchorCredentialCancellationState::Unavailable)
            }
            _ => Err(Error::State),
        }
    }
    /// The full immutable command this reply answers.
    pub fn command_id(&self) -> [u8; 32] {
        self.command
    }
    /// Last applied transition of the observed subject, or explicit trusted genesis.
    pub fn last_command_id(&self) -> Option<[u8; 32]> {
        self.last
    }
}

fn command_id(
    authority: &[u8; 32],
    subject: AnchorSubject,
    operation: AnchorOperation,
) -> [u8; 32] {
    let mut bytes = authority.to_vec();
    subject.encode(&mut bytes);
    operation.encode(&mut bytes);
    digest(b"Q-PERIAPT-CONTINUITY-ANCHOR-COMMAND/v1", &bytes)
}
fn request_id(body: &[u8]) -> [u8; 32] {
    digest(b"Q-PERIAPT-CONTINUITY-ANCHOR-REQUEST/v1", body)
}
fn encode_last(last: Option<[u8; 32]>, out: &mut Vec<u8>) {
    out.push(u8::from(last.is_some()));
    out.extend_from_slice(&last.unwrap_or([0; 32]));
}
fn decode_last(d: &mut Decoder<'_>, head: AnchorHead) -> Result<Option<[u8; 32]>, Error> {
    let [present] = d.array()?;
    let bytes = d.array()?;
    match present {
        0 if bytes == [0; 32] && head.fence == 1 && head.revision == 1 => Ok(None),
        1 if head.fence != 1 || head.revision != 1 => Ok(Some(bytes)),
        _ => Err(Error::Encoding),
    }
}

struct Incoming<'a> {
    subject: AnchorSubject,
    operation: AnchorOperation,
    command: [u8; 32],
    attempt: [u8; 32],
    body: &'a [u8],
    signature: &'a [u8],
}
fn incoming<'a>(pin: &AnchorPin, wire: &'a [u8]) -> Result<Incoming<'a>, Error> {
    let (body, signature) = open_envelope(wire)?;
    let mut d = Decoder::new(body);
    if d.array::<8>()? != *b"QPANRQ01" || d.array::<32>()? != pin.binding {
        return Err(Error::Scope);
    }
    let subject = AnchorSubject::decode(&mut d)?;
    let command = d.array()?;
    nonzero(&d.array::<32>()?)?;
    let operation = AnchorOperation::decode(&mut d)?;
    d.finish()?;
    if command != command_id(&pin.binding, subject, operation) {
        return Err(Error::Scope);
    }
    Ok(Incoming {
        subject,
        operation,
        command,
        attempt: request_id(body),
        body,
        signature,
    })
}
fn reply(
    pin: &AnchorPin,
    signer: &AnchorSigningKey,
    request: &Incoming<'_>,
    outcome: AnchorOutcome,
    head: AnchorHead,
    last: Option<[u8; 32]>,
) -> Result<Vec<u8>, Error> {
    let mut body = b"QPANRS01".to_vec();
    body.extend_from_slice(&pin.binding);
    request.subject.encode(&mut body);
    body.extend_from_slice(&request.attempt);
    body.extend_from_slice(&request.command);
    body.push(outcome as u8);
    head.encode(&mut body);
    encode_last(last, &mut body);
    envelope(&body, &signer.sign(Purpose::AnchorReply, &body)?)
}
