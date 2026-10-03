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

mod store;
pub use store::AnchorStore;
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
        policy: &VerifiedSessionPolicy,
    ) -> Result<Self, Error> {
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

/// Public enrollment input obtained from an authenticated empty journal at revision 1.
/// It is not an anchor receipt or permission to use that journal without a live witness.
pub struct AnchorGenesis {
    subject: AnchorSubject,
    digest: [u8; 32],
}
impl AnchorGenesis {
    pub(crate) fn from_journal(
        journal: JournalIdentity,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        digest: [u8; 32],
    ) -> Result<Self, Error> {
        nonzero(&digest)?;
        Ok(Self {
            subject: AnchorSubject::for_device(journal, device, policy)?,
            digest,
        })
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Command {
    Query,
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
            Command::Query => {
                out.push(1);
                out.extend_from_slice(&[0; 96]);
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
        if kind == 1 {
            if d.take(96)?.iter().any(|byte| *byte != 0) {
                return Err(Error::Encoding);
            }
            return Ok(Self::query());
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
            Command::Query => None,
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
            _ => return Err(Error::Encoding),
        };
        let head = AnchorHead::decode(&mut d)?;
        let last = decode_last(&mut d, head)?;
        d.finish()?;
        match (request.operation.0, outcome) {
            (Command::Query, AnchorOutcome::Current) => {}
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
}
/// A reply authenticated against the caller's fresh attempt and pinned witness.
pub struct AnchorReply {
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
