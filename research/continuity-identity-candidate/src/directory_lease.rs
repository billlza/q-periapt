// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Accountable one-time prekey assignments. Issuance is separate from durable
//! allocation, requester authentication, dispatch and receiver consumption.
use crate::{
    codec::{generation, nonzero, Decoder},
    crypto::{digest, envelope, open_envelope, Purpose, SIGNATURE_BYTES},
    AuthenticatedPrekeySelection, DirectorySigningKey, Error, LeafKind, PrekeyLeaf,
    PrekeyQuality, PublicKey, Validity, VerifiedDevice, VerifiedSessionPolicy,
};
use q_periapt_backends::ML_KEM_768_PK_LEN;

const LEASE_TAG: &[u8; 8] = b"QPDLSE01";
const CONFLICT_TAG: &[u8; 8] = b"QPDLCF01";
const BODY_BYTES: usize = 8 + 12 * 32 + 16 + 3 * 8 + 68 + 16 + 32 + ML_KEM_768_PK_LEN + 64;
/// Exact signed one-time assignment envelope, including both signatures.
pub const DIRECTORY_LEASE_BYTES: usize = 4 + BODY_BYTES + SIGNATURE_BYTES;
/// Exact portable conflict proof: tag followed by two original signed leases.
pub const DIRECTORY_LEASE_CONFLICT_BYTES: usize = 8 + 2 * DIRECTORY_LEASE_BYTES;

/// Independently provisioned directory identity and exact hybrid verification key.
/// An incoming advertisement or lease cannot establish or replace this pin.
#[derive(Clone)]
pub struct DirectoryPin {
    identity: [u8; 32],
    key: PublicKey,
    binding: [u8; 32],
}
impl DirectoryPin {
    /// Load independently authenticated service configuration.
    pub fn new(identity: [u8; 32], key: PublicKey) -> Result<Self, Error> {
        nonzero(&identity)?;
        let mut bytes = identity.to_vec();
        bytes.extend_from_slice(&key.encode());
        Ok(Self {
            identity,
            key,
            binding: digest(b"Q-PERIAPT-CONTINUITY-DIRECTORY-AUTHORITY/v1", &bytes),
        })
    }
    /// Independently retained service identity.
    pub fn identity(&self) -> [u8; 32] {
        self.identity
    }
    /// Exact pinned key, without signing capability.
    pub fn public_key(&self) -> &PublicKey {
        &self.key
    }
    /// Commitment to both service identity and full verification key.
    pub fn binding(&self) -> [u8; 32] {
        self.binding
    }
    /// Verify a historical signed claim without admitting current use.
    /// Expiry, signer closure and current SDK/policy availability do not erase
    /// attributable history. No manifest, requester or live grant is inferred.
    pub fn verify_historical_lease(&self, wire: &[u8]) -> Result<VerifiedDirectoryLease, Error> {
        if wire.len() != DIRECTORY_LEASE_BYTES {
            return Err(Error::Encoding);
        }
        let (body, signature) = open_envelope(wire)?;
        self.key.verify(Purpose::DirectoryLease, body, signature)?;
        let statement = Statement::decode(body)?;
        if statement.service != self.binding {
            return Err(Error::Scope);
        }
        Ok(VerifiedDirectoryLease {
            statement,
            binding: digest(b"Q-PERIAPT-CONTINUITY-DIRECTORY-LEASE-STATEMENT/v1", body),
            wire: wire.to_vec(),
        })
    }
    /// Verify the exact independently expected allocation against current signed
    /// device, policy and prekey material. The requester fingerprint is supplied
    /// by the host's authentication layer, never learned from this lease.
    pub fn verify_lease(
        &self,
        wire: &[u8],
        request: DirectoryLeaseRequest,
        selection: &AuthenticatedPrekeySelection,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<VerifiedDirectoryLease, Error> {
        let expected = current_statement(self, request, selection, device, policy, now)?;
        let verified = self.verify_historical_lease(wire)?;
        if verified.statement != expected {
            return Err(Error::Scope);
        }
        policy.check_mode(PrekeyQuality::OneTimeBoth, now)?;
        policy.check_device(device, now)?;
        Ok(verified)
    }
}

/// Exact host-retained request. Its fingerprint is an authenticated requester
/// expectation supplied by the caller, not a bearer token or self-authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryLeaseRequest {
    operation: [u8; 32],
    requester: [u8; 32],
    checkpoint: [u8; 32],
    validity: Validity,
}
impl DirectoryLeaseRequest {
    /// Bind the original operation, authenticated requester, independently selected
    /// directory checkpoint and exact half-open lease interval.
    pub fn new(
        operation: [u8; 32],
        requester: [u8; 32],
        checkpoint: [u8; 32],
        validity: Validity,
    ) -> Result<Self, Error> {
        nonzero(&operation)?;
        nonzero(&requester)?;
        nonzero(&checkpoint)?;
        Ok(Self {
            operation,
            requester,
            checkpoint,
            validity,
        })
    }
    /// Original operation identity; changed allocation bytes are not a retry.
    pub fn operation(self) -> [u8; 32] {
        self.operation
    }
    /// Fingerprint supplied by the independent requester authentication layer.
    pub fn requester(self) -> [u8; 32] {
        self.requester
    }
    /// Independently retained directory checkpoint.
    pub fn checkpoint(self) -> [u8; 32] {
        self.checkpoint
    }
    /// Exact permitted use interval; expiration does not make either key reusable.
    pub fn validity(self) -> Validity {
        self.validity
    }
}

/// Signed allocation bytes. A durable service must commit these exact bytes and
/// its global key occupancy before dispatch; this owner does not do that itself.
pub struct IssuedDirectoryLease {
    wire: Vec<u8>,
}
impl IssuedDirectoryLease {
    /// Original signed receipt. Retain it for byte-identical operation retries.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }
}

#[derive(Clone, Eq, PartialEq)]
struct Statement {
    service: [u8; 32],
    request: DirectoryLeaseRequest,
    account: [u8; 32],
    device: [u8; 16],
    generation: u64,
    credential: [u8; 32],
    authority: [u8; 32],
    manifest: [u8; 32],
    selection: [u8; 32],
    epoch: u64,
    family: [u8; 32],
    policy_version: u64,
    policy_digest: [u8; 32],
    sdk: [u8; 68],
    suite: [u8; 32],
    classical: [u8; 32],
    pq: [u8; ML_KEM_768_PK_LEN],
    classical_fingerprint: [u8; 32],
    pq_fingerprint: [u8; 32],
}
impl Statement {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BODY_BYTES);
        out.extend_from_slice(LEASE_TAG);
        out.extend_from_slice(&self.service);
        out.extend_from_slice(&self.request.operation);
        out.extend_from_slice(&self.request.requester);
        out.extend_from_slice(&self.request.checkpoint);
        out.extend_from_slice(&self.account);
        out.extend_from_slice(&self.device);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.credential);
        out.extend_from_slice(&self.authority);
        out.extend_from_slice(&self.manifest);
        out.extend_from_slice(&self.selection);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.family);
        out.extend_from_slice(&self.policy_version.to_be_bytes());
        out.extend_from_slice(&self.policy_digest);
        out.extend_from_slice(&self.sdk);
        out.extend_from_slice(&self.suite);
        self.request.validity.encode(&mut out);
        out.extend_from_slice(&self.classical);
        out.extend_from_slice(&self.pq);
        out.extend_from_slice(&self.classical_fingerprint);
        out.extend_from_slice(&self.pq_fingerprint);
        out
    }
    fn decode(body: &[u8]) -> Result<Self, Error> {
        if body.len() != BODY_BYTES {
            return Err(Error::Encoding);
        }
        let mut d = Decoder::new(body);
        if d.array::<8>()? != *LEASE_TAG {
            return Err(Error::Encoding);
        }
        let service = d.array()?;
        let operation = d.array()?;
        let requester = d.array()?;
        let checkpoint = d.array()?;
        let account = d.array()?;
        let device = d.array()?;
        let generation_value = d.u64()?;
        let credential = d.array()?;
        let authority = d.array()?;
        let manifest = d.array()?;
        let selection = d.array()?;
        let epoch = d.u64()?;
        let family = d.array()?;
        let policy_version = d.u64()?;
        let policy_digest = d.array()?;
        let sdk: [u8; 68] = d.array()?;
        let suite = d.array()?;
        let validity = Validity::decode(&mut d)?;
        let classical: [u8; 32] = d.array()?;
        let pq: [u8; ML_KEM_768_PK_LEN] = d.array()?;
        let classical_fingerprint = d.array()?;
        let pq_fingerprint = d.array()?;
        d.finish()?;
        let request = DirectoryLeaseRequest::new(operation, requester, checkpoint, validity)?;
        for value in [
            &service,
            &account,
            &credential,
            &authority,
            &manifest,
            &selection,
            &family,
            &policy_digest,
        ] {
            nonzero(value)?;
        }
        nonzero(&device)?;
        generation(generation_value)?;
        generation(epoch)?;
        generation(policy_version)?;
        let sdk_authority: [u8; 32] = sdk
            .get(..32)
            .ok_or(Error::Encoding)?
            .try_into()
            .map_err(|_| Error::Encoding)?;
        nonzero(&sdk_authority)?;
        q_periapt_policy::TrustedPolicyState::decode(sdk.get(32..).ok_or(Error::Encoding)?)
            .map_err(|_| Error::Encoding)?;
        if suite != crate::bootstrap_suite_digest()
            || fingerprint(LeafKind::OneTimeClassical, &classical, validity)? != classical_fingerprint
            || fingerprint(LeafKind::OneTimePq, &pq, validity)? != pq_fingerprint
        {
            return Err(Error::Scope);
        }
        Ok(Self {
            service,
            request,
            account,
            device,
            generation: generation_value,
            credential,
            authority,
            manifest,
            selection,
            epoch,
            family,
            policy_version,
            policy_digest,
            sdk,
            suite,
            classical,
            pq,
            classical_fingerprint,
            pq_fingerprint,
        })
    }
}
fn fingerprint(kind: LeafKind, public: &[u8], validity: Validity) -> Result<[u8; 32], Error> {
    Ok(PrekeyLeaf::new(kind, public, validity)?.key_fingerprint())
}

fn current_statement(
    pin: &DirectoryPin,
    request: DirectoryLeaseRequest,
    selection: &AuthenticatedPrekeySelection,
    device: &VerifiedDevice,
    policy: &VerifiedSessionPolicy,
    now: u64,
) -> Result<Statement, Error> {
    policy.check_mode(PrekeyQuality::OneTimeBoth, now)?;
    policy.check_device(device, now)?;
    selection.check_time(now)?;
    request.validity.check(now)?;
    let context = selection.manifest_context();
    if selection.quality() != PrekeyQuality::OneTimeBoth
        || selection.classical().kind() != LeafKind::OneTimeClassical
        || selection.post_quantum().kind() != LeafKind::OneTimePq
        || !selection.matches_device(device)
        || context.directory_checkpoint() != request.checkpoint
        || context.policy_digest() != policy.runtime.trusted_state().digest()
        || context.suite_digest() != crate::bootstrap_suite_digest()
        || pin.key.shares_component(&device.key)
        || pin.key.shares_component(device.roster().continuation_authority().0)
    {
        return Err(Error::Scope);
    }
    policy.check_external_signer(&pin.key)?;
    if !selection.validity().contains(request.validity)
        || !policy.validity().contains(request.validity)
    {
        return Err(Error::Validity);
    }
    Ok(Statement {
        service: pin.binding,
        request,
        account: device.account_id(),
        device: device.device_id(),
        generation: device.generation(),
        credential: device.credential_digest(),
        authority: device.authority_binding(),
        manifest: selection.manifest_digest(),
        selection: selection.digest(),
        epoch: context.bundle_epoch(),
        family: policy.family(),
        policy_version: policy.checkpoint().version(),
        policy_digest: policy.checkpoint().digest(),
        sdk: policy.sdk_binding(),
        suite: context.suite_digest(),
        classical: selection
            .classical()
            .public_key()
            .try_into()
            .map_err(|_| Error::Encoding)?,
        pq: selection
            .post_quantum()
            .public_key()
            .try_into()
            .map_err(|_| Error::Encoding)?,
        classical_fingerprint: selection.classical().key_fingerprint(),
        pq_fingerprint: selection.post_quantum().key_fingerprint(),
    })
}
impl DirectorySigningKey {
    /// Sign only a current, independently scoped OneTimeBoth allocation. Service
    /// authentication, durable global occupancy and exact replay are obligations
    /// of the caller; repeated calls can produce different signatures of one body.
    pub fn issue_lease(
        &self,
        pin: &DirectoryPin,
        request: DirectoryLeaseRequest,
        selection: &AuthenticatedPrekeySelection,
        device: &VerifiedDevice,
        policy: &VerifiedSessionPolicy,
        now: u64,
    ) -> Result<IssuedDirectoryLease, Error> {
        if self.public_key()? != pin.key {
            return Err(Error::Scope);
        }
        let statement = current_statement(pin, request, selection, device, policy, now)?;
        let body = statement.encode();
        if body.len() != BODY_BYTES {
            return Err(Error::Encoding);
        }
        let wire = envelope(&body, &self.sign(Purpose::DirectoryLease, &body)?)?;
        policy.check_mode(PrekeyQuality::OneTimeBoth, now)?;
        policy.check_device(device, now)?;
        Ok(IssuedDirectoryLease { wire })
    }
}

/// Authenticated historical service assertion. Its presence alone grants neither
/// current traffic authority nor proof of durable occupancy or receiver consumption.
pub struct VerifiedDirectoryLease {
    statement: Statement,
    binding: [u8; 32],
    wire: Vec<u8>,
}
impl VerifiedDirectoryLease {
    /// Original signed bytes, suitable for independent historical verification.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }
    /// Immutable assignment commitment, independent of signature randomness.
    pub fn statement_digest(&self) -> [u8; 32] {
        self.binding
    }
    /// Exact independently pinned service identity/key commitment.
    pub fn service_binding(&self) -> [u8; 32] {
        self.statement.service
    }
    /// Signed request identity, requester expectation, checkpoint and interval.
    pub fn request(&self) -> DirectoryLeaseRequest {
        self.statement.request
    }
    /// Signed manifest body commitment.
    pub fn manifest_digest(&self) -> [u8; 32] {
        self.statement.manifest
    }
    /// Complete authenticated prekey-selection commitment.
    pub fn selection_digest(&self) -> [u8; 32] {
        self.statement.selection
    }
    /// Compare original request and authenticated selection for historical replay.
    /// This does not require a live policy or interval and grants no fresh use.
    pub fn matches_request(
        &self,
        request: DirectoryLeaseRequest,
        selection: &AuthenticatedPrekeySelection,
    ) -> bool {
        self.statement.request == request
            && selection.quality() == PrekeyQuality::OneTimeBoth
            && request.checkpoint() == selection.manifest_context().directory_checkpoint()
            && self.statement.selection == selection.digest()
            && self.statement.manifest == selection.manifest_digest()
            && self.statement.epoch == selection.manifest_context().bundle_epoch()
            && self.statement.classical.as_slice() == selection.classical().public_key()
            && self.statement.pq.as_slice() == selection.post_quantum().public_key()
            && self.classical_fingerprint() == selection.classical().key_fingerprint()
            && self.post_quantum_fingerprint() == selection.post_quantum().key_fingerprint()
    }
    /// Algorithm-tagged exact public-key fingerprint, stable across epochs/manifests.
    pub fn classical_fingerprint(&self) -> [u8; 32] {
        self.statement.classical_fingerprint
    }
    /// Algorithm-tagged exact public-key fingerprint, stable across epochs/manifests.
    pub fn post_quantum_fingerprint(&self) -> [u8; 32] {
        self.statement.pq_fingerprint
    }
}

/// Two valid signatures by the same pinned service assigning at least one
/// one-time public key to different immutable allocation bodies. Exact body
/// replay is not a conflict, even if the signatures differ. Non-overlapping
/// lease intervals, different manifests or epochs do not permit key reuse.
pub struct DirectoryLeaseConflict {
    first: VerifiedDirectoryLease,
    second: VerifiedDirectoryLease,
    classical: bool,
    pq: bool,
}
impl DirectoryLeaseConflict {
    /// Verify both original service signatures and a shared exact public key.
    /// This historical check requires no current policy, signer or wall clock.
    pub fn verify(pin: &DirectoryPin, first: &[u8], second: &[u8]) -> Result<Self, Error> {
        let mut first = pin.verify_historical_lease(first)?;
        let mut second = pin.verify_historical_lease(second)?;
        if first.statement == second.statement {
            return Err(Error::Scope);
        }
        let classical = first.classical_fingerprint() == second.classical_fingerprint()
            && first.statement.classical == second.statement.classical;
        let pq = first.post_quantum_fingerprint() == second.post_quantum_fingerprint()
            && first.statement.pq == second.statement.pq;
        if !classical && !pq {
            return Err(Error::Scope);
        }
        if (&first.binding, &first.wire) > (&second.binding, &second.wire) {
            std::mem::swap(&mut first, &mut second);
        }
        Ok(Self {
            first,
            second,
            classical,
            pq,
        })
    }
    /// Decode a bounded canonical proof and verify both original signatures.
    /// Reversed receipt order is rejected rather than silently normalized.
    pub fn from_bytes(pin: &DirectoryPin, wire: &[u8]) -> Result<Self, Error> {
        if wire.len() != DIRECTORY_LEASE_CONFLICT_BYTES {
            return Err(Error::Encoding);
        }
        let mut d = Decoder::new(wire);
        if d.array::<8>()? != *CONFLICT_TAG {
            return Err(Error::Encoding);
        }
        let first = d.take(DIRECTORY_LEASE_BYTES)?;
        let second = d.take(DIRECTORY_LEASE_BYTES)?;
        d.finish()?;
        let proof = Self::verify(pin, first, second)?;
        // The unordered verification API normalizes inputs. An archived container
        // must already use that order, so one receipt pair has one outer encoding.
        if proof.first.as_bytes() != first || proof.second.as_bytes() != second {
            return Err(Error::Encoding);
        }
        Ok(proof)
    }
    /// Serialize both original receipts in stable statement-commitment order.
    /// Full wire bytes break a hypothetical digest collision deterministically.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DIRECTORY_LEASE_CONFLICT_BYTES);
        out.extend_from_slice(CONFLICT_TAG);
        out.extend_from_slice(self.first.as_bytes());
        out.extend_from_slice(self.second.as_bytes());
        out
    }
    /// One original authenticated allocation.
    pub fn first(&self) -> &VerifiedDirectoryLease {
        &self.first
    }
    /// The other original authenticated allocation.
    pub fn second(&self) -> &VerifiedDirectoryLease {
        &self.second
    }
    /// Whether the conflicting assignments reuse the classical one-time key.
    pub fn classical_conflict(&self) -> bool {
        self.classical
    }
    /// Whether the conflicting assignments reuse the PQ one-time key.
    pub fn post_quantum_conflict(&self) -> bool {
        self.pq
    }
}
