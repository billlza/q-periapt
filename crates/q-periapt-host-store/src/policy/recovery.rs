// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independently pinned, bounded recovery of the online SDK policy authority.
use super::*;
use q_periapt_backends::MlDsa65;
use q_periapt_sig::Verifier;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub(super) const SCHEMA_RECOVERY: &[u8] = b"QPeriapt-Host-Policy-v2";
const TAG: &[u8; 8] = b"QPRCV001";
const REQUEST_BYTES: usize = 8 + 32 + 8 + 32 + 32 + 36 + 32 + ML_DSA_65_VK_LEN + 36;
const TRUST_BYTES: usize = 32 + 2 * ML_DSA_65_VK_LEN;
const HISTORY_ENTRY_BYTES: usize = 96;
/// Lifetime bound on explicitly authorized root replacements in one store.
/// Ordinary online policy updates cannot consume this independent budget.
pub const MAX_POLICY_AUTHORITY_RECOVERIES: usize = 4096;
/// Exact encoded recovery statement plus independent authority and incoming-key signatures.
pub const POLICY_RECOVERY_AUTHORIZATION_BYTES: usize = REQUEST_BYTES + 2 * ML_DSA_65_SIG_LEN;

fn hash(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(bytes);
    h.finalize().into()
}
fn root_digest(root: &[u8]) -> [u8; 32] {
    Sha256::digest(root).into()
}
fn message(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + body.len());
    out.extend_from_slice(domain);
    out.extend_from_slice(body);
    out
}
fn take<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], StoreError> {
    let (value, rest) = input
        .split_at_checked(N)
        .ok_or(StoreError::RecoveryDenied)?;
    *input = rest;
    value.try_into().map_err(|_| StoreError::RecoveryDenied)
}
fn verify(key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), StoreError> {
    if signature.len() != ML_DSA_65_SIG_LEN {
        return Err(StoreError::RecoveryDenied);
    }
    MlDsa65
        .verify(key, message, signature)
        .map_err(|_| StoreError::RecoveryDenied)
}

/// Original independently supplied deployment and two distinct ML-DSA-65 roots.
/// Retain this configuration outside incoming policy/recovery messages. The
/// recovery key must remain independent of the online policy key. It is immutable
/// in this profile; losing/compromising it requires a separate trust ceremony.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyRecoveryTrust {
    scope: [u8; 32],
    initial: [u8; ML_DSA_65_VK_LEN],
    recovery: [u8; ML_DSA_65_VK_LEN],
}
impl PolicyRecoveryTrust {
    /// Explicit first-use configuration; this never enrolls an existing v1 store.
    pub fn new(
        scope: [u8; 32],
        initial_root: &[u8],
        recovery_root: &[u8],
    ) -> Result<Self, StoreError> {
        if scope == [0; 32] || initial_root == recovery_root {
            return Err(StoreError::RecoveryDenied);
        }
        Ok(Self {
            scope,
            initial: initial_root
                .try_into()
                .map_err(|_| StoreError::RecoveryDenied)?,
            recovery: recovery_root
                .try_into()
                .map_err(|_| StoreError::RecoveryDenied)?,
        })
    }
    fn encode(&self) -> Vec<u8> {
        let mut out = self.scope.to_vec();
        out.extend_from_slice(&self.initial);
        out.extend_from_slice(&self.recovery);
        out
    }
    fn decode(mut bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() != TRUST_BYTES {
            return Err(StoreError::RecoveryDenied);
        }
        Self::new(
            take(&mut bytes)?,
            &take::<ML_DSA_65_VK_LEN>(&mut bytes)?,
            &take::<ML_DSA_65_VK_LEN>(&mut bytes)?,
        )
    }
    /// Commitment to the original scope and both independent roots. This is
    /// descriptive metadata, never a signature or durable receipt.
    pub fn binding(&self) -> [u8; 32] {
        hash(b"Q-PERIAPT-SDK-RECOVERY-TRUST/v1", &self.encode())
    }
    /// Sign once using the independent recovery key before provisioning. This
    /// proves possession of the configured recovery key, not authority from a peer.
    pub fn enrollment_message(&self) -> Vec<u8> {
        message(b"Q-PERIAPT-SDK-RECOVERY-ENROLL/v1", &self.encode())
    }
}

/// Exact, bounded statement to retain before requesting either signature.
/// Parsing grants no authority. Both roles sign this same transition under
/// distinct domains; an old signature on the candidate policy cannot substitute.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyRecoveryRequest {
    trust: [u8; 32],
    generation: u64,
    operation: [u8; 32],
    previous_root: [u8; 32],
    previous: TrustedPolicyState,
    history: [u8; 32],
    root: [u8; ML_DSA_65_VK_LEN],
    next: TrustedPolicyState,
}
impl PolicyRecoveryRequest {
    /// Restore exact canonical public statement bytes; signatures remain unverified.
    pub fn from_bytes(mut bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() != REQUEST_BYTES || take::<8>(&mut bytes)? != *TAG {
            return Err(StoreError::RecoveryDenied);
        }
        let trust = take(&mut bytes)?;
        let generation = u64::from_be_bytes(take(&mut bytes)?);
        let operation = take(&mut bytes)?;
        let previous_root = take(&mut bytes)?;
        let previous = TrustedPolicyState::decode(&take::<36>(&mut bytes)?)
            .map_err(|_| StoreError::RecoveryDenied)?;
        let history = take(&mut bytes)?;
        let root = take(&mut bytes)?;
        let next = TrustedPolicyState::decode(&take::<36>(&mut bytes)?)
            .map_err(|_| StoreError::RecoveryDenied)?;
        if generation == 0
            || generation > MAX_POLICY_AUTHORITY_RECOVERIES as u64
            || operation == [0; 32]
        {
            return Err(StoreError::RecoveryDenied);
        }
        Ok(Self {
            trust,
            generation,
            operation,
            previous_root,
            previous,
            history,
            root,
            next,
        })
    }
    /// Canonical original statement. Keep it and the original signatures across retries.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(REQUEST_BYTES);
        out.extend_from_slice(TAG);
        out.extend_from_slice(&self.trust);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.extend_from_slice(&self.operation);
        out.extend_from_slice(&self.previous_root);
        out.extend_from_slice(&self.previous.encode());
        out.extend_from_slice(&self.history);
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.next.encode());
        out
    }
    /// Original independently configured trust commitment for issuer comparison.
    pub fn trust_binding(&self) -> [u8; 32] {
        self.trust
    }
    /// SHA-256 of the exact predecessor online root for issuer comparison.
    pub fn previous_root_digest(&self) -> [u8; 32] {
        self.previous_root
    }
    /// Original public operation identity, never a receipt or permission token.
    pub fn operation(&self) -> [u8; 32] {
        self.operation
    }
    /// Recovery generation, exactly one above the predecessor's retained history.
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// Independently approved previous and next online policy states.
    pub fn states(&self) -> (TrustedPolicyState, TrustedPolicyState) {
        (self.previous, self.next)
    }
    /// Candidate root which the offline approver must independently inspect.
    pub fn replacement_root(&self) -> &[u8] {
        &self.root
    }
    /// Full transition message for the independently pinned recovery signer.
    pub fn authorization_message(&self) -> Vec<u8> {
        message(b"Q-PERIAPT-SDK-RECOVERY-AUTHORIZE/v1", &self.to_bytes())
    }
    /// Full transition proof of possession for the incoming online policy key.
    pub fn possession_message(&self) -> Vec<u8> {
        message(b"Q-PERIAPT-SDK-RECOVERY-POSSESSION/v1", &self.to_bytes())
    }
    fn digest(&self) -> [u8; 32] {
        hash(b"Q-PERIAPT-SDK-RECOVERY-REQUEST/v1", &self.to_bytes())
    }
}

/// Original request and its two signatures; construction/decoding does not verify them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyRecoveryAuthorization {
    request: PolicyRecoveryRequest,
    approval: Vec<u8>,
    possession: Vec<u8>,
}
impl PolicyRecoveryAuthorization {
    /// Assemble bounded approvals without interpreting either as verified authority.
    pub fn new(
        request: PolicyRecoveryRequest,
        approval: &[u8],
        possession: &[u8],
    ) -> Result<Self, StoreError> {
        if approval.len() != ML_DSA_65_SIG_LEN || possession.len() != ML_DSA_65_SIG_LEN {
            return Err(StoreError::RecoveryDenied);
        }
        Ok(Self {
            request,
            approval: approval.to_vec(),
            possession: possession.to_vec(),
        })
    }
    /// Parse the exact fixed-length container. Trailing/truncated input is rejected.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() != POLICY_RECOVERY_AUTHORIZATION_BYTES {
            return Err(StoreError::RecoveryDenied);
        }
        let (request, signatures) = bytes
            .split_at_checked(REQUEST_BYTES)
            .ok_or(StoreError::RecoveryDenied)?;
        let (approval, possession) = signatures
            .split_at_checked(ML_DSA_65_SIG_LEN)
            .ok_or(StoreError::RecoveryDenied)?;
        Self::new(
            PolicyRecoveryRequest::from_bytes(request)?,
            approval,
            possession,
        )
    }
    /// Exact original signed container to retain for uncertain-outcome recovery.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.request.to_bytes();
        out.extend_from_slice(&self.approval);
        out.extend_from_slice(&self.possession);
        out
    }
    /// Public statement, not evidence that this operation has committed.
    pub fn request(&self) -> &PolicyRecoveryRequest {
        &self.request
    }
    fn verify(&self, trust: &PolicyRecoveryTrust) -> Result<(), StoreError> {
        if self.request.trust != trust.binding() || self.request.root == trust.recovery {
            return Err(StoreError::RecoveryDenied);
        }
        verify(
            &trust.recovery,
            &self.request.authorization_message(),
            &self.approval,
        )?;
        verify(
            &self.request.root,
            &self.request.possession_message(),
            &self.possession,
        )
    }
}

/// Durable outcome of the exact original recovery operation, not a freshness claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyRecoveryOutcome {
    /// This call committed the original request and activated its successor.
    Applied,
    /// That request was already committed and its exact policy remains current.
    AlreadyApplied,
    /// That request committed, but a later policy/root is now current. Never roll back.
    AppliedThenAdvanced,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Entry {
    root: [u8; 32],
    operation: [u8; 32],
    request: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RecoveryImage {
    trust: PolicyRecoveryTrust,
    enrollment: Vec<u8>,
    history: Vec<Entry>,
    receipt: Option<PolicyRecoveryAuthorization>,
}
impl RecoveryImage {
    fn initial(trust: &PolicyRecoveryTrust, enrollment: &[u8]) -> Result<Self, StoreError> {
        verify(&trust.recovery, &trust.enrollment_message(), enrollment)?;
        Ok(Self {
            trust: trust.clone(),
            enrollment: enrollment.to_vec(),
            history: vec![Entry {
                root: root_digest(&trust.initial),
                operation: [0; 32],
                request: [0; 32],
            }],
            receipt: None,
        })
    }
    fn history_bytes(&self) -> Vec<u8> {
        encode_history(&self.history)
    }
    fn history_digest(&self) -> [u8; 32] {
        history_digest(&self.history)
    }
    pub(super) fn write(&self, table: &mut redb::Table<&str, &[u8]>) -> Result<(), StoreError> {
        for (name, bytes) in [
            ("recovery_trust", self.trust.encode()),
            ("recovery_enrollment", self.enrollment.clone()),
            ("recovery_history", self.history_bytes()),
            (
                "recovery_receipt",
                self.receipt
                    .as_ref()
                    .map_or_else(Vec::new, PolicyRecoveryAuthorization::to_bytes),
            ),
        ] {
            table.insert(name, bytes.as_slice()).map_err(storage)?;
        }
        Ok(())
    }
    pub(super) fn read(
        table: &impl ReadableTable<&'static str, &'static [u8]>,
    ) -> Result<Self, StoreError> {
        let trust = PolicyRecoveryTrust::decode(&field(
            table,
            "recovery_trust",
            TRUST_BYTES,
            TRUST_BYTES,
        )?)?;
        let enrollment = field(
            table,
            "recovery_enrollment",
            ML_DSA_65_SIG_LEN,
            ML_DSA_65_SIG_LEN,
        )?;
        let wire = field(
            table,
            "recovery_history",
            HISTORY_ENTRY_BYTES,
            (MAX_POLICY_AUTHORITY_RECOVERIES + 1) * HISTORY_ENTRY_BYTES,
        )?;
        let (entries, remainder) = wire.as_chunks::<HISTORY_ENTRY_BYTES>();
        if !remainder.is_empty() {
            return Err(StoreError::Corrupt);
        }
        let mut history = Vec::with_capacity(entries.len());
        for entry in entries {
            let mut chunk = entry.as_slice();
            history.push(Entry {
                root: take(&mut chunk)?,
                operation: take(&mut chunk)?,
                request: take(&mut chunk)?,
            });
        }
        let receipt = field(
            table,
            "recovery_receipt",
            0,
            POLICY_RECOVERY_AUTHORIZATION_BYTES,
        )?;
        let receipt = if receipt.is_empty() {
            None
        } else {
            Some(PolicyRecoveryAuthorization::from_bytes(&receipt)?)
        };
        Ok(Self {
            trust,
            enrollment,
            history,
            receipt,
        })
    }
    pub(super) fn verify(
        &self,
        trust: &PolicyRecoveryTrust,
        root: &[u8],
        state: TrustedPolicyState,
    ) -> Result<(), StoreError> {
        if &self.trust != trust {
            return Err(StoreError::RootMismatch);
        }
        verify(
            &trust.recovery,
            &trust.enrollment_message(),
            &self.enrollment,
        )?;
        let (first, remaining) = self.history.split_first().ok_or(StoreError::Corrupt)?;
        if first
            != &(Entry {
                root: root_digest(&trust.initial),
                operation: [0; 32],
                request: [0; 32],
            })
            || remaining.len() > MAX_POLICY_AUTHORITY_RECOVERIES
        {
            return Err(StoreError::Corrupt);
        }
        let mut roots = BTreeSet::from([first.root]);
        let mut operations = BTreeSet::new();
        for entry in remaining {
            if entry.operation == [0; 32]
                || !roots.insert(entry.root)
                || !operations.insert(entry.operation)
                || entry.root == root_digest(&trust.recovery)
            {
                return Err(StoreError::Corrupt);
            }
        }
        let (last, prefix) = self.history.split_last().ok_or(StoreError::Corrupt)?;
        if last.root != root_digest(root) {
            return Err(StoreError::Corrupt);
        }
        match &self.receipt {
            None if remaining.is_empty() && root == trust.initial => Ok(()),
            Some(receipt) if !remaining.is_empty() => {
                receipt.verify(trust)?;
                let r = &receipt.request;
                if r.generation != remaining.len() as u64
                    || r.history != history_digest(prefix)
                    || prefix.last().is_none_or(|e| e.root != r.previous_root)
                    || last.operation != r.operation
                    || last.request != r.digest()
                    || root != r.root
                    || state.version() < r.next.version()
                    || (state.version() == r.next.version() && state != r.next)
                {
                    return Err(StoreError::Corrupt);
                }
                Ok(())
            }
            _ => Err(StoreError::Corrupt),
        }
    }
}
fn encode_history(entries: &[Entry]) -> Vec<u8> {
    let mut out = Vec::with_capacity(entries.len() * HISTORY_ENTRY_BYTES);
    for entry in entries {
        out.extend_from_slice(&entry.root);
        out.extend_from_slice(&entry.operation);
        out.extend_from_slice(&entry.request);
    }
    out
}
fn history_digest(entries: &[Entry]) -> [u8; 32] {
    hash(
        b"Q-PERIAPT-SDK-RECOVERY-HISTORY/v1",
        &encode_history(entries),
    )
}

impl PolicyStore {
    /// Provision a new recoverable store using the original independently retained
    /// trust configuration and its recovery-key enrollment proof. Existing paths
    /// are never overwritten or enrolled implicitly. This fixed one-key recovery
    /// profile does not implement threshold governance or recovery-key rotation.
    pub fn provision_recoverable(
        path: &Path,
        policy: &[u8],
        signature: &[u8],
        trust: &PolicyRecoveryTrust,
        enrollment_signature: &[u8],
        limits: Limits,
    ) -> Result<Self, StoreError> {
        let recovery = RecoveryImage::initial(trust, enrollment_signature)?;
        let owner =
            PolicyOwner::from_signed_policy(policy, signature, &trust.initial, None, limits)?;
        let database = provision_private_database(path, |database| {
            let transaction = write_transaction(database)?;
            if let Err(error) = write_image(
                &transaction,
                None,
                &trust.initial,
                policy,
                signature,
                owner.trusted_state(),
                Some(&recovery),
            ) {
                transaction.abort().map_err(storage)?;
                return Err(error);
            }
            transaction.commit().map_err(StoreError::CommitUncertain)?;
            Ok::<_, StoreError>(())
        })?;
        Ok(Self {
            active: Some(Active {
                database,
                owner,
                root: trust.initial.to_vec(),
                recovery: Some(recovery),
            }),
        })
    }

    /// Reopen an existing recovery-enabled store and authenticate its entire
    /// authority image before lending a runtime. The exact ORIGINAL trust must
    /// come from the host, never from the incoming candidate or database alone.
    /// Whole-disk rollback protection is not supplied by protected-file storage.
    /// Reconcile an uncertain recovery through `open_recovering` instead.
    pub fn open_recoverable(
        path: &Path,
        trust: &PolicyRecoveryTrust,
        limits: Limits,
    ) -> Result<Self, StoreError> {
        Self::open_inner(path, &trust.initial, Some(trust), limits)
    }

    /// Reconcile a desired ordinary policy update under the currently authorized
    /// root before exposing a runtime. Use this after uncertain normal updates;
    /// use `open_recovering` for uncertain root-recovery operations. Neither path
    /// treats an older, missing or invalid image as first provisioning.
    pub fn open_recoverable_configured(
        path: &Path,
        trust: &PolicyRecoveryTrust,
        policy: &[u8],
        signature: &[u8],
        limits: Limits,
    ) -> Result<Self, StoreError> {
        let mut store = Self::open_recoverable(path, trust, limits)?;
        let active = store.active.as_ref().ok_or(StoreError::Closed)?;
        let previous = active.owner.trusted_state();
        let requested =
            Runtime::from_signed_policy(policy, signature, &active.root, Some(&previous), limits)?;
        if requested.trusted_state() != previous {
            store.replace_policy(previous, policy, signature)?;
        }
        Ok(store)
    }

    /// Build an exact request without reserving authority, changing state, or
    /// releasing a candidate runtime. Generate a nonzero operation ID once and
    /// retain this statement before collecting independent authorization and
    /// incoming-key possession proofs. A concurrent policy change makes it stale.
    pub fn prepare_authority_recovery(
        &self,
        operation: [u8; 32],
        policy: &[u8],
        signature: &[u8],
        root: &[u8],
    ) -> Result<PolicyRecoveryRequest, StoreError> {
        let active = self.active.as_ref().ok_or(StoreError::Closed)?;
        let recovery = active
            .recovery
            .as_ref()
            .ok_or(StoreError::RecoveryRequired)?;
        if recovery.history.len() > MAX_POLICY_AUTHORITY_RECOVERIES {
            return Err(StoreError::RecoveryLimit);
        }
        if operation == [0; 32]
            || root == recovery.trust.recovery
            || recovery
                .history
                .iter()
                .any(|e| e.operation == operation || e.root == root_digest(root))
        {
            return Err(StoreError::RecoveryDenied);
        }
        let update = active
            .owner
            .prepare_authority_replacement(policy, signature, root)?;
        let (previous, next) = update.states()?;
        Ok(PolicyRecoveryRequest {
            trust: recovery.trust.binding(),
            generation: recovery.history.len() as u64,
            operation,
            previous_root: root_digest(&active.root),
            previous,
            history: recovery.history_digest(),
            root: root.try_into().map_err(|_| StoreError::RecoveryDenied)?,
            next,
        })
    }

    /// Verify BOTH role signatures and the exact predecessor; durably commit the
    /// new root/policy/history/receipt before revoking old aliases and activating.
    /// Historical roots and operation IDs cannot be reused. Every normal update
    /// still requires a strictly greater policy version under the current root.
    /// Rejected signatures/stale requests leave the current owner unchanged.
    /// Storage, uncertain commit and post-commit activation errors close the store.
    /// Retry only the original signed authorization and exact target policy.
    pub fn recover_authority(
        &mut self,
        authorization: &PolicyRecoveryAuthorization,
        policy: &[u8],
        signature: &[u8],
    ) -> Result<PolicyRecoveryOutcome, StoreError> {
        let active = self.active.as_mut().ok_or(StoreError::Closed)?;
        active.owner.runtime()?;
        let recovery = active
            .recovery
            .as_ref()
            .ok_or(StoreError::RecoveryRequired)?;
        authorization.verify(&recovery.trust)?;
        let request = &authorization.request;
        // Verification-only runtime; it is never exposed or used for operations.
        // Product successor preparation below inherits the original owner's limits.
        let proposed =
            Runtime::from_signed_policy(policy, signature, &request.root, None, Limits::default())?;
        if proposed.trusted_state() != request.next {
            return Err(StoreError::RecoveryDenied);
        }
        if let Some((generation, entry)) = recovery
            .history
            .iter()
            .enumerate()
            .find(|(_, e)| e.operation == request.operation)
        {
            if generation as u64 != request.generation
                || entry.request != request.digest()
                || entry.root != root_digest(&request.root)
            {
                return Err(StoreError::RecoveryDenied);
            }
            return Ok(
                if generation + 1 == recovery.history.len()
                    && active.owner.trusted_state() == request.next
                {
                    PolicyRecoveryOutcome::AlreadyApplied
                } else {
                    PolicyRecoveryOutcome::AppliedThenAdvanced
                },
            );
        }
        if recovery.history.len() > MAX_POLICY_AUTHORITY_RECOVERIES {
            return Err(StoreError::RecoveryLimit);
        }
        if request.generation != recovery.history.len() as u64
            || request.previous_root != root_digest(&active.root)
            || request.previous != active.owner.trusted_state()
            || request.history != recovery.history_digest()
        {
            return Err(StoreError::Stale);
        }
        if recovery
            .history
            .iter()
            .any(|e| e.root == root_digest(&request.root))
        {
            return Err(StoreError::RecoveryDenied);
        }
        let update =
            active
                .owner
                .prepare_authority_replacement(policy, signature, &request.root)?;
        let (_, next) = update.states()?;
        if next != request.next {
            return Err(StoreError::RecoveryDenied);
        }
        let mut successor = recovery.clone();
        successor.history.push(Entry {
            root: root_digest(&request.root),
            operation: request.operation,
            request: request.digest(),
        });
        successor.receipt = Some(authorization.clone());
        let next_root = request.root.to_vec();
        // Preserve ownership through unwinding, including after a real commit.
        // Active::drop revokes every alias; self stays closed until completion.
        let mut active = self.active.take().ok_or(StoreError::Closed)?;
        let outcome: Result<PolicyOwner, StoreError> = (|| {
            let transaction = write_transaction(&active.database)?;
            {
                let mut table = transaction.open_table(TABLE).map_err(storage)?;
                let image = read_image(&table, Some(&active.root))?;
                if image.state != request.previous || image.recovery != active.recovery {
                    return Err(StoreError::Corrupt);
                }
                write_fields(
                    &mut table,
                    &request.root,
                    policy,
                    signature,
                    next,
                    Some(&successor),
                )?;
            }
            transaction.commit().map_err(StoreError::CommitUncertain)?;
            #[cfg(all(test, unix))]
            tests::after_recovery_commit();
            let owner = update
                .activate_after_persist()
                .map_err(StoreError::ActivationAfterCommit)?;
            Ok(owner)
        })();
        let owner = outcome?;
        active.owner = owner;
        active.root = next_root;
        active.recovery = Some(successor);
        self.active = Some(active);
        Ok(PolicyRecoveryOutcome::Applied)
    }

    /// Reconcile the original uncertain recovery BEFORE exposing any runtime.
    /// This can apply the unchanged request to its exact predecessor or recognize
    /// its retained receipt after later updates. Any other state fails explicitly;
    /// an old image is never silently returned as a successful recovery.
    pub fn open_recovering(
        path: &Path,
        trust: &PolicyRecoveryTrust,
        authorization: &PolicyRecoveryAuthorization,
        policy: &[u8],
        signature: &[u8],
        limits: Limits,
    ) -> Result<(Self, PolicyRecoveryOutcome), StoreError> {
        let mut store = Self::open_recoverable(path, trust, limits)?;
        let outcome = store.recover_authority(authorization, policy, signature)?;
        Ok((store, outcome))
    }
}
