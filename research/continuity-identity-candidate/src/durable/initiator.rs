// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::bootstrap::staged::InitiationPlan;
use crate::InitiatorOperation;
use q_periapt_sdk::expert::replay::RecoveryKey;

const PREFIX: usize = 40 + 5817;
const WAITING: usize = PREFIX + 1 + 32 + q_periapt_sdk::expert::EXPANDED_KEY_LEN;
const FINISHED: usize = PREFIX + 1 + 4633 + 32 + 136;

/// Public correlation ID retained before a reservation call, not an authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitiationId([u8; 32]);
impl InitiationId {
    /// Generate a request ID using OS randomness, separate from KEM entropy.
    pub fn generate() -> Result<Self, Error> {
        let mut id = [0; 32];
        getrandom::fill(&mut id).map_err(|_| Error::Entropy)?;
        Self::from_trusted_state(id)
    }
    /// Load a retained host request ID; context substitution under it is rejected.
    pub fn from_trusted_state(bytes: [u8; 32]) -> Result<Self, Error> {
        crate::codec::nonzero(&bytes)?;
        Ok(Self(bytes))
    }
    /// Public bytes for the host request queue, never a secret or commit receipt.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Result returned after the initiator root and final outbox commit. It does not
/// assert that the responder received the final flight.
pub struct CommittedInitiation {
    final_wire: Vec<u8>,
    session: [u8; 32],
}
impl CommittedInitiation {
    /// Exact committed final message for dispatch/replay.
    pub fn final_message(&self) -> &[u8] {
        &self.final_wire
    }
    /// Public transcript identity; no application key is exposed.
    pub fn session_id(&self) -> [u8; 32] {
        self.session
    }
}

fn operation_id(request: InitiationId) -> [u8; 32] {
    digest(
        b"Q-PERIAPT-CONTINUITY-VAULT-INITIATION-CANDIDATE/v1",
        &request.0,
    )
}
fn checkpoint(record: &Record) -> Result<&[u8], DurableError> {
    let length = match record.phase {
        DurableStatus::Prepared | DurableStatus::AwaitingReply | DurableStatus::ProcessingReply => {
            WAITING
        }
        DurableStatus::FinalPrepared | DurableStatus::FinalCommitted => FINISHED,
        DurableStatus::Executing
        | DurableStatus::InitialKeyReserved
        | DurableStatus::InitialKemReserved
        | DurableStatus::InitialSignatureReserved => return Err(DurableError::Suspended),
        DurableStatus::Rejected => return Err(DurableError::Rejected),
        _ => return Err(DurableError::Corrupt),
    };
    record
        .payload
        .get(32..32 + length)
        .ok_or(DurableError::Corrupt)
}
fn initial(record: &Record) -> Result<&[u8], DurableError> {
    checkpoint(record)?
        .get(40..PREFIX)
        .ok_or(DurableError::Corrupt)
}
fn selected_reply(record: &Record) -> Result<&[u8], DurableError> {
    match record.phase {
        DurableStatus::ProcessingReply => record.payload.get(32 + WAITING..),
        DurableStatus::FinalPrepared | DurableStatus::FinalCommitted => {
            checkpoint(record)?.get(PREFIX + 1..PREFIX + 1 + 4633)
        }
        _ => None,
    }
    .ok_or(DurableError::Corrupt)
}
fn check_request(
    record: &Record,
    context: &BootstrapContext,
    request: InitiationId,
) -> Result<(), DurableError> {
    if record.kind != RecordKind::Initiator
        || record.context != context.digest()
        || !record.keys.is_empty()
        || record.payload.get(..32) != Some(request.0.as_slice())
    {
        return Err(DurableError::Conflict);
    }
    Ok(())
}
fn pack(request: InitiationId, private: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(32 + private.len()));
    bytes.extend_from_slice(&request.0);
    bytes.extend_from_slice(private);
    bytes
}

fn plan_scope(journal: &[u8; 32], context: &[u8; 32], operation: &[u8; 32]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(96);
    bytes.extend_from_slice(journal);
    bytes.extend_from_slice(context);
    bytes.extend_from_slice(operation);
    digest(b"Q-PERIAPT-CONTINUITY-INITIATION-PLAN/v1", &bytes)
}

fn is_plan(phase: DurableStatus) -> bool {
    matches!(
        phase,
        DurableStatus::InitialKeyReserved
            | DurableStatus::InitialKemReserved
            | DurableStatus::InitialSignatureReserved
    )
}

impl DeviceJournal {
    fn initiation_query(
        &self,
        context: &BootstrapContext,
        request: InitiationId,
    ) -> Result<[u8; 32], DurableError> {
        self.check_policy(context.policy())?;
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        if context.initiator_storage_owner() != active.owner {
            return Err(DurableError::Conflict);
        }
        Ok(operation_id(request))
    }
    /// Read-only exact-request reconciliation remains available after policy close/expiry.
    pub fn initiation_status(
        &mut self,
        context: &BootstrapContext,
        request: InitiationId,
    ) -> Result<DurableStatus, DurableError> {
        let id = self.initiation_query(context, request)?;
        let image = self.image()?;
        match image.records.get(&id) {
            None => Ok(DurableStatus::Absent),
            Some(record) => {
                check_request(record, context, request)?;
                Ok(record.phase)
            }
        }
    }
    /// Reserve before creating an initial flight; commit its exact private reply
    /// state and public outbox before returning bytes. Keep the request ID for recovery.
    pub fn initiate(
        &mut self,
        context: Arc<BootstrapContext>,
        request: InitiationId,
        signer: &DeviceSigningKey,
        now: u64,
    ) -> Result<Vec<u8>, DurableError> {
        context.check(now)?;
        let id = self.initiation_query(&context, request)?;
        let mut image = self.image()?;
        if let Some(record) = image.records.get(&id) {
            check_request(record, &context, request)?;
            if !is_plan(record.phase) {
                return self.release_initial(&mut image, id, context, now);
            }
        } else if image.operation_count() >= MAX_RECORDS {
            return Err(DurableError::Capacity);
        }
        InitiationPlan::check_signer(&context, signer)?;
        let scope = plan_scope(&image.id, &context.digest(), &id);
        let recovery = RecoveryKey::from_host_key(
            self.active
                .as_ref()
                .ok_or(DurableError::Closed)?
                .key
                .0
                .as_bytes(),
        )
        .map_err(Error::from)?;
        let mut plan = if let Some(record) = image.records.get(&id) {
            match InitiationPlan::decode(
                &context.digest(),
                &scope,
                record.phase as u8,
                record.payload.get(32..).ok_or(DurableError::Corrupt)?,
            ) {
                Ok(plan) => plan,
                Err(error) => {
                    self.close();
                    return Err(DurableError::InvalidCheckpoint(error));
                }
            }
        } else {
            let plan = InitiationPlan::reserve(&context, scope, &recovery)?;
            image.records.insert(
                id,
                Record {
                    kind: RecordKind::Initiator,
                    context: context.digest(),
                    phase: DurableStatus::InitialKeyReserved,
                    keys: Vec::new(),
                    prekeys: Vec::new(),
                    payload: pack(request, &plan.encode()),
                },
            );
            self.persist(&mut image)?;
            plan
        };
        // There are exactly two unsigned stages. Each next command's randomness
        // and complete inputs are durable before that command can execute.
        for _ in 0..2 {
            if plan.phase() == bootstrap::staged::SIGNATURE_RESERVED {
                break;
            }
            context.check(now)?;
            #[cfg(all(test, unix))]
            let effect = plan.phase();
            plan = match plan.advance(&context, &scope, &recovery) {
                Ok(plan) => plan,
                Err(error) => return self.initial_failure(&mut image, id, request, error),
            };
            #[cfg(all(test, unix))]
            tests::after_effect(effect, &plan.public_effect()?);
            let record = image.records.get_mut(&id).ok_or(DurableError::Corrupt)?;
            record.phase = DurableStatus::decode(plan.phase())?;
            record.payload = pack(request, &plan.encode());
            self.persist(&mut image)?;
        }
        context.check(now)?;
        let operation = match plan.complete(Arc::clone(&context), &scope, &recovery, signer) {
            Ok(operation) => operation,
            Err(error) => return self.initial_failure(&mut image, id, request, error),
        };
        #[cfg(all(test, unix))]
        tests::after_effect(
            bootstrap::staged::SIGNATURE_RESERVED,
            operation.initial_message(now)?,
        );
        let private = match operation.checkpoint() {
            Ok(private) => private,
            Err(error) => return self.initial_failure(&mut image, id, request, error),
        };
        context.check(now)?;
        let record = image.records.get_mut(&id).ok_or(DurableError::Corrupt)?;
        record.payload = pack(request, &private);
        record.phase = DurableStatus::Prepared;
        self.persist(&mut image)?;
        self.release_initial(&mut image, id, context, now)
    }
    fn initial_failure(
        &mut self,
        image: &mut Image,
        id: [u8; 32],
        request: InitiationId,
        error: Error,
    ) -> Result<Vec<u8>, DurableError> {
        if error == Error::Runtime(q_periapt_sdk::Error::InvalidKeyShare) {
            let record = image.records.get_mut(&id).ok_or(DurableError::Corrupt)?;
            record.payload = Zeroizing::new(request.0.to_vec());
            record.phase = DurableStatus::Rejected;
            self.persist(image)?;
        } else if matches!(
            error,
            Error::Encoding
                | Error::Scope
                | Error::State
                | Error::Conflict
                | Error::Runtime(q_periapt_sdk::Error::InvalidPrivateKey)
        ) {
            self.close();
            return Err(DurableError::InvalidCheckpoint(error));
        }
        // Local/transient failure preserves the selected, sealed computation.
        Err(DurableError::Protocol(error))
    }
    fn release_initial(
        &mut self,
        image: &mut Image,
        id: [u8; 32],
        context: Arc<BootstrapContext>,
        now: u64,
    ) -> Result<Vec<u8>, DurableError> {
        let record = image.records.get(&id).ok_or(DurableError::Absent)?;
        let wire = initial(record)?.to_vec();
        if let Err(error) = context.validate_initial_signature(&wire) {
            self.close();
            return Err(DurableError::InvalidCheckpoint(error));
        }
        if record.phase == DurableStatus::Prepared {
            context.check(now)?;
            image
                .records
                .get_mut(&id)
                .ok_or(DurableError::Corrupt)?
                .phase = DurableStatus::AwaitingReply;
            self.persist(image)?;
        }
        context.check(now)?;
        self.check_release(image)?;
        Ok(wire)
    }
    /// Replay a pinned/committed initial without key import, signing or new KEM
    /// randomness. A reservation with no pinned result remains suspended.
    pub fn resume_initial(
        &mut self,
        context: Arc<BootstrapContext>,
        request: InitiationId,
        now: u64,
    ) -> Result<Vec<u8>, DurableError> {
        context.check(now)?;
        let id = self.initiation_query(&context, request)?;
        let mut image = self.image()?;
        let record = image.records.get(&id).ok_or(DurableError::Absent)?;
        check_request(record, &context, request)?;
        self.release_initial(&mut image, id, context, now)
    }
    fn restore_initiator(
        &mut self,
        context: Arc<BootstrapContext>,
        bytes: &[u8],
    ) -> Result<InitiatorOperation, DurableError> {
        match InitiatorOperation::restore_checkpoint(context, bytes) {
            Ok(operation) => Ok(operation),
            Err(
                error @ Error::Runtime(
                    q_periapt_sdk::Error::Entropy
                    | q_periapt_sdk::Error::ResourceLimit
                    | q_periapt_sdk::Error::Closed,
                ),
            ) => Err(DurableError::Protocol(error)),
            Err(error) => {
                self.close();
                Err(DurableError::InvalidCheckpoint(error))
            }
        }
    }
    /// Persist one exact signed reply before deterministic confirmation processing.
    /// Its result and final outbox/root commit before success is exposed.
    pub fn accept_reply(
        &mut self,
        context: Arc<BootstrapContext>,
        request: InitiationId,
        reply: &[u8],
        now: u64,
    ) -> Result<CommittedInitiation, DurableError> {
        context.check(now)?;
        let id = self.initiation_query(&context, request)?;
        let mut image = self.image()?;
        let record = image.records.get_mut(&id).ok_or(DurableError::Absent)?;
        check_request(record, &context, request)?;
        match record.phase {
            DurableStatus::AwaitingReply => {
                context.validate_reply_signature(initial(record)?, reply)?;
                record.payload.extend_from_slice(reply);
                record.phase = DurableStatus::ProcessingReply;
                self.persist(&mut image)?;
            }
            DurableStatus::ProcessingReply
            | DurableStatus::FinalPrepared
            | DurableStatus::FinalCommitted => {
                if selected_reply(record)? != reply {
                    return Err(DurableError::Conflict);
                }
                if let Err(error) = context.validate_reply_signature(initial(record)?, reply) {
                    self.close();
                    return Err(DurableError::InvalidCheckpoint(error));
                }
            }
            DurableStatus::Rejected => return Err(DurableError::Rejected),
            _ => return Err(DurableError::Suspended),
        }
        let record = image.records.get(&id).ok_or(DurableError::Corrupt)?;
        let mut operation = self.restore_initiator(Arc::clone(&context), checkpoint(record)?)?;
        let result = match operation.finish(reply, now) {
            Ok(result) => CommittedInitiation {
                final_wire: result.final_message().to_vec(),
                session: result.pending_session().id(),
            },
            Err(error) => {
                if matches!(
                    error,
                    Error::Authentication | Error::Runtime(q_periapt_sdk::Error::InvalidKeyShare)
                ) {
                    let record = image.records.get_mut(&id).ok_or(DurableError::Corrupt)?;
                    // Only definitive peer-confirmation rejection clears this input.
                    // A local/transient error preserves the exact selected reply.
                    record.payload.truncate(32 + WAITING);
                    record.phase = DurableStatus::AwaitingReply;
                    self.persist(&mut image)?;
                }
                return Err(DurableError::Protocol(error));
            }
        };
        if image.records.get(&id).ok_or(DurableError::Corrupt)?.phase
            == DurableStatus::ProcessingReply
        {
            let private = operation.checkpoint()?;
            let record = image.records.get_mut(&id).ok_or(DurableError::Corrupt)?;
            record.payload = pack(request, &private);
            record.phase = DurableStatus::FinalPrepared;
            self.persist(&mut image)?;
        }
        if image.records.get(&id).ok_or(DurableError::Corrupt)?.phase
            == DurableStatus::FinalPrepared
        {
            context.check(now)?;
            image
                .records
                .get_mut(&id)
                .ok_or(DurableError::Corrupt)?
                .phase = DurableStatus::FinalCommitted;
            self.persist(&mut image)?;
        }
        context.check(now)?;
        self.check_release(&image)?;
        Ok(result)
    }
    /// Continue the already-selected reply/result, with no caller replacement input.
    pub fn resume_reply(
        &mut self,
        context: Arc<BootstrapContext>,
        request: InitiationId,
        now: u64,
    ) -> Result<CommittedInitiation, DurableError> {
        context.check(now)?;
        let id = self.initiation_query(&context, request)?;
        let image = self.image()?;
        let record = image.records.get(&id).ok_or(DurableError::Absent)?;
        check_request(record, &context, request)?;
        if !matches!(
            record.phase,
            DurableStatus::ProcessingReply
                | DurableStatus::FinalPrepared
                | DurableStatus::FinalCommitted
        ) {
            return Err(DurableError::Suspended);
        }
        let reply = selected_reply(record)?.to_vec();
        drop(image);
        self.accept_reply(context, request, &reply, now)
    }
}

pub(super) fn validate_record(
    journal: &[u8; 32],
    op: &[u8; 32],
    context: &[u8; 32],
    phase: DurableStatus,
    payload: &[u8],
) -> Result<(), DurableError> {
    let request = InitiationId::from_trusted_state(
        payload
            .get(..32)
            .ok_or(DurableError::Corrupt)?
            .try_into()
            .map_err(|_| DurableError::Corrupt)?,
    )?;
    if operation_id(request) != *op {
        return Err(DurableError::Corrupt);
    }
    if is_plan(phase) {
        InitiationPlan::decode(
            context,
            &plan_scope(journal, context, op),
            phase as u8,
            payload.get(32..).ok_or(DurableError::Corrupt)?,
        )
        .map_err(|_| DurableError::Corrupt)?;
        return Ok(());
    }
    let (length, marker) = match phase {
        DurableStatus::Rejected => {
            return if payload.len() == 32 {
                Ok(())
            } else {
                Err(DurableError::Corrupt)
            }
        }
        DurableStatus::Prepared | DurableStatus::AwaitingReply => (WAITING, 1),
        DurableStatus::ProcessingReply => (WAITING + 4633, 1),
        DurableStatus::FinalPrepared | DurableStatus::FinalCommitted => (FINISHED, 2),
        _ => return Err(DurableError::Corrupt),
    };
    if payload.len() != 32 + length
        || payload.get(32..40) != Some(b"QPICHK01")
        || payload.get(40..72) != Some(context.as_slice())
        || payload.get(32 + PREFIX) != Some(&marker)
    {
        return Err(DurableError::Corrupt);
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests;
