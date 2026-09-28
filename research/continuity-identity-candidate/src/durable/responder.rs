// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::bootstrap::response_staged::{self, ResponsePlan};
use q_periapt_sdk::expert::replay::RecoveryKey;

fn scope(journal: &[u8; 32], context: &[u8; 32], operation: &[u8; 32]) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(96);
    bytes.extend_from_slice(journal);
    bytes.extend_from_slice(context);
    bytes.extend_from_slice(operation);
    digest(b"Q-PERIAPT-CONTINUITY-RESPONSE-PLAN/v1", &bytes)
}
pub(super) fn is_plan(phase: DurableStatus) -> bool {
    matches!(
        phase,
        DurableStatus::ResponseKemReserved | DurableStatus::ResponseSignatureReserved
    )
}
pub(super) fn initial_bytes(phase: DurableStatus, payload: &[u8]) -> Result<&[u8], DurableError> {
    let bytes = if matches!(phase, DurableStatus::Executing | DurableStatus::Rejected) {
        Some(payload)
    } else if is_plan(phase) {
        payload.get(response_staged::INITIAL_OFFSET..response_staged::INITIAL_OFFSET + 5817)
    } else {
        payload.get(40..40 + 5817)
    };
    bytes
        .filter(|bytes| bytes.len() == 5817)
        .ok_or(DurableError::Corrupt)
}
pub(super) fn validate_record(
    journal: &[u8; 32],
    op: &[u8; 32],
    context: &[u8; 32],
    phase: DurableStatus,
    payload: &[u8],
) -> Result<(), DurableError> {
    match phase {
        DurableStatus::Executing | DurableStatus::Rejected if payload.len() == 5817 => {}
        DurableStatus::ResponseKemReserved | DurableStatus::ResponseSignatureReserved => {
            ResponsePlan::decode(context, &scope(journal, context, op), phase as u8, payload)
                .map_err(|_| DurableError::Corrupt)?;
        }
        DurableStatus::Prepared
        | DurableStatus::AwaitingFinal
        | DurableStatus::Complete
        | DurableStatus::Messages => {
            let (length, marker) = if phase == DurableStatus::Messages {
                if payload.get(40 + 5817 + 4633..40 + 5817 + 4633 + 32) != Some(&[0; 32]) {
                    return Err(DurableError::Corrupt);
                }
                (COMPLETE_CHECKPOINT, 3)
            } else if phase == DurableStatus::Complete {
                (COMPLETE_CHECKPOINT, 2)
            } else {
                (PENDING_CHECKPOINT, 1)
            };
            if payload.len() != length
                || payload.get(..8) != Some(b"QPRCHK01")
                || payload.get(8..40) != Some(context.as_slice())
                || payload.get(PENDING_CHECKPOINT - 33) != Some(&marker)
            {
                return Err(DurableError::Corrupt);
            }
        }
        _ => return Err(DurableError::Corrupt),
    }
    if operation_id(context, initial_bytes(phase, payload)?) != *op {
        return Err(DurableError::Corrupt);
    }
    Ok(())
}

impl DeviceJournal {
    /// Reserve before authentication, seal the admitted contribution and exact
    /// KEM/signing plans before execution, and commit the immutable response before
    /// returning it. Executing recovery requires the original selected prekeys;
    /// after their authenticated contribution is pinned, they are not used again.
    pub fn respond(
        &mut self,
        context: Arc<BootstrapContext>,
        initial: &[u8],
        signer: &DeviceSigningKey,
        pq: PqKeySource<'_>,
        classical: TraditionalKeySource<'_>,
        now: u64,
    ) -> Result<Vec<u8>, DurableError> {
        let id = self.admission(&context, initial, now)?;
        let mut image = self.image()?;
        if let Some(record) = image.records.get(&id) {
            record.check_request(&context, initial)?;
            if record.phase != DurableStatus::Executing {
                return self.drive_response(image, id, context, signer, now);
            }
        }
        ResponsePlan::check_signer(&context, signer)?;
        ResponsePlan::check_prekeys(&context, pq, classical)?;
        if !image.records.contains_key(&id) {
            if image.operation_count() >= MAX_RECORDS {
                return Err(DurableError::Capacity);
            }
            let keys = context.one_time_fingerprints();
            if image
                .records
                .values()
                .any(|record| record.keys.iter().any(|key| keys.contains(key)))
            {
                return Err(DurableError::PrekeyClaimed);
            }
            image.records.insert(
                id,
                Record {
                    kind: RecordKind::Responder,
                    context: context.digest(),
                    phase: DurableStatus::Executing,
                    keys,
                    prekeys: Vec::new(),
                    payload: Zeroizing::new(initial.to_vec()),
                },
            );
            self.persist(&mut image)?;
        }
        let recovery = self.response_recovery_key()?;
        let scope = scope(&image.id, &context.digest(), &id);
        let plan = match ResponsePlan::reserve(&context, scope, initial, pq, classical, &recovery) {
            Ok(plan) => plan,
            Err(error) => {
                if matches!(
                    error,
                    Error::Authentication | Error::Runtime(q_periapt_sdk::Error::InvalidKeyShare)
                ) {
                    self.reject_response(&mut image, id, initial)?;
                }
                return Err(DurableError::Protocol(error));
            }
        };
        let record = image.records.get_mut(&id).ok_or(DurableError::Corrupt)?;
        record.phase = DurableStatus::ResponseKemReserved;
        record.payload = plan.encode();
        self.persist(&mut image)?;
        self.drive_response(image, id, context, signer, now)
    }
    /// Continue a committed responder contribution with its original signing
    /// owner, without the original prekeys. Executing has no saved contribution
    /// yet and requires `respond` with the exact selected prekeys instead.
    pub fn resume_response(
        &mut self,
        context: Arc<BootstrapContext>,
        initial: &[u8],
        signer: &DeviceSigningKey,
        now: u64,
    ) -> Result<Vec<u8>, DurableError> {
        let id = self.admission(&context, initial, now)?;
        let image = self.image()?;
        image
            .records
            .get(&id)
            .ok_or(DurableError::Absent)?
            .check_request(&context, initial)?;
        self.drive_response(image, id, context, signer, now)
    }
    fn response_recovery_key(&self) -> Result<RecoveryKey, DurableError> {
        RecoveryKey::from_host_key(
            self.active
                .as_ref()
                .ok_or(DurableError::Closed)?
                .key
                .0
                .as_bytes(),
        )
        .map_err(|error| DurableError::Protocol(error.into()))
    }
    fn reject_response(
        &mut self,
        image: &mut Image,
        id: [u8; 32],
        initial: &[u8],
    ) -> Result<(), DurableError> {
        let record = image.records.get_mut(&id).ok_or(DurableError::Corrupt)?;
        record.phase = DurableStatus::Rejected;
        record.keys.clear();
        record.prekeys.clear();
        record.payload = Zeroizing::new(initial.to_vec());
        self.persist(image)
    }
    fn drive_response(
        &mut self,
        mut image: Image,
        id: [u8; 32],
        context: Arc<BootstrapContext>,
        signer: &DeviceSigningKey,
        now: u64,
    ) -> Result<Vec<u8>, DurableError> {
        let record = image.records.get(&id).ok_or(DurableError::Absent)?;
        if !is_plan(record.phase) {
            return self.release_prepared(&mut image, id, context, now);
        }
        ResponsePlan::check_signer(&context, signer)?;
        let scope = scope(&image.id, &context.digest(), &id);
        let recovery = self.response_recovery_key()?;
        let mut plan = match ResponsePlan::decode(
            &context.digest(),
            &scope,
            record.phase as u8,
            &record.payload,
        ) {
            Ok(plan) => plan,
            Err(error) => {
                self.close();
                return Err(DurableError::InvalidCheckpoint(error));
            }
        };
        if plan.phase() == response_staged::KEM_RESERVED {
            context.check(now)?;
            plan = match plan.advance(&context, &scope, &recovery) {
                Ok(plan) => plan,
                Err(error) => return self.response_failure(&mut image, id, error),
            };
            #[cfg(all(test, unix))]
            tests::after_response_effect(response_staged::KEM_RESERVED, plan.public_effect()?);
            let record = image.records.get_mut(&id).ok_or(DurableError::Corrupt)?;
            record.phase = DurableStatus::ResponseSignatureReserved;
            record.payload = plan.encode();
            self.persist(&mut image)?;
        }
        context.check(now)?;
        let operation = match plan.complete(Arc::clone(&context), &scope, &recovery, signer) {
            Ok(operation) => operation,
            Err(error) => return self.response_failure(&mut image, id, error),
        };
        #[cfg(all(test, unix))]
        tests::after_response_effect(
            response_staged::SIGNATURE_RESERVED,
            operation.stored_reply()?,
        );
        let private = operation.checkpoint()?;
        context.check(now)?;
        let record = image.records.get_mut(&id).ok_or(DurableError::Corrupt)?;
        record.phase = DurableStatus::Prepared;
        record.payload = private;
        self.persist(&mut image)?;
        self.release_prepared(&mut image, id, context, now)
    }
    fn response_failure(
        &mut self,
        image: &mut Image,
        id: [u8; 32],
        error: Error,
    ) -> Result<Vec<u8>, DurableError> {
        if error == Error::Runtime(q_periapt_sdk::Error::InvalidKeyShare) {
            let record = image.records.get(&id).ok_or(DurableError::Corrupt)?;
            let initial = initial_bytes(record.phase, &record.payload)?.to_vec();
            self.reject_response(image, id, &initial)?;
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
        Err(DurableError::Protocol(error))
    }
}
