// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Retained parent decisions, independent of replaceable journal backups.
use super::*;
const MAX_BYTES: usize = crate::durable::WitnessAdoptionLineage::DECISION_BYTES;
const RECEIPT_BYTES: usize = 4 + 80 + crate::crypto::SIGNATURE_BYTES;
const DOMAIN: &[u8] = b"Q-PERIAPT-ENROLLMENT-WITNESS-SELECTION/v1";

#[derive(Clone, Eq, PartialEq)]
pub(in crate::enrollment) struct State {
    pub(super) identity: SigningKeyId,
    pub(super) request: Vec<u8>,
    pub(super) prepared_at: u64,
    pub(super) receipt: Option<Vec<u8>>,
    pub(super) lineage: crate::durable::WitnessAdoptionLineage,
}
impl State {
    pub(super) fn reserve_capacity(plan: &WitnessJournalAdoptionPlan) -> Result<(), DurableError> {
        // Complete parent header, MAC and exact future target receipt, before
        // the journal's first selection commit can occur.
        let fixed = 8 + 32 + 32 + 8 + 4 + 2 + 32 + RECEIPT_BYTES;
        let current = plan
            .authorization_request()
            .len()
            .checked_add(fixed)
            .ok_or(DurableError::Capacity)?;
        if current > MAX_BYTES
            || current
                .checked_add(plan.lineage_reservation()?)
                .ok_or(DurableError::Capacity)?
                > crate::durable::WitnessAdoptionLineage::MAX_BYTES
        {
            return Err(DurableError::Capacity);
        }
        Ok(())
    }
    pub(in crate::enrollment) fn check_image(&self, image: &Image) -> Result<(), DurableError> {
        self.lineage.check(&self.request, self.prepared_at)?;
        let Phase::Accepted {
            admission, stage, ..
        } = &image.phase
        else {
            return Err(DurableError::Conflict);
        };
        let scope =
            crate::session_policy::RetainedAdoptionRequest::unverified_scope(&self.request)?;
        scope.validity().check(self.prepared_at)?;
        let (journal, _, policy) = scope.subject.journal_parts();
        if image.identity != self.identity
            || journal != *admission.journal.as_bytes()
            || policy != admission.policy
            || !matches!(
                stage,
                AdmissionPhase::Active
                    | AdmissionPhase::Refreshing { .. }
                    | AdmissionPhase::RosterResolved { .. }
            )
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    pub(super) fn check_plan(&self, plan: &WitnessJournalAdoptionPlan) -> Result<(), DurableError> {
        plan.check_selection(
            &self.request,
            self.prepared_at,
            self.receipt.as_deref(),
            &self.lineage,
        )
    }
    pub(super) fn preparation_is_successor(
        &self,
        plan: &WitnessJournalAdoptionPlan,
    ) -> Result<bool, DurableError> {
        if self.request == plan.authorization_request() {
            self.check_plan(plan)?;
            Ok(false)
        } else {
            plan.check_predecessor(
                &self.request,
                self.prepared_at,
                self.receipt.as_deref(),
                &self.lineage,
            )?;
            Ok(true)
        }
    }
    pub(super) fn check_child(
        &self,
        child: &crate::durable::WitnessSelectionProgress,
    ) -> Result<(), DurableError> {
        if self.prepared_at != child.prepared_at
            || self.lineage != child.lineage
            || self
                .receipt
                .as_ref()
                .is_some_and(|receipt| child.receipt.as_ref() != Some(receipt))
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    pub(super) fn status(&self) -> WitnessJournalAdoptionState {
        if self.receipt.is_some() {
            WitnessJournalAdoptionState::Adopted
        } else {
            WitnessJournalAdoptionState::Prepared
        }
    }
    pub(super) fn encode(
        &self,
        key: &JournalKey,
        binding: [u8; 32],
    ) -> Result<Vec<u8>, DurableError> {
        self.lineage.check(&self.request, self.prepared_at)?;
        let mut wire = if self.lineage.is_empty() {
            b"QPEWAH01"
        } else {
            b"QPEWAH02"
        }
        .to_vec();
        wire.extend_from_slice(&binding);
        wire.extend_from_slice(self.identity.as_bytes());
        wire.extend_from_slice(&self.prepared_at.to_be_bytes());
        wire.extend_from_slice(
            &u32::try_from(self.request.len())
                .map_err(|_| DurableError::Capacity)?
                .to_be_bytes(),
        );
        wire.extend_from_slice(&self.request);
        let receipt = self.receipt.as_deref().unwrap_or(&[]);
        if !receipt.is_empty() && receipt.len() != RECEIPT_BYTES {
            return Err(DurableError::Corrupt);
        }
        wire.extend_from_slice(
            &u16::try_from(receipt.len())
                .map_err(|_| DurableError::Capacity)?
                .to_be_bytes(),
        );
        wire.extend_from_slice(receipt);
        let reserved = if self.receipt.is_none() {
            RECEIPT_BYTES
        } else {
            0
        };
        if wire
            .len()
            .checked_add(reserved + 32)
            .ok_or(DurableError::Capacity)?
            > MAX_BYTES
        {
            return Err(DurableError::Capacity);
        }
        if !self.lineage.is_empty() {
            wire.extend_from_slice(&self.lineage.encode()?);
        }
        if wire
            .len()
            .checked_add(reserved + 32)
            .ok_or(DurableError::Capacity)?
            > self.lineage.maximum_bytes()
        {
            return Err(DurableError::Capacity);
        }
        let mut mac = auth(key)?;
        mac.update(DOMAIN);
        mac.update(&wire);
        wire.extend_from_slice(&mac.finalize().into_bytes());
        Ok(wire)
    }
    pub(in crate::enrollment) fn decode(
        key: &JournalKey,
        binding: [u8; 32],
        wire: &[u8],
    ) -> Result<Self, DurableError> {
        if !(118..=crate::durable::WitnessAdoptionLineage::MAX_BYTES).contains(&wire.len()) {
            return Err(DurableError::Corrupt);
        }
        let (body, tag) = wire.split_at(wire.len() - 32);
        let mut mac = auth(key)?;
        mac.update(DOMAIN);
        mac.update(body);
        mac.verify_slice(tag)
            .map_err(|_| DurableError::Authentication)?;
        let mut d = Decoder::new(body);
        let successive = match d.array::<8>()? {
            tag if tag == *b"QPEWAH01" && wire.len() <= MAX_BYTES => false,
            tag if tag == *b"QPEWAH02" => true,
            _ => return Err(DurableError::Conflict),
        };
        if d.array::<32>()? != binding {
            return Err(DurableError::Conflict);
        }
        let identity = SigningKeyId::from_trusted_state(d.array()?)?;
        let prepared_at = d.u64()?;
        let n =
            usize::try_from(u32::from_be_bytes(d.array()?)).map_err(|_| DurableError::Capacity)?;
        let request = d.take(n)?.to_vec();
        crate::session_policy::RetainedAdoptionRequest::unverified_scope(&request)?;
        let n = usize::from(d.u16()?);
        let receipt = match n {
            0 => None,
            RECEIPT_BYTES => Some(d.take(n)?.to_vec()),
            _ => return Err(DurableError::Corrupt),
        };
        let lineage = if successive {
            crate::durable::WitnessAdoptionLineage::decode(&mut d)?
        } else {
            crate::durable::WitnessAdoptionLineage::default()
        };
        d.finish()?;
        let result = Self {
            identity,
            request,
            prepared_at,
            receipt,
            lineage,
        };
        if result.encode(key, binding)? != wire {
            return Err(DurableError::Corrupt);
        }
        Ok(result)
    }
}
