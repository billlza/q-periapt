// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Independently retain one exact report after the original inventory is retained.
use super::*;

const BYTES: usize = 8 + 313 + 32;
const ACK_TAG: &[u8; 8] = b"QPRACK01";

pub(super) struct ReportRecord {
    pub(super) proposal: AnchorRetiredReportProposal,
    pub(super) acknowledged: bool,
}
fn acknowledgement_body(proposal: &AnchorRetiredReportProposal) -> Vec<u8> {
    let mut body = ACK_TAG.to_vec();
    body.extend_from_slice(&proposal.inventory.to_bytes());
    body.extend_from_slice(&proposal.report);
    body
}
/// Independent durable host-accounting decision, never authenticated peer delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorRetiredReportAcknowledgementState {
    /// The exact already-retained report was explicitly acknowledged by the host controller.
    Acknowledged,
    /// No acknowledgement is retained at this observation; outstanding requests remain unresolved.
    Unavailable,
}
/// Verified independent host-accounting acknowledgement for one original report.
/// No currentness or physical-erasure capability is implied.
/// ```compile_fail
/// use q_periapt_continuity_identity_candidate::{AnchorRetiredReportAcknowledgement, AnchorReply};
/// fn current(ack: AnchorRetiredReportAcknowledgement) -> AnchorReply { ack }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorRetiredReportAcknowledgement {
    proposal: AnchorRetiredReportProposal,
}
impl AnchorRetiredReportAcknowledgement {
    /// Original report and inventory to which the host decision is permanently bound.
    pub fn proposal(&self) -> &AnchorRetiredReportProposal {
        &self.proposal
    }
}

/// Complete original inventory and private-keyed report identity. Not a host ACK.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorRetiredReportProposal {
    inventory: AnchorRetiredCleanupProposal,
    report: [u8; 32],
}
impl AnchorRetiredReportProposal {
    pub(crate) fn from_report(
        inventory: AnchorRetiredCleanupProposal,
        report: [u8; 32],
    ) -> Result<Self, Error> {
        nonzero(&report)?;
        Ok(Self { inventory, report })
    }
    /// Restore canonical independently retained expectation; this grants no authority.
    pub fn from_trusted_state(wire: &[u8]) -> Result<Self, Error> {
        if wire.len() != BYTES || wire.get(..8) != Some(b"QPRRPT01") {
            return Err(Error::Encoding);
        }
        Self::from_report(
            AnchorRetiredCleanupProposal::from_trusted_state(
                wire.get(8..321).ok_or(Error::Encoding)?,
            )?,
            wire.get(321..)
                .ok_or(Error::Encoding)?
                .try_into()
                .map_err(|_| Error::Encoding)?,
        )
    }
    /// Canonical 353-byte request; persist independently before dispatch.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = b"QPRRPT01".to_vec();
        out.extend_from_slice(&self.inventory.to_bytes());
        out.extend_from_slice(&self.report);
        out
    }
    /// Exact original independently retained cleanup inventory.
    pub fn inventory(&self) -> &AnchorRetiredCleanupProposal {
        &self.inventory
    }
    /// HMAC of the complete canonical public report under a separated original key.
    pub fn report_id(&self) -> &[u8; 32] {
        &self.report
    }
}
/// Permanent retention observation, separate from accepting host accounting effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnchorRetiredReportState {
    /// This exact report identity is permanently retained.
    Retained,
    /// No report is retained at this observation; outstanding invocation remains unresolved.
    Unavailable,
}
/// Verified report retention; cannot become an ordinary currentness receipt or erase permit.
/// ```compile_fail
/// use q_periapt_continuity_identity_candidate::{AnchorRetiredReport, AnchorReply};
/// fn operating_reply(report: AnchorRetiredReport) -> AnchorReply { report }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorRetiredReport {
    proposal: AnchorRetiredReportProposal,
}
impl AnchorRetiredReport {
    /// Original authenticated report proposal, without ACK authority.
    pub fn proposal(&self) -> &AnchorRetiredReportProposal {
        &self.proposal
    }
}
impl Image {
    fn admit_report(
        &self,
        p: &AnchorRetiredReportProposal,
        pin: &AnchorPin,
    ) -> Result<(), DurableError> {
        nonzero(&p.report)?;
        if self
            .retired_cleanup
            .get(&p.inventory.subject().id(&pin.binding))
            != Some(&p.inventory)
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    pub(super) fn check_retired_reports(&self, pin: &AnchorPin) -> Result<(), DurableError> {
        if self.retired_reports.len() > MAX_ENTRIES {
            return Err(DurableError::Capacity);
        }
        for (id, saved) in &self.retired_reports {
            let p = &saved.proposal;
            if *id != p.inventory.subject().id(&pin.binding) || self.admit_report(p, pin).is_err() {
                return Err(DurableError::Corrupt);
            }
        }
        Ok(())
    }
}
impl AnchorStore {
    /// Independently authorized controller action, requiring the exact previously
    /// retained inventory. First report wins permanently; a different report conflicts.
    /// The witness authenticates retention, not the journal's semantic truth or host effects.
    /// On uncertain commit reopen and reconcile this same proposal.
    pub fn retain_retired_report(
        &mut self,
        proposal: &AnchorRetiredReportProposal,
    ) -> Result<AnchorRetiredReportState, DurableError> {
        let pin = self.pin()?;
        let mut image = self.image()?;
        image.admit_report(proposal, &pin)?;
        let id = proposal.inventory.subject().id(&pin.binding);
        if let Some(saved) = image.retired_reports.get(&id) {
            return if &saved.proposal == proposal {
                Ok(AnchorRetiredReportState::Retained)
            } else {
                Err(DurableError::Conflict)
            };
        }
        if image.retired_reports.len() >= MAX_ENTRIES {
            return Err(DurableError::Capacity);
        }
        image.retired_reports.insert(
            id,
            ReportRecord {
                proposal: proposal.clone(),
                acknowledged: false,
            },
        );
        self.persist(&mut image)?;
        Ok(AnchorRetiredReportState::Retained)
    }
    /// Unavailable is a current observation, not a resolution of an outstanding invocation.
    pub fn retired_report_status(
        &mut self,
        proposal: &AnchorRetiredReportProposal,
    ) -> Result<AnchorRetiredReportState, DurableError> {
        let pin = self.pin()?;
        let image = self.image()?;
        image.admit_report(proposal, &pin)?;
        Ok(
            match image
                .retired_reports
                .get(&proposal.inventory.subject().id(&pin.binding))
            {
                Some(saved) if &saved.proposal == proposal => AnchorRetiredReportState::Retained,
                Some(_) => return Err(DurableError::Conflict),
                None => AnchorRetiredReportState::Unavailable,
            },
        )
    }
    /// Purpose 20 historical report retention, without current policy or ACK semantics.
    pub fn retired_report_receipt(
        &mut self,
        proposal: &AnchorRetiredReportProposal,
    ) -> Result<Vec<u8>, DurableError> {
        if self.retired_report_status(proposal)? != AnchorRetiredReportState::Retained {
            return Err(DurableError::Absent);
        }
        let result = (|| {
            let active = self.active.as_ref().ok_or(DurableError::Closed)?;
            let body = proposal.to_bytes();
            let signature = active.signer.sign(Purpose::AnchorRetiredReport, &body)?;
            Ok(envelope(&body, &signature)?)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
impl AnchorPin {
    /// Authenticate purpose-separated historical retention of this exact saved report.
    pub fn verify_retired_report(
        &self,
        inventory: &AnchorRetiredCleanup,
        proposal: &AnchorRetiredReportProposal,
        wire: &[u8],
    ) -> Result<AnchorRetiredReport, Error> {
        if wire.len() != 4 + BYTES + crate::crypto::SIGNATURE_BYTES {
            return Err(Error::Encoding);
        }
        if inventory.proposal() != &proposal.inventory
            || self.binding != proposal.inventory.witness_binding()
        {
            return Err(Error::Scope);
        }
        let (body, signature) = open_envelope(wire)?;
        self.key
            .verify(Purpose::AnchorRetiredReport, body, signature)?;
        if body != proposal.to_bytes() {
            return Err(Error::Scope);
        }
        Ok(AnchorRetiredReport {
            proposal: proposal.clone(),
        })
    }
}
pub(super) fn encode_records(
    records: &BTreeMap<[u8; 32], ReportRecord>,
    out: &mut Vec<u8>,
) -> Result<(), DurableError> {
    out.extend_from_slice(
        &u16::try_from(records.len())
            .map_err(|_| DurableError::Capacity)?
            .to_be_bytes(),
    );
    for (id, record) in records {
        out.extend_from_slice(id);
        out.extend_from_slice(&if record.acknowledged {
            acknowledgement_body(&record.proposal)
        } else {
            record.proposal.to_bytes()
        });
    }
    Ok(())
}
pub(super) fn decode_records(
    d: &mut Decoder<'_>,
    pin: &AnchorPin,
    allow_acknowledged: bool,
    allow_empty: bool,
) -> Result<BTreeMap<[u8; 32], ReportRecord>, DurableError> {
    let count = usize::from(d.u16()?);
    if (!allow_empty && count == 0) || count > MAX_ENTRIES {
        return Err(DurableError::Corrupt);
    }
    let mut records = BTreeMap::new();
    let mut previous = None;
    for _ in 0..count {
        let id = d.array()?;
        let mut bytes = d.take(BYTES)?.to_vec();
        let acknowledged = if bytes.get(..8) == Some(ACK_TAG.as_slice()) {
            if !allow_acknowledged {
                return Err(DurableError::Corrupt);
            }
            bytes
                .get_mut(..8)
                .ok_or(DurableError::Corrupt)?
                .copy_from_slice(b"QPRRPT01");
            true
        } else {
            false
        };
        let p = AnchorRetiredReportProposal::from_trusted_state(&bytes)
            .map_err(|_| DurableError::Corrupt)?;
        if id != p.inventory.subject().id(&pin.binding) || previous.is_some_and(|old| old >= id) {
            return Err(DurableError::Corrupt);
        }
        previous = Some(id);
        records.insert(
            id,
            ReportRecord {
                proposal: p,
                acknowledged,
            },
        );
    }
    Ok(records)
}

impl AnchorStore {
    /// Explicit independently authorized controller action AFTER the host durably
    /// records the complete report and deduplicates its effects by the original report ID.
    /// The same report is an idempotent retry; a competing report or absent retention fails.
    /// The fixed-width state tag changes without increasing the already admitted image size.
    pub fn acknowledge_retired_report(
        &mut self,
        proposal: &AnchorRetiredReportProposal,
    ) -> Result<AnchorRetiredReportAcknowledgementState, DurableError> {
        let pin = self.pin()?;
        let mut image = self.image()?;
        image.admit_report(proposal, &pin)?;
        let saved = image
            .retired_reports
            .get_mut(&proposal.inventory.subject().id(&pin.binding))
            .ok_or(DurableError::Absent)?;
        if &saved.proposal != proposal {
            return Err(DurableError::Conflict);
        }
        if !saved.acknowledged {
            saved.acknowledged = true;
            self.persist(&mut image)?;
        }
        Ok(AnchorRetiredReportAcknowledgementState::Acknowledged)
    }
    /// Historical observation of this exact acknowledgement. Unavailable never
    /// resolves an unknown host-side commit or permits repeating external effects.
    pub fn retired_report_acknowledgement_status(
        &mut self,
        proposal: &AnchorRetiredReportProposal,
    ) -> Result<AnchorRetiredReportAcknowledgementState, DurableError> {
        let pin = self.pin()?;
        let image = self.image()?;
        image.admit_report(proposal, &pin)?;
        match image
            .retired_reports
            .get(&proposal.inventory.subject().id(&pin.binding))
        {
            Some(saved) if &saved.proposal != proposal => Err(DurableError::Conflict),
            Some(saved) if saved.acknowledged => {
                Ok(AnchorRetiredReportAcknowledgementState::Acknowledged)
            }
            _ => Ok(AnchorRetiredReportAcknowledgementState::Unavailable),
        }
    }
    /// Purpose 21 receipt for the independent durable host acknowledgement.
    /// It does not assert remote consumption, current authority or physical erasure.
    pub fn retired_report_acknowledgement_receipt(
        &mut self,
        proposal: &AnchorRetiredReportProposal,
    ) -> Result<Vec<u8>, DurableError> {
        if self.retired_report_acknowledgement_status(proposal)?
            != AnchorRetiredReportAcknowledgementState::Acknowledged
        {
            return Err(DurableError::Absent);
        }
        let result = (|| {
            let active = self.active.as_ref().ok_or(DurableError::Closed)?;
            let body = acknowledgement_body(proposal);
            let signature = active
                .signer
                .sign(Purpose::AnchorRetiredReportAcknowledgement, &body)?;
            Ok(envelope(&body, &signature)?)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
impl AnchorPin {
    /// Authenticate the original saved host-ACK expectation and permanent retirement.
    /// No journal read or new current-policy admission is performed.
    pub fn verify_retired_report_acknowledgement(
        &self,
        retired: AnchorRetiredSubject,
        proposal: &AnchorRetiredReportProposal,
        wire: &[u8],
    ) -> Result<AnchorRetiredReportAcknowledgement, Error> {
        if wire.len() != 4 + BYTES + crate::crypto::SIGNATURE_BYTES {
            return Err(Error::Encoding);
        }
        proposal.inventory.check_retirement(retired)?;
        if self.binding != proposal.inventory.witness_binding() {
            return Err(Error::Scope);
        }
        let (body, signature) = open_envelope(wire)?;
        self.key
            .verify(Purpose::AnchorRetiredReportAcknowledgement, body, signature)?;
        if body != acknowledgement_body(proposal) {
            return Err(Error::Scope);
        }
        Ok(AnchorRetiredReportAcknowledgement {
            proposal: proposal.clone(),
        })
    }
}
