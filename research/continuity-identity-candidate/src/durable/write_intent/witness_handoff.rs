// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Adopt witness authority without resealing the original image or pending work.
use super::*;
use crate::{
    AnchorHandoffAdoptionMaterials, AnchorHandoffClientAuthorizationReceipt, AnchorHandoffHistory,
    HistoricalAnchorHandoffAdoption,
};
mod codec;
mod transaction;
use codec::Fence;
#[cfg(all(test, unix))]
mod tests;

pub(super) const ROW: &str = "witness-handoff";

/// Independently verified exact approval and history for one original journal.
/// Retain these original inputs in the host's authenticated controller before
/// starting. Neither incoming storage nor a peer may select a replacement plan.
#[derive(Clone)]
pub struct WitnessJournalAdoptionPlan {
    request: Vec<u8>,
    approved: HistoricalAnchorHandoffAdoption,
    history: AnchorHandoffHistory,
    account: [u8; 32],
}
impl WitnessJournalAdoptionPlan {
    /// Revalidate both root approvals against independent identity, policy and
    /// activation material. Expired material is historical, not renewed traffic
    /// permission. New local preparation separately checks the admission window.
    pub fn new(
        approved: &HistoricalAnchorHandoffAdoption,
        materials: &AnchorHandoffAdoptionMaterials<'_>,
    ) -> Result<Self, Error> {
        Ok(Self {
            request: approved.prepare_witness_authorization(materials)?,
            approved: approved.clone(),
            history: materials.history.clone(),
            account: materials.original_device.account,
        })
    }
    /// Exact public request to use for the target authorization transaction.
    pub fn authorization_request(&self) -> &[u8] {
        &self.request
    }
    /// Independently approved original statement, not a persisted-adoption claim.
    pub fn scope(&self) -> &crate::AnchorHandoffAdoptionScope {
        self.approved.scope()
    }
    fn check_image(&self, image: &Image) -> Result<(), DurableError> {
        let Protection::Required {
            policy, witness, ..
        } = image.protection
        else {
            return Err(DurableError::AnchorRequired);
        };
        let scope = self.scope();
        if scope.subject.journal_parts() != (image.id, image.owner, policy)
            || scope.logical != witness
            || self.account != image.local_account
        {
            return Err(Error::Scope.into());
        }
        Ok(())
    }
    fn verify_receipt(
        &self,
        wire: &[u8],
    ) -> Result<AnchorHandoffClientAuthorizationReceipt, Error> {
        AnchorHandoffClientAuthorizationReceipt::verify(wire, &self.approved, &self.history)
    }
}

/// Durable control-plane progress. Neither state asserts current credential or
/// policy permission, or successful reconciliation of an original G/P/R.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WitnessJournalAdoptionState {
    /// Original local snapshot and exact issuer decision are fenced; the target
    /// may already have committed an authorization whose response was lost.
    Prepared,
    /// The exact target authorization is durably selected for this journal.
    /// Original pending operations still require transfer-aware reconciliation.
    Adopted,
}
struct Owners {
    db: Database,
    key: JournalKey,
    plan: WitnessJournalAdoptionPlan,
}
impl Owners {
    fn snapshot(&self) -> Result<(Image, Option<PendingIntent>), DurableError> {
        let owner = self.plan.scope().subject.journal_parts().1;
        let snapshot = load_pending_snapshot(
            &self.db,
            &self.key,
            owner,
            SnapshotAdmission::WitnessHandoff,
        )?;
        self.plan.check_image(&snapshot.0)?;
        Ok(snapshot)
    }
    fn read(&self) -> Result<Fence, DurableError> {
        let (image, pending) = self.snapshot()?;
        let read = self.db.begin_read().map_err(storage)?;
        let table = image_table(&read)?;
        let saved = table
            .get(ROW)
            .map_err(storage)?
            .ok_or(DurableError::Absent)?;
        let fence = Fence::decode(&self.key, saved.value())?;
        fence.check(&image, pending.as_ref())?;
        if fence.request != self.plan.request {
            return Err(DurableError::Conflict);
        }
        if let Some(receipt) = &fence.receipt {
            self.plan.verify_receipt(receipt)?;
        }
        Ok(fence)
    }
}

/// Exclusive owner of the original journal's durable witness selection. It does
/// not expose a traffic owner until transfer-aware reconciliation is available.
/// Keep the independently approved plan when reopening; missing state never
/// authorizes fallback to the old witness or provisioning another journal.
/// ```compile_fail
/// use q_periapt_continuity_identity_candidate::{DeviceJournal, WitnessJournalAdoption};
/// fn traffic(owner: WitnessJournalAdoption) -> DeviceJournal { owner }
/// ```
pub struct WitnessJournalAdoption {
    active: Option<Owners>,
}
impl WitnessJournalAdoption {
    /// Reconcile a first preparation on existing original storage. A retained
    /// exact preparation is historical; absence requires a fresh decision within
    /// the original admission interval. A different plan is never replaced.
    pub fn prepare_original(
        path: &Path,
        key: JournalKey,
        plan: WitnessJournalAdoptionPlan,
        trusted_time: impl FnMut() -> Result<u64, DurableError>,
    ) -> Result<Self, DurableError> {
        Owners {
            db: open_private_database(path)?,
            key,
            plan,
        }
        .prepare(trusted_time)
    }
    /// Open only an already prepared original. Missing/damaged control state is
    /// an error, even if the old encrypted image alone still parses. The host's
    /// independently retained plan/checkpoint is required after process restart.
    pub fn resume_original(
        path: &Path,
        key: JournalKey,
        plan: WitnessJournalAdoptionPlan,
    ) -> Result<Self, DurableError> {
        let owner = Owners {
            db: open_private_database(path)?,
            key,
            plan,
        };
        owner.read()?;
        Ok(Self {
            active: Some(owner),
        })
    }
    /// Observe authenticated local progress without contacting either witness.
    pub fn status(&mut self) -> Result<WitnessJournalAdoptionState, DurableError> {
        let result = self
            .active
            .as_ref()
            .ok_or(DurableError::Closed)
            .and_then(Owners::read)
            .map(|f| {
                if f.receipt.is_some() {
                    WitnessJournalAdoptionState::Adopted
                } else {
                    WitnessJournalAdoptionState::Prepared
                }
            });
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Recover the exact committed target receipt without a signing key. This
    /// does not classify original pending operations or renew their permissions.
    pub fn authorization_receipt(
        &mut self,
    ) -> Result<AnchorHandoffClientAuthorizationReceipt, DurableError> {
        let result = (|| {
            let owner = self.active.as_ref().ok_or(DurableError::Closed)?;
            let receipt = owner.read()?.receipt.ok_or(DurableError::Absent)?;
            Ok(owner.plan.verify_receipt(&receipt)?)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Release this lease and key; preserve all original data and control state.
    pub fn close(&mut self) {
        self.active = None;
    }
}
impl DeviceJournal {
    /// Consume this owner and fence its original image and pending intent. Any
    /// error consumes the handle and may follow commit; reconcile the same plan
    /// on the same original path/key. No encrypted state is resealed or advanced.
    pub fn begin_witness_handoff(
        &mut self,
        plan: WitnessJournalAdoptionPlan,
        trusted_time: impl FnMut() -> Result<u64, DurableError>,
    ) -> Result<WitnessJournalAdoption, DurableError> {
        let active = self.active.take().ok_or(DurableError::Closed)?;
        Owners {
            db: active.db,
            key: active.key,
            plan,
        }
        .prepare(trusted_time)
    }
}
pub(super) fn validate_snapshot(
    key: &JournalKey,
    image: &Image,
    pending: Option<&PendingIntent>,
    wire: &[u8],
) -> Result<(), DurableError> {
    Fence::decode(key, wire)?.check(image, pending)
}
