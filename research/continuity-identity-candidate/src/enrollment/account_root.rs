// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Keep original root-replacement approval outside replaceable journal backups.
use super::*;
use crate::durable::account_root_transfer::{self as transfer, ParentCheckpoint, Transfer};
use crate::{AccountRootJournalRecovery, AnchorAccountReplacementProposal as Proposal};
use redb::ReadableTable;
pub(super) mod cleanup;
mod codec;
mod transferred;
mod transition;

pub(super) const ROW: &str = "root-replacement";
const TAG: &[u8; 8] = b"QPERPL01";
const TRANSFER_TAG: &[u8; 8] = b"QPERPL02";
const RECEIPT_BYTES: usize = 3449;
const CONTEXT_TAG: &[u8; 8] = b"QPERPL03";
const CURRENT_RECEIPT_BYTES: usize = crate::AnchorTransferredAccountDecision::WIRE_BYTES;
#[cfg(all(test, unix))]
pub(super) fn managed_boundary(stage: &str) {
    tests::at_boundary(&format!("managed-{stage}"), true);
}
const MAX_BYTES: usize = 174
    + 65_536
    + CURRENT_RECEIPT_BYTES
    + 163
    + 2
    + transfer::MAX_TRANSFERS * transfer::TRANSFER_BYTES;

#[derive(Clone, Eq, PartialEq)]
pub(super) struct State {
    identity: SigningKeyId,
    image: [u8; 32],
    journal: JournalIdentity,
    proposal: Proposal,
    receipt: Option<Vec<u8>>,
    history: Vec<Transfer>,
    child: Option<[u8; 32]>,
    authority: Option<crate::durable::RootWitnessBinding>,
    selection: Option<[u8; 32]>,
}
fn image_digest(wire: &[u8]) -> [u8; 32] {
    digest(b"Q-PERIAPT-CONTINUITY-ROOT-ENROLLMENT/v1", wire)
}
pub(super) fn selection_binding(wire: &[u8]) -> [u8; 32] {
    digest(b"Q-PERIAPT-ROOT-PARENT-WITNESS-SELECTION/v1", wire)
}
impl State {
    pub(super) fn check_selection_binding(
        &self,
        selected: Option<[u8; 32]>,
    ) -> Result<(), DurableError> {
        if (self.authority.is_none() && selected.is_some()) || self.selection != selected {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    pub(super) fn check_image(&self, image: &Image, wire: &[u8]) -> Result<(), DurableError> {
        let Phase::Accepted { admission, .. } = &image.phase else {
            return Err(DurableError::Corrupt);
        };
        if image.identity != self.identity
            || admission.journal != self.journal
            || image_digest(wire) != self.image
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
}
fn validate(
    enrollment: &DeviceEnrollment,
    image: &Image,
    pin: &AnchorPin,
    proposal: &Proposal,
) -> Result<VerifiedDevice, DurableError> {
    enrollment.validate_roster_resolution(image)?;
    enrollment.validate_witness_roster(image)?;
    enrollment.validate_policy_pending(image)?;
    let original = enrollment.original_device_metadata(image)?;
    let Phase::Accepted {
        admission, stage, ..
    } = &image.phase
    else {
        return Err(DurableError::Suspended);
    };
    if *stage == AdmissionPhase::Accepted
        || pin.binding() != proposal.witness_binding()
        || original.account_id() != proposal.previous_account()
        || !proposal.predecessors().any(|s| {
            s.journal_parts()
                == (
                    *admission.journal.as_bytes(),
                    crate::bootstrap::storage_owner(&original),
                    admission.policy,
                )
        })
    {
        return Err(DurableError::Conflict);
    }
    Ok(original)
}
fn original_digest(enrollment: &DeviceEnrollment) -> Result<[u8; 32], DurableError> {
    let active = enrollment.active.as_ref().ok_or(DurableError::Closed)?;
    let tx = active.database.begin_read().map_err(storage)?;
    let table = tx.open_table(TABLE).map_err(storage)?;
    let row = table
        .get("enrollment")
        .map_err(storage)?
        .ok_or(DurableError::Corrupt)?;
    Ok(image_digest(row.value()))
}
fn save(
    enrollment: &DeviceEnrollment,
    previous: Option<&State>,
    next: &State,
    stage: &'static str,
) -> Result<(), DurableError> {
    let active = enrollment.active.as_ref().ok_or(DurableError::Closed)?;
    let expected = previous
        .map(|s| s.encode(&active.key, enrollment.binding))
        .transpose()?;
    let wire = next.encode(&active.key, enrollment.binding)?;
    let tx = transaction(&active.database)?;
    {
        let mut table = tx.open_table(TABLE).map_err(storage)?;
        let witness = table.get(witness_handoff::ROW).map_err(storage)?;
        next.check_selection_binding(witness.as_ref().map(|row| selection_binding(row.value())))?;
        if table.len().map_err(storage)?
            != 1 + u64::from(previous.is_some()) + u64::from(witness.is_some())
            || table.get(ROW).map_err(storage)?.as_ref().map(|v| v.value()) != expected.as_deref()
            || table
                .get("enrollment")
                .map_err(storage)?
                .as_ref()
                .map(|v| image_digest(v.value()))
                != Some(next.image)
        {
            return Err(DurableError::Conflict);
        }
        drop(witness);
        table.insert(ROW, wire.as_slice()).map_err(storage)?;
    }
    #[cfg(all(test, unix))]
    tests::at_boundary(stage, false);
    tx.commit().map_err(DurableError::CommitUncertain)?;
    #[cfg(all(test, unix))]
    tests::at_boundary(stage, true);
    let _ = stage;
    Ok(())
}

struct Owners {
    // Drop the child lease before releasing its independently retained parent.
    journal: Option<AccountRootJournalRecovery>,
    enrollment: DeviceEnrollment,
    pin: AnchorPin,
    state: State,
    transferred: Option<Box<crate::TransferredAccountRootJournalPlan>>,
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl Owners {
    fn read(&self) -> Result<VerifiedDevice, DurableError> {
        let active = self
            .enrollment
            .active
            .as_ref()
            .ok_or(DurableError::Closed)?;
        let snapshot = read_snapshot(&active.database, &active.key, self.enrollment.binding)?;
        if snapshot.retirement.is_some()
            || snapshot.root_replacement.as_deref() != Some(&self.state)
        {
            return Err(DurableError::Conflict);
        }
        let original = validate(
            &self.enrollment,
            &snapshot.image,
            &self.pin,
            &self.state.proposal,
        )?;
        self.check_authority(&snapshot, &original)?;
        if let Some(receipt) = &self.state.receipt {
            self.outcome(receipt)?;
        }
        Ok(original)
    }
    async fn fence_journal(&mut self) -> Result<(), DurableError> {
        let original = self.read()?;
        self.journal = None;
        if let Some(plan) = &self.transferred {
            let child = AccountRootJournalRecovery::prepare_transferred_parent(
                self.enrollment.paths.installation.files()[1],
                self.enrollment.key().await?,
                &original,
                self.state.journal,
                (**plan).clone(),
                self.state.child,
            )?;
            let mut journal = child.commit()?;
            if let Some(receipt) = &self.state.receipt {
                journal.retain_account_decision(receipt)?;
            }
            self.journal = Some(journal);
            return Ok(());
        }
        let mut journal = AccountRootJournalRecovery::resume_parent(
            self.enrollment.paths.installation.files()[1],
            self.enrollment.key().await?,
            &original,
            self.state.journal,
            self.pin.clone(),
            ParentCheckpoint {
                proposal: &self.state.proposal,
                history: &self.state.history,
                child: self.state.child,
            },
        )?;
        if let Some(receipt) = &self.state.receipt {
            journal.retain_witness_retirement(receipt)?;
        }
        self.journal = Some(journal);
        Ok(())
    }
}

/// Durable parent observations; none admits the target account.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountRootEnrollmentState {
    /// Exact intent is retained outside journal backups. Witness outcome is unknown.
    IntentRetained,
    /// Exact signed historical retirement is retained in the parent enrollment.
    WitnessCommitted,
    /// Original current-authority non-commit is retained; no original or target traffic is released.
    WitnessClosed,
}
/// Restricted root-replacement owner retaining the original enrollment lease.
/// The host independently authenticates approval of the exact complete proposal.
/// Keep this enrollment outside journal backups. This is not whole-host rollback
/// protection, a successor installer or a peer-account authority registry.
/// ```compile_fail
/// use q_periapt_continuity_identity_candidate::{AccountRootEnrollmentRecovery, EnrolledDevice};
/// fn traffic(owner: AccountRootEnrollmentRecovery) -> EnrolledDevice { owner }
/// ```
pub struct AccountRootEnrollmentRecovery {
    active: Option<Box<Owners>>,
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl EnrolledDevice {
    /// Consume this service/signer, retain the independently approved original
    /// root intent in its enrollment, then fence its exact journal. Failure can
    /// follow either commit; resume this original operation, never reopen for traffic.
    pub async fn begin_account_root_replacement(
        mut self,
        pin: AnchorPin,
        proposal: Proposal,
    ) -> Result<AccountRootEnrollmentRecovery, DurableError> {
        let owners = *self.active.take().ok_or(DurableError::Closed)?;
        drop(owners.service);
        drop(owners.signer);
        AccountRootEnrollmentRecovery::prepare(owners.enrollment, pin, proposal).await
    }
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl AccountRootEnrollmentRecovery {
    /// Recover only the existing enrollment and original independently retained
    /// proposal. Also reconciles a failed first parent commit; never provisions
    /// missing configuration, keys or journal. The original signer is not opened.
    pub async fn resume_original(
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
        pin: AnchorPin,
        proposal: Proposal,
    ) -> Result<Self, DurableError> {
        Self::prepare(
            DeviceEnrollment::open_original_storage(paths, intent).await?,
            pin,
            proposal,
        )
        .await
    }
    pub(super) async fn prepare(
        enrollment: DeviceEnrollment,
        pin: AnchorPin,
        proposal: Proposal,
    ) -> Result<Self, DurableError> {
        let active = enrollment.active.as_ref().ok_or(DurableError::Closed)?;
        let snapshot = read_snapshot(&active.database, &active.key, enrollment.binding)?;
        if snapshot.retirement.is_some() {
            return Err(DurableError::Conflict);
        }
        let original = validate(&enrollment, &snapshot.image, &pin, &proposal)?;
        let fresh = snapshot.root_replacement.is_none();
        let mut state = match snapshot.root_replacement {
            Some(state) if state.proposal == proposal => *state,
            Some(_) => return Err(DurableError::Conflict),
            None => {
                let Phase::Accepted { admission, .. } = snapshot.image.phase else {
                    return Err(DurableError::Suspended);
                };
                State {
                    identity: snapshot.image.identity,
                    image: original_digest(&enrollment)?,
                    journal: admission.journal,
                    proposal,
                    receipt: None,
                    history: Vec::new(),
                    child: None,
                    authority: None,
                    selection: None,
                }
            }
        };
        let child = AccountRootJournalRecovery::prepare_parent(
            enrollment.paths.installation.files()[1],
            enrollment.key().await?,
            &original,
            state.journal,
            pin.clone(),
            ParentCheckpoint {
                proposal: &state.proposal,
                history: &state.history,
                child: state.child,
            },
        )?;
        if fresh {
            state.child = Some(child.checkpoint());
            save(&enrollment, None, &state, "intent")?;
        }
        let mut journal = child.commit()?;
        if let Some(receipt) = &state.receipt {
            journal.retain_witness_retirement(receipt)?;
        }
        let owners = Owners {
            enrollment,
            pin,
            state,
            journal: Some(journal),
            transferred: None,
        };
        owners.read()?;
        Ok(Self {
            active: Some(Box::new(owners)),
        })
    }
    /// Exact approved historical operation; no signer, service or plaintext.
    pub fn proposal(&mut self) -> Result<Proposal, DurableError> {
        let result = (|| {
            let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
            owners.read()?;
            Ok(owners.state.proposal.clone())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Read parent durable progress. IntentRetained does not imply no witness commit.
    pub fn status(&mut self) -> Result<AccountRootEnrollmentState, DurableError> {
        let result = (|| {
            let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
            owners.read()?;
            match &owners.state.receipt {
                Some(wire) => owners.outcome(wire),
                None => Ok(AccountRootEnrollmentState::IntentRetained),
            }
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Authenticate the exact receipt, retain it in the original journal and then
    /// its independent parent before acknowledging historical WitnessCommitted.
    /// Original re-signatures keep the first parent receipt. Any error closes all
    /// local owners; the exact receipt and proposal reconcile unknown outcomes.
    pub fn retain_witness_retirement(
        &mut self,
        receipt: &[u8],
    ) -> Result<AccountRootEnrollmentState, DurableError> {
        let result = (|| {
            let owners = self.active.as_mut().ok_or(DurableError::Closed)?;
            owners.read()?;
            if owners.transferred.is_some() {
                return Err(DurableError::Suspended);
            }
            owners
                .pin
                .verify_retired_account(&owners.state.proposal, receipt)?;
            owners
                .journal
                .as_mut()
                .ok_or(DurableError::Closed)?
                .retain_witness_retirement(receipt)?;
            if owners.state.receipt.is_none() {
                let mut next = owners.state.clone();
                next.receipt = Some(receipt.to_vec());
                save(&owners.enrollment, Some(&owners.state), &next, "receipt")?;
                owners.state = next;
            }
            owners.read()?;
            Ok(AccountRootEnrollmentState::WitnessCommitted)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Release the original journal and enrollment leases without deleting state.
    pub fn close(&mut self) {
        self.active = None;
    }
}

#[cfg(all(test, unix))]
#[path = "account_root/tests.rs"]
mod tests;
