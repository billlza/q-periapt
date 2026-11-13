// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Retain original enrollment authority through whole-device cleanup and signer erasure.
use super::*;
use crate::retired_device::transferred::control::Control;
use crate::TransferredRetirementContext;
use crate::{
    crypto::SigningFilePlan, retired_device::JournalErasureState, AnchorRetiredCleanupProposal,
    AnchorRetiredReportAcknowledgement, AnchorRetiredSubject, RetiredInstallationRecovery,
};
use redb::ReadableTable;
mod codec;
mod signer;
mod transferred;

/// Logical state of the original acknowledged signer file, not retained pages or backups.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningFileErasureState {
    /// Original encrypted seed bytes remain; ordinary opening may already be blocked by a partial marker.
    Retained,
    /// Only the exact nonempty retirement marker remains in the original admitted inode.
    Erased,
}
#[derive(Clone, Eq, PartialEq)]
struct SignerPlan {
    file: SigningFilePlan,
    proof: SignerProof,
}
#[derive(Clone, Eq, PartialEq)]
enum SignerProof {
    Legacy(Vec<u8>),
    Transferred(Vec<u8>),
}
#[derive(Clone, Eq, PartialEq)]
struct TransferredMetadata {
    binding: [u8; 32],
    original_child: [u8; 32],
}
#[derive(Clone, Eq, PartialEq)]
pub(super) struct State {
    identity: SigningKeyId,
    enrollment_digest: [u8; 32],
    inventory: AnchorRetiredCleanupProposal,
    signer: Option<Box<SignerPlan>>,
    context: Option<TransferredMetadata>,
}
impl State {
    pub(super) fn requires_account_root(&self) -> bool {
        self.context.is_some()
    }
    pub(super) fn check_account_retirement(
        &self,
        root: &account_root::State,
    ) -> Result<(), DurableError> {
        root.check_retirement_inventory(&self.inventory, self.context.is_some())
    }
    pub(super) fn check_image(&self, image: &Image, wire: &[u8]) -> Result<(), DurableError> {
        let Phase::Accepted { admission, .. } = &image.phase else {
            return Err(DurableError::Corrupt);
        };
        let (journal, _, policy) = self.inventory.subject().journal_parts();
        if image.identity != self.identity
            || *admission.journal.as_bytes() != journal
            || admission.policy != policy
            || self.enrollment_digest != enrollment_digest(wire)
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
}
fn enrollment_digest(wire: &[u8]) -> [u8; 32] {
    digest(b"Q-PERIAPT-CONTINUITY-RETIRED-ENROLLMENT/v1", wire)
}
fn original_digest(enrollment: &DeviceEnrollment) -> Result<[u8; 32], DurableError> {
    let active = enrollment.active.as_ref().ok_or(DurableError::Closed)?;
    let tx = active.database.begin_read().map_err(storage)?;
    let table = tx.open_table(TABLE).map_err(storage)?;
    let row = table
        .get("enrollment")
        .map_err(storage)?
        .ok_or(DurableError::Corrupt)?;
    Ok(enrollment_digest(row.value()))
}
fn read_retired_snapshot(
    enrollment: &DeviceEnrollment,
    pin: &AnchorPin,
    retired: AnchorRetiredSubject,
    context: Option<&TransferredRetirementContext>,
) -> Result<EnrollmentSnapshot, DurableError> {
    let active = enrollment.active.as_ref().ok_or(DurableError::Closed)?;
    let snapshot = read_snapshot(&active.database, &active.key, enrollment.binding)?;
    if let Some(context) = context {
        transferred::check_snapshot(enrollment, &snapshot, context)?;
    } else if let Some(root) = &snapshot.root_replacement {
        if root.retirement_subject(pin, retired.subject())? != retired {
            return Err(DurableError::Conflict);
        }
    }
    if snapshot
        .retirement
        .as_ref()
        .and_then(|s| s.context.as_ref())
        .map(|m| m.binding)
        != context.map(|c| c.binding())
        && snapshot.retirement.is_some()
    {
        return Err(DurableError::Conflict);
    }
    Ok(snapshot)
}
fn save(
    enrollment: &DeviceEnrollment,
    old: Option<&State>,
    next: &State,
) -> Result<(), DurableError> {
    let active = enrollment.active.as_ref().ok_or(DurableError::Closed)?;
    let snapshot = read_snapshot(&active.database, &active.key, enrollment.binding)?;
    if snapshot.retirement.as_ref() != old {
        return Err(DurableError::Conflict);
    }
    if let Some(root) = &snapshot.root_replacement {
        next.check_account_retirement(root)?;
    }
    let root_rows = u64::from(snapshot.root_replacement.is_some());
    let selection_rows = u64::from(snapshot.witness_handoff.is_some());
    let wire = next.encode(&active.key, enrollment.binding)?;
    let expected = old
        .map(|s| s.encode(&active.key, enrollment.binding))
        .transpose()?;
    let tx = transaction(&active.database)?;
    {
        let mut table = tx.open_table(TABLE).map_err(storage)?;
        let root = table
            .get(account_root::ROW)
            .map_err(storage)?
            .map(|r| account_root::State::decode(r.value(), &active.key, enrollment.binding))
            .transpose()?;
        let selection = table
            .get(witness_handoff::ROW)
            .map_err(storage)?
            .map(|r| witness_handoff::State::decode(&active.key, enrollment.binding, r.value()))
            .transpose()?;
        if root.as_deref() != snapshot.root_replacement.as_deref()
            || selection != snapshot.witness_handoff
            || table.len().map_err(storage)?
                != 1 + u64::from(old.is_some()) + root_rows + selection_rows
            || table
                .get("retirement")
                .map_err(storage)?
                .as_ref()
                .map(|v| v.value())
                != expected.as_deref()
            || table
                .get("enrollment")
                .map_err(storage)?
                .as_ref()
                .map(|v| enrollment_digest(v.value()))
                != Some(next.enrollment_digest)
        {
            return Err(DurableError::Conflict);
        }
        table
            .insert("retirement", wire.as_slice())
            .map_err(storage)?;
    }
    #[cfg(all(test, unix))]
    if root_rows == 1 {
        account_root::cleanup::at_boundary(false);
    }
    tx.commit().map_err(DurableError::CommitUncertain)?;
    #[cfg(all(test, unix))]
    if root_rows == 1 {
        account_root::cleanup::at_boundary(true);
    }
    Ok(())
}
struct Owners {
    enrollment: DeviceEnrollment,
    pin: AnchorPin,
    retired: AnchorRetiredSubject,
    state: State,
    installation: Option<RetiredInstallationRecovery>,
    context: Option<Box<TransferredRetirementContext>>,
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl Owners {
    fn read(&self) -> Result<(Image, State, VerifiedDevice), DurableError> {
        let snapshot = read_retired_snapshot(
            &self.enrollment,
            &self.pin,
            self.retired,
            self.context.as_deref(),
        )?;
        let image = snapshot.image;
        let state = snapshot.retirement;
        let state = state.ok_or(DurableError::Conflict)?;
        if state != self.state {
            return Err(DurableError::Conflict);
        }
        state.inventory.check_retirement(self.retired)?;
        validate_metadata(&self.enrollment, &image)?;
        let original = self.enrollment.original_device_metadata(&image)?;
        check_original(
            &image,
            &original,
            self.retired,
            &self.pin,
            self.context.as_deref(),
        )?;
        if let Some(plan) = &state.signer {
            self.verify_plan(plan)?;
        }
        Ok((image, state, original))
    }
    fn verify_plan(
        &self,
        plan: &SignerPlan,
    ) -> Result<AnchorRetiredReportAcknowledgement, DurableError> {
        if plan.file.report().inventory() != &self.state.inventory
            || plan.file.identity() != self.state.identity
        {
            return Err(DurableError::Conflict);
        }
        self.verify_plan_receipt(plan, None)
    }
    async fn installation(&mut self) -> Result<&mut RetiredInstallationRecovery, DurableError> {
        self.read()?;
        // Reconcile the same saved request, including after erase_journal closed its
        // restricted child. This does not replay host effects or select another backup.
        self.installation = None;
        let mut child =
            transferred::installation(&self.enrollment, self.retired, self.context.as_deref())
                .await?;
        if child.proposal()? != self.state.inventory {
            return Err(DurableError::Conflict);
        }
        self.installation = Some(child);
        self.installation.as_mut().ok_or(DurableError::Closed)
    }
}
fn validate_metadata(enrollment: &DeviceEnrollment, image: &Image) -> Result<(), DurableError> {
    enrollment.validate_roster_resolution(image)?;
    enrollment.validate_witness_roster(image)?;
    enrollment.validate_policy_pending(image)
}
fn check_original(
    image: &Image,
    original: &VerifiedDevice,
    retired: AnchorRetiredSubject,
    pin: &AnchorPin,
    context: Option<&TransferredRetirementContext>,
) -> Result<(), DurableError> {
    let Phase::Accepted { admission, .. } = &image.phase else {
        return Err(DurableError::Suspended);
    };
    let (journal, owner, policy) = retired.subject().journal_parts();
    if journal != *admission.journal.as_bytes()
        || owner != crate::bootstrap::storage_owner(original)
        || policy != admission.policy
        || context.map_or(pin.binding() != retired.witness_binding(), |c| {
            c.retired_subject() != retired || c.accounting_pin().binding() != pin.binding()
        })
    {
        return Err(DurableError::Conflict);
    }
    Ok(())
}

/// Restricted original enrollment owner for permanent device or account retirement.
/// Holds the enrollment lease across reporting and host acknowledgement; no signer,
/// enrollment request or operational service is exposed. Historical metadata retains
/// the original identity even after credential/policy expiry.
/// ```compile_fail
/// use q_periapt_continuity_identity_candidate::{EnrolledDevice, RetiredDeviceEnrollment};
/// fn active(old: RetiredDeviceEnrollment) -> EnrolledDevice { old }
/// ```
pub struct RetiredDeviceEnrollment {
    active: Option<Owners>,
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl RetiredDeviceEnrollment {
    /// Open the original existing enrollment with independently verified permanent
    /// retirement and its original witness pin. First admission retains the existing
    /// installation's original inventory, then freezes the enrollment metadata.
    /// An unknown commit returns no owner; reopen these exact paths/intent/proof.
    pub async fn open(
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
        pin: AnchorPin,
        retired: AnchorRetiredSubject,
    ) -> Result<Self, DurableError> {
        Self::open_with_storage(
            crate::storage::Storage::native()?,
            paths,
            intent,
            pin,
            retired,
        )
        .await
    }
    pub(crate) async fn open_with_storage(
        store: crate::storage::Storage,
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
        pin: AnchorPin,
        retired: AnchorRetiredSubject,
    ) -> Result<Self, DurableError> {
        Self::from_enrollment(
            DeviceEnrollment::open_original_storage_with_storage(store, paths, intent).await?,
            pin,
            retired,
        )
        .await
    }
    pub(super) fn is_closed(&self) -> bool {
        self.active.is_none()
    }
    pub(super) async fn check_managed_scope(
        &self,
        paths: &EnrollmentPaths,
        intent: &EnrollmentIntent,
        pin: &AnchorPin,
        proposal: &crate::AnchorAccountReplacementProposal,
    ) -> Result<(), DurableError> {
        let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
        owners.read()?;
        let original_pin = if let Some(context) = &owners.context {
            context.plan().witness_pin()?
        } else {
            &owners.pin
        };
        if original_pin.binding() != pin.binding()
            || owners.enrollment.binding
                != paths.binding(&owners.enrollment.key().await?, intent)?
        {
            return Err(DurableError::Conflict);
        }
        owners.state.inventory.check_account_proposal(proposal)?;
        Ok(())
    }
    #[cfg(all(test, unix))]
    pub(crate) fn open_in_database(
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
        pin: AnchorPin,
        retired: AnchorRetiredSubject,
        database: Database,
    ) -> Result<Self, DurableError> {
        Self::open_context_in_database(paths, intent, pin, retired, None, database)
    }
    #[cfg(all(test, unix))]
    fn open_context_in_database(
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
        pin: AnchorPin,
        retired: AnchorRetiredSubject,
        context: Option<Box<TransferredRetirementContext>>,
        database: Database,
    ) -> Result<Self, DurableError> {
        let key = JournalKey::open(&paths.wrapping)?;
        let binding = paths.binding(&key, &intent)?;
        Self::from_enrollment_context(
            DeviceEnrollment {
                storage: crate::storage::Storage::native()?,
                active: Some(Active { database, key }),
                paths,
                intent,
                binding,
                account_authority: None,
            },
            pin,
            retired,
            context,
        )
    }
    pub(super) async fn from_enrollment(
        enrollment: DeviceEnrollment,
        pin: AnchorPin,
        retired: AnchorRetiredSubject,
    ) -> Result<Self, DurableError> {
        Self::from_enrollment_context(enrollment, pin, retired, None).await
    }
    async fn from_enrollment_context(
        enrollment: DeviceEnrollment,
        pin: AnchorPin,
        retired: AnchorRetiredSubject,
        context: Option<Box<TransferredRetirementContext>>,
    ) -> Result<Self, DurableError> {
        let snapshot = read_retired_snapshot(&enrollment, &pin, retired, context.as_deref())?;
        let image = &snapshot.image;
        validate_metadata(&enrollment, image)?;
        let original = enrollment.original_device_metadata(image)?;
        check_original(image, &original, retired, &pin, context.as_deref())?;
        let state = match snapshot.retirement {
            Some(state) => {
                state.inventory.check_retirement(retired)?;
                state
            }
            None => {
                let observed = if let Some(context) = &context {
                    let key = enrollment.key().await?;
                    let db = enrollment
                        .storage
                        .open_database(enrollment.paths.installation.files()[1])
                        .await?;
                    let observation =
                        crate::DeviceJournal::observe_transferred_retirement_in_database(
                            &db,
                            &key,
                            JournalIdentity::from_trusted_state(
                                retired.subject().journal_parts().0,
                            )?,
                            context,
                        )?;
                    snapshot
                        .root_replacement
                        .as_ref()
                        .ok_or(DurableError::Conflict)?
                        .check_retirement_observation(&observation)?;
                    Some(observation)
                } else {
                    None
                };
                let mut child =
                    transferred::installation(&enrollment, retired, context.as_deref()).await?;
                let inventory = child.proposal()?;
                if observed.as_ref().is_some_and(|o| o.inventory != inventory) {
                    return Err(DurableError::Conflict);
                }
                let state = State {
                    identity: image.identity,
                    enrollment_digest: original_digest(&enrollment)?,
                    inventory,
                    signer: None,
                    context: match (&context, observed) {
                        (Some(context), Some(o)) => Some(TransferredMetadata {
                            binding: context.binding(),
                            original_child: o.original_child,
                        }),
                        (None, None) => None,
                        _ => return Err(DurableError::Conflict),
                    },
                };
                save(&enrollment, None, &state)?;
                state
            }
        };
        let owner = Owners {
            enrollment,
            pin,
            retired,
            state,
            installation: None,
            context,
        };
        owner.read()?;
        Ok(Self {
            active: Some(owner),
        })
    }
    /// Borrow the existing restricted installation flow for full report retention,
    /// explicit host acknowledgement and journal erasure. Each new borrow reopens
    /// the same independently saved expectation; missing originals are never replaced.
    pub async fn installation(&mut self) -> Result<&mut RetiredInstallationRecovery, DurableError> {
        let result = match self.active.as_mut() {
            Some(owner) => owner.installation().await.map(|_| ()),
            None => Err(DurableError::Closed),
        };
        if let Err(error) = result {
            self.close();
            return Err(error);
        }
        self.active
            .as_mut()
            .and_then(|o| o.installation.as_mut())
            .ok_or(DurableError::Closed)
    }
    /// Close all held enrollment, wrapping and restricted installation owners.
    pub fn close(&mut self) {
        self.active = None;
    }
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl EnrolledDevice {
    /// Consume this device's service and signer, retaining its original enrollment
    /// lease for permanent retirement under independently verified witness authority.
    pub async fn retire(
        mut self,
        pin: AnchorPin,
        retired: AnchorRetiredSubject,
    ) -> Result<RetiredDeviceEnrollment, DurableError> {
        let owners = self.active.take().ok_or(DurableError::Closed)?;
        let EnrolledOwners {
            enrollment,
            mut service,
            mut signer,
            ..
        } = *owners;
        service.close();
        signer.close();
        RetiredDeviceEnrollment::from_enrollment(enrollment, pin, retired).await
    }
}
