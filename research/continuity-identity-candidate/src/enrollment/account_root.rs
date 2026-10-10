// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Keep original root-replacement approval outside replaceable journal backups.
use super::*;
use crate::{AccountRootJournalRecovery, AnchorAccountReplacementProposal as Proposal};
use redb::ReadableTable;

pub(super) const ROW: &str = "root-replacement";
const TAG: &[u8; 8] = b"QPERPL01";
const RECEIPT_BYTES: usize = 3449;
const MAX_BYTES: usize = 174 + 65_536 + RECEIPT_BYTES;

#[derive(Clone, Eq, PartialEq)]
pub(super) struct State {
    identity: SigningKeyId,
    image: [u8; 32],
    journal: JournalIdentity,
    proposal: Proposal,
    receipt: Option<Vec<u8>>,
}
fn image_digest(wire: &[u8]) -> [u8; 32] {
    digest(b"Q-PERIAPT-CONTINUITY-ROOT-ENROLLMENT/v1", wire)
}
impl State {
    pub(super) fn decode(
        wire: &[u8],
        key: &JournalKey,
        binding: [u8; 32],
    ) -> Result<Box<Self>, DurableError> {
        if !(174..=MAX_BYTES).contains(&wire.len()) {
            return Err(DurableError::Corrupt);
        }
        let (body, tag) = wire.split_at(wire.len() - 32);
        let mut mac = auth(key)?;
        mac.update(body);
        mac.verify_slice(tag)
            .map_err(|_| DurableError::Authentication)?;
        let mut d = Decoder::new(body);
        if d.array::<8>()? != *TAG || d.array::<32>()? != binding {
            return Err(DurableError::Conflict);
        }
        let identity = SigningKeyId::from_trusted_state(d.array()?)?;
        let image = d.array()?;
        crate::codec::nonzero(&image)?;
        let journal = JournalIdentity::from_trusted_state(d.array()?)?;
        let n =
            usize::try_from(u32::from_be_bytes(d.array()?)).map_err(|_| DurableError::Capacity)?;
        if n > 65_536 {
            return Err(DurableError::Capacity);
        }
        let proposal = Proposal::from_trusted_state(d.take(n)?)?;
        let receipt = match usize::from(d.u16()?) {
            0 => None,
            RECEIPT_BYTES => Some(d.take(RECEIPT_BYTES)?.to_vec()),
            _ => return Err(DurableError::Corrupt),
        };
        d.finish()?;
        Ok(Box::new(Self {
            identity,
            image,
            journal,
            proposal,
            receipt,
        }))
    }
    fn encode(&self, key: &JournalKey, binding: [u8; 32]) -> Result<Vec<u8>, DurableError> {
        let proposal = self.proposal.to_bytes()?;
        let receipt = self.receipt.as_deref().unwrap_or(&[]);
        if !receipt.is_empty() && receipt.len() != RECEIPT_BYTES {
            return Err(DurableError::Corrupt);
        }
        let mut wire = TAG.to_vec();
        wire.extend_from_slice(&binding);
        wire.extend_from_slice(self.identity.as_bytes());
        wire.extend_from_slice(&self.image);
        wire.extend_from_slice(self.journal.as_bytes());
        wire.extend_from_slice(
            &u32::try_from(proposal.len())
                .map_err(|_| DurableError::Capacity)?
                .to_be_bytes(),
        );
        wire.extend_from_slice(&proposal);
        wire.extend_from_slice(
            &u16::try_from(receipt.len())
                .map_err(|_| DurableError::Capacity)?
                .to_be_bytes(),
        );
        wire.extend_from_slice(receipt);
        let mut mac = auth(key)?;
        mac.update(&wire);
        wire.extend_from_slice(&mac.finalize().into_bytes());
        if wire.len() > MAX_BYTES {
            return Err(DurableError::Capacity);
        }
        Ok(wire)
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
        if table.len().map_err(storage)? != 1 + u64::from(previous.is_some())
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
}
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
        if let Some(receipt) = &self.state.receipt {
            self.pin
                .verify_retired_account(&self.state.proposal, receipt)?;
        }
        Ok(original)
    }
    fn fence_journal(&mut self) -> Result<(), DurableError> {
        let original = self.read()?;
        self.journal = None;
        let mut journal = AccountRootJournalRecovery::resume_original(
            self.enrollment.paths.installation.files()[1],
            self.enrollment.key()?,
            &original,
            self.state.journal,
            self.pin.clone(),
            self.state.proposal.clone(),
        )?;
        if let Some(receipt) = &self.state.receipt {
            journal.retain_witness_retirement(receipt)?;
        }
        self.journal = Some(journal);
        Ok(())
    }
}

/// Durable parent observations; neither state admits the target account.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountRootEnrollmentState {
    /// Exact intent is retained outside journal backups. Witness outcome is unknown.
    IntentRetained,
    /// Exact signed historical retirement is retained in the parent enrollment.
    WitnessCommitted,
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
impl EnrolledDevice {
    /// Consume this service/signer, retain the independently approved original
    /// root intent in its enrollment, then fence its exact journal. Failure can
    /// follow either commit; resume this original operation, never reopen for traffic.
    pub fn begin_account_root_replacement(
        mut self,
        pin: AnchorPin,
        proposal: Proposal,
    ) -> Result<AccountRootEnrollmentRecovery, DurableError> {
        let owners = *self.active.take().ok_or(DurableError::Closed)?;
        drop(owners.service);
        drop(owners.signer);
        AccountRootEnrollmentRecovery::prepare(owners.enrollment, pin, proposal)
    }
}
impl AccountRootEnrollmentRecovery {
    /// Recover only the existing enrollment and original independently retained
    /// proposal. Also reconciles a failed first parent commit; never provisions
    /// missing configuration, keys or journal. The original signer is not opened.
    pub fn resume_original(
        paths: EnrollmentPaths,
        intent: EnrollmentIntent,
        pin: AnchorPin,
        proposal: Proposal,
    ) -> Result<Self, DurableError> {
        let key = JournalKey::open(&paths.wrapping)?;
        let binding = paths.binding(&key, &intent)?;
        let database = open_private_database(&paths.configuration)?;
        Self::prepare(
            DeviceEnrollment {
                active: Some(Active { database, key }),
                paths,
                intent,
                binding,
            },
            pin,
            proposal,
        )
    }
    fn prepare(
        enrollment: DeviceEnrollment,
        pin: AnchorPin,
        proposal: Proposal,
    ) -> Result<Self, DurableError> {
        let active = enrollment.active.as_ref().ok_or(DurableError::Closed)?;
        let snapshot = read_snapshot(&active.database, &active.key, enrollment.binding)?;
        if snapshot.retirement.is_some() {
            return Err(DurableError::Conflict);
        }
        validate(&enrollment, &snapshot.image, &pin, &proposal)?;
        let state = match snapshot.root_replacement {
            Some(state) if state.proposal == proposal => *state,
            Some(_) => return Err(DurableError::Conflict),
            None => {
                let Phase::Accepted { admission, .. } = snapshot.image.phase else {
                    return Err(DurableError::Suspended);
                };
                let state = State {
                    identity: snapshot.image.identity,
                    image: original_digest(&enrollment)?,
                    journal: admission.journal,
                    proposal,
                    receipt: None,
                };
                save(&enrollment, None, &state, "intent")?;
                state
            }
        };
        let mut owners = Owners {
            enrollment,
            pin,
            state,
            journal: None,
        };
        owners.fence_journal()?;
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
            Ok(if owners.state.receipt.is_some() {
                AccountRootEnrollmentState::WitnessCommitted
            } else {
                AccountRootEnrollmentState::IntentRetained
            })
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
