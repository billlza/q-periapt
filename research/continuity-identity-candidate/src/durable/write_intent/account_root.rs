// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Fence one original journal without advancing or rewriting its witnessed image.
use super::*;
use crate::{
    AnchorAccountReplacementProposal as Proposal, AnchorPin, AnchorRetiredAccount, AnchorSubject,
};

pub(crate) mod transfer;
pub use transfer::AccountRootJournalTransition;

const ROW: &str = "account-root-fence";
const TAG: &[u8; 8] = b"QPARJF01";
const TRANSFER_TAG: &[u8; 8] = b"QPARJF02";
const RECEIPT_BYTES: usize = 3449;
const MAX_FENCE_BYTES: usize =
    207 + 65_536 + RECEIPT_BYTES + 2 + transfer::MAX_TRANSFERS * transfer::TRANSFER_BYTES;

#[derive(Clone, Eq, PartialEq)]
struct Fence {
    subject: AnchorSubject,
    image: [u8; 32],
    pending: Option<[u8; 32]>,
    proposal: Proposal,
    receipt: Option<Vec<u8>>,
    history: Vec<transfer::Transfer>,
}
fn pending_digest(bytes: &[u8]) -> [u8; 32] {
    digest(b"Q-PERIAPT-CONTINUITY-ACCOUNT-ROOT-LOCAL-INTENT/v1", bytes)
}
fn mac(key: &JournalKey) -> Result<Hmac<Sha256>, DurableError> {
    let derived = key.account_root_fence_key()?;
    <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(derived.as_bytes())
        .map_err(|_| Error::Provider.into())
}
fn subject(
    key: &JournalKey,
    image: &Image,
    pending: Option<&PendingIntent>,
    proposal: &Proposal,
) -> Result<AnchorSubject, DurableError> {
    let Protection::Required {
        policy, witness, ..
    } = image.protection
    else {
        return Err(DurableError::AnchorRequired);
    };
    if proposal.previous_account() != image.local_account || proposal.witness_binding() != witness {
        return Err(Error::Scope.into());
    }
    let subject = proposal
        .predecessors()
        .find(|s| s.journal_parts() == (image.id, image.owner, policy))
        .ok_or(Error::Scope)?;
    let observed = proposal.predecessor_observation(subject)?.observed_head();
    if image.protection.head(image.revision, image.digest)? != observed {
        let Some(PendingIntent::Write(pending)) = pending else {
            return Err(DurableError::Conflict);
        };
        let target = pending.authenticated_target(key, image.owner)?;
        if target.protection.head(target.revision, target.digest)? != observed {
            return Err(DurableError::Conflict);
        }
    }
    Ok(subject)
}
impl Fence {
    fn new(
        key: &JournalKey,
        image: &Image,
        pending: Option<&PendingIntent>,
        proposal: Proposal,
    ) -> Result<Self, DurableError> {
        Ok(Self {
            subject: subject(key, image, pending, &proposal)?,
            image: image.digest,
            pending: pending.map(|p| pending_digest(p.wire())),
            proposal,
            receipt: None,
            history: Vec::new(),
        })
    }
    fn check(
        &self,
        key: &JournalKey,
        image: &Image,
        pending: Option<&PendingIntent>,
    ) -> Result<(), DurableError> {
        transfer::check_history(&self.history, &self.proposal)?;
        if self.subject != subject(key, image, pending, &self.proposal)?
            || self.image != image.digest
            || self.pending != pending.map(|p| pending_digest(p.wire()))
        {
            return Err(DurableError::Conflict);
        }
        Ok(())
    }
    fn encode(&self, key: &JournalKey) -> Result<Vec<u8>, DurableError> {
        transfer::check_history(&self.history, &self.proposal)?;
        let proposal = self.proposal.to_bytes()?;
        let receipt = self.receipt.as_deref().unwrap_or(&[]);
        if !receipt.is_empty() && receipt.len() != RECEIPT_BYTES {
            return Err(DurableError::Corrupt);
        }
        let extended = !self.history.is_empty();
        let mut bytes = if extended { TRANSFER_TAG } else { TAG }.to_vec();
        bytes.extend_from_slice(&self.subject.to_bytes());
        bytes.extend_from_slice(&self.image);
        bytes.push(u8::from(self.pending.is_some()));
        bytes.extend_from_slice(&self.pending.unwrap_or([0; 32]));
        bytes.extend_from_slice(
            &u32::try_from(proposal.len())
                .map_err(|_| DurableError::Capacity)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&proposal);
        bytes.extend_from_slice(
            &u16::try_from(receipt.len())
                .map_err(|_| DurableError::Capacity)?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(receipt);
        if extended {
            transfer::encode_history(&self.history, &mut bytes)?;
        }
        let mut auth = mac(key)?;
        auth.update(&bytes);
        bytes.extend_from_slice(&auth.finalize().into_bytes());
        if bytes.len() > MAX_FENCE_BYTES {
            return Err(DurableError::Capacity);
        }
        Ok(bytes)
    }
    fn decode(key: &JournalKey, bytes: &[u8]) -> Result<Self, DurableError> {
        if !(207..=MAX_FENCE_BYTES).contains(&bytes.len()) {
            return Err(DurableError::Corrupt);
        }
        let (body, tag) = bytes.split_at(bytes.len() - 32);
        let mut auth = mac(key)?;
        auth.update(body);
        auth.verify_slice(tag)
            .map_err(|_| DurableError::Authentication)?;
        let mut d = Decoder::new(body);
        let extended = match &d.array::<8>()? {
            tag if tag == TAG => false,
            tag if tag == TRANSFER_TAG => true,
            _ => return Err(DurableError::Corrupt),
        };
        let subject = AnchorSubject::from_trusted_state(d.take(96)?)?;
        let image = d.array()?;
        crate::codec::nonzero(&image)?;
        let [present] = d.array()?;
        let fingerprint = d.array()?;
        let pending = match present {
            0 if fingerprint == [0; 32] => None,
            1 => {
                crate::codec::nonzero(&fingerprint)?;
                Some(fingerprint)
            }
            _ => return Err(DurableError::Corrupt),
        };
        let size =
            usize::try_from(u32::from_be_bytes(d.array()?)).map_err(|_| DurableError::Capacity)?;
        if size > 65_536 {
            return Err(DurableError::Capacity);
        }
        let proposal = Proposal::from_trusted_state(d.take(size)?)?;
        let size = usize::from(d.u16()?);
        let receipt = match size {
            0 => None,
            RECEIPT_BYTES => Some(d.take(size)?.to_vec()),
            _ => return Err(DurableError::Corrupt),
        };
        let history = if extended {
            transfer::decode_history(&mut d)?
        } else {
            Vec::new()
        };
        d.finish()?;
        transfer::check_history(&history, &proposal)?;
        Ok(Self {
            subject,
            image,
            pending,
            proposal,
            receipt,
            history,
        })
    }
}

pub(super) fn validate_fence_snapshot(
    key: &JournalKey,
    image: &Image,
    pending: Option<&PendingIntent>,
    wire: &[u8],
) -> Result<(), DurableError> {
    Fence::decode(key, wire)?.check(key, image, pending)
}

/// Original local fence state. Neither variant is permission to operate a successor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountRootJournalState {
    /// Original image and pending intent are locally frozen; witness outcome is unknown.
    LocalFenced,
    /// An authentic receipt for the exact original witness decision is durably retained.
    WitnessCommitted,
}
struct Owners {
    db: Database,
    key: JournalKey,
    owner: [u8; 32],
    identity: JournalIdentity,
    pin: AnchorPin,
    proposal: Proposal,
}
impl Owners {
    fn read(&self) -> Result<Fence, DurableError> {
        let fence = self.read_snapshot()?;
        if fence.proposal != self.proposal {
            return Err(DurableError::Conflict);
        }
        Ok(fence)
    }
    fn read_snapshot(&self) -> Result<Fence, DurableError> {
        let (image, pending) = load_pending_snapshot(
            &self.db,
            &self.key,
            self.owner,
            SnapshotAdmission::AccountRootReplacement,
        )?;
        if image.id != *self.identity.as_bytes() {
            return Err(DurableError::Conflict);
        }
        let read = self.db.begin_read().map_err(storage)?;
        let table = image_table(&read)?;
        let saved = table
            .get(ROW)
            .map_err(storage)?
            .ok_or(DurableError::Absent)?;
        let fence = Fence::decode(&self.key, saved.value())?;
        fence.check(&self.key, &image, pending.as_ref())?;
        if self.pin.binding() != fence.proposal.witness_binding() {
            return Err(DurableError::Conflict);
        }
        if let Some(receipt) = &fence.receipt {
            self.pin.verify_retired_account(&fence.proposal, receipt)?;
        }
        Ok(fence)
    }
    fn save(
        &self,
        previous: Option<&Fence>,
        next: &Fence,
        stage: &'static str,
    ) -> Result<(), DurableError> {
        let expected = previous.map(|f| f.encode(&self.key)).transpose()?;
        let wire = next.encode(&self.key)?;
        let tx = transaction(&self.db)?;
        {
            let mut table = tx.open_table(TABLE).map_err(storage)?;
            let image = table
                .get("image")
                .map_err(storage)?
                .ok_or(DurableError::Corrupt)?;
            if image_hash(image.value()) != next.image {
                return Err(DurableError::Conflict);
            }
            drop(image);
            let pending = table.get("pending").map_err(storage)?;
            if pending.as_ref().map(|p| pending_digest(p.value())) != next.pending
                || table.get(ROW).map_err(storage)?.as_ref().map(|v| v.value())
                    != expected.as_deref()
                || table.len().map_err(storage)?
                    != 1 + u64::from(pending.is_some()) + u64::from(previous.is_some())
            {
                return Err(DurableError::Conflict);
            }
            drop(pending);
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
    fn prepare(self) -> Result<AccountRootJournalRecovery, DurableError> {
        if self.pin.binding() != self.proposal.witness_binding() {
            return Err(Error::Scope.into());
        }
        let (image, pending) = load_pending_snapshot(
            &self.db,
            &self.key,
            self.owner,
            SnapshotAdmission::AccountRootReplacement,
        )?;
        if image.id != *self.identity.as_bytes() {
            return Err(DurableError::Conflict);
        }
        let next = Fence::new(&self.key, &image, pending.as_ref(), self.proposal.clone())?;
        let read = self.db.begin_read().map_err(storage)?;
        let table = image_table(&read)?;
        let exists = table.get(ROW).map_err(storage)?.is_some();
        drop(table);
        drop(read);
        if !exists {
            self.save(None, &next, "fence")?;
        }
        self.read()?;
        Ok(AccountRootJournalRecovery {
            active: Some(Box::new(self)),
        })
    }
}

/// Exclusive, non-operational owner of a locally fenced original journal.
/// It retains the image, pending transaction and exact independently approved root
/// proposal. It cannot activate a device or erase/resolve original deliveries.
/// This component does not supply application-account authentication, whole-host
/// anti-rollback, successor installation or a witness-key transfer.
/// ```compile_fail
/// use q_periapt_continuity_identity_candidate::{AccountRootJournalRecovery, DeviceJournal};
/// fn traffic(owner: AccountRootJournalRecovery) -> DeviceJournal { owner }
/// ```
pub struct AccountRootJournalRecovery {
    active: Option<Box<Owners>>,
}
impl DeviceJournal {
    /// Close this operational handle and durably freeze its exact original state
    /// without advancing the witnessed head. The host must independently approve
    /// and retain this complete proposal before calling; parsing it is not approval.
    /// Any failure consumes this journal owner. Reconcile only the original inputs.
    pub fn begin_account_root_replacement(
        &mut self,
        pin: AnchorPin,
        proposal: Proposal,
    ) -> Result<AccountRootJournalRecovery, DurableError> {
        let active = self.active.take().ok_or(DurableError::Closed)?;
        Owners {
            db: active.db,
            key: active.key,
            owner: active.owner,
            identity: JournalIdentity(active.id),
            pin,
            proposal,
        }
        .prepare()
    }
}
impl AccountRootJournalRecovery {
    /// Reconcile the original fence after lost return or restart, including a
    /// failed first fence write. Existing storage and independently retained original
    /// identity/proposal are required. Missing storage is never provisioned; a
    /// competing snapshot cannot be selected and the old account is never reopened
    /// for traffic. Historical credential metadata does not grant current authority.
    pub fn resume_original(
        path: &Path,
        key: JournalKey,
        original: &VerifiedDevice,
        identity: JournalIdentity,
        pin: AnchorPin,
        proposal: Proposal,
    ) -> Result<Self, DurableError> {
        Owners {
            db: open_private_database(path)?,
            key,
            owner: bootstrap::storage_owner(original),
            identity,
            pin,
            proposal,
        }
        .prepare()
    }
    /// Exact retained proposal. No original ciphertext, secret or live owner is released.
    pub fn proposal(&mut self) -> Result<Proposal, DurableError> {
        let result = self
            .active
            .as_ref()
            .ok_or(DurableError::Closed)
            .and_then(|o| o.read())
            .map(|f| f.proposal);
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Read the durable local observation. LocalFenced makes no claim about whether
    /// the witness committed; losing a reply must reconcile the exact proposal.
    pub fn status(&mut self) -> Result<AccountRootJournalState, DurableError> {
        let result = self
            .active
            .as_ref()
            .ok_or(DurableError::Closed)
            .and_then(|o| o.read())
            .map(|f| {
                if f.receipt.is_some() {
                    AccountRootJournalState::WitnessCommitted
                } else {
                    AccountRootJournalState::LocalFenced
                }
            });
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Authenticate and retain a purpose-22 receipt before acknowledging the witness
    /// decision. Exact-statement retries keep the first receipt, even if re-signing
    /// produced different signature bytes. I/O failure closes this owner and may
    /// follow commit. This historical fact grants no successor operating permission.
    pub fn retain_witness_retirement(
        &mut self,
        wire: &[u8],
    ) -> Result<AccountRootJournalState, DurableError> {
        let result = (|| {
            let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
            let original = owners.read()?;
            owners.pin.verify_retired_account(&owners.proposal, wire)?;
            if original.receipt.is_none() {
                let mut next = original.clone();
                next.receipt = Some(wire.to_vec());
                owners.save(Some(&original), &next, "receipt")?;
            }
            owners.read()?.receipt.ok_or(DurableError::Corrupt)?;
            Ok(AccountRootJournalState::WitnessCommitted)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Authenticate the immutable retained retirement statement for historical
    /// accounting. Absence is explicit and closes this recovery handle.
    pub fn retirement(&mut self) -> Result<AnchorRetiredAccount, DurableError> {
        let result = (|| {
            let owners = self.active.as_ref().ok_or(DurableError::Closed)?;
            let fence = owners.read()?;
            let receipt = fence.receipt.ok_or(DurableError::Absent)?;
            Ok(owners
                .pin
                .verify_retired_account(&owners.proposal, &receipt)?)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Release the wrapping key and exclusive lease; never remove the durable fence.
    pub fn close(&mut self) {
        self.active = None;
    }
}

#[cfg(all(test, unix))]
#[path = "account_root/tests.rs"]
mod tests;
