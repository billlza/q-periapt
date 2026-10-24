// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

impl AnchorStore {
    /// Durably authorize one exact dual-approved inherited client. Validate the
    /// complete original entry and public root/identity/policy metadata, then
    /// commit its immutable authorization row and primary digest index together.
    /// This does not assert client-journal adoption or unlock the legacy handler.
    ///
    /// Retain and retry the exact request. A transaction error closes this owner
    /// and may follow commit; reopen the same target and recover its receipt.
    /// Exact committed retries are historical and do not consult the clock.
    pub fn authorize_handoff_client(
        &mut self,
        request: &[u8],
        mut trusted_time: impl FnMut() -> Result<u64, DurableError>,
    ) -> Result<AnchorHandoffClientAuthorizationReceipt, DurableError> {
        let claimed = RetainedAdoptionRequest::unverified_scope(request)?;
        let mut current = self.image()?;
        let owner = self.active.as_ref().ok_or(DurableError::Closed)?;
        let transferred = owner.transferred.as_ref().ok_or(DurableError::Suspended)?;
        let id = claimed.subject.id(&current.namespace);
        let mut image =
            storage::load_authenticated(&owner.db, &owner.wrapping, &transferred.approval)?;
        transferred.admit(&image)?;
        if current.digest != image.digest {
            return Err(DurableError::Conflict);
        }
        let records = load_records(
            &owner.db,
            &transferred.approval,
            &image,
            &transferred.original,
        )?;
        if let Some(existing) = records.get(&id) {
            return if existing.request.as_bytes() == request {
                Ok(existing.receipt.clone())
            } else {
                Err(DurableError::Conflict)
            };
        }
        if records
            .values()
            .any(|r| r.request.scope().operation() == claimed.operation())
        {
            return Err(DurableError::Conflict);
        }
        if current.subject_retired(claimed.subject) || current.subject_frozen(claimed.subject) {
            return Err(Error::Retired.into());
        }
        if !current.inherited.contains(&id) {
            return Err(DurableError::Conflict);
        }
        let activation = image.activation.as_ref().ok_or(DurableError::Corrupt)?;
        let (activation_receipt, history) = verify(
            &transferred.approval,
            &image.freeze,
            &image.acknowledgement,
            &activation.retirement,
            &activation.receipt,
        )?;
        let entry = transferred
            .original
            .entries
            .get(&id)
            .ok_or(DurableError::Absent)?;
        let request = RetainedAdoptionRequest::restore(
            request,
            &entry.device,
            &history,
            &activation_receipt,
        )?;
        check_request(
            &request,
            id,
            &transferred.original,
            &transferred.approval,
            &history,
        )?;
        let admitted = trusted_time()?;
        request.approved.check_admission(admitted)?;
        let receipt = AnchorHandoffClientAuthorizationReceipt::sign(
            &owner.signer,
            &request.approved,
            &history,
            admitted,
        )?;
        let record = Record { request, receipt };
        let encoded = record.encode()?;
        if image.client_index.len() >= MAX_ENTRIES {
            return Err(DurableError::Capacity);
        }
        current.revision = increment(current.revision)?;
        image
            .activation
            .as_mut()
            .ok_or(DurableError::Corrupt)?
            .content = image_codec::encode_content(&history, &current)?;
        image.client_index.insert(id, record_digest(&encoded));
        let bytes = storage::seal(&owner.wrapping, &transferred.approval, &image)?;
        let result = (|| {
            let owner = self.active.as_mut().ok_or(DurableError::Closed)?;
            let transferred = owner.transferred.as_ref().ok_or(DurableError::Suspended)?;
            let tx = crate::durable::transaction(&owner.db)?;
            {
                let mut primary = tx.open_table(IMPORT_TABLE).map_err(storage)?;
                if primary.len().map_err(storage)? != 1 {
                    return Err(DurableError::Corrupt);
                }
                let saved = primary
                    .get("image")
                    .map_err(storage)?
                    .ok_or(DurableError::Corrupt)?;
                if storage::image_digest(saved.value()) != image.digest {
                    return Err(DurableError::Conflict);
                }
                drop(saved);
                let mut clients = tx.open_table(TABLE).map_err(storage)?;
                if clients.len().map_err(storage)?
                    != u64::try_from(records.len()).map_err(|_| DurableError::Capacity)?
                    || clients.get(id.as_slice()).map_err(storage)?.is_some()
                {
                    return Err(DurableError::Conflict);
                }
                clients
                    .insert(id.as_slice(), encoded.as_slice())
                    .map_err(storage)?;
                primary.insert("image", bytes.as_slice()).map_err(storage)?;
            }
            let commit_time = trusted_time()?;
            if commit_time < admitted {
                return Err(Error::Scope.into());
            }
            record.request.approved.check_admission(commit_time)?;
            tx.commit().map_err(DurableError::CommitUncertain)?;
            #[cfg(all(test, unix))]
            testing::after_commit("client-authorize");
            let approved = transferred.approval.clone();
            let readback = storage::load(&owner.db, &owner.wrapping, &approved)?;
            if readback.client_index != image.client_index
                || readback.digest != storage::image_digest(&bytes)
            {
                return Err(DurableError::Corrupt);
            }
            owner.transferred = Some(Transferred::new(
                &owner.db,
                &owner.wrapping,
                approved,
                &readback,
            )?);
            Ok(record.receipt)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }

    /// Observe the exact durable server authorization. It grants no client
    /// adoption assertion and cannot replace a fresh current-policy admission.
    pub fn handoff_client_authorization(
        &mut self,
        subject: AnchorSubject,
    ) -> Result<AnchorHandoffClientAuthorizationReceipt, DurableError> {
        self.image()?;
        let owner = self.active.as_ref().ok_or(DurableError::Closed)?;
        let transferred = owner.transferred.as_ref().ok_or(DurableError::Suspended)?;
        let image = storage::load_authenticated(&owner.db, &owner.wrapping, &transferred.approval)?;
        transferred.admit(&image)?;
        load_records(
            &owner.db,
            &transferred.approval,
            &image,
            &transferred.original,
        )?
        .remove(&subject.id(&transferred.namespace()))
        .map(|r| r.receipt)
        .ok_or(DurableError::Absent)
    }
}
