// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

mod schema;

fn key(account: &Account, request: [u8; 32]) -> Vec<u8> {
    [account.application_id.as_slice(), request.as_slice()].concat()
}

impl Store {
    pub(super) fn extension(
        &self,
        account: &Account,
        id: [u8; 32],
    ) -> Result<Option<Vec<u8>>, Error> {
        let tx = self.db.begin_read().map_err(db_error)?;
        let table = tx.open_table(EXTENSIONS).map_err(db_error)?;
        let row = table.get(key(account, id).as_slice()).map_err(db_error)?;
        row.map(|row| {
            let value = row.value().to_vec();
            let issued: IssuedCredentialExtension = decode(&value, MAX_RECORD)?;
            if issued.request.request_id != id {
                return Err(Error::Internal);
            }
            Ok(value)
        })
        .transpose()
    }

    fn extension_predecessor(
        &self,
        account: &Account,
        request: &CredentialExtensionRequest,
        original: &Operation,
        response: &[u8],
        root: &Root,
        info: &RootInfo,
    ) -> Result<(usize, sdk::VerifiedDevice), Error> {
        let (certificate, roster, checkpoint) = match request.previous_extension {
            None => {
                let issued: IssuedEnrollment = decode(response, MAX_RECORD)?;
                if issued.operation != request.enrollment || issued.root_revision != root.revision {
                    return Err(Error::Internal);
                }
                (issued.certificate, issued.roster, issued.checkpoint)
            }
            Some(id) => {
                let bytes = self
                    .extension(account, id)?
                    .ok_or(Error::Conflict("Original predecessor extension is absent"))?;
                let issued: IssuedCredentialExtension = decode(&bytes, MAX_RECORD)?;
                if issued.request.enrollment != request.enrollment
                    || issued.root_revision != root.revision
                {
                    return Err(Error::Conflict(
                        "Predecessor extension belongs to another enrollment",
                    ));
                }
                (issued.certificate, issued.roster, issued.checkpoint)
            }
        };
        let member = root
            .members
            .iter()
            .position(|m| m.device == original.invitation.device)
            .ok_or(Error::Conflict("Device is no longer a current member"))?;
        if root.members[member].certificate != certificate {
            return Err(Error::Conflict("Selected predecessor credential changed"));
        }
        // Use the issuance's historical roster, not a fabricated clock or
        // an expired credential paired with a disjoint newer roster. Current
        // membership comes separately from the serialized authoritative root.
        let pin = sdk::AccountPin::new(
            info.account,
            sdk::PublicKey::decode(&info.public_key).map_err(db_error)?,
            checkpoint.as_sdk().map_err(db_error)?,
            info.family,
        )
        .map_err(db_error)?;
        let previous = pin
            .verify_historical_device(&certificate, &roster)
            .map_err(db_error)?;
        if previous.device_id() != original.invitation.device
            || previous.generation() != original.invitation.generation
        {
            return Err(Error::Internal);
        }
        Ok((member, previous))
    }

    fn commit_extension(
        &self,
        account: &Account,
        request: &CredentialExtensionRequest,
        root: &Root,
        response: &[u8],
        at: u64,
    ) -> Result<(), Error> {
        let tx = transaction(&self.db)?;
        {
            let mut table = tx.open_table(EXTENSIONS).map_err(db_error)?;
            if table.len().map_err(db_error)? >= MAX_OPERATIONS {
                return Err(Error::Capacity);
            }
            if table
                .insert(key(account, request.request_id).as_slice(), response)
                .map_err(db_error)?
                .is_some()
            {
                return Err(Error::Internal);
            }
        }
        save_root(&tx, root)?;
        // Do not commit a new target after it has already expired or after
        // the host clock has moved behind this operation's roster interval.
        let committed_at = now()?;
        if committed_at < at || committed_at >= request.valid_until {
            return Err(Error::Conflict(
                "Credential extension target is no longer current",
            ));
        }
        #[cfg(test)]
        test_boundary("credential-extension-before-commit", response)?;
        tx.commit().map_err(db_error)?;
        #[cfg(test)]
        test_boundary("credential-extension-after-commit", response)?;
        Ok(())
    }

    /// Explicitly authorize one same-key certificate extension for fresh
    /// admission. The current member and roster must still match the selected
    /// predecessor. This does not authorize retained sessions, issue G, update a
    /// client journal, or extend protocol policy. Retrying returns original bytes
    /// even after later roster changes; those bytes are history, not current use.
    pub fn extend_enrollment_credential(
        &mut self,
        account: &Account,
        request: &CredentialExtensionRequest,
    ) -> Result<Vec<u8>, Error> {
        self.action(|store| {
            store.authorized(account)?;
            if !store.enrollment_extensions {
                return Err(Error::Conflict(
                    "Credential extension requires explicit schema-4 upgrade",
                ));
            }
            if request.request_id == [0; 32]
                || request.enrollment == [0; 32]
                || request.previous_extension == Some([0; 32])
                || request.previous_extension == Some(request.request_id)
            {
                return Err(Error::Invalid("Invalid credential extension identity"));
            }
            // Authenticate ownership of the original operation even on retry.
            let original = store.operation(account, request.enrollment)?;
            let Phase::Issued { response, .. } = &original.phase else {
                return Err(Error::Conflict(
                    "Credential extension requires original issuance",
                ));
            };
            if let Some(saved) = store.extension(account, request.request_id)? {
                let issued: IssuedCredentialExtension = decode(&saved, MAX_RECORD)?;
                return if issued.request == *request {
                    Ok(saved)
                } else {
                    Err(Error::Conflict(
                        "Original credential extension request differs",
                    ))
                };
            }
            let mut root = store.root(account)?;
            root.admits_authority(&original.invitation, store.family()?)?;
            let info = root.info(store.family()?)?;
            if info.roster.as_ref().map(|r| r.checkpoint) != Some(request.predecessor) {
                return Err(Error::Conflict(
                    "Selected current roster predecessor changed",
                ));
            }
            let (member, previous) =
                store.extension_predecessor(account, request, &original, response, &root, &info)?;
            let at = now()?;
            let signer = store.open_signer(&root)?;
            let certificate = signer
                .issue_credential_extension(&previous, request.valid_until, at)
                .map_err(|error| match error {
                    sdk::Error::Validity => Error::Invalid(
                        "Target validity must extend the original credential and be current",
                    ),
                    other => Error::internal("issue credential extension", other),
                })?;
            let version = request
                .predecessor
                .version
                .checked_add(1)
                .ok_or(Error::Capacity)?;
            root.members[member].certificate = certificate.clone();
            let entries = root
                .members
                .iter()
                .map(|m| signer.roster_entry(&m.certificate))
                .collect::<Result<Vec<_>, _>>()
                .map_err(db_error)?;
            let roster = signer
                .issue_roster(
                    version,
                    sdk::Validity::new(at, request.valid_until).map_err(db_error)?,
                    &entries,
                )
                .map_err(db_error)?;
            let response = encode(
                &IssuedCredentialExtension {
                    request: request.clone(),
                    root_revision: root.revision,
                    certificate,
                    roster: roster.as_bytes().to_vec(),
                    checkpoint: roster.checkpoint().into(),
                },
                MAX_RECORD,
            )?;
            root.roster = Some(RosterSnapshot {
                checkpoint: roster.checkpoint().into(),
                bytes: roster.as_bytes().to_vec(),
            });
            store.commit_extension(account, request, &root, &response, at)?;
            Ok(response)
        })
    }
}
