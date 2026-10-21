// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exact host-issued credential ancestry shared by G and policy-only approval.
use super::*;

#[derive(Clone, Copy)]
pub(super) struct CredentialHistory {
    pub enrollment: [u8; 32],
    pub revision: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CredentialSnapshot {
    #[serde(with = "wire")]
    pub(super) certificate: Vec<u8>,
    #[serde(with = "wire")]
    pub(super) roster: Vec<u8>,
    pub(super) checkpoint: Checkpoint,
}
impl Store {
    /// Resolve the exact currently stored certificate to its own issuance
    /// snapshot. Never select an extension by recency or maximum version.
    pub(super) fn current_certificate_snapshot(
        &self,
        account: &Account,
        history: CredentialHistory,
        original: &IssuedEnrollment,
        certificate: &[u8],
    ) -> Result<CredentialSnapshot, Error> {
        if original.operation != history.enrollment || original.root_revision != history.revision {
            return Err(Error::Internal);
        }
        if original.certificate == certificate {
            return Ok(CredentialSnapshot {
                certificate: original.certificate.clone(),
                roster: original.roster.clone(),
                checkpoint: original.checkpoint,
            });
        }
        let tx = self.db.begin_read().map_err(db_error)?;
        let table = tx.open_table(EXTENSIONS).map_err(db_error)?;
        if table.len().map_err(db_error)? > MAX_OPERATIONS {
            return Err(Error::Internal);
        }
        let mut selected = None;
        for row in table.iter().map_err(db_error)? {
            let (key, value) = row.map_err(db_error)?;
            let key = key.value();
            if key.len() != 64 {
                return Err(Error::Internal);
            }
            if key[..32] != account.application_id {
                continue;
            }
            let value: IssuedCredentialExtension = decode(value.value(), MAX_RECORD)?;
            if value.request.enrollment == history.enrollment
                && value.root_revision == history.revision
                && value.certificate == certificate
            {
                if selected.is_some() || value.request.request_id != key[32..] {
                    return Err(Error::Internal);
                }
                selected = Some(CredentialSnapshot {
                    certificate: value.certificate,
                    roster: value.roster,
                    checkpoint: value.checkpoint,
                });
            }
        }
        selected.ok_or(Error::Conflict(
            "Current credential has no exact retained issuance history",
        ))
    }
    pub(super) fn selected_extension(
        &self,
        account: &Account,
        history: CredentialHistory,
        id: [u8; 32],
    ) -> Result<IssuedCredentialExtension, Error> {
        let bytes = self
            .extension(account, id)?
            .ok_or(Error::Conflict("Selected credential extension is absent"))?;
        let value: IssuedCredentialExtension = decode(&bytes, MAX_RECORD)?;
        if value.request.request_id != id
            || value.request.enrollment != history.enrollment
            || value.root_revision != history.revision
        {
            return Err(Error::Conflict(
                "Selected extension belongs to another enrollment or root",
            ));
        }
        Ok(value)
    }
    pub(super) fn selected_certificate(
        &self,
        account: &Account,
        history: CredentialHistory,
        original: &IssuedEnrollment,
        selection: Option<[u8; 32]>,
    ) -> Result<Vec<u8>, Error> {
        if original.operation != history.enrollment || original.root_revision != history.revision {
            return Err(Error::Internal);
        }
        Ok(match selection {
            None => original.certificate.clone(),
            Some(id) => self.selected_extension(account, history, id)?.certificate,
        })
    }
    pub(super) fn extension_descends(
        &self,
        account: &Account,
        history: CredentialHistory,
        mut child: Option<[u8; 32]>,
        ancestor: Option<[u8; 32]>,
    ) -> Result<(), Error> {
        for _ in 0..=MAX_OPERATIONS {
            if child == ancestor {
                return Ok(());
            }
            let id = child.ok_or(Error::Conflict(
                "Selected credential is not in the original extension chain",
            ))?;
            child = self
                .selected_extension(account, history, id)?
                .request
                .previous_extension;
        }
        Err(Error::Internal)
    }
}
