// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Exact host-issued credential ancestry shared by G and policy-only approval.
use super::*;

#[derive(Clone, Copy)]
pub(super) struct CredentialHistory {
    pub enrollment: [u8; 32],
    pub revision: u64,
}
impl Store {
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
