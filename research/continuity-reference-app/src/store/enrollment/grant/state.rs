// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::credential_grant::CredentialGrantStatus;

impl Store {
    fn grant_context(
        &self,
        account: &Account,
        request: &CredentialGrantRequest,
    ) -> Result<(), Error> {
        self.authorized(account)?;
        if !self.credential_grants {
            return Err(Error::Conflict("Retained grants are not enabled"));
        }
        inputs::shape(request)?;
        let original = self.operation(account, request.retained.enrollment)?;
        if request.retained.application != account.application_id
            || request.retained.root_revision != original.invitation.root_revision
            || !matches!(original.phase, Phase::Issued { .. })
        {
            return Err(Error::Conflict(
                "Retained grant requires its original account issuance",
            ));
        }
        Ok(())
    }
    /// Observe only: an absent or pending decision is never signed by this call.
    pub fn credential_grant_status(
        &mut self,
        account: &Account,
        request: &CredentialGrantRequest,
    ) -> Result<CredentialGrantStatus, Error> {
        self.action(|store| {
            store.grant_context(account, request)?;
            let Some(record) = store.grant(account, request.retained.operation)? else {
                return Ok(CredentialGrantStatus::Absent);
            };
            if record.request != *request {
                return Err(Error::Conflict("Original retained grant request differs"));
            }
            Ok(match record.phase {
                GrantPhase::Pending => CredentialGrantStatus::Pending,
                GrantPhase::Closed => CredentialGrantStatus::Closed,
                GrantPhase::Issued { response } => CredentialGrantStatus::Issued { response },
            })
        })
    }
    /// Close an exact unresolved decision, including before a delayed first
    /// dispatch. A retained Closed record fences later issuance of that ID.
    pub fn cancel_credential_grant(
        &mut self,
        account: &Account,
        request: &CredentialGrantRequest,
    ) -> Result<(), Error> {
        self.action(|store| {
            store.grant_context(account, request)?;
            let existing = store.grant(account, request.retained.operation)?;
            let create = existing.is_none();
            if let Some(record) = existing {
                if record.request != *request {
                    return Err(Error::Conflict("Original retained grant request differs"));
                }
                match record.phase {
                    GrantPhase::Closed => return Ok(()),
                    GrantPhase::Issued { .. } => {
                        return Err(Error::Conflict("Issued grant cannot be cancelled"))
                    }
                    GrantPhase::Pending => {}
                }
            }
            store.save_grant(
                account,
                &Record {
                    request: request.clone(),
                    phase: GrantPhase::Closed,
                },
                create,
                now()?,
                None,
            )
        })
    }
}
