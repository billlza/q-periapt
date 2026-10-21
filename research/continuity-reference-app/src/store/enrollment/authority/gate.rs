// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Hold the original native registry owner through each fresh issuer operation.
use super::*;

pub(in super::super) enum Guard {
    Unassociated,
    Associated {
        // The exclusive owner keeps this lease and original registry admission alive.
        _owner: Box<sdk::AccountAuthorityStore>,
        lease: sdk::AccountAuthorityLease,
    },
}
impl Guard {
    pub(in super::super) fn check(&self) -> Result<(), Error> {
        match self {
            Self::Unassociated => Ok(()),
            Self::Associated { lease, .. } => lease
                .check()
                .map_err(|e| Error::internal("original authority lease", e)),
        }
    }
}
impl AssociationRecord {
    pub(super) fn expected(
        &self,
        root: &Root,
        family: [u8; 32],
    ) -> Result<sdk::AccountAuthorityCheckpoint, Error> {
        if root.application != self.application || root.authority != Some(self.registry) {
            return Err(Error::Internal);
        }
        let info = root.info(family)?;
        let revision = root
            .revision
            .checked_sub(self.request.root.revision)
            .and_then(|r| r.checked_add(1))
            .ok_or(Error::Internal)?;
        sdk::AccountAuthorityCheckpoint::from_trusted_state(
            sdk::ApplicationAccountId::from_trusted_state(self.application).map_err(db_error)?,
            revision,
            info.account,
        )
        .map_err(db_error)
    }
}
impl Store {
    pub(in super::super) fn authority_guard(
        &self,
        account: &Account,
        root: &Root,
    ) -> Result<Guard, Error> {
        if !self.account_authorities {
            return if root.authority.is_none() {
                Ok(Guard::Unassociated)
            } else {
                Err(Error::Internal)
            };
        }
        let record = self.authority_record(account)?;
        let Some(identity) = root.authority else {
            return if record.is_none() {
                Ok(Guard::Unassociated)
            } else {
                Err(Error::Internal)
            };
        };
        let record = record.ok_or(Error::Internal)?;
        if record.registry != identity {
            return Err(Error::Internal);
        }
        if !matches!(record.phase, RegistryPhase::Ready) {
            return Err(Error::Conflict(
                "Original authority initialization requires reconciliation",
            ));
        }
        let (_, pin) = record
            .selected(self.family()?)
            .map_err(|e| Error::internal("retained authority association", e))?;
        let owner = self.open_authority_registry(&record, &pin)?;
        let expected = record.expected(root, self.family()?)?;
        let lease = owner
            .access()
            .map_err(db_error)?
            .admit(expected)
            .map_err(|e| match e {
                sdk::DurableError::Suspended | sdk::DurableError::Conflict => {
                    Error::Conflict("Current root requires original authority reconciliation")
                }
                other => Error::internal("admit original account authority", other),
            })?;
        Ok(Guard::Associated {
            _owner: Box::new(owner),
            lease,
        })
    }
}
