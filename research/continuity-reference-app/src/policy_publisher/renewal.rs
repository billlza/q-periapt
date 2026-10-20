// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Policy-side approval only; the account decision and device adoption are separate.
use super::{
    renewal_store::{Phase, Record},
    *,
};
use crate::{enrollment::RootInfo, policy_renewal};

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenewalRequest {
    pub retained: policy_renewal::Request,
    /// Explicit selections from this original publisher's issued inventory.
    pub original_publication: [u8; 32],
    pub previous_publication: [u8; 32],
    pub target_publication: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedRenewal {
    pub operation: [u8; 32],
    pub statement: [u8; 32],
    #[serde(with = "wire")]
    pub approval: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", deny_unknown_fields)]
pub enum RenewalStatus {
    Absent,
    Pending { statement: [u8; 32] },
    Issued { result: IssuedRenewal },
    Closed,
}
impl RenewalRequest {
    pub(super) fn shape(&self) -> Result<(), Error> {
        if [
            self.original_publication,
            self.previous_publication,
            self.target_publication,
        ]
        .contains(&[0; 32])
        {
            return Err(Error::Invalid(
                "Policy publication selection must be nonzero",
            ));
        }
        self.retained
            .check_shape()
            .map_err(|_| Error::Invalid("Policy renewal request"))?;
        // Keep malformed or unbounded device reports out of every ledger phase,
        // including cancellation before a delayed first issuance.
        super::store::encode(self)?;
        Ok(())
    }
}
impl Publisher {
    fn renewal_context(
        &self,
        request: &RenewalRequest,
        account: &RootInfo,
    ) -> Result<Option<Record>, Error> {
        request.shape()?;
        let saved = self.renewal_record(request.retained.scope.operation)?;
        if saved
            .as_ref()
            .is_some_and(|r| r.request != *request || r.account != *account)
        {
            return Err(Error::Conflict(
                "Original policy approval request or account pins differ",
            ));
        }
        Ok(saved)
    }
    fn renewal_policies(
        &self,
        request: &RenewalRequest,
        account: &RootInfo,
    ) -> Result<
        (
            sdk::HistoricalSessionPolicy,
            sdk::HistoricalSessionPolicy,
            PolicyPins,
            PolicyMaterials,
        ),
        Error,
    > {
        let authority = self.authority()?;
        if account.family != authority.family {
            return Err(Error::Conflict(
                "Selected account belongs to another policy family",
            ));
        }
        let (pins, materials) = self.export(request.original_publication)?;
        let original = pins.verify_historical(&materials, authority.family)?.0;
        let (pins, materials) = self.export(request.previous_publication)?;
        let previous = pins.verify_historical(&materials, authority.family)?.0;
        let (target_pins, target_materials) = self.export(request.target_publication)?;
        if original.checkpoint()
            != request
                .retained
                .scope
                .as_sdk()
                .map_err(fail)?
                .original_policy
            || previous.checkpoint()
                != request
                    .retained
                    .scope
                    .as_sdk()
                    .map_err(fail)?
                    .previous_policy
        {
            return Err(Error::Conflict(
                "Selected publication differs from original policy scope",
            ));
        }
        Ok((original, previous, target_pins, target_materials))
    }
    fn renewal_statement(
        &self,
        request: &RenewalRequest,
        account: &RootInfo,
        now: u64,
    ) -> Result<sdk::PolicyRenewalStatement, Error> {
        if account.suspended {
            return Err(Error::Conflict("Selected account authority is suspended"));
        }
        let (original, previous, pins, materials) = self.renewal_policies(request, account)?;
        let target = pins.verify(&materials, account.family, now)?.0;
        let identities = request
            .retained
            .verify_identities(account, now)
            .map_err(|_| Error::Invalid("Policy renewal device identities"))?;
        sdk::PolicyRenewalStatement::new(
            identities.scope(),
            &identities.materials(&original, &previous, &target),
            now,
        )
        .map_err(|_| Error::Conflict("Policy renewal relation or current permission differs"))
    }
    fn checked_renewal_result(
        &self,
        request: &RenewalRequest,
        account: &RootInfo,
        result: &IssuedRenewal,
    ) -> Result<IssuedRenewal, Error> {
        let (original, previous, pins, materials) = self.renewal_policies(request, account)?;
        let target = pins.verify_historical(&materials, account.family)?.0;
        let identities = request
            .retained
            .verify_historical_identities(account)
            .map_err(fail)?;
        let commitment = sdk::PolicyRenewalApproval::from_bytes(&result.approval)
            .map_err(fail)?
            .verify_policy(
                identities.scope(),
                &identities.historical_materials(&original, &previous, &target),
            )
            .map_err(fail)?;
        if result.operation != request.retained.scope.operation || result.statement != commitment {
            return Err(Error::Internal);
        }
        Ok(result.clone())
    }
    /// Read-only historical decision. Absent/Pending never signs or resumes.
    pub fn renewal_status(
        &self,
        request: &RenewalRequest,
        account: &RootInfo,
    ) -> Result<RenewalStatus, Error> {
        Ok(
            match self.renewal_context(request, account)?.map(|r| r.phase) {
                None => RenewalStatus::Absent,
                Some(Phase::Pending { statement }) => RenewalStatus::Pending { statement },
                Some(Phase::Closed) => RenewalStatus::Closed,
                Some(Phase::Issued { result }) => RenewalStatus::Issued {
                    result: self.checked_renewal_result(request, account, &result)?,
                },
            },
        )
    }
    /// Explicit operator authorization of these independently selected account
    /// pins and publication IDs. A signed device report alone is not permission.
    /// Save the exact intent before signing; return only a persisted, reverified
    /// result. Historical retries neither sign again nor create a live lease.
    pub fn approve_renewal(
        &mut self,
        request: &RenewalRequest,
        account: &RootInfo,
    ) -> Result<IssuedRenewal, Error> {
        self.action(|owner| {
            let saved = owner.renewal_context(request, account)?;
            if let Some(record) = &saved {
                match &record.phase {
                    Phase::Closed => {
                        return Err(Error::Conflict("Original policy approval is closed"))
                    }
                    Phase::Issued { result } => {
                        return owner.checked_renewal_result(request, account, result)
                    }
                    Phase::Pending { .. } => {}
                }
            }
            let at = crate::enrollment::now()?;
            let statement = owner.renewal_statement(request, account, at)?;
            let pending = Record {
                request: request.clone(),
                account: account.clone(),
                phase: Phase::Pending {
                    statement: statement.digest(),
                },
            };
            if let Some(saved) = &saved {
                if *saved != pending {
                    return Err(Error::Conflict("Original policy statement differs"));
                }
            } else {
                owner.save_renewal(&pending, None)?;
            }
            let signer = owner.open_signer(&owner.config()?)?;
            let approval = signer.approve_policy_renewal(&statement).map_err(fail)?;
            #[cfg(test)]
            boundary("policy-renewal-signed-before-commit", approval.as_bytes())?;
            let committed_at = crate::enrollment::now()?;
            if committed_at < at
                || owner
                    .renewal_statement(request, account, committed_at)?
                    .digest()
                    != statement.digest()
            {
                return Err(Error::Conflict(
                    "Policy renewal is no longer currently admissible",
                ));
            }
            let result = IssuedRenewal {
                operation: request.retained.scope.operation,
                statement: statement.digest(),
                approval: approval.as_bytes().to_vec(),
            };
            owner.checked_renewal_result(request, account, &result)?;
            owner.save_renewal(
                &Record {
                    phase: Phase::Issued {
                        result: result.clone(),
                    },
                    ..pending.clone()
                },
                Some(&pending),
            )?;
            let Some(Record {
                phase: Phase::Issued { result: saved },
                ..
            }) = owner.renewal_record(result.operation)?
            else {
                return Err(Error::Internal);
            };
            if saved != result {
                return Err(Error::Internal);
            }
            owner.checked_renewal_result(request, account, &saved)
        })
    }
    /// Retain an exact Closed tombstone, including before delayed issuance.
    /// Issued signatures cannot be cancelled or retroactively revoked here.
    pub fn cancel_renewal(
        &mut self,
        request: &RenewalRequest,
        account: &RootInfo,
    ) -> Result<(), Error> {
        self.action(|owner| {
            let saved = owner.renewal_context(request, account)?;
            match saved.as_ref().map(|r| &r.phase) {
                Some(Phase::Issued { .. }) => {
                    return Err(Error::Conflict(
                        "Issued policy approval cannot be cancelled",
                    ))
                }
                Some(Phase::Closed) => return Ok(()),
                _ => {}
            }
            owner.save_renewal(
                &Record {
                    request: request.clone(),
                    account: account.clone(),
                    phase: Phase::Closed,
                },
                saved.as_ref(),
            )
        })
    }
}
