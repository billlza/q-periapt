// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
impl Store {
    /// Query only; an unresolved operation is never resumed or signed here.
    pub fn policy_approval_status(
        &mut self,
        account: &Account,
        request: &PolicyApprovalRequest,
    ) -> Result<PolicyApprovalStatus, Error> {
        self.action(|store| {
            store.policy_context(account, request)?;
            Ok(
                match store.policy_record(account, request)?.map(|r| r.phase) {
                    None => PolicyApprovalStatus::Absent,
                    Some(Decision::Pending { statement, .. }) => {
                        PolicyApprovalStatus::Pending { statement }
                    }
                    Some(Decision::Closed) => PolicyApprovalStatus::Closed,
                    Some(Decision::Issued { account, response }) => PolicyApprovalStatus::Issued {
                        response: Self::checked_policy_response(request, &account, &response)?,
                    },
                },
            )
        })
    }
    /// Exact Closed tombstone can precede delayed issuance. Cancellation cannot
    /// revoke an existing signature or reset a device's policy operation.
    pub fn cancel_policy_approval(
        &mut self,
        account: &Account,
        request: &PolicyApprovalRequest,
    ) -> Result<(), Error> {
        self.action(|store| {
            store.policy_context(account, request)?;
            let previous = store.policy_record(account, request)?;
            match previous.as_ref().map(|r| &r.phase) {
                Some(Decision::Closed) => return Ok(()),
                Some(Decision::Issued { .. }) => {
                    return Err(Error::Conflict(
                        "Issued policy approval cannot be cancelled",
                    ))
                }
                _ => {}
            }
            store.save_policy_approval(
                account,
                &Record {
                    request: request.clone(),
                    phase: Decision::Closed,
                },
                previous.as_ref(),
                None,
            )
        })
    }
}
