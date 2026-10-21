// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Durable account-side decision for the exact original policy-only operation.
use super::*;
use crate::policy_approval::{IssuedPolicyApproval, PolicyApprovalRequest, PolicyApprovalStatus};
mod inputs;
mod schema;
mod state;

const MAX_POLICY_RECORD: usize = 768 * 1024;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    request: PolicyApprovalRequest,
    phase: Decision,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", deny_unknown_fields)]
enum Decision {
    Pending {
        account: RootInfo,
        statement: [u8; 32],
    },
    Issued {
        account: RootInfo,
        #[serde(with = "wire")]
        response: Vec<u8>,
    },
    Closed,
}
fn key(account: &Account, operation: [u8; 32]) -> Vec<u8> {
    [account.application_id.as_slice(), operation.as_slice()].concat()
}
impl Store {
    fn policy_record(
        &self,
        account: &Account,
        request: &PolicyApprovalRequest,
    ) -> Result<Option<Record>, Error> {
        let tx = self.db.begin_read().map_err(db_error)?;
        let table = tx.open_table(POLICY_APPROVALS).map_err(db_error)?;
        let saved = table
            .get(key(account, request.retained.scope.operation).as_slice())
            .map_err(db_error)?
            .map(|v| decode::<Record>(v.value(), MAX_POLICY_RECORD))
            .transpose()?;
        if saved.as_ref().is_some_and(|r| r.request != *request) {
            return Err(Error::Conflict("Original policy approval request differs"));
        }
        Ok(saved)
    }
    fn checked_policy_response(
        request: &PolicyApprovalRequest,
        account: &RootInfo,
        response: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let issued: IssuedPolicyApproval = decode(response, MAX_RECORD)?;
        request.verify_result(account, &issued)?;
        Ok(response.to_vec())
    }
    fn save_policy_approval(
        &self,
        account: &Account,
        record: &Record,
        previous: Option<&Record>,
        live_at: Option<u64>,
    ) -> Result<(), Error> {
        let bytes = encode(record, MAX_POLICY_RECORD)?;
        let tx = transaction(&self.db)?;
        {
            let mut table = tx.open_table(POLICY_APPROVALS).map_err(db_error)?;
            let identity = key(account, record.request.retained.scope.operation);
            let old = table
                .get(identity.as_slice())
                .map_err(db_error)?
                .map(|v| decode::<Record>(v.value(), MAX_POLICY_RECORD))
                .transpose()?;
            if old.as_ref() != previous {
                return Err(Error::Conflict("Original policy decision changed"));
            }
            if previous.is_none() && table.len().map_err(db_error)? >= MAX_OPERATIONS {
                return Err(Error::Capacity);
            }
            table
                .insert(identity.as_slice(), bytes.as_slice())
                .map_err(db_error)?;
        }
        let current = match &record.phase {
            Decision::Pending { account, statement } => Some((account, *statement)),
            Decision::Issued { account, response } => {
                let issued: IssuedPolicyApproval = decode(response, MAX_RECORD)?;
                Some((account, issued.statement))
            }
            Decision::Closed => None,
        };
        match (current, live_at) {
            (Some((expected, statement)), Some(at)) => {
                let table = tx.open_table(ROOTS).map_err(db_error)?;
                let row = table
                    .get(account.application_id.as_slice())
                    .map_err(db_error)?
                    .ok_or(Error::Internal)?;
                let root: Root = decode(row.value(), MAX_ROOT)?;
                let info = root.info(self.family()?)?;
                if info.suspended || info != *expected {
                    return Err(Error::Conflict("Policy approval account authority changed"));
                }
                let committed_at = now()?;
                if committed_at < at
                    || record.request.statement(&info, committed_at)?.0.digest() != statement
                {
                    return Err(Error::Conflict(
                        "Policy approval is no longer currently admissible",
                    ));
                }
            }
            (None, None) => {}
            _ => return Err(Error::Internal),
        }
        let stage = match &record.phase {
            Decision::Pending { .. } => "policy-approval-pending",
            Decision::Issued { .. } => "policy-approval-issued",
            Decision::Closed => "policy-approval-closed",
        };
        #[cfg(test)]
        test_boundary(&format!("{stage}-before-commit"), &bytes)?;
        tx.commit().map_err(db_error)?;
        #[cfg(test)]
        test_boundary(&format!("{stage}-after-commit"), &bytes)?;
        #[cfg(not(test))]
        let _ = stage;
        Ok(())
    }
    /// Requires authenticated host authorization of the exact selection. Device
    /// metadata alone never selects the account issuer or grants permission.
    pub fn issue_policy_approval(
        &mut self,
        account: &Account,
        request: &PolicyApprovalRequest,
    ) -> Result<Vec<u8>, Error> {
        self.action(|store| {
            let original = store.policy_context(account, request)?;
            let previous = store.policy_record(account, request)?;
            if let Some(record) = &previous {
                match &record.phase {
                    Decision::Issued { account, response } => {
                        return Self::checked_policy_response(request, account, response)
                    }
                    Decision::Closed => {
                        return Err(Error::Conflict("Original policy approval is closed"))
                    }
                    Decision::Pending { .. } => {}
                }
            }
            let at = now()?;
            let (root, info) = store.policy_inputs(account, request, &original)?;
            let authority = store.authority_guard(account, &root)?;
            let (statement, target) = request.statement(&info, at)?;
            let pending = Record {
                request: request.clone(),
                phase: Decision::Pending {
                    account: info.clone(),
                    statement: statement.digest(),
                },
            };
            if let Some(previous) = &previous {
                if *previous != pending {
                    return Err(Error::Conflict(
                        "Original policy approval authority differs",
                    ));
                }
            } else {
                authority.check()?;
                store.save_policy_approval(account, &pending, None, Some(at))?;
            }
            let approval = store
                .open_signer(&root)?
                .approve_policy_renewal(&statement)
                .map_err(db_error)?;
            #[cfg(test)]
            test_boundary("policy-approval-signed-before-commit", approval.as_bytes())?;
            let response = encode(
                &IssuedPolicyApproval {
                    enrollment: request.retained.enrollment,
                    operation: request.retained.scope.operation,
                    journal: request.retained.scope.journal,
                    root_revision: request.retained.root_revision,
                    statement: statement.digest(),
                    target,
                    approval: approval.as_bytes().to_vec(),
                },
                MAX_RECORD,
            )?;
            Self::checked_policy_response(request, &info, &response)?;
            authority.check()?;
            store.save_policy_approval(
                account,
                &Record {
                    request: request.clone(),
                    phase: Decision::Issued {
                        account: info.clone(),
                        response: response.clone(),
                    },
                },
                Some(&pending),
                Some(at),
            )?;
            let Some(Record {
                phase:
                    Decision::Issued {
                        account: saved_info,
                        response: saved,
                    },
                ..
            }) = store.policy_record(account, request)?
            else {
                return Err(Error::Internal);
            };
            if saved != response || saved_info != info {
                return Err(Error::Internal);
            }
            Self::checked_policy_response(request, &saved_info, &saved)
        })
    }
}
