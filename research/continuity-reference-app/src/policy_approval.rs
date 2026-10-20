// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Account-side P approval inputs; account authority comes from the host store.
use crate::{
    enrollment::{wire, Checkpoint, RootInfo},
    error::Error,
    policy_publisher::{PolicyMaterials, PolicyPins},
    policy_renewal,
};
use q_periapt_continuity_identity_candidate as sdk;
use serde::{Deserialize, Serialize};

pub const MAX_POLICY_APPROVAL_REQUEST: usize = 512 * 1024;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyInput {
    pub pins: PolicyPins,
    pub materials: PolicyMaterials,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyApprovalRequest {
    pub retained: policy_renewal::Request,
    #[serde(deserialize_with = "selection")]
    pub original_extension: Option<[u8; 32]>,
    #[serde(deserialize_with = "selection")]
    pub current_extension: Option<[u8; 32]>,
    /// Explicit policy selections under the host's independently configured
    /// family, which commits to the policy signing key. No account root input.
    pub original: PolicyInput,
    pub previous: PolicyInput,
    pub target: PolicyInput,
}
fn selection<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
    Option::deserialize(d)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedPolicyApproval {
    pub enrollment: [u8; 32],
    pub operation: [u8; 32],
    pub journal: [u8; 32],
    pub root_revision: u64,
    pub statement: [u8; 32],
    pub target: Checkpoint,
    #[serde(with = "wire")]
    pub approval: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "state", deny_unknown_fields)]
pub enum PolicyApprovalStatus {
    Absent,
    Pending {
        statement: [u8; 32],
    },
    Issued {
        #[serde(with = "wire")]
        response: Vec<u8>,
    },
    Closed,
}
impl PolicyApprovalRequest {
    pub(crate) fn shape(&self) -> Result<(), Error> {
        self.retained
            .check_shape()
            .map_err(|_| Error::Invalid("Retained policy request"))?;
        if [self.original_extension, self.current_extension].contains(&Some([0; 32])) {
            return Err(Error::Invalid("Selected policy credential history"));
        }
        if serde_json::to_vec(self)
            .map_err(|e| Error::internal("policy request size", e))?
            .len()
            > MAX_POLICY_APPROVAL_REQUEST
        {
            return Err(Error::Capacity);
        }
        Ok(())
    }
    pub(crate) fn statement(
        &self,
        account: &RootInfo,
        now: u64,
    ) -> Result<(sdk::PolicyRenewalStatement, Checkpoint), Error> {
        let original = self
            .original
            .pins
            .verify_historical(&self.original.materials, account.family)?
            .0;
        let previous = self
            .previous
            .pins
            .verify_historical(&self.previous.materials, account.family)?
            .0;
        let target = self
            .target
            .pins
            .verify(&self.target.materials, account.family, now)?
            .0;
        let devices = self
            .retained
            .verify_identities(account, now)
            .map_err(|_| Error::Invalid("Policy approval identities"))?;
        let statement = sdk::PolicyRenewalStatement::new(
            devices.scope(),
            &devices.materials(&original, &previous, &target),
            now,
        )
        .map_err(|_| Error::Conflict("Policy approval relation or live permission differs"))?;
        Ok((statement, policy_renewal::checkpoint(target.checkpoint())))
    }
    /// Historical signature verification only, never new account authorization.
    pub(crate) fn verify_result(
        &self,
        account: &RootInfo,
        result: &IssuedPolicyApproval,
    ) -> Result<(), Error> {
        let original = self
            .original
            .pins
            .verify_historical(&self.original.materials, account.family)?
            .0;
        let previous = self
            .previous
            .pins
            .verify_historical(&self.previous.materials, account.family)?
            .0;
        let target = self
            .target
            .pins
            .verify_historical(&self.target.materials, account.family)?
            .0;
        let devices = self
            .retained
            .verify_historical_identities(account)
            .map_err(|e| Error::internal("retained policy identities", e))?;
        let statement = sdk::PolicyRenewalApproval::from_bytes(&result.approval)
            .and_then(|a| {
                a.verify_account(
                    devices.scope(),
                    &devices.historical_materials(&original, &previous, &target),
                )
            })
            .map_err(|e| Error::internal("retained account policy signature", e))?;
        if result.enrollment != self.retained.enrollment
            || result.operation != self.retained.scope.operation
            || result.journal != self.retained.scope.journal
            || result.root_revision != self.retained.root_revision
            || result.statement != statement
            || result.target != policy_renewal::checkpoint(target.checkpoint())
        {
            return Err(Error::Internal);
        }
        Ok(())
    }
}
