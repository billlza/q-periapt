// SPDX-License-Identifier: Apache-2.0 OR MIT
//! A plan can terminate even before its original freeze has committed.
use super::closure::{check_scope, ClosureRecord};
use super::*;
mod receipt;

/// Permanent non-commit of the original plan's operation for every snapshot.
/// It neither cancels a potentially in-flight freeze nor revives old authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorClosedAccountPreparation {
    plan: AnchorAccountReplacementPlan,
}
impl AnchorClosedAccountPreparation {
    /// Exact original target and freeze request; neither is incoming replacement authority.
    pub fn plan(&self) -> &AnchorAccountReplacementPlan {
        &self.plan
    }
}
impl Image {
    fn closed_preparation(
        &self,
        plan: &AnchorAccountReplacementPlan,
    ) -> Result<bool, DurableError> {
        match self.account_closures.get(plan.operation().as_bytes()) {
            Some(ClosureRecord::Plan { binding, freeze })
                if *binding == plan.binding()?
                    && freeze == plan.request().operation().as_bytes() =>
            {
                Ok(true)
            }
            Some(_) => Err(DurableError::Conflict),
            None => Ok(false),
        }
    }
}
impl AnchorStore {
    /// Independently close this original target operation even if its freeze lost
    /// a race or its target expired. A committed matching operation stays committed.
    /// This does not cancel the freeze request or prove that its snapshot existed.
    pub fn close_account_preparation(
        &mut self,
        plan: &AnchorAccountReplacementPlan,
    ) -> Result<AnchorAccountReplacementState, DurableError> {
        check_scope(plan.target(), &self.pin()?)?;
        let mut image = self.image()?;
        if let Some(saved) = image
            .account_replacements
            .values()
            .find(|p| p.operation() == plan.operation())
        {
            return if plan.check_retained(saved)? {
                Ok(AnchorAccountReplacementState::Committed)
            } else {
                Err(DurableError::Conflict)
            };
        }
        if image.closed_preparation(plan)? {
            return Ok(AnchorAccountReplacementState::Closed);
        }
        if image.account_closures.len() >= MAX_ENTRIES {
            return Err(DurableError::Capacity);
        }
        image.account_closures.insert(
            *plan.operation().as_bytes(),
            ClosureRecord::Plan {
                binding: plan.binding()?,
                freeze: *plan.request().operation().as_bytes(),
            },
        );
        self.persist(&mut image)?;
        Ok(AnchorAccountReplacementState::Closed)
    }
    /// Recover only an original durable plan non-commit; absence is not closure.
    pub fn closed_account_preparation(
        &mut self,
        plan: &AnchorAccountReplacementPlan,
    ) -> Result<AnchorClosedAccountPreparation, DurableError> {
        check_scope(plan.target(), &self.pin()?)?;
        if !self.image()?.closed_preparation(plan)? {
            return Err(DurableError::Absent);
        }
        Ok(AnchorClosedAccountPreparation { plan: plan.clone() })
    }
}
