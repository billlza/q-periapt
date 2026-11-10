// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Preserve the distinction between a prepared plan and an adopted exact winner.
use super::*;

pub(super) enum Operation {
    Prepared(Box<Plan>),
    Adopted(Box<Proposal>),
    Transferred(Box<crate::TransferredAccountRootPreparation>),
}
impl Operation {
    pub(super) fn expectation(&self) -> &Proposal {
        match self {
            Self::Prepared(plan) => plan.target(),
            Self::Adopted(proposal) => proposal,
            Self::Transferred(plan) => plan.target.target(),
        }
    }
    pub(super) fn id(&self) -> crate::AnchorAccountReplacementId {
        self.expectation().operation()
    }
    pub(super) fn plan(&self) -> Result<&Plan, DurableError> {
        match self {
            Self::Prepared(plan) => Ok(plan),
            Self::Adopted(_) | Self::Transferred(_) => Err(DurableError::Conflict),
        }
    }
    pub(super) fn matches_plan(&self, expected: &Plan) -> bool {
        matches!(self, Self::Prepared(plan) if plan.as_ref() == expected)
    }
    pub(super) fn state(
        &self,
        registry: &AccountAuthorityStore,
        expected: AccountAuthorityCheckpoint,
    ) -> Result<State, DurableError> {
        let (application, state) = match self {
            Self::Prepared(plan) => {
                let (application, state, retained) = registry.preparation(self.id())?;
                if retained != plan.as_ref() {
                    return Err(DurableError::Conflict);
                }
                (application, state)
            }
            Self::Adopted(proposal) => {
                let (application, state, retained) = registry.replacement(self.id())?;
                if retained != proposal.as_ref() || state != State::Committed {
                    return Err(DurableError::Conflict);
                }
                (application, state)
            }
            Self::Transferred(plan) => {
                registry.managed_transferred_checkpoint(self.id())?;
                plan.target.check(&plan.history)?;
                let (application, state, retained) = registry.transferred_preparation(self.id())?;
                if retained != &plan.target {
                    return Err(DurableError::Conflict);
                }
                (application, state)
            }
        };
        if application != expected.application()
            || registry.operation_checkpoint(self.id())? != expected
        {
            return Err(DurableError::Conflict);
        }
        Ok(state)
    }
}
