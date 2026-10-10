// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Terminal outcomes retain original intent and keep the old account disabled.
use super::*;
use crate::{
    AnchorAccountFreezeRequest, AnchorClosedAccountPreparation, AnchorClosedAccountReplacement,
};

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Decision {
    Pending,
    Committed,
    ClosedExact,
    ClosedPlan,
    Adopted,
}
impl Decision {
    pub(super) fn committed(self) -> bool {
        matches!(self, Self::Committed | Self::Adopted)
    }
    pub(super) fn closed(self) -> bool {
        matches!(self, Self::ClosedExact | Self::ClosedPlan)
    }
    pub(super) fn extended(self) -> bool {
        !matches!(self, Self::Pending | Self::Committed)
    }
}
#[derive(Clone)]
pub(super) struct RetryScope {
    request: Option<AnchorAccountFreezeRequest>,
    binding: Option<[u8; 32]>,
}
impl Current {
    pub(super) fn admit_next(
        &self,
        proposal: &Proposal,
        plan: Option<&AnchorAccountReplacementPlan>,
        adopted: bool,
    ) -> Result<(), DurableError> {
        if !self.pending {
            return if adopted {
                Err(DurableError::Conflict)
            } else {
                Ok(())
            };
        }
        let scope = self.retry.as_ref().ok_or(DurableError::Suspended)?;
        if adopted {
            if plan.is_some()
                || scope
                    .binding
                    .is_some_and(|binding| proposal.preparation_binding() != Some(binding))
            {
                return Err(DurableError::Conflict);
            }
        } else {
            let plan = plan.ok_or(DurableError::Suspended)?;
            if scope
                .request
                .as_ref()
                .is_some_and(|request| request != plan.request())
                || scope.binding.is_some_and(|binding| {
                    proposal
                        .preparation_binding()
                        .is_some_and(|actual| actual != binding)
                })
            {
                return Err(DurableError::Conflict);
            }
        }
        Ok(())
    }
    pub(super) fn apply(&mut self, record: &Replacement) -> Result<(), DurableError> {
        let p = &record.proposal;
        let previous_retry = self.retry.take();
        if record.decision.committed() {
            let (_, successor, _, roster) = p.authority_transition();
            self.checkpoint.revision = self
                .checkpoint
                .revision
                .checked_add(1)
                .filter(|r| *r != u64::MAX)
                .ok_or(DurableError::Capacity)?;
            self.checkpoint.account = p.successor_account();
            self.root = successor.clone();
            self.roster = roster;
            self.pending = false;
        } else {
            self.pending = true;
            if record.decision.closed() {
                // Never forget an already authenticated freeze when an unbound
                // follow-up attempt closes. Unknown freeze results grant no traffic.
                self.retry = Some(match p.preparation_binding() {
                    Some(binding) => RetryScope {
                        request: record.preparation.as_ref().map(|p| p.request().clone()),
                        binding: Some(binding),
                    },
                    None => previous_retry.unwrap_or(RetryScope {
                        request: None,
                        binding: None,
                    }),
                });
            }
        }
        Ok(())
    }
}
impl AccountAuthorityStore {
    /// Recover the exact original public checkpoint from authenticated local history.
    /// This is an expectation for original-operation recovery, never live permission.
    pub fn operation_checkpoint(
        &self,
        operation: AnchorAccountReplacementId,
    ) -> Result<AccountAuthorityCheckpoint, DurableError> {
        let active = self.active.as_ref().ok_or(DurableError::Closed)?;
        let r = active
            .image
            .replacements
            .iter()
            .find(|r| r.proposal.operation() == operation)
            .ok_or(DurableError::Absent)?;
        Ok(AccountAuthorityCheckpoint {
            application: r.application,
            revision: r.revision,
            account: r.proposal.previous_account(),
        })
    }
    /// Retain an exact original proposal non-commit. Old authority remains disabled.
    /// An unbound preparation requires its original-plan proof instead.
    pub fn close_replacement(
        &mut self,
        closed: &AnchorClosedAccountReplacement,
    ) -> Result<AccountAuthorityReplacementState, DurableError> {
        let mut image = self
            .active
            .as_ref()
            .ok_or(DurableError::Closed)?
            .image
            .clone();
        let r = image
            .replacements
            .iter_mut()
            .find(|r| r.proposal.operation() == closed.proposal().operation())
            .ok_or(DurableError::Absent)?;
        if r.decision.committed() || &r.proposal != closed.proposal() {
            return Err(DurableError::Conflict);
        }
        if r.preparation
            .as_ref()
            .is_some_and(|p| p.target() == &r.proposal)
        {
            return Err(DurableError::Suspended);
        }
        if r.decision.closed() {
            return Ok(AccountAuthorityReplacementState::Closed);
        }
        r.decision = Decision::ClosedExact;
        let app = r.application;
        self.save(image, app)?;
        Ok(AccountAuthorityReplacementState::Closed)
    }
    /// Retain permanent non-commit of the original plan, including before a freeze
    /// result exists. No old lease revives and no new target is selected.
    pub fn close_preparation(
        &mut self,
        closed: &AnchorClosedAccountPreparation,
    ) -> Result<AccountAuthorityReplacementState, DurableError> {
        let mut image = self
            .active
            .as_ref()
            .ok_or(DurableError::Closed)?
            .image
            .clone();
        let r = image
            .replacements
            .iter_mut()
            .find(|r| r.proposal.operation() == closed.plan().operation())
            .ok_or(DurableError::Absent)?;
        if r.decision.committed() || r.preparation.as_ref() != Some(closed.plan()) {
            return Err(DurableError::Conflict);
        }
        if r.decision.closed() {
            return Ok(AccountAuthorityReplacementState::Closed);
        }
        r.decision = Decision::ClosedPlan;
        let app = r.application;
        self.save(image, app)?;
        Ok(AccountAuthorityReplacementState::Closed)
    }
    /// Independently approve and retain the actual committed winner after the old
    /// attempt has terminally closed. The signed retirement and approved descriptor
    /// must be identical. This never treats a network-selected target as approval.
    /// A root seen only in closed attempts may be adopted from this exact committed
    /// fact; a previously active or cross-application root cannot be reused.
    pub fn adopt_committed_replacement(
        &mut self,
        expected: AccountAuthorityCheckpoint,
        approved: Proposal,
        retired: &AnchorRetiredAccount,
    ) -> Result<AccountAuthorityReplacementState, DurableError> {
        if &approved != retired.proposal() || approved.previous_account() != expected.account {
            return Err(DurableError::Conflict);
        }
        let mut image = self
            .active
            .as_ref()
            .ok_or(DurableError::Closed)?
            .image
            .clone();
        if let Some(old) = image
            .replacements
            .iter()
            .find(|r| r.proposal.operation() == approved.operation())
        {
            if old.application != expected.application || old.revision != expected.revision {
                return Err(DurableError::Conflict);
            }
            return self.commit_replacement(retired);
        }
        let current = image.current(self.family, &self.pin)?;
        let selected = current
            .get(&expected.application)
            .ok_or(DurableError::Absent)?;
        if selected.checkpoint != expected {
            return Err(DurableError::Conflict);
        }
        selected.admit_next(&approved, None, true)?;
        if image.replacements.len() >= MAX_REPLACEMENTS {
            return Err(DurableError::Capacity);
        }
        image.replacements.push(Replacement {
            application: expected.application,
            revision: expected.revision,
            proposal: approved,
            preparation: None,
            decision: Decision::Adopted,
        });
        self.save(image, expected.application)?;
        Ok(AccountAuthorityReplacementState::Committed)
    }
}
