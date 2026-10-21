// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

impl Witness {
    /// Select a new target after permanent non-commit, retaining the original freeze.
    pub fn replan_frozen_account_root(
        &mut self,
        trust: &AccountRootTrust,
        request: &EnrollmentRequest,
        original: &AccountRootPlan,
        frozen: &AccountRootFreeze,
        now: u64,
    ) -> Result<AccountRootPlan> {
        let config = self.config()?;
        account_root::replan(
            &mut self.original_store(&config)?,
            trust,
            request,
            original,
            frozen,
            now,
        )
    }
    /// Read-only target selection. Retain and approve this plan before freezing.
    pub fn plan_account_root_replacement(
        &mut self,
        trust: &AccountRootTrust,
        request: &EnrollmentRequest,
        now: u64,
    ) -> Result<AccountRootPlan> {
        let config = self.config()?;
        account_root::plan(&mut self.original_store(&config)?, trust, request, now)
    }
    /// Trusted account-wide freeze. An error can follow commit; retry this plan.
    /// It does not retire the root or enroll the successor.
    pub fn freeze_account_root(&mut self, plan: &AccountRootPlan) -> Result<AccountRootFreeze> {
        let config = self.config()?;
        account_root::freeze(&mut self.original_store(&config)?, plan)
    }
    /// Bind the independently retained plan to its authenticated original freeze.
    pub fn bind_account_root_replacement(
        &mut self,
        trust: &AccountRootTrust,
        request: &EnrollmentRequest,
        plan: &AccountRootPlan,
        frozen: &AccountRootFreeze,
        now: u64,
    ) -> Result<AccountRootDecision> {
        let config = self.config()?;
        account_root::bind(
            &mut self.original_store(&config)?,
            trust,
            request,
            plan,
            frozen,
            now,
        )
    }
    /// Commit only the same frozen target under live successor authority.
    /// A lost result is recovered with status, including after target expiry.
    pub fn commit_account_root_replacement(
        &mut self,
        trust: &AccountRootTrust,
        request: &EnrollmentRequest,
        plan: &AccountRootPlan,
        frozen: &AccountRootFreeze,
        decision: &AccountRootDecision,
        now: u64,
    ) -> Result<AccountRootOutcome> {
        let config = self.config()?;
        account_root::commit(
            &mut self.original_store(&config)?,
            trust,
            request,
            plan,
            frozen,
            decision,
            now,
        )
    }
    /// Historical signed outcome only, never fresh runtime permission.
    pub fn account_root_replacement_status(
        &mut self,
        decision: &AccountRootDecision,
    ) -> Result<AccountRootOutcome> {
        let config = self.config()?;
        account_root::status(&mut self.original_store(&config)?, decision)
    }
    /// Close the original bound proposal permanently; a committed decision stays committed.
    pub fn close_account_root_replacement(
        &mut self,
        decision: &AccountRootDecision,
    ) -> Result<AccountRootOutcome> {
        let config = self.config()?;
        account_root::close(&mut self.original_store(&config)?, decision)
    }
    /// Close an original plan before or after freeze. This never unfreezes authority.
    /// If already committed, recover the retained bound decision through status.
    pub fn close_account_root_plan(
        &mut self,
        plan: &AccountRootPlan,
    ) -> Result<AccountRootOutcome> {
        let config = self.config()?;
        account_root::close_plan(&mut self.original_store(&config)?, plan)
    }
}
