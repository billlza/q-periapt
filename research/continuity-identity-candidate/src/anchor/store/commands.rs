// SPDX-License-Identifier: Apache-2.0 OR MIT
//! One command state machine for original and transferred authenticated requests.
use super::*;
impl Entry {
    pub(super) fn execute(
        &mut self,
        request: &Incoming<'_>,
        now: u64,
    ) -> Result<(AnchorOutcome, bool), Error> {
        let entry = self;
        let roster_pending = entry
            .independent_roster
            .as_ref()
            .is_some_and(RosterRefresh::pending);
        let mut changed = false;
        let outcome = match request.operation.0 {
            Command::Query => AnchorOutcome::Current,
            Command::PolicyCommit(_)
            | Command::PolicyStatus(_)
            | Command::PolicyClose(_)
            | Command::PolicyAcknowledge(_) => {
                let (result, mutation) = entry.handle_independent_policy(request, now)?;
                changed = mutation;
                result
            }
            Command::AdmitPolicy(authority, statement) => {
                let live = |v: Validity| match v.check(now) {
                    Ok(()) => Ok(true),
                    Err(Error::Validity) => Ok(false),
                    Err(e) => Err(e),
                };
                let state = entry.independent_policy.as_ref();
                let current = state.and_then(|s| s.current);
                if !roster_pending
                    && entry.authority == authority
                    && state.is_some_and(|s| !s.pending())
                    && current.is_some_and(|p| p.statement == statement)
                    && live(entry.validity)?
                {
                    AnchorOutcome::AuthorityCurrent
                } else {
                    AnchorOutcome::AuthorityDenied
                }
            }
            Command::AdmitAuthority(expected) => {
                let live = match entry.validity.check(now) {
                    Ok(()) => true,
                    Err(Error::Validity) => false,
                    Err(error) => return Err(error),
                };
                if !roster_pending
                    && entry.policy_authorization.is_none()
                    && entry
                        .independent_policy
                        .as_ref()
                        .is_none_or(|s| s.current.is_none() && !s.pending())
                    && entry.authority == expected
                    && live
                {
                    AnchorOutcome::AuthorityCurrent
                } else {
                    AnchorOutcome::AuthorityDenied
                }
            }
            Command::AdmitContinuation(authority, credential, statement) => {
                let live = |validity: Validity| match validity.check(now) {
                    Ok(()) => Ok(true),
                    Err(Error::Validity) => Ok(false),
                    Err(error) => Err(error),
                };
                let policy_live = match entry.policy_authorization {
                    Some(policy) => policy.statement == statement && live(policy.validity)?,
                    None => false,
                };
                if !roster_pending
                    && entry.authority == authority
                    && entry.renewal.is_none()
                    && entry.credential_authorization == Some(credential)
                    && policy_live
                    && live(entry.validity)?
                {
                    AnchorOutcome::AuthorityCurrent
                } else {
                    AnchorOutcome::AuthorityDenied
                }
            }
            Command::RosterCommit(_)
            | Command::RosterStatus(_)
            | Command::RosterClose(_)
            | Command::RosterAcknowledge(_) => {
                let (outcome, mutation) = entry.handle_independent_roster(request, now)?;
                changed = mutation;
                outcome
            }
            Command::CredentialCommit(_)
            | Command::CredentialStatus(_)
            | Command::CredentialClose(_)
            | Command::CredentialAcknowledge(_) => {
                let (outcome, mutation) = entry.handle_renewal(request, now)?;
                changed = mutation;
                outcome
            }
            Command::Advance(expected, next) | Command::Fence(expected, next) => {
                // Neither ordinary commands nor a writer fence may bypass an
                // unacknowledged joint transition, including its terminal state.
                if entry
                    .independent_roster
                    .as_ref()
                    .is_some_and(RosterRefresh::pending)
                    || entry.renewal.is_some()
                    || entry
                        .independent_policy
                        .as_ref()
                        .is_some_and(PolicyRenewal::pending)
                {
                    return Err(Error::State);
                }
                if entry.head == next && entry.last == Some(request.command) {
                    // Exact last-command confirmation is read-only after expiry too.
                    AnchorOutcome::AlreadyAppliedExact
                } else {
                    entry.validity.check(now)?;
                    if entry.head != expected {
                        AnchorOutcome::Conflict
                    } else {
                        entry.head = next;
                        entry.last = Some(request.command);
                        AnchorOutcome::Advanced
                    }
                }
            }
        };
        Ok((outcome, changed || outcome == AnchorOutcome::Advanced))
    }
}
