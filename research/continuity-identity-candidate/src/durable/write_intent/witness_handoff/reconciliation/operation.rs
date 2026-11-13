// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::{AnchorHead, AnchorOperation as Op, AnchorOutcome, AnchorReply, AnchorSubject};
pub(super) enum Expected {
    Current(AnchorHead),
    Advance {
        previous: AnchorHead,
        next: AnchorHead,
        command: [u8; 32],
    },
    Credential(crate::AnchorCredentialRenewalProposal),
    Policy(crate::AnchorPolicyRenewalProposal),
    Roster(crate::AnchorRosterRefreshProposal),
    Cancellation(crate::AnchorCredentialRenewalCancellation),
}
impl Expected {
    pub(super) fn from_snapshot(
        image: &Image,
        pending: Option<&PendingIntent>,
        subject: AnchorSubject,
    ) -> Result<Self, DurableError> {
        Ok(match pending {
            None => Self::Current(image.protection.head(image.revision, image.digest)?),
            Some(PendingIntent::Cancellation(p)) => Self::Cancellation(p.cancellation),
            Some(PendingIntent::Write(p)) => match p.binding {
                Some(BoundTransaction::Credential(_)) => {
                    Self::Credential(p.credential_proposal(image)?)
                }
                Some(BoundTransaction::Policy(_)) => Self::Policy(p.policy_proposal(image)?),
                Some(BoundTransaction::Roster { .. }) => Self::Roster(p.roster_proposal(image)?),
                None => {
                    let Protection::Required { witness, .. } = image.protection else {
                        return Err(DurableError::AnchorRequired);
                    };
                    let previous = image
                        .protection
                        .head(p.expected_revision, p.expected_digest)?;
                    let next = image.protection.head(p.next_revision, p.next_digest)?;
                    Self::Advance {
                        previous,
                        next,
                        command: crate::anchor::command_id(
                            &witness,
                            subject,
                            Op::advance(previous, p.next_digest)?,
                        ),
                    }
                }
            },
        })
    }
    pub(super) fn operation(&self) -> Op {
        match self {
            Self::Current(_) | Self::Advance { .. } => Op::query(),
            Self::Credential(p) => Op::credential_renewal_status(p),
            Self::Policy(p) => Op::policy_renewal_status(p),
            Self::Roster(p) => Op::roster_refresh_status(p),
            Self::Cancellation(p) => Op::credential_cancellation_status(p),
        }
    }
    pub(super) fn classify(
        &self,
        reply: &AnchorReply,
    ) -> Result<(WitnessPendingRecovery, bool), DurableError> {
        if reply.handoff_context().is_none() {
            return Err(Error::Scope.into());
        }
        Ok(match self {
            Self::Current(expected)
                if reply.outcome() == AnchorOutcome::Current
                    && reply.observed_head() == *expected =>
            {
                (WitnessPendingRecovery::Current, false)
            }
            Self::Advance {
                previous,
                next,
                command,
            } if reply.outcome() == AnchorOutcome::Current => {
                if reply.observed_head() == *next && reply.last_command_id() == Some(*command) {
                    (WitnessPendingRecovery::AdvanceApplied, true)
                } else if reply.observed_head() == *previous {
                    (WitnessPendingRecovery::AdvancePending, false)
                } else {
                    return Err(DurableError::Conflict);
                }
            }
            Self::Credential(p) => {
                let s = reply.credential_renewal_state(p)?;
                (
                    WitnessPendingRecovery::Credential(s),
                    s == crate::AnchorCredentialRenewalState::Applied,
                )
            }
            Self::Policy(p) => {
                let s = reply.policy_renewal_state(p)?;
                (
                    WitnessPendingRecovery::Policy(s),
                    s == crate::AnchorPolicyRenewalState::Applied,
                )
            }
            Self::Roster(p) => {
                let s = reply.roster_refresh_state(p)?;
                (
                    WitnessPendingRecovery::Roster(s),
                    s == crate::AnchorRosterRefreshState::Applied,
                )
            }
            Self::Cancellation(p) => (
                WitnessPendingRecovery::Cancellation(reply.credential_cancellation_state(p)?),
                false,
            ),
            _ => return Err(DurableError::Conflict),
        })
    }
}
