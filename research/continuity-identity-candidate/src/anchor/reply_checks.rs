// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

pub(super) fn decode_outcome(d: &mut Decoder<'_>) -> Result<AnchorOutcome, Error> {
    let [outcome] = d.array()?;
    Ok(match outcome {
        1 => AnchorOutcome::Current,
        2 => AnchorOutcome::Advanced,
        3 => AnchorOutcome::AlreadyAppliedExact,
        4 => AnchorOutcome::Conflict,
        5 => AnchorOutcome::AuthorityCurrent,
        6 => AnchorOutcome::AuthorityDenied,
        7 => AnchorOutcome::CredentialPrepared,
        8 => AnchorOutcome::CredentialApplied,
        9 => AnchorOutcome::CredentialClosed,
        10 => AnchorOutcome::CredentialUnavailable,
        11 => AnchorOutcome::CredentialAcknowledged,
        12 => AnchorOutcome::PolicyPrepared,
        13 => AnchorOutcome::PolicyApplied,
        14 => AnchorOutcome::PolicyClosed,
        15 => AnchorOutcome::PolicyUnavailable,
        16 => AnchorOutcome::PolicyAcknowledged,
        17 => AnchorOutcome::RosterPrepared,
        18 => AnchorOutcome::RosterApplied,
        19 => AnchorOutcome::RosterClosed,
        20 => AnchorOutcome::RosterUnavailable,
        21 => AnchorOutcome::RosterAcknowledged,
        _ => return Err(Error::Encoding),
    })
}

pub(super) fn validate(
    operation: AnchorOperation,
    command: [u8; 32],
    outcome: AnchorOutcome,
    head: AnchorHead,
    last: Option<[u8; 32]>,
) -> Result<(), Error> {
    match (operation.0, outcome) {
        (Command::Query, AnchorOutcome::Current) => {}
        (
            Command::RosterStatus(_),
            AnchorOutcome::RosterPrepared
            | AnchorOutcome::RosterApplied
            | AnchorOutcome::RosterClosed
            | AnchorOutcome::RosterUnavailable,
        ) => {}
        (
            Command::RosterCommit(_) | Command::RosterClose(_),
            AnchorOutcome::RosterApplied
            | AnchorOutcome::RosterClosed
            | AnchorOutcome::RosterUnavailable,
        ) => {}
        (
            Command::RosterAcknowledge(_),
            AnchorOutcome::RosterAcknowledged | AnchorOutcome::RosterUnavailable,
        ) => {}
        (
            Command::PolicyStatus(_),
            AnchorOutcome::PolicyPrepared
            | AnchorOutcome::PolicyApplied
            | AnchorOutcome::PolicyClosed
            | AnchorOutcome::PolicyUnavailable,
        ) => {}
        (
            Command::PolicyCommit(_) | Command::PolicyClose(_),
            AnchorOutcome::PolicyApplied
            | AnchorOutcome::PolicyClosed
            | AnchorOutcome::PolicyUnavailable,
        ) => {}
        (
            Command::PolicyAcknowledge(_),
            AnchorOutcome::PolicyAcknowledged | AnchorOutcome::PolicyUnavailable,
        ) => {}
        (
            Command::AdmitAuthority(_) | Command::AdmitContinuation(..) | Command::AdmitPolicy(..),
            AnchorOutcome::AuthorityCurrent | AnchorOutcome::AuthorityDenied,
        ) => {}
        (
            Command::CredentialStatus(_),
            AnchorOutcome::CredentialPrepared
            | AnchorOutcome::CredentialApplied
            | AnchorOutcome::CredentialClosed
            | AnchorOutcome::CredentialUnavailable,
        ) => {}
        (
            Command::CredentialCommit(_) | Command::CredentialClose(_),
            AnchorOutcome::CredentialApplied
            | AnchorOutcome::CredentialClosed
            | AnchorOutcome::CredentialUnavailable,
        ) => {}
        (
            Command::CredentialAcknowledge(_),
            AnchorOutcome::CredentialAcknowledged | AnchorOutcome::CredentialUnavailable,
        ) => {}
        (
            Command::Advance(_, next) | Command::Fence(_, next),
            AnchorOutcome::Advanced | AnchorOutcome::AlreadyAppliedExact,
        ) if head == next && last == Some(command) => {}
        (Command::Advance(expected, _) | Command::Fence(expected, _), AnchorOutcome::Conflict)
            if head != expected && !(Some(head) == operation.next() && last == Some(command)) => {}
        _ => return Err(Error::State),
    }
    Ok(())
}
