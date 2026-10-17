// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Complete-roster operations over the portable authenticated session carrier.
use super::*;
use crate::{FanoutId, FanoutInput, FanoutMember, FanoutOutput, FanoutStatus, FanoutTarget};

/// One member's outcome; no variant asserts remote atomic account delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccountDeliveryOutcome {
    /// The original session's authenticated consumption-prefix result.
    Consumption(Consumption),
    /// A frozen epoch still needs durable host accounting.
    ResolutionPending,
    /// Host accounting recorded unknown delivery, not successful consumption.
    DeliveryUnknown,
    /// Settled history no longer distinguishes consumption from recorded loss.
    HistoryRetired,
    /// The reservation was abandoned through whole-session accounting.
    ReservationAbandoned,
}
/// Exact selected member of one original complete-roster transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountDelivered {
    /// Credential-bound recipient derived by the journal.
    pub device: [u8; 16],
    /// Original member session.
    pub session: [u8; 32],
    /// Original journal-allocated message, retained on every retry.
    pub message: MessageId,
    /// Authenticated delivery or explicit retained accounting outcome.
    pub outcome: AccountDeliveryOutcome,
    /// Zero for retained outcomes; the portable carrier attempts one exchange.
    pub exchanges: u16,
}
/// Exact shared input for all required current devices in a recipient account.
pub struct AccountSubmission<'a> {
    /// Original journal-bound aggregate ID, never replaced after an error.
    pub id: FanoutId,
    /// Independently authenticated recipient account.
    pub account: [u8; 32],
    /// All original sessions; no duplicate or omitted required member is allowed.
    pub sessions: &'a [Session],
    /// Original plaintext, bounded by the ordinary message limit.
    pub plaintext: &'a [u8],
    /// Original associated data, bounded by the ordinary message limit.
    pub associated_data: &'a [u8],
}
fn targets(sessions: &[Session]) -> Result<Vec<FanoutTarget<'_>>, Error> {
    if sessions.is_empty() || sessions.len() > crate::MAX_DEVICES {
        return Err(DurableError::Capacity.into());
    }
    Ok(sessions
        .iter()
        .map(|s| FanoutTarget {
            context: &s.context,
            session: s.id,
        })
        .collect())
}
pub(crate) fn retained_outcome(output: FanoutOutput) -> Option<AccountDeliveryOutcome> {
    match output {
        FanoutOutput::Committed(_) => None,
        FanoutOutput::Acknowledged => {
            Some(AccountDeliveryOutcome::Consumption(Consumption::Confirmed))
        }
        FanoutOutput::ResolutionPending => Some(AccountDeliveryOutcome::ResolutionPending),
        FanoutOutput::DeliveryUnknown => Some(AccountDeliveryOutcome::DeliveryUnknown),
        FanoutOutput::HistoryRetired => Some(AccountDeliveryOutcome::HistoryRetired),
        FanoutOutput::ReservationAbandoned => Some(AccountDeliveryOutcome::ReservationAbandoned),
    }
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
async fn member(
    journal: &mut crate::DeviceJournal,
    input: &AccountSubmission<'_>,
    targets: &[FanoutTarget<'_>],
    session: [u8; 32],
    now: u64,
) -> Result<FanoutMember, Error> {
    journal
        .send_account_message(
            FanoutInput {
                id: input.id,
                account: input.account,
                targets,
                plaintext: input.plaintext,
                associated_data: input.associated_data,
            },
            now,
        )
        .await?
        .into_iter()
        .find(|member| member.session == session)
        .ok_or_else(|| crate::Error::Scope.into())
}
#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl EnrolledDevice {
    /// Observe the next original ID; this does not reserve input or send authority.
    pub async fn next_account_message_id(&mut self) -> Result<FanoutId, Error> {
        let op = Operation::new(self);
        let result = async { Ok(op.owner.parts()?.0.stores()?.0.next_fanout_id().await?) }.await;
        op.finish(result)
    }
    /// Read retained aggregate progress; no ciphertext or traffic authority escapes.
    pub async fn account_message_status(&mut self, id: FanoutId) -> Result<FanoutStatus, Error> {
        let op = Operation::new(self);
        let result = async { Ok(op.owner.parts()?.0.stores()?.0.fanout_status(id).await?) }.await;
        op.finish(result)
    }
    /// Reconcile all original committed/accounted members without sending or
    /// advancing a reservation. Reserved work remains suspended for exact retry.
    pub async fn reconcile_account_message(
        &mut self,
        id: FanoutId,
        sessions: &[Session],
    ) -> Result<crate::FanoutReconciliation, Error> {
        let op = Operation::new(self);
        let result = async {
            let targets = targets(sessions)?;
            let (journal, archives) = op.owner.parts()?.0.stores()?;
            for target in &targets {
                archives.require(journal, target.context, target.session)?;
            }
            Ok(journal.reconcile_fanout(id, &targets).await?)
        }
        .await;
        op.finish(result)
    }
    /// Retire metadata only after every original member is acknowledged or
    /// separately accounted. This never abandons reserved work or reuses its ID.
    pub async fn retire_account_message(
        &mut self,
        id: FanoutId,
        sessions: &[Session],
    ) -> Result<(), Error> {
        let op = Operation::new(self);
        let result = async {
            let targets = targets(sessions)?;
            let (journal, archives) = op.owner.parts()?.0.stores()?;
            for target in &targets {
                archives.require(journal, target.context, target.session)?;
            }
            Ok(journal.retire_fanout(id, &targets).await?)
        }
        .await;
        op.finish(result)
    }
    /// Commit every mandatory target together, then deliver one selected member.
    /// Every invocation re-admits the entire original aggregate. Network failure
    /// can follow remote consumption; reopen this owner and retry the same input.
    /// Remote application effects are independently committed, not atomic as a set.
    pub async fn deliver_account_member(
        &mut self,
        input: AccountSubmission<'_>,
        selected: usize,
        transport: &mut impl Transport,
        run: &Run<'_>,
        clock: impl FnMut() -> io::Result<u64>,
    ) -> Result<AccountDelivered, Error> {
        let op = Operation::new(self);
        // Keep successful early returns inside the attempt function. The native
        // sync transform removes async-block scope, but cannot bypass this finish.
        let result = op
            .owner
            .deliver_account_member_attempt(input, selected, transport, run, clock)
            .await;
        op.finish(result)
    }
    async fn deliver_account_member_attempt(
        &mut self,
        input: AccountSubmission<'_>,
        selected: usize,
        transport: &mut impl Transport,
        run: &Run<'_>,
        mut clock: impl FnMut() -> io::Result<u64>,
    ) -> Result<AccountDelivered, Error> {
        let targets = targets(input.sessions)?;
        let session = input.sessions.get(selected).ok_or(crate::Error::Scope)?;
        let context = &session.context;
        run.time(context, &mut clock)?;
        let (journal, archives) = self.parts()?.0.stores()?;
        for target in &targets {
            archives.require(journal, target.context, target.session)?;
        }
        let original = member(
            journal,
            &input,
            &targets,
            session.id,
            run.time(context, &mut clock)?,
        )
        .await?;
        run.time(context, &mut clock)?;
        let result = |outcome, exchanges| AccountDelivered {
            device: original.device,
            session: session.id,
            message: original.message,
            outcome,
            exchanges,
        };
        let FanoutOutput::Committed(wire) = original.output else {
            return Ok(result(
                retained_outcome(original.output).ok_or(crate::Error::State)?,
                0,
            ));
        };
        let request = frame(MESSAGE, &codec::pair(input.associated_data, &wire)?)?;
        run.time(context, &mut clock)?;
        let reply = transport
            .exchange(&request, run.deadline, run.cancel)
            .await
            .map_err(Error::Transport)?;
        run.time(context, &mut clock)?;
        let proof = payload(&reply, ACK)?;
        if crate::durable::acknowledgement_epoch(proof)?
            != crate::durable::message_epoch(original.message)?
        {
            return Err(crate::Error::Authentication.into());
        }
        journal
            .accept_message_acknowledgement(
                context,
                session.id,
                proof,
                run.time(context, &mut clock)?,
            )
            .await?;
        let consumption = match journal
            .message_status(context, session.id, original.message)
            .await?
        {
            MessageStatus::Acknowledged => Consumption::Confirmed,
            MessageStatus::Committed => Consumption::PrefixPending,
            _ => return Err(crate::Error::State.into()),
        };
        // An ACK may already be durable when another required member loses
        // authority. Preserve that fact, but do not report successful admission.
        let checked = member(
            journal,
            &input,
            &targets,
            session.id,
            run.time(context, &mut clock)?,
        )
        .await?;
        if checked.device != original.device || checked.message != original.message {
            return Err(crate::Error::Scope.into());
        }
        let outcome = retained_outcome(checked.output)
            .unwrap_or(AccountDeliveryOutcome::Consumption(consumption));
        run.time(context, &mut clock)?;
        Ok(result(outcome, 1))
    }
}
