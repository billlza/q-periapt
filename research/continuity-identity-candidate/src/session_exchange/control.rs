// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Finite delivery of the existing signed rekey flights over an opaque carrier.
use super::*;
use crate::{RekeyControlMessage, RekeyControlStep, RekeyProgress};

/// Original target completed in the local authenticated journal. This does not
/// establish remote receipt, fresh peer liveness or secrecy recovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RekeyCompleted {
    /// Exact target; an invocation never silently starts a later epoch.
    pub epoch: u64,
    /// Number of request/reply exchanges attempted in this successful invocation.
    pub exchanges: u16,
}

#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl EnrolledDevice {
    /// Read original local rekey progress. Observation grants no dispatch authority.
    pub async fn session_rekey_progress(
        &mut self,
        session: &Session,
    ) -> Result<RekeyProgress, Error> {
        let op = Operation::new(self);
        let result = async {
            let (journal, archives) = op.owner.parts()?.0.stores()?;
            archives.require(journal, &session.context, session.id)?;
            Ok(journal.rekey_progress(&session.context, session.id).await?)
        }
        .await;
        op.finish(result)
    }

    /// Deliver/resume one explicit target with at most `exchanges` requests
    /// (1..=128), no implicit I/O retries, and the original invocation deadline.
    /// A lost result closes this owner; reopen and retry the same target. A
    /// retained receipt is redispatched even when its sender already completed.
    pub async fn drive_session_rekey(
        &mut self,
        session: &Session,
        target: u64,
        exchanges: u16,
        transport: &mut impl Transport,
        run: &Run<'_>,
        mut clock: impl FnMut() -> io::Result<u64>,
    ) -> Result<RekeyCompleted, Error> {
        let op = Operation::new(self);
        let result = async {
            crate::codec::generation(target)?;
            if !(1..=crate::contract::MAX_NETWORK_EXCHANGES).contains(&exchanges) {
                return Err(crate::Error::Encoding.into());
            }
            let context = &session.context;
            let (service, signer, _) = op.owner.parts()?;
            let (journal, archives) = service.stores()?;
            archives.require(journal, context, session.id)?;
            let mut step = journal.start_control_delivery(context, session.id, target, signer,
                run.time(context, &mut clock)?).await?;
            let mut attempted = 0;
            loop {
                run.time(context, &mut clock)?;
                let message = match step {
                    RekeyControlStep::LocallyConfirmed(epoch) => {
                        if epoch != target { return Err(crate::Error::Scope.into()); }
                        break Ok(RekeyCompleted { epoch, exchanges: attempted });
                    }
                    RekeyControlStep::Output(message) => message,
                };
                if message.target_epoch() != target { return Err(crate::Error::Scope.into()); }
                if attempted == exchanges { return Err(Error::ExchangeLimit); }
                let wire = journal.replay_control_delivery(context, session.id, &message, signer,
                    run.time(context, &mut clock)?).await?;
                run.time(context, &mut clock)?;
                attempted += 1;
                let reply = transport.exchange(&frame(codec::CONTROL, &wire)?, run.deadline, run.cancel)
                    .await.map_err(Error::Transport)?;
                run.time(context, &mut clock)?;
                let body = payload(&reply, codec::CONTROL_REPLY)?;
                step = match body.split_first() {
                    Some((1, wire)) => {
                        if RekeyControlMessage::inspect_target(wire)? != target {
                            return Err(crate::Error::Scope.into());
                        }
                        journal.receive_rekey_control(context, session.id, wire, signer,
                            run.time(context, &mut clock)?).await?
                    }
                    Some((0, [])) => {
                        // This unauthenticated carrier marker cannot advance the
                        // completion. Only authenticated local journal state counts.
                        let local = journal.advance_rekey_control(context, session.id, target, signer,
                            run.time(context, &mut clock)?).await?;
                        if !matches!(local, RekeyControlStep::LocallyConfirmed(epoch) if epoch == target) {
                            return Err(crate::Error::Authentication.into());
                        }
                        local
                    }
                    _ => return Err(crate::Error::Encoding.into()),
                };
            }
        }.await;
        op.finish(result)
    }

    /// Authenticate one signed control request for this original session. Keep
    /// serving after local completion so a lost final/receipt can be replayed.
    /// The empty reply marker is carrier metadata, not a peer completion proof.
    pub async fn serve_session_control(
        &mut self,
        session: &Session,
        request: &[u8],
        run: &Run<'_>,
        mut clock: impl FnMut() -> io::Result<u64>,
    ) -> Result<Vec<u8>, Error> {
        let op = Operation::new(self);
        let result = async {
            let context = &session.context;
            run.time(context, &mut clock)?;
            let wire = payload(request, codec::CONTROL)?;
            let target = RekeyControlMessage::inspect_target(wire)?;
            let (service, signer, _) = op.owner.parts()?;
            let (journal, archives) = service.stores()?;
            archives.require(journal, context, session.id)?;
            let step = journal
                .receive_rekey_control(
                    context,
                    session.id,
                    wire,
                    signer,
                    run.time(context, &mut clock)?,
                )
                .await?;
            let body = match step {
                RekeyControlStep::Output(message) => {
                    if message.target_epoch() != target {
                        return Err(crate::Error::Scope.into());
                    }
                    let mut body = vec![1];
                    body.extend_from_slice(
                        &journal
                            .replay_control_delivery(
                                context,
                                session.id,
                                &message,
                                signer,
                                run.time(context, &mut clock)?,
                            )
                            .await?,
                    );
                    body
                }
                RekeyControlStep::LocallyConfirmed(epoch) => {
                    if epoch != target {
                        return Err(crate::Error::Scope.into());
                    }
                    vec![0]
                }
            };
            run.time(context, &mut clock)?;
            frame(codec::CONTROL_REPLY, &body)
        }
        .await;
        op.finish(result)
    }
}
