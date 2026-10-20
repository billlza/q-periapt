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

/// One original committed public control flight, owning no key or storage lease.
pub struct PreparedRekey {
    journal: crate::JournalIdentity,
    session: [u8; 32],
    context: [u8; 32],
    role: BootstrapRole,
    target: u64,
    request: Vec<u8>,
}
impl PreparedRekey {
    /// Exact QPCXCH01 request, not fresh dispatch authority.
    pub fn as_bytes(&self) -> &[u8] {
        &self.request
    }
    /// The original target; no later epoch is selected implicitly.
    pub fn target_epoch(&self) -> u64 {
        self.target
    }
}

/// A bounded original rekey step, after current owner and authority checks.
pub enum RekeyDeliveryStep {
    /// The host may close this owner before carrying these committed public bytes.
    Output(PreparedRekey),
    /// Authenticated local completion, not remote receipt or secrecy recovery.
    LocallyConfirmed(u64),
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
            let mut step = op
                .owner
                .prepare_session_rekey(session, target, run, &mut clock)
                .await?;
            let mut attempted = 0;
            loop {
                run.time(&session.context, &mut clock)?;
                let message = match step {
                    RekeyDeliveryStep::LocallyConfirmed(epoch) => {
                        if epoch != target {
                            return Err(crate::Error::Scope.into());
                        }
                        break Ok(RekeyCompleted {
                            epoch,
                            exchanges: attempted,
                        });
                    }
                    RekeyDeliveryStep::Output(message) => message,
                };
                if message.target_epoch() != target {
                    return Err(crate::Error::Scope.into());
                }
                if attempted == exchanges {
                    return Err(Error::ExchangeLimit);
                }
                attempted += 1;
                let reply = transport
                    .exchange(message.as_bytes(), run.deadline, run.cancel)
                    .await
                    .map_err(Error::Transport)?;
                step = op
                    .owner
                    .complete_session_rekey(session, &message, &reply, run, &mut clock)
                    .await?;
            }
        }
        .await;
        op.finish(result)
    }

    /// Prepare/resume one original control target. A retained final receipt is
    /// still dispatched after local completion. The host may close this owner
    /// for I/O, then reopen the original installation to complete this step.
    pub async fn prepare_session_rekey(
        &mut self,
        session: &Session,
        target: u64,
        run: &Run<'_>,
        mut clock: impl FnMut() -> io::Result<u64>,
    ) -> Result<RekeyDeliveryStep, Error> {
        let op = Operation::new(self);
        let result = async {
            crate::codec::generation(target)?;
            let context = &session.context;
            run.time(context, &mut clock)?;
            let (service, signer, _) = op.owner.parts()?;
            let (journal, archives) = service.stores()?;
            archives.require(journal, context, session.id)?;
            let step = journal
                .start_control_delivery(
                    context,
                    session.id,
                    target,
                    signer,
                    run.time(context, &mut clock)?,
                )
                .await?;
            op.owner
                .bound_rekey_step(session, target, step, run, &mut clock)
                .await
        }
        .await;
        op.finish(result)
    }

    /// Admit a real reply under fresh original-owner authority. Incoming control
    /// may already have advanced the same target while this request was in
    /// transit; the durable exact-flight handlers authenticate that history.
    pub async fn complete_session_rekey(
        &mut self,
        session: &Session,
        prepared: &PreparedRekey,
        reply: &[u8],
        run: &Run<'_>,
        mut clock: impl FnMut() -> io::Result<u64>,
    ) -> Result<RekeyDeliveryStep, Error> {
        let op = Operation::new(self);
        let result = async {
            let context = &session.context;
            run.time(context, &mut clock)?;
            let (service, signer, _) = op.owner.parts()?;
            let (journal, archives) = service.stores()?;
            archives.require(journal, context, session.id)?;
            if journal.identity()? != prepared.journal
                || session.id != prepared.session || context.digest() != prepared.context
                || session.role != prepared.role
            {
                return Err(crate::Error::Scope.into());
            }
            let target = prepared.target;
            let step = match payload(reply, codec::CONTROL_REPLY)?.split_first() {
                Some((1, wire)) => {
                    if RekeyControlMessage::inspect_target(wire)? != target {
                        return Err(crate::Error::Scope.into());
                    }
                    journal.receive_rekey_control(context, session.id, wire, signer,
                        run.time(context, &mut clock)?).await?
                }
                Some((0, [])) => {
                    // Carrier metadata cannot establish authenticated completion.
                    let local = journal.advance_rekey_control(context, session.id, target, signer,
                        run.time(context, &mut clock)?).await?;
                    if !matches!(local, RekeyControlStep::LocallyConfirmed(epoch) if epoch == target) {
                        return Err(crate::Error::Authentication.into());
                    }
                    local
                }
                _ => return Err(crate::Error::Encoding.into()),
            };
            op.owner.bound_rekey_step(session, target, step, run, &mut clock).await
        }.await;
        op.finish(result)
    }

    async fn bound_rekey_step(
        &mut self,
        session: &Session,
        target: u64,
        step: RekeyControlStep,
        run: &Run<'_>,
        clock: &mut impl FnMut() -> io::Result<u64>,
    ) -> Result<RekeyDeliveryStep, Error> {
        let context = &session.context;
        run.time(context, clock)?;
        let result = match step {
            RekeyControlStep::LocallyConfirmed(epoch) => {
                if epoch != target {
                    return Err(crate::Error::Scope.into());
                }
                RekeyDeliveryStep::LocallyConfirmed(epoch)
            }
            RekeyControlStep::Output(message) => {
                if message.target_epoch() != target {
                    return Err(crate::Error::Scope.into());
                }
                let (service, signer, _) = self.parts()?;
                let (journal, _) = service.stores()?;
                let wire = journal
                    .replay_control_delivery(
                        context,
                        session.id,
                        &message,
                        signer,
                        run.time(context, clock)?,
                    )
                    .await?;
                RekeyDeliveryStep::Output(PreparedRekey {
                    journal: journal.identity()?,
                    session: session.id,
                    context: context.digest(),
                    role: session.role,
                    target,
                    request: frame(codec::CONTROL, &wire)?,
                })
            }
        };
        run.time(context, clock)?;
        Ok(result)
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
