// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl EnrolledDevice {
    /// Establish/reconcile the original initiation through two authenticated
    /// exchanges. A forged public READY/session ID is insufficient. There is no
    /// implicit transport retry: reopen this original owner after any error and
    /// repeat the same request ID. No third-party code borrows the signer.
    pub async fn establish_session(
        &mut self,
        peer: &BootstrapPeer,
        request: InitiationId,
        transport: &mut impl Transport,
        run: &Run<'_>,
        mut clock: impl FnMut() -> io::Result<u64>,
    ) -> Result<Session, Error> {
        let op = Operation::new(self);
        let result = async {
            if peer.role() != BootstrapRole::Initiator {
                return Err(crate::Error::Scope.into());
            }
            let context = peer.context();
            let (service, signer, _) = op.owner.parts()?;
            let (journal, archives) = service.stores()?;
            archives.check_journal(journal)?;
            let initial = journal
                .initiate(
                    Arc::clone(context),
                    request,
                    signer,
                    run.time(context, &mut clock)?,
                )
                .await?;
            run.time(context, &mut clock)?;
            let reply = transport
                .exchange(&frame(INITIAL, &initial)?, run.deadline, run.cancel)
                .await
                .map_err(Error::Transport)?;
            let now = run.time(context, &mut clock)?;
            let committed = journal
                .accept_reply(Arc::clone(context), request, payload(&reply, REPLY)?, now)
                .await?;
            let id = committed.session_id();
            run.time(context, &mut clock)?;
            let archive = journal.archive_session_closure(context, id).await?;
            archives.retain(journal, context, id, &archive)?;
            let initial = journal
                .resume_initial(Arc::clone(context), request, run.time(context, &mut clock)?)
                .await?;
            let final_wire = journal
                .resume_reply(Arc::clone(context), request, run.time(context, &mut clock)?)
                .await?;
            if final_wire.session_id() != id {
                return Err(crate::Error::Scope.into());
            }
            let wire = frame(FINAL, &codec::pair(&initial, final_wire.final_message())?)?;
            run.time(context, &mut clock)?;
            let reply = transport
                .exchange(&wire, run.deadline, run.cancel)
                .await
                .map_err(Error::Transport)?;
            run.time(context, &mut clock)?;
            let (remote_id, proof) = codec::split(payload(&reply, READY)?)?;
            if remote_id != id || crate::durable::acknowledgement_epoch(proof)? != 0 {
                return Err(crate::Error::Authentication.into());
            }
            let activated = journal
                .activate_initiator_messages(
                    Arc::clone(context),
                    request,
                    run.time(context, &mut clock)?,
                )
                .await?;
            if activated != id {
                return Err(crate::Error::Scope.into());
            }
            archives.require(journal, context, id)?;
            journal
                .accept_message_acknowledgement(context, id, proof, run.time(context, &mut clock)?)
                .await?;
            run.time(context, &mut clock)?;
            Ok(Session {
                context: Arc::clone(context),
                role: peer.role(),
                id,
            })
        }
        .await;
        op.finish(result)
    }

    /// Observe the original next message ID. Observation reserves no plaintext
    /// and grants no authority; delivery repeats current journal checks.
    pub async fn next_session_message_id(
        &mut self,
        session: &Session,
        now: u64,
    ) -> Result<MessageId, Error> {
        let op = Operation::new(self);
        let result = async {
            let (journal, archives) = op.owner.parts()?.0.stores()?;
            archives.require(journal, &session.context, session.id)?;
            Ok(journal
                .next_message_id(&session.context, session.id, now)
                .await?)
        }
        .await;
        op.finish(result)
    }

    /// Reconcile only the original ID, including after an unknown acknowledgement
    /// commit. Acknowledged concerns that ID; erased history cannot authenticate
    /// replacement plaintext. This metadata does not authorize another send.
    pub async fn session_message_status(
        &mut self,
        session: &Session,
        message: MessageId,
    ) -> Result<MessageStatus, Error> {
        let op = Operation::new(self);
        let result = async {
            let (journal, archives) = op.owner.parts()?.0.stores()?;
            archives.require(journal, &session.context, session.id)?;
            Ok(journal
                .message_status(&session.context, session.id, message)
                .await?)
        }
        .await;
        op.finish(result)
    }

    /// Submit/reconcile one original application operation. Success returns an
    /// authenticated consumption-prefix outcome; PrefixPending is not delivery.
    /// Failed invocations retain their original ID and input, not a fresh send.
    pub async fn deliver_session_message(
        &mut self,
        session: &Session,
        input: Submission<'_>,
        transport: &mut impl Transport,
        run: &Run<'_>,
        mut clock: impl FnMut() -> io::Result<u64>,
    ) -> Result<Consumption, Error> {
        let op = Operation::new(self);
        let result = async {
            let context = &session.context;
            let (journal, archives) = op.owner.parts()?.0.stores()?;
            archives.require(journal, context, session.id)?;
            let wire = journal
                .send_message(
                    context,
                    session.id,
                    input.message,
                    input.plaintext,
                    input.associated_data,
                    run.time(context, &mut clock)?,
                )
                .await?;
            run.time(context, &mut clock)?;
            let request = frame(MESSAGE, &codec::pair(input.associated_data, &wire)?)?;
            let reply = transport
                .exchange(&request, run.deadline, run.cancel)
                .await
                .map_err(Error::Transport)?;
            run.time(context, &mut clock)?;
            let proof = payload(&reply, ACK)?;
            if crate::durable::acknowledgement_epoch(proof)?
                != crate::durable::message_epoch(input.message)?
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
            let result = match journal
                .message_status(context, session.id, input.message)
                .await?
            {
                MessageStatus::Acknowledged => Consumption::Confirmed,
                MessageStatus::Committed => Consumption::PrefixPending,
                _ => return Err(crate::Error::State.into()),
            };
            run.time(context, &mut clock)?;
            Ok(result)
        }
        .await;
        op.finish(result)
    }
}
