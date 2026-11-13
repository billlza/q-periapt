// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

/// One committed original ciphertext, with no storage lease or private key.
/// Retaining these already-admitted public bytes confers no new send authority.
/// Reply admission must reopen the original owner and recheck current authority.
pub struct PreparedMessage {
    journal: crate::JournalIdentity,
    session: [u8; 32],
    context: [u8; 32],
    role: BootstrapRole,
    message: MessageId,
    request: Vec<u8>,
}
impl PreparedMessage {
    /// Exact original QPCXCH01 request for the bounded untrusted carrier.
    pub fn as_bytes(&self) -> &[u8] {
        &self.request
    }
    /// Original message identity, not evidence of peer consumption.
    pub fn message_id(&self) -> MessageId {
        self.message
    }
}

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
            let prepared = op
                .owner
                .prepare_session_message(session, input, run, &mut clock)
                .await?;
            let reply = transport
                .exchange(prepared.as_bytes(), run.deadline, run.cancel)
                .await
                .map_err(Error::Transport)?;
            op.owner
                .complete_session_message(session, &prepared, &reply, run, clock)
                .await
        }
        .await;
        op.finish(result)
    }

    /// Commit the original ciphertext before releasing any bytes. Hosts may
    /// close this owner before network I/O, then reopen the same installation
    /// for `complete_session_message`. Retrying preparation keeps the same ID
    /// and exact input; no fresh operation is synthesized after an unknown result.
    pub async fn prepare_session_message(
        &mut self,
        session: &Session,
        input: Submission<'_>,
        run: &Run<'_>,
        mut clock: impl FnMut() -> io::Result<u64>,
    ) -> Result<PreparedMessage, Error> {
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
            Ok(PreparedMessage {
                journal: journal.identity()?,
                session: session.id,
                context: context.digest(),
                role: session.role,
                message: input.message,
                request,
            })
        }
        .await;
        op.finish(result)
    }

    /// Authenticate a reply under fresh original-owner admission after transport.
    /// The prepared operation binds the original journal/context/direction/ID.
    /// An unrelated, absent, reserved or retired operation cannot be acknowledged.
    pub async fn complete_session_message(
        &mut self,
        session: &Session,
        prepared: &PreparedMessage,
        reply: &[u8],
        run: &Run<'_>,
        mut clock: impl FnMut() -> io::Result<u64>,
    ) -> Result<Consumption, Error> {
        let op = Operation::new(self);
        let result = async {
            let context = &session.context;
            run.time(context, &mut clock)?;
            let (journal, archives) = op.owner.parts()?.0.stores()?;
            archives.require(journal, context, session.id)?;
            if journal.identity()? != prepared.journal
                || session.id != prepared.session
                || context.digest() != prepared.context
                || session.role != prepared.role
            {
                return Err(crate::Error::Scope.into());
            }
            let original = journal
                .message_status(context, session.id, prepared.message)
                .await?;
            if !matches!(
                original,
                MessageStatus::Committed | MessageStatus::Acknowledged
            ) {
                return Err(crate::Error::State.into());
            }
            let proof = payload(reply, ACK)?;
            if crate::durable::acknowledgement_epoch(proof)?
                != crate::durable::message_epoch(prepared.message)?
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
                .message_status(context, session.id, prepared.message)
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
