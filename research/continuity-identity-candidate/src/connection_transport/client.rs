// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

fn accept_consumption(
    journal: &mut DeviceJournal,
    context: &BootstrapContext,
    session: [u8; 32],
    message: MessageId,
    reply: &[u8],
    clock: &mut impl FnMut() -> io::Result<u64>,
) -> Result<Consumption, Error> {
    let ack = payload(reply, ACK)?;
    if crate::durable::acknowledgement_epoch(ack).map_err(|_| Error::Protocol)?
        != crate::durable::message_epoch(message).map_err(Error::Authority)?
    {
        return Err(Error::Protocol);
    }
    journal.accept_message_acknowledgement(
        context,
        session,
        ack,
        clock().map_err(Error::Clock)?,
    )?;
    match journal.message_status(context, session, message)? {
        MessageStatus::Acknowledged => Ok(Consumption::Confirmed),
        MessageStatus::Committed => Ok(Consumption::PrefixPending),
        _ => Err(Error::Protocol),
    }
}

fn account_member(
    journal: &mut DeviceJournal,
    input: &FanoutInput<'_>,
    session: [u8; 32],
    now: u64,
) -> Result<FanoutMember, Error> {
    // This is the same complete-roster reservation/replay transaction on every
    // attempt. No individual send and no cached member wire bypass its checks.
    let members = journal.send_account_message(
        FanoutInput {
            id: input.id,
            account: input.account,
            targets: input.targets,
            plaintext: input.plaintext,
            associated_data: input.associated_data,
        },
        now,
    )?;
    members
        .into_iter()
        .find(|member| member.session == session)
        .ok_or(Error::Binding)
}

fn retained_outcome(output: FanoutOutput) -> Option<AccountDeliveryOutcome> {
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

struct Invocation<'a> {
    endpoint: &'a ConnectionEndpoint,
    context: &'a BootstrapContext,
    run: Run<'a>,
    deadline: Instant,
    attempts: u16,
    channel: Option<Channel>,
}
impl<'a> Invocation<'a> {
    fn new(
        endpoint: &'a ConnectionEndpoint,
        context: &'a BootstrapContext,
        run: Run<'a>,
    ) -> Result<Self, Error> {
        endpoint.binding(context, true)?;
        native_transport::address(run.address)?;
        let deadline = run.limits.deadline()?;
        Ok(Self {
            endpoint,
            context,
            run,
            deadline,
            attempts: 0,
            channel: None,
        })
    }
    fn call(
        &mut self,
        clock: &mut impl FnMut() -> io::Result<u64>,
        mut prepare: impl FnMut(u64) -> Result<Vec<u8>, Error>,
    ) -> Result<Vec<u8>, Error> {
        while self.attempts < self.run.limits.exchanges {
            check(self.context, self.run.cancel, self.deadline, clock)?;
            self.attempts += 1;
            // Re-release from the journal on every attempt. A cached wire never
            // bypasses current roster/policy/witness checks after reconnection.
            let wire = prepare(clock().map_err(Error::Clock)?)?;
            check(self.context, self.run.cancel, self.deadline, clock)?;
            let result = (|| {
                if self.channel.is_none() {
                    let stream = native_transport::connect(
                        self.run.address,
                        self.run.cancel,
                        self.deadline,
                        self.run.limits.connect_timeout,
                    )?;
                    check(self.context, self.run.cancel, self.deadline, clock)?;
                    self.channel = Some(Channel::new(
                        stream,
                        self.endpoint.endpoint.connect(self.run.server_name)?,
                    )?);
                }
                self.channel.as_mut().ok_or(Error::Protocol)?.exchange(
                    &wire,
                    self.context,
                    self.run.cancel,
                    self.deadline,
                    clock,
                )
            })();
            match result {
                Ok(reply) => {
                    check(self.context, self.run.cancel, self.deadline, clock)?;
                    return Ok(reply);
                }
                Err(error) if retryable(&error) => {
                    self.channel = None;
                    check(self.context, self.run.cancel, self.deadline, clock)?;
                    if self.attempts == self.run.limits.exchanges {
                        return Err(Error::RetryExhausted {
                            attempts: self.attempts,
                            last: Box::new(error),
                        });
                    }
                }
                Err(error) => return Err(error),
            }
        }
        Err(Error::AttemptsExhausted)
    }
}
impl ConnectionEndpoint {
    /// Establish from a retained initiation ID through the original three signed
    /// bootstrap flights and two network exchanges. Both journals activate their
    /// message states; no in-memory root or naked prekey is passed to this carrier.
    pub fn establish(
        &self,
        actor: Actor<'_>,
        request: InitiationId,
        run: Run<'_>,
        mut clock: impl FnMut() -> io::Result<u64>,
    ) -> Result<Established, Error> {
        let Actor {
            journal,
            archives,
            context,
            signer,
        } = actor;
        let mut invocation = Invocation::new(self, context, run)?;
        archives.check_journal(journal).map_err(Error::Archive)?;
        let reply = invocation.call(&mut clock, |now| {
            frame(
                INITIAL,
                &journal.initiate(Arc::clone(context), request, signer, now)?,
            )
        })?;
        let reply = codec::initial(payload(&reply, REPLY)?)?;
        let committed = journal.accept_reply(
            Arc::clone(context),
            request,
            reply,
            clock().map_err(Error::Clock)?,
        )?;
        let expected = committed.session_id();
        check(
            context,
            invocation.run.cancel,
            invocation.deadline,
            &mut clock,
        )?;
        let archive = journal.archive_session_closure(context, expected)?;
        archives
            .retain(journal, context, expected, &archive)
            .map_err(Error::Archive)?;
        #[cfg(all(test, unix))]
        super::test_support::archive_boundary(
            "client-archive",
            &expected,
            invocation.run.cancel,
            invocation.deadline,
        )?;
        check(
            context,
            invocation.run.cancel,
            invocation.deadline,
            &mut clock,
        )?;
        let ready = invocation.call(&mut clock, |now| {
            let initial = journal.resume_initial(Arc::clone(context), request, now)?;
            let final_wire = journal.resume_reply(Arc::clone(context), request, now)?;
            if final_wire.session_id() != expected {
                return Err(Error::Binding);
            }
            frame(
                BOOTSTRAP,
                &codec::pair(&initial, final_wire.final_message())?,
            )
        })?;
        if payload(&ready, READY)? != expected {
            return Err(Error::Protocol);
        }
        check(
            context,
            invocation.run.cancel,
            invocation.deadline,
            &mut clock,
        )?;
        let session = journal.activate_initiator_messages(
            Arc::clone(context),
            request,
            clock().map_err(Error::Clock)?,
        )?;
        if session != expected {
            return Err(Error::Binding);
        }
        check(
            context,
            invocation.run.cancel,
            invocation.deadline,
            &mut clock,
        )?;
        Ok(Established {
            session,
            exchanges: invocation.attempts,
        })
    }
    /// Send exact new/reserved input and accept only the peer's authenticated
    /// consumption prefix. The server's Consumer must make its external effect
    /// durable before it can produce this proof. Network retries keep the same ID.
    pub fn send(
        &self,
        actor: Actor<'_>,
        input: Submission<'_>,
        run: Run<'_>,
        mut clock: impl FnMut() -> io::Result<u64>,
    ) -> Result<Delivered, Error> {
        let Actor {
            journal,
            archives,
            context,
            ..
        } = actor;
        let mut invocation = Invocation::new(self, context, run)?;
        archives
            .require(journal, context, input.session)
            .map_err(Error::Archive)?;
        let reply = invocation.call(&mut clock, |now| {
            let wire = journal.send_message(
                context,
                input.session,
                input.message,
                input.plaintext,
                input.associated_data,
                now,
            )?;
            frame(MESSAGE, &codec::pair(input.associated_data, &wire)?)
        })?;
        let consumption = accept_consumption(
            journal,
            context,
            input.session,
            input.message,
            &reply,
            &mut clock,
        )?;
        check(
            context,
            invocation.run.cancel,
            invocation.deadline,
            &mut clock,
        )?;
        Ok(Delivered {
            message: input.message,
            consumption,
            exchanges: invocation.attempts,
        })
    }

    /// Commit/resume the original complete-roster input, then deliver one member.
    /// All target archives must exist before reservation. Every network attempt
    /// re-admits the entire saved recipient set, exact input and current authority
    /// through the aggregate journal operation. Never substitute a new aggregate
    /// ID or omit a failed recipient. Individual remote effects are not atomic.
    /// Already accounted outcomes return explicitly without connecting. A failure
    /// or cancellation can follow local or remote commit; reconcile the same ID.
    pub fn send_account_member(
        &self,
        actor: Actor<'_>,
        input: FanoutInput<'_>,
        session: [u8; 32],
        run: Run<'_>,
        mut clock: impl FnMut() -> io::Result<u64>,
    ) -> Result<AccountDelivered, Error> {
        let Actor {
            journal,
            archives,
            context,
            ..
        } = actor;
        let mut invocation = Invocation::new(self, context, run)?;
        if input.targets.is_empty() || input.targets.len() > crate::MAX_DEVICES {
            return Err(crate::DurableError::Capacity.into());
        }
        if input
            .targets
            .iter()
            .filter(|target| {
                target.session == session && target.context.digest() == context.digest()
            })
            .count()
            != 1
        {
            return Err(Error::Binding);
        }
        check(
            context,
            invocation.run.cancel,
            invocation.deadline,
            &mut clock,
        )?;
        for target in input.targets {
            archives
                .require(journal, target.context, target.session)
                .map_err(Error::Archive)?;
        }
        check(
            context,
            invocation.run.cancel,
            invocation.deadline,
            &mut clock,
        )?;
        let original = account_member(journal, &input, session, clock().map_err(Error::Clock)?)?;
        check(
            context,
            invocation.run.cancel,
            invocation.deadline,
            &mut clock,
        )?;
        let result = |outcome, exchanges| AccountDelivered {
            device: original.device,
            session,
            message: original.message,
            outcome,
            exchanges,
        };
        if let Some(outcome) = retained_outcome(original.output) {
            return Ok(result(outcome, 0));
        }
        let reply = invocation.call(&mut clock, |now| {
            let member = account_member(journal, &input, session, now)?;
            if member.device != original.device || member.message != original.message {
                return Err(Error::Binding);
            }
            let FanoutOutput::Committed(wire) = member.output else {
                return Err(Error::Protocol);
            };
            frame(MESSAGE, &codec::pair(input.associated_data, &wire)?)
        })?;
        let consumption = accept_consumption(
            journal,
            context,
            session,
            original.message,
            &reply,
            &mut clock,
        )?;
        // ACK persistence is per member. A later roster/policy/witness failure
        // retains that commit but cannot become a successful account admission.
        let checked = account_member(journal, &input, session, clock().map_err(Error::Clock)?)?;
        if checked.device != original.device || checked.message != original.message {
            return Err(Error::Binding);
        }
        let outcome = retained_outcome(checked.output)
            .unwrap_or(AccountDeliveryOutcome::Consumption(consumption));
        check(
            context,
            invocation.run.cancel,
            invocation.deadline,
            &mut clock,
        )?;
        Ok(result(outcome, invocation.attempts))
    }
}
