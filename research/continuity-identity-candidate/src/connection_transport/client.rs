// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

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
                    let stream = TcpStream::connect_timeout(
                        &self.run.address,
                        remaining(self.deadline)?.min(self.run.limits.connect_timeout),
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
            context,
            signer,
        } = actor;
        let mut invocation = Invocation::new(self, context, run)?;
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
            journal, context, ..
        } = actor;
        let mut invocation = Invocation::new(self, context, run)?;
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
        let ack = payload(&reply, ACK)?;
        if crate::durable::acknowledgement_epoch(ack).map_err(|_| Error::Protocol)?
            != crate::durable::message_epoch(input.message).map_err(Error::Authority)?
        {
            return Err(Error::Protocol);
        }
        journal.accept_message_acknowledgement(
            context,
            input.session,
            ack,
            clock().map_err(Error::Clock)?,
        )?;
        let consumption = match journal.message_status(context, input.session, input.message)? {
            MessageStatus::Acknowledged => Consumption::Confirmed,
            MessageStatus::Committed => Consumption::PrefixPending,
            _ => return Err(Error::Protocol),
        };
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
}
