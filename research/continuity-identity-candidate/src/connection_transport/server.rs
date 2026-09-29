// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::durable::Delivery;

impl ConnectionEndpoint {
    /// Serve one bounded accepted connection. Prekeys are selected from the
    /// existing encrypted inventory. Application effects pass through Consumer
    /// only after authenticated inbox commit; no success is inferred from its start.
    /// Keep the listener available for exact replay after a lost final response.
    pub fn serve(
        &self,
        stream: TcpStream,
        actor: Actor<'_>,
        consumer: &mut impl Consumer,
        limits: RunLimits,
        cancel: &Cancellation,
        mut clock: impl FnMut() -> io::Result<u64>,
    ) -> Result<Served, Error> {
        let Actor {
            journal,
            context,
            signer,
        } = actor;
        self.binding(context, false)?;
        let deadline = limits.deadline()?;
        check(context, cancel, deadline, &mut clock)?;
        let mut channel = Channel::new(stream, self.endpoint.accept()?)?;
        for _ in 0..limits.exchanges {
            let request = channel.request(context, cancel, deadline, &mut clock)?;
            check(context, cancel, deadline, &mut clock)?;
            let (kind, body) = codec::open(request.bytes())?;
            let (response, event) = match kind {
                INITIAL => {
                    let reply = journal.respond_from_inventory(
                        Arc::clone(context),
                        codec::initial(body)?,
                        signer,
                        clock().map_err(Error::Clock)?,
                    )?;
                    (frame(REPLY, &reply)?, None)
                }
                BOOTSTRAP => {
                    let (initial, final_wire) = codec::split(body)?;
                    codec::initial(initial)?;
                    codec::initial(final_wire)?;
                    let session = journal.finish(
                        Arc::clone(context),
                        initial,
                        final_wire,
                        clock().map_err(Error::Clock)?,
                    )?;
                    let activated = journal.activate_responder_messages(
                        Arc::clone(context),
                        initial,
                        clock().map_err(Error::Clock)?,
                    )?;
                    if session != activated {
                        return Err(Error::Binding);
                    }
                    (frame(READY, &session)?, Some(Served::Established(session)))
                }
                MESSAGE => {
                    let (ad, wire) = codec::split(body)?;
                    let (session, message, epoch) =
                        crate::durable::message_route(wire).map_err(|_| Error::Protocol)?;
                    let delivered = journal.receive_delivery(
                        context,
                        session,
                        wire,
                        ad,
                        clock().map_err(Error::Clock)?,
                    )?;
                    let duplicate = match delivered {
                        Delivery::Pending(plaintext) => {
                            if plaintext.message_id() != message {
                                return Err(Error::Protocol);
                            }
                            check(context, cancel, deadline, &mut clock)?;
                            #[cfg(all(test, unix))]
                            super::test_support::after_stage("inbox", wire)?;
                            consumer
                                .commit(session, &plaintext)
                                .map_err(Error::Application)?;
                            #[cfg(all(test, unix))]
                            super::test_support::after_stage("application", wire)?;
                            check(context, cancel, deadline, &mut clock)?;
                            journal.consume_message(
                                context,
                                session,
                                message,
                                clock().map_err(Error::Clock)?,
                            )?;
                            false
                        }
                        Delivery::PreviouslyConsumed(id) => {
                            if id != message {
                                return Err(Error::Protocol);
                            }
                            true
                        }
                    };
                    let ack = journal.message_acknowledgement_for_epoch(
                        context,
                        session,
                        epoch,
                        clock().map_err(Error::Clock)?,
                    )?;
                    (
                        frame(ACK, &ack)?,
                        Some(Served::Consumed {
                            session,
                            message,
                            duplicate,
                        }),
                    )
                }
                _ => return Err(Error::Protocol),
            };
            #[cfg(all(test, unix))]
            let response = super::test_support::response(kind, response)?;
            #[cfg(all(test, unix))]
            super::test_support::after_reply(kind, &response)?;
            check(context, cancel, deadline, &mut clock)?;
            channel.respond(
                request.id(),
                &response,
                context,
                cancel,
                deadline,
                &mut clock,
            )?;
            if let Some(event) = event {
                channel.finish(context, cancel, deadline, &mut clock)?;
                return Ok(event);
            }
        }
        Err(Error::AttemptsExhausted)
    }
}
