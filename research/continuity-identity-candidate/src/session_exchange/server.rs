// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;
use crate::durable::Delivery;

#[cfg_attr(
    not(all(target_arch = "wasm32", target_os = "unknown")),
    maybe_async::must_be_sync
)]
impl EnrolledDevice {
    /// Process one bounded request through this enrolled owner. This adapter
    /// returns no raw key or signing capability. Host consumption happens only
    /// after durable authenticated inbox admission. Keep the original service
    /// available for exact replay after a lost response.
    pub async fn serve_session_exchange(
        &mut self,
        peer: &BootstrapPeer,
        request: &[u8],
        consumer: &mut impl Consumer,
        run: &Run<'_>,
        mut clock: impl FnMut() -> io::Result<u64>,
    ) -> Result<Vec<u8>, Error> {
        self.serve_exchange(
            peer.context(),
            Some(peer.role()),
            request,
            consumer,
            run,
            &mut clock,
        )
        .await
    }

    /// Serve data on an independently reopened original session, in either
    /// traffic direction. Historical context cannot admit another bootstrap.
    pub async fn serve_session_message(
        &mut self,
        session: &Session,
        request: &[u8],
        consumer: &mut impl Consumer,
        run: &Run<'_>,
        mut clock: impl FnMut() -> io::Result<u64>,
    ) -> Result<Vec<u8>, Error> {
        let op = Operation::new(self);
        let result = async {
            let wire = payload(request, MESSAGE)?;
            let (_, message) = codec::split(wire)?;
            if crate::durable::message_route(message)?.0 != session.id {
                return Err(crate::Error::Scope.into());
            }
            op.owner
                .serve_exchange(&session.context, None, request, consumer, run, &mut clock)
                .await
        }
        .await;
        op.finish(result)
    }

    async fn serve_exchange(
        &mut self,
        context: &Arc<BootstrapContext>,
        bootstrap_role: Option<BootstrapRole>,
        request: &[u8],
        consumer: &mut impl Consumer,
        run: &Run<'_>,
        clock: &mut impl FnMut() -> io::Result<u64>,
    ) -> Result<Vec<u8>, Error> {
        let op = Operation::new(self);
        let result = async {
            run.time(context, clock)?;
            let (kind, body) = codec::open(request)?;
            let (service, signer, _) = op.owner.parts()?;
            let (journal, archives) = service.stores()?;
            archives.check_journal(journal)?;
            let response = match kind {
                INITIAL if bootstrap_role == Some(BootstrapRole::Responder) => {
                    let reply = journal
                        .respond_from_inventory(
                            Arc::clone(context),
                            body,
                            signer,
                            run.time(context, clock)?,
                        )
                        .await?;
                    frame(REPLY, &reply)?
                }
                FINAL if bootstrap_role == Some(BootstrapRole::Responder) => {
                    let (initial, final_wire) = codec::split(body)?;
                    let id = journal
                        .finish(
                            Arc::clone(context),
                            initial,
                            final_wire,
                            run.time(context, clock)?,
                        )
                        .await?;
                    run.time(context, clock)?;
                    let archive = journal.archive_session_closure(context, id).await?;
                    archives.retain(journal, context, id, &archive)?;
                    let activated = journal
                        .activate_responder_messages(
                            Arc::clone(context),
                            initial,
                            run.time(context, clock)?,
                        )
                        .await?;
                    if id != activated {
                        return Err(crate::Error::Scope.into());
                    }
                    archives.require(journal, context, id)?;
                    let proof = journal
                        .message_acknowledgement_for_epoch(
                            context,
                            id,
                            0,
                            run.time(context, clock)?,
                        )
                        .await?;
                    frame(READY, &codec::pair(&id, &proof)?)?
                }
                MESSAGE => {
                    let (ad, wire) = codec::split(body)?;
                    let (id, message, epoch) = crate::durable::message_route(wire)?;
                    archives.require(journal, context, id)?;
                    match journal
                        .receive_delivery(context, id, wire, ad, run.time(context, clock)?)
                        .await?
                    {
                        Delivery::Pending(plaintext) => {
                            if plaintext.message_id() != message {
                                return Err(crate::Error::Scope.into());
                            }
                            run.time(context, clock)?;
                            consumer
                                .commit(id, &plaintext)
                                .await
                                .map_err(Error::Application)?;
                            journal
                                .consume_message(context, id, message, run.time(context, clock)?)
                                .await?;
                        }
                        Delivery::PreviouslyConsumed(saved) => {
                            if saved != message {
                                return Err(crate::Error::Scope.into());
                            }
                        }
                    }
                    let proof = journal
                        .message_acknowledgement_for_epoch(
                            context,
                            id,
                            epoch,
                            run.time(context, clock)?,
                        )
                        .await?;
                    frame(ACK, &proof)?
                }
                _ => return Err(crate::Error::Encoding.into()),
            };
            run.time(context, clock)?;
            Ok(response)
        }
        .await;
        op.finish(result)
    }
}
