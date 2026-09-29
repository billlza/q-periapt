// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Native delivery reconciliation reuses the ordinary authenticated inbox path.
use super::*;

pub(crate) enum Delivery {
    Pending(CommittedPlaintext),
    PreviouslyConsumed(MessageId),
}

pub(crate) fn message_route(wire: &[u8]) -> Result<([u8; 32], MessageId, u64), Error> {
    let header = Header::decode(wire)?;
    Ok((header.session, header.id, header.epoch))
}
pub(crate) fn message_epoch(id: MessageId) -> Result<u64, Error> {
    id.epoch()
}
pub(crate) fn acknowledgement_epoch(wire: &[u8]) -> Result<u64, Error> {
    acknowledgement::wire_epoch(wire)
}

impl DeviceJournal {
    // PreviouslyConsumed proves only an earlier local consumption of this ID.
    // Below the retained prefix, the old key and input commitment have already
    // been erased; this path never authenticates or delivers replacement bytes.
    pub(crate) fn receive_delivery(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
        wire: &[u8],
        ad: &[u8],
        now: u64,
    ) -> Result<Delivery, DurableError> {
        let image = self.image()?;
        let state = self.message_state(&image, context, &session, now)?;
        let header = Header::decode(wire)?;
        if header.session != session || header.role == state.role {
            return Err(Error::Scope.into());
        }
        if ad.len() > MAX_AD
            || header.index >= u64::from(context.policy().application_send_budget().messages())
        {
            return Err(Error::PolicyDenied.into());
        }
        if header.epoch > state.receive_epoch {
            return Err(DurableError::Suspended);
        }
        let traffic = state.traffic(header.epoch)?;
        traffic.require_unresolved()?;
        if traffic
            .receive_limit
            .is_some_and(|limit| header.index >= limit)
        {
            return Err(Error::Retired.into());
        }
        let consumed = if header.index < traffic.receive_floor {
            true
        } else if let Some(saved) = traffic.incoming.get(&header.id) {
            if saved.intent != intent(b"receive-intent", wire, ad) {
                return Err(Error::Authentication.into());
            }
            saved.consumed
        } else {
            false
        };
        if consumed {
            self.check_context_release(&image, context, now)?;
            return Ok(Delivery::PreviouslyConsumed(header.id));
        }
        drop(state);
        drop(image);
        Ok(Delivery::Pending(
            self.receive_message(context, session, wire, ad, now)?,
        ))
    }
}
