// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Cumulative application-consumption acknowledgements and bounded retention.
use super::*;
use hmac::{Hmac, Mac};

const ACK_TAG: &[u8; 8] = b"QPCMACK1";
const ACK_PREFIX: usize = 8 + 32 + 1 + 8;
const ACK_LENGTH: usize = ACK_PREFIX + 32;
const EPOCH_ACK_TAG: &[u8; 8] = b"QPCMACK2";

pub(super) fn wire_epoch(wire: &[u8]) -> Result<u64, Error> {
    if wire.len() == ACK_LENGTH && wire.get(..8) == Some(ACK_TAG.as_slice()) {
        return Ok(0);
    }
    if wire.len() != ACK_LENGTH + 8 || wire.get(..8) != Some(EPOCH_ACK_TAG.as_slice()) {
        return Err(Error::Encoding);
    }
    let mut d = Decoder::new(wire.get(41..49).ok_or(Error::Encoding)?);
    let epoch = d.u64()?;
    crate::codec::generation(epoch)?;
    Ok(epoch)
}

impl Traffic {
    pub(super) fn consume(&mut self, id: MessageId) -> Result<bool, Error> {
        self.require_unresolved()?;
        let index = id.check(&self.session, 3 - self.role)?;
        if id.epoch()? != self.epoch {
            return Err(Error::Scope);
        }
        if index < self.receive_floor {
            return Ok(false);
        }
        let saved = self.incoming.get_mut(&id).ok_or(Error::State)?;
        if saved.consumed {
            return Ok(false);
        }
        // Drop the Zeroizing allocation while its original length is intact.
        saved.plaintext = Zeroizing::new(Vec::new());
        saved.consumed = true;
        while self.receive_floor < self.received {
            let next =
                MessageId::for_epoch(&self.session, 3 - self.role, self.epoch, self.receive_floor)?;
            if !self.incoming.get(&next).is_some_and(|saved| saved.consumed) {
                break;
            }
            self.incoming.remove(&next);
            self.receive_floor += 1;
        }
        Ok(true)
    }
    pub(super) fn acknowledgement(&self) -> Result<Vec<u8>, Error> {
        self.require_unresolved()?;
        let mut wire = if self.epoch == 0 {
            ACK_TAG.to_vec()
        } else {
            EPOCH_ACK_TAG.to_vec()
        };
        wire.extend_from_slice(&self.session);
        wire.push(3 - self.role);
        if self.epoch != 0 {
            wire.extend_from_slice(&self.epoch.to_be_bytes());
        }
        wire.extend_from_slice(&self.receive_floor.to_be_bytes());
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(self.receive_ack.as_bytes())
            .map_err(|_| Error::Provider)?;
        mac.update(&label(b"acknowledgement"));
        mac.update(&wire);
        wire.extend_from_slice(&mac.finalize().into_bytes());
        Ok(wire)
    }
    pub(super) fn accept_acknowledgement(&mut self, wire: &[u8]) -> Result<bool, Error> {
        self.require_unresolved()?;
        let epoch = wire_epoch(wire)?;
        if epoch != self.epoch {
            return Err(Error::Scope);
        }
        let mut d = Decoder::new(wire);
        d.array::<8>()?;
        let session = d.array::<32>()?;
        let [role] = d.array()?;
        if epoch != 0 {
            d.u64()?;
        }
        let floor = d.u64()?;
        let tag = d.take(32)?;
        d.finish()?;
        if session != self.session || role != self.role {
            return Err(Error::Scope);
        }
        let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(self.send_ack.as_bytes())
            .map_err(|_| Error::Provider)?;
        mac.update(&label(b"acknowledgement"));
        mac.update(wire.get(..wire.len() - 32).ok_or(Error::Encoding)?);
        mac.verify_slice(tag).map_err(|_| Error::Authentication)?;
        if floor > self.sent {
            return Err(Error::Authentication);
        }
        if floor <= self.send_floor {
            return Ok(false);
        }
        let mut retired = Vec::new();
        for id in self.outgoing.keys() {
            if id.index()? < floor {
                retired.push(*id);
            }
        }
        for id in retired {
            self.outgoing.remove(&id);
        }
        self.send_floor = floor;
        Ok(true)
    }
}

impl DeviceJournal {
    /// Commit the application's consumption of an authenticated inbox delivery.
    /// This erases its retained plaintext and advances only the contiguous consumed
    /// prefix. External application effects must be durably deduplicated separately.
    pub fn consume_message(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
        id: MessageId,
        now: u64,
    ) -> Result<u64, DurableError> {
        let mut image = self.image()?;
        let mut state = self.message_state(&image, context, &session, now)?;
        let epoch = id.epoch()?;
        if state.traffic_mut(epoch)?.consume(id)? {
            image
                .records
                .get_mut(&record_id(&session))
                .ok_or(DurableError::Corrupt)?
                .payload = state.encode();
            self.persist(&mut image)?;
            #[cfg(all(test, unix))]
            super::tests::after_stage("consumed");
        }
        context.check_session_identity(now)?;
        self.check_session_context_release(&image, context, now)?;
        Ok(state.traffic(epoch)?.receive_floor)
    }
    /// Return a MAC of the currently committed contiguous application-consumed
    /// prefix. Recompute after loss/restart; no message key or nonce is consumed.
    pub fn message_acknowledgement(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
        now: u64,
    ) -> Result<Vec<u8>, DurableError> {
        let image = self.image()?;
        let state = self.message_state(&image, context, &session, now)?;
        let wire = state.traffic(state.receive_epoch)?.acknowledgement()?;
        self.check_session_context_release(&image, context, now)?;
        Ok(wire)
    }
    /// Recompute the exact epoch's committed consumption acknowledgement. Old
    /// ACKs retain authority only over that old epoch's outboxes.
    pub fn message_acknowledgement_for_epoch(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
        epoch: u64,
        now: u64,
    ) -> Result<Vec<u8>, DurableError> {
        let image = self.image()?;
        let state = self.message_state(&image, context, &session, now)?;
        if epoch > state.receive_epoch {
            return Err(DurableError::Suspended);
        }
        let wire = state.traffic(epoch)?.acknowledgement()?;
        self.check_session_context_release(&image, context, now)?;
        Ok(wire)
    }
    /// Verify the peer's cumulative application-consumption acknowledgement and
    /// atomically retire corresponding outboxes. Old acknowledgements cannot
    /// regress the floor; retired message IDs never become new send requests.
    pub fn accept_message_acknowledgement(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
        wire: &[u8],
        now: u64,
    ) -> Result<u64, DurableError> {
        let mut image = self.image()?;
        let mut state = self.message_state(&image, context, &session, now)?;
        let epoch = wire_epoch(wire)?;
        if epoch > state.send_epoch {
            return Err(DurableError::Suspended);
        }
        if state.traffic_mut(epoch)?.accept_acknowledgement(wire)? {
            image
                .records
                .get_mut(&record_id(&session))
                .ok_or(DurableError::Corrupt)?
                .payload = state.encode();
            self.persist(&mut image)?;
            #[cfg(all(test, unix))]
            super::tests::after_stage("acknowledged");
        }
        context.check_session_identity(now)?;
        self.check_session_context_release(&image, context, now)?;
        Ok(state.traffic(epoch)?.send_floor)
    }
}
