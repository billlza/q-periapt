// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Terminal grammar contains no key, plaintext, signing coin, KEM coin or outbox.
use super::*;

struct Counts {
    epoch: u64,
    sent: u64,
    acknowledged: u64,
}
pub(in crate::durable::messages) struct Retired {
    pub(in crate::durable::messages) source: [u8; 32],
    pub(in crate::durable::messages) session: [u8; 32],
    pub(in crate::durable::messages) role: u8,
    pub(in crate::durable::messages) batch: FanoutId,
    pub(in crate::durable::messages) report: FanoutAbandonmentId,
    pub(in crate::durable::messages) pending: MessageId,
    progress: RekeyProgress,
    epochs: Vec<Counts>,
}
impl Retired {
    pub(super) fn new(
        state: &State,
        batch: FanoutId,
        report: FanoutAbandonmentId,
        pending: MessageId,
    ) -> Result<Self, Error> {
        Ok(Self {
            source: state.source,
            session: state.session,
            role: state.role,
            batch,
            report,
            pending,
            progress: progress(state)?,
            epochs: state
                .epochs
                .values()
                .map(|t| Counts {
                    epoch: t.epoch,
                    sent: t.sent,
                    acknowledged: t.send_floor,
                })
                .collect(),
        })
    }
    pub(super) fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(b"QPABND01".to_vec());
        for value in [
            &self.source,
            &self.session,
            self.batch.as_bytes(),
            self.report.as_bytes(),
            self.pending.as_bytes(),
        ] {
            bytes.extend_from_slice(value);
        }
        bytes.push(self.role);
        for value in [
            self.progress.confirmed_epoch,
            self.progress.sending_epoch,
            self.progress.receiving_epoch,
        ] {
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        match self.progress.pending_epoch {
            None => bytes.push(0),
            Some(epoch) => {
                bytes.push(1);
                bytes.extend_from_slice(&epoch.to_be_bytes());
            }
        }
        bytes.push(self.epochs.len() as u8);
        for c in &self.epochs {
            for value in [c.epoch, c.sent, c.acknowledged] {
                bytes.extend_from_slice(&value.to_be_bytes());
            }
        }
        bytes
    }
    pub(in crate::durable::messages) fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut d = Decoder::new(bytes);
        if d.array::<8>()? != *b"QPABND01" {
            return Err(Error::Encoding);
        }
        let source = d.array()?;
        let session = d.array()?;
        crate::codec::nonzero(&source)?;
        crate::codec::nonzero(&session)?;
        let batch = FanoutId::from_trusted_state(d.array()?)?;
        let report = FanoutAbandonmentId::from_trusted_state(d.array()?)?;
        let pending = MessageId::from_trusted_state(d.array()?)?;
        let [role] = d.array()?;
        let confirmed_epoch = d.u64()?;
        let sending_epoch = d.u64()?;
        let receiving_epoch = d.u64()?;
        let pending_epoch = match d.array::<1>()? {
            [0] => None,
            [1] => Some(d.u64()?),
            _ => return Err(Error::Encoding),
        };
        let newest = sending_epoch.max(receiving_epoch);
        if newest == u64::MAX
            || confirmed_epoch > sending_epoch
            || confirmed_epoch > receiving_epoch
            || sending_epoch - confirmed_epoch > 1
            || receiving_epoch - confirmed_epoch > 1
            || pending_epoch.is_some_and(|p| confirmed_epoch.checked_add(1) != Some(p))
        {
            return Err(Error::Encoding);
        }
        let [count] = d.array()?;
        let first = first_retained_epoch(newest);
        if u64::from(count) != newest - first + 1 {
            return Err(Error::Encoding);
        }
        let mut epochs = Vec::with_capacity(usize::from(count));
        for expected in first..=newest {
            let epoch = d.u64()?;
            let sent = d.u64()?;
            let acknowledged = d.u64()?;
            if epoch != expected || sent == u64::MAX || acknowledged > sent {
                return Err(Error::Encoding);
            }
            epochs.push(Counts {
                epoch,
                sent,
                acknowledged,
            });
        }
        d.finish()?;
        let index = pending.check(&session, role)?;
        if pending.epoch()? != sending_epoch
            || !epochs
                .iter()
                .any(|c| c.epoch == sending_epoch && c.sent == index)
        {
            return Err(Error::Encoding);
        }
        Ok(Self {
            source,
            session,
            role,
            batch,
            report,
            pending,
            progress: RekeyProgress {
                confirmed_epoch,
                sending_epoch,
                receiving_epoch,
                pending_epoch,
            },
            epochs,
        })
    }
    pub(in crate::durable::messages) fn status(
        &self,
        id: MessageId,
    ) -> Result<MessageStatus, Error> {
        let index = id.check(&self.session, self.role)?;
        let epoch = id.epoch()?;
        let c = match self.epochs.iter().find(|c| c.epoch == epoch) {
            Some(c) => c,
            None if self.epochs.first().is_some_and(|c| epoch < c.epoch) => {
                return Err(Error::Retired)
            }
            None => return Ok(MessageStatus::Absent),
        };
        Ok(if id == self.pending {
            MessageStatus::ReservationAbandoned
        } else if index < c.acknowledged {
            MessageStatus::Acknowledged
        } else if index < c.sent {
            MessageStatus::DeliveryUnknown
        } else {
            MessageStatus::Absent
        })
    }
}
