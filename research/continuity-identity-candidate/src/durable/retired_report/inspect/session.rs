// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

impl Reader<'_> {
    pub(super) fn session_role(&mut self) -> Result<u8, Error> {
        match self.byte()? {
            value @ (1 | 2) => Ok(value),
            _ => Err(Error::Encoding),
        }
    }
    pub(super) fn session(&mut self) -> Result<Session, Error> {
        let source = BootstrapOperationId::from_trusted_state(self.array()?)?;
        let session = self.array()?;
        let role = self.session_role()?;
        let peer_account = self.array()?;
        let peer_device = self.array()?;
        let peer_generation = self.number()?;
        let progress = RekeyProgress {
            confirmed_epoch: self.number()?,
            sending_epoch: self.number()?,
            receiving_epoch: self.number()?,
            pending_epoch: self.option(Self::number)?,
        };
        let state = match self.byte()? {
            1 => {
                let previous_closure =
                    self.option(|r| SessionClosureId::from_trusted_state(r.array()?))?;
                SessionState::Live {
                    previous_closure,
                    epochs: self.list(76, Self::epoch)?,
                }
            }
            2 => SessionState::Terminal {
                report: self.array()?,
                batch: self.option(|r| FanoutId::from_trusted_state(r.array()?))?,
                pending: self.option(|r| MessageId::from_trusted_state(r.array()?))?,
                epochs: self.list(25, |r| {
                    Ok(TerminalEpoch {
                        epoch: r.number()?,
                        sent: r.number()?,
                        acknowledged: r.number()?,
                        reservation_abandoned: r.boolean()?,
                    })
                })?,
            },
            _ => return Err(Error::Encoding),
        };
        Ok(Session {
            source,
            session,
            role,
            peer_account,
            peer_device,
            peer_generation,
            progress,
            state,
        })
    }
    fn epoch(&mut self) -> Result<Epoch, Error> {
        let epoch = self.number()?;
        let acknowledged_before = self.number()?;
        let sent = self.number()?;
        let consumed_before = self.number()?;
        let received = self.number()?;
        let peer_sent = self.option(Self::number)?;
        let resolution = match self.byte()? {
            0 => EpochResolutionStatus::Unrequested,
            1 => EpochResolutionStatus::Pending(EpochResolutionId::from_trusted_state(
                self.array()?,
            )?),
            2 => EpochResolutionStatus::Acknowledged(EpochResolutionId::from_trusted_state(
                self.array()?,
            )?),
            _ => return Err(Error::Encoding),
        };
        let unconfirmed = self.list(64, |r| {
            Ok(UnconfirmedMessage::from_recorded_metadata(
                MessageId::from_trusted_state(r.array()?)?,
                r.array()?,
            ))
        })?;
        let deliveries = self.list(48, |r| {
            Ok(AbandonedDelivery {
                message: MessageId::from_trusted_state(r.array()?)?,
                index: r.number()?,
                plaintext_bytes: r.size()?,
            })
        })?;
        let skipped = self.list(8, Self::number)?;
        let consumed_out_of_order = self.list(40, |r| {
            Ok(ConsumedDelivery {
                message: MessageId::from_trusted_state(r.array()?)?,
                index: r.number()?,
            })
        })?;
        let reservation = self.option(|r| {
            Ok(Reservation {
                input: ReservedAbandonment {
                    message: MessageId::from_trusted_state(r.array()?)?,
                    plaintext_bytes: r.size()?,
                    associated_data_bytes: r.size()?,
                },
                fanout: r.option(|r| FanoutId::from_trusted_state(r.array()?))?,
            })
        })?;
        let send_closed = self.boolean()?;
        Ok(Epoch {
            accounting: AbandonedEpoch {
                epoch,
                acknowledged_before,
                sent,
                consumed_before,
                received,
                peer_sent,
                resolution,
                unconfirmed,
                deliveries,
                skipped,
            },
            consumed_out_of_order,
            reservation,
            send_closed,
        })
    }
}
