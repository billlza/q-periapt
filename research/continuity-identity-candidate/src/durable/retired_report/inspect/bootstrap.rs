// SPDX-License-Identifier: Apache-2.0 OR MIT
use super::*;

impl Reader<'_> {
    pub(super) fn bootstrap(&mut self) -> Result<RecordMetadata, Error> {
        let operation = BootstrapOperationId::from_trusted_state(self.array()?)?;
        let context = self.array()?;
        // BootstrapRole's existing wire discriminants are 0/1. Session/member
        // roles in the same report grammar deliberately use 1/2 instead.
        let role = match self.byte()? {
            0 => crate::BootstrapRole::Initiator,
            1 => crate::BootstrapRole::Responder,
            _ => return Err(Error::Encoding),
        };
        let entry = BootstrapEntry {
            operation,
            context,
            role,
            status: self.phase()?,
        };
        let request = self.option(|r| InitiationId::from_trusted_state(r.array()?))?;
        let flights = BootstrapFlights {
            initial: self.option(Self::array)?,
            reply: self.option(Self::array)?,
            final_confirmation: self.option(Self::array)?,
            session: self.option(Self::array)?,
        };
        let cancellation = self.option(|r| {
            Ok(Box::new(BootstrapCancellation {
                entry: entry.clone(),
                previous: r.phase()?,
                report: r.array()?,
                initial_hash: flights.initial,
                reply_hash: flights.reply,
                final_hash: flights.final_confirmation,
                session: flights.session,
                one_time_claims: r.list(32, Self::array)?,
                inventory: r.list(34, |r| {
                    Ok(BootstrapPrekeyUse {
                        request: PrekeyId::from_trusted_state(r.array()?)?,
                        kind: LeafKind::decode(r.byte()?)?,
                        disposition: match r.byte()? {
                            1 => BootstrapPrekeyDisposition::AbandonedByCancellation,
                            2 => BootstrapPrekeyDisposition::AlreadyConsumed,
                            3 => BootstrapPrekeyDisposition::ReusableUnchanged,
                            _ => return Err(Error::Encoding),
                        },
                    })
                })?,
            }))
        })?;
        Ok(RecordMetadata::Bootstrap {
            entry,
            request,
            flights,
            cancellation,
        })
    }
    pub(super) fn fanout(&mut self) -> Result<RecordMetadata, Error> {
        let batch = FanoutId::from_trusted_state(self.array()?)?;
        let account = self.array()?;
        let roster = self.checkpoint()?;
        let status = match self.byte()? {
            1 => FanoutStatus::Reserved,
            2 => FanoutStatus::Committed,
            3 => FanoutStatus::Abandoning(FanoutAbandonmentId::from_trusted_state(self.array()?)?),
            4 => FanoutStatus::Abandoned(FanoutAbandonmentId::from_trusted_state(self.array()?)?),
            _ => return Err(Error::Encoding),
        };
        let members = self.list(155, |r| {
            let device = r.array()?;
            let generation = r.number()?;
            let credential = r.array()?;
            let context = r.array()?;
            let session = r.array()?;
            let role = r.session_role()?;
            let message = MessageId::from_trusted_state(r.array()?)?;
            let state = match r.byte()? {
                0 => MemberState::Reserved,
                1 => MemberState::Retained(FanoutMemberState::Committed),
                2 => MemberState::Retained(FanoutMemberState::Acknowledged),
                3 => MemberState::Retained(FanoutMemberState::ResolutionPending),
                4 => MemberState::Retained(FanoutMemberState::DeliveryUnknown),
                5 => MemberState::Retained(FanoutMemberState::HistoryRetired),
                6 => MemberState::Retained(FanoutMemberState::ReservationAbandoned),
                _ => return Err(Error::Encoding),
            };
            Ok(Member {
                device,
                generation,
                credential,
                context,
                session,
                role,
                message,
                state,
                ciphertext_digest: r.option(Self::array)?,
            })
        })?;
        Ok(RecordMetadata::Fanout {
            batch,
            account,
            roster,
            status,
            members,
        })
    }
}
