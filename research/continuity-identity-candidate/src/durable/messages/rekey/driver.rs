// SPDX-License-Identifier: Apache-2.0 OR MIT
//! One bounded control step per call, independent of application message traffic.
use super::*;

/// Exact committed, authority-checked control output. Dropping it does not undo
/// the journal transaction or acknowledge peer receipt.
pub struct RekeyControlMessage {
    target: u64,
    wire: Vec<u8>,
}
impl RekeyControlMessage {
    /// Epoch requested by or installed through this control exchange.
    pub fn target_epoch(&self) -> u64 {
        self.target
    }
    /// Send these exact public bytes; retries must not synthesize replacement work.
    pub fn as_bytes(&self) -> &[u8] {
        &self.wire
    }
}

/// One exact control result. Local completion is not peer receipt or PQ recovery.
pub enum RekeyControlStep {
    /// Dispatch the committed output through the independent control transport.
    Output(RekeyControlMessage),
    /// This exact target completed locally; no new target was implicitly started.
    LocallyConfirmed(u64),
}
fn output(wire: Vec<u8>) -> Result<RekeyControlStep, DurableError> {
    Ok(RekeyControlStep::Output(RekeyControlMessage {
        target: target(open_envelope(&wire)?.0)?,
        wire,
    }))
}
pub(super) fn target(body: &[u8]) -> Result<u64, Error> {
    let target = u64::from_be_bytes(
        body.get(112..120)
            .ok_or(Error::Encoding)?
            .try_into()
            .map_err(|_| Error::Encoding)?,
    );
    crate::codec::generation(target)?;
    Ok(target)
}

enum Work {
    Offer,
    Request,
    Receive(Vec<u8>),
}
impl DeviceJournal {
    /// Start/resume one explicit target without dummy application traffic. Each
    /// call executes at most one existing flight preparation and returns at most
    /// one bounded output. The host bounds transport retries and deadlines; it
    /// keeps servicing incoming control after local completion. Cancellation stops
    /// dispatch, never resets a pending target, and recovery uses this same target.
    pub fn advance_rekey_control(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
        target: u64,
        signer: &DeviceSigningKey,
        now: u64,
    ) -> Result<RekeyControlStep, DurableError> {
        let image = self.image()?;
        let state = self.message_state(&image, context, &session, now)?;
        crate::codec::generation(target)?;
        if target == state.control.epoch {
            let last = state.control.last.as_ref().ok_or(Error::State)?;
            self.check_completed(context, last)?;
            self.check_context_release(&image, context, now)?;
            return Ok(RekeyControlStep::LocallyConfirmed(target));
        }
        if target != state.control.target()? {
            return Err(if target < state.control.epoch {
                Error::Retired
            } else {
                Error::Scope
            }
            .into());
        }
        let work = match &state.control.plan {
            Some(Plan::Response(plan)) => Work::Receive(plan.offer.clone()),
            Some(Plan::Completing(plan)) => Work::Receive(plan.resume_input().to_vec()),
            Some(Plan::Key(_) | Plan::Signing { .. } | Plan::Ready { .. }) => Work::Offer,
            None if state.role == proposer(target)? => Work::Offer,
            None => Work::Request,
        };
        match work {
            Work::Offer => output(self.prepare_rekey_offer(context, session, signer, now)?),
            Work::Request => output(self.prepare_rekey_request(context, session, signer, now)?),
            Work::Receive(wire) => self.receive_rekey_control(context, session, &wire, signer, now),
        }
    }

    /// Authenticate and process one independent control input using the existing
    /// exact-flight transactions. Unknown tags, invalid signatures and stale
    /// authority fail explicitly; an accepted receipt produces no extra flight.
    pub fn receive_rekey_control(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
        wire: &[u8],
        signer: &DeviceSigningKey,
        now: u64,
    ) -> Result<RekeyControlStep, DurableError> {
        let (body, _) = open_envelope(wire)?;
        let tag = body.get(..8).ok_or(Error::Encoding)?;
        if tag == request::TAG {
            output(self.respond_rekey_request(context, session, wire, signer, now)?)
        } else if tag == TAG {
            output(self.respond_rekey_offer(context, session, wire, signer, now)?)
        } else if tag == response::TAG {
            output(self.accept_rekey_response(context, session, wire, signer, now)?)
        } else if tag == completion::FINAL_TAG {
            output(self.finish_rekey(context, session, wire, signer, now)?)
        } else if tag == completion::RECEIPT_TAG {
            Ok(RekeyControlStep::LocallyConfirmed(
                self.accept_rekey_receipt(context, session, wire, now)?,
            ))
        } else {
            Err(Error::Encoding.into())
        }
    }
}
