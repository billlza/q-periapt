// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Current-signer evidence over unchanged original command identities.
use super::*;
use crate::{
    AnchorHandoffClientAuthorizationReceipt, AnchorHandoffHistory, HistoricalAnchorHandoffAdoption,
};
pub(crate) const REQUEST_BYTES: usize = 3674 + 128;
pub(crate) const REPLY_BYTES: usize = 3659 + 128;
pub(crate) fn reply_width(request: usize) -> Option<usize> {
    match request {
        3674 => Some(3659),
        REQUEST_BYTES => Some(REPLY_BYTES),
        _ => None,
    }
}

/// Verified provenance of a transferred reply. The logical authority identifies
/// original commands; the current authority actually signed this distinct wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchorHandoffReplyContext {
    namespace: [u8; 32],
    logical: [u8; 32],
    current: [u8; 32],
    history: [u8; 32],
    authorization: [u8; 32],
}
impl AnchorHandoffReplyContext {
    /// Immutable subject namespace inherited from the independently pinned origin.
    pub fn namespace_binding(&self) -> [u8; 32] {
        self.namespace
    }
    /// Original authority used to derive unchanged command identities.
    pub fn logical_witness_binding(&self) -> [u8; 32] {
        self.logical
    }
    /// Current witness that actually signed this distinct reply format.
    pub fn current_witness_binding(&self) -> [u8; 32] {
        self.current
    }
    /// Exact independently verified authority-history checkpoint.
    pub fn history_checkpoint(&self) -> [u8; 32] {
        self.history
    }
    /// Commitment to the exact retained target client-authorization receipt.
    pub fn authorization_digest(&self) -> [u8; 32] {
        self.authorization
    }
    pub(crate) fn verified(
        approved: &HistoricalAnchorHandoffAdoption,
        history: &AnchorHandoffHistory,
        receipt: &[u8],
    ) -> Result<Self, Error> {
        AnchorHandoffClientAuthorizationReceipt::verify(receipt, approved, history)?;
        let scope = approved.scope();
        Ok(Self {
            namespace: scope.namespace,
            logical: scope.logical,
            current: scope.successor,
            history: scope.history,
            authorization: digest(b"Q-PERIAPT-TRANSFERRED-WITNESS-AUTHORIZATION/v1", receipt),
        })
    }
    fn encode(self, out: &mut Vec<u8>) {
        for value in [
            self.namespace,
            self.logical,
            self.current,
            self.history,
            self.authorization,
        ] {
            out.extend_from_slice(&value);
        }
    }
    fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        let mut next = || {
            let v = d.array()?;
            nonzero(&v)?;
            Ok::<_, Error>(v)
        };
        Ok(Self {
            namespace: next()?,
            logical: next()?,
            current: next()?,
            history: next()?,
            authorization: next()?,
        })
    }
}
#[derive(Clone)]
pub(crate) struct Authority {
    pub(crate) context: AnchorHandoffReplyContext,
    pub(crate) logical: AnchorPin,
    current: AnchorPin,
    subject: AnchorSubject,
    selection_request: [u8; 32],
}
impl Authority {
    pub(crate) fn verified(
        approved: &HistoricalAnchorHandoffAdoption,
        history: &AnchorHandoffHistory,
        receipt: &[u8],
        request: &[u8],
    ) -> Result<Self, Error> {
        let context = AnchorHandoffReplyContext::verified(approved, history, receipt)?;
        Ok(Self {
            context,
            logical: history.historical_pin(context.logical)?.clone(),
            current: history.current_pin().clone(),
            subject: approved.scope().subject(),
            selection_request: digest(b"Q-PERIAPT-JOURNAL-WITNESS-SELECTION/v1", request),
        })
    }
    pub(crate) fn current(&self) -> &AnchorPin {
        &self.current
    }
    pub(crate) fn check_selection(&self, request: &[u8], receipt: &[u8]) -> Result<(), Error> {
        if self.selection_request != digest(b"Q-PERIAPT-JOURNAL-WITNESS-SELECTION/v1", request)
            || self.context.authorization
                != digest(b"Q-PERIAPT-TRANSFERRED-WITNESS-AUTHORIZATION/v1", receipt)
        {
            return Err(Error::Scope);
        }
        Ok(())
    }
    pub(crate) fn request(
        &self,
        subject: AnchorSubject,
        operation: AnchorOperation,
        signer: &DeviceSigningKey,
    ) -> Result<Request, Error> {
        if subject != self.subject
            || signer.public_key()?.shares_component(&self.current.key)
            || signer.public_key()?.shares_component(&self.logical.key)
        {
            return Err(Error::Scope);
        }
        let command = command_id(&self.context.logical, subject, operation);
        let mut challenge = [0; 32];
        getrandom::fill(&mut challenge).map_err(|_| Error::Entropy)?;
        nonzero(&challenge)?;
        let mut body = b"QPATRQ01".to_vec();
        self.context.encode(&mut body);
        subject.encode(&mut body);
        body.extend_from_slice(&command);
        body.extend_from_slice(&challenge);
        operation.encode(&mut body);
        let wire = envelope(
            &body,
            &signer.sign(Purpose::AnchorTransferredRequest, &body)?,
        )?;
        if wire.len() != REQUEST_BYTES {
            return Err(Error::Encoding);
        }
        Ok(Request {
            context: self.context,
            subject,
            operation,
            command,
            attempt: attempt_id(&body),
            wire,
            closed: AtomicBool::new(false),
        })
    }
    pub(crate) fn verify(&self, request: &Request, wire: &[u8]) -> Result<AnchorReply, Error> {
        if request.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        if request.context != self.context
            || request.subject != self.subject
            || wire.len() != REPLY_BYTES
        {
            return Err(Error::Scope);
        }
        let (body, signature) = open_envelope(wire)?;
        self.current
            .key
            .verify(Purpose::AnchorTransferredReply, body, signature)?;
        let mut d = Decoder::new(body);
        if d.array::<8>()? != *b"QPATRS01"
            || AnchorHandoffReplyContext::decode(&mut d)? != self.context
            || AnchorSubject::decode(&mut d)? != request.subject
            || d.array::<32>()? != request.attempt
            || d.array::<32>()? != request.command
        {
            return Err(Error::Scope);
        }
        let outcome = reply_checks::decode_outcome(&mut d)?;
        let head = AnchorHead::decode(&mut d)?;
        let last = decode_last(&mut d, head)?;
        d.finish()?;
        reply_checks::validate(request.operation, request.command, outcome, head, last)?;
        request
            .closed
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::Closed)?;
        Ok(AnchorReply {
            handoff: Some(self.context),
            authority: self.context.logical,
            subject: request.subject,
            operation: request.operation,
            outcome,
            head,
            command: request.command,
            last,
        })
    }
}
pub(crate) struct Request {
    context: AnchorHandoffReplyContext,
    subject: AnchorSubject,
    operation: AnchorOperation,
    command: [u8; 32],
    attempt: [u8; 32],
    wire: Vec<u8>,
    closed: AtomicBool,
}
impl Request {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.wire
    }
}
fn attempt_id(body: &[u8]) -> [u8; 32] {
    digest(b"Q-PERIAPT-TRANSFERRED-WITNESS-REQUEST/v1", body)
}
pub(crate) fn is_request(wire: &[u8]) -> bool {
    wire.len() == REQUEST_BYTES && wire.get(4..12) == Some(b"QPATRQ01".as_slice())
}
pub(super) struct Parsed<'a> {
    pub(super) context: AnchorHandoffReplyContext,
    pub(super) request: Incoming<'a>,
}
pub(super) fn incoming<'a>(current: &AnchorPin, wire: &'a [u8]) -> Result<Parsed<'a>, Error> {
    if !is_request(wire) {
        return Err(Error::Encoding);
    }
    let (body, signature) = open_envelope(wire)?;
    let mut d = Decoder::new(body);
    d.take(8)?;
    let context = AnchorHandoffReplyContext::decode(&mut d)?;
    if context.current != current.binding {
        return Err(Error::Scope);
    }
    let subject = AnchorSubject::decode(&mut d)?;
    let command = d.array()?;
    nonzero(&d.array::<32>()?)?;
    let operation = AnchorOperation::decode(&mut d)?;
    d.finish()?;
    if command != command_id(&context.logical, subject, operation) {
        return Err(Error::Scope);
    }
    Ok(Parsed {
        context,
        request: Incoming {
            subject,
            operation,
            command,
            attempt: attempt_id(body),
            body,
            signature,
        },
    })
}
pub(super) fn reply(
    pin: &AnchorPin,
    signer: &AnchorSigningKey,
    parsed: &Parsed<'_>,
    outcome: AnchorOutcome,
    head: AnchorHead,
    last: Option<[u8; 32]>,
) -> Result<Vec<u8>, Error> {
    if pin.binding != parsed.context.current || signer.public_key()? != pin.key {
        return Err(Error::Scope);
    }
    let mut body = b"QPATRS01".to_vec();
    parsed.context.encode(&mut body);
    parsed.request.subject.encode(&mut body);
    body.extend_from_slice(&parsed.request.attempt);
    body.extend_from_slice(&parsed.request.command);
    body.push(outcome as u8);
    head.encode(&mut body);
    encode_last(last, &mut body);
    envelope(&body, &signer.sign(Purpose::AnchorTransferredReply, &body)?)
}
