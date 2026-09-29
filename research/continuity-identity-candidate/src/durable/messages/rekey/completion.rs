// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Durable identity-authenticated cutovers and exact final/receipt outboxes.
use super::*;
use hmac::{Hmac, Mac};
use q_periapt_sdk::Ciphertext;

const FINAL_TAG: &[u8; 8] = b"QPRKFN01";
const RECEIPT_TAG: &[u8; 8] = b"QPRKRC01";
const FINAL_CORE: usize = 153 + 32 + 32 + 8;
const RECEIPT_CORE: usize = FINAL_CORE + 32;
const FINAL_BODY: usize = FINAL_CORE + 32;
const RECEIPT_BODY: usize = RECEIPT_CORE + 32;
const FINAL_WIRE: usize = 4 + FINAL_BODY + SIGNATURE_BYTES;
const RECEIPT_WIRE: usize = 4 + RECEIPT_BODY + SIGNATURE_BYTES;

/// Exact signed control flight retained by the journal, selected by target epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RekeyFlight {
    /// Designated proposer public key and identity proof.
    Offer,
    /// Responder encapsulation, key confirmation and identity proof.
    Response,
    /// Proposer key confirmation and authenticated old sending-chain length.
    Final,
    /// Responder completion and authenticated old sending-chain length.
    Receipt,
}
impl RekeyFlight {
    fn purpose(self) -> Purpose {
        match self {
            Self::Offer => Purpose::RekeyOffer,
            Self::Response => Purpose::RekeyResponse,
            Self::Final => Purpose::RekeyFinal,
            Self::Receipt => Purpose::RekeyReceipt,
        }
    }
    fn role(self, target: u64) -> Result<u8, Error> {
        let role = proposer(target)?;
        Ok(if matches!(self, Self::Offer | Self::Final) {
            role
        } else {
            3 - role
        })
    }
}
/// Observed local progress, not a statement about an adversary's key knowledge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RekeyProgress {
    /// Highest locally completed, transcript-bound rekey exchange.
    pub confirmed_epoch: u64,
    /// Key epoch used for new outgoing application messages.
    pub sending_epoch: u64,
    /// Highest key epoch admitted for incoming application messages.
    pub receiving_epoch: u64,
    /// Target of the retained in-progress control exchange, if one exists.
    pub pending_epoch: Option<u64>,
}

enum Step {
    FinalSigning {
        root: ZeroizingBytes<32>,
        body: Vec<u8>,
        signing: SigningReservation,
    },
    FinalReady {
        wire: Vec<u8>,
    },
    ReceiptSigning {
        final_wire: Vec<u8>,
        root: ZeroizingBytes<32>,
        body: Vec<u8>,
        signing: SigningReservation,
    },
}
pub(super) struct Plan {
    offer: Vec<u8>,
    response: Vec<u8>,
    step: Step,
}
impl Plan {
    pub(super) fn phase(&self) -> u8 {
        match self.step {
            Step::FinalSigning { .. } => 7,
            Step::FinalReady { .. } => 8,
            Step::ReceiptSigning { .. } => 9,
        }
    }
    pub(super) fn send_fenced(&self) -> bool {
        !matches!(self.step, Step::FinalReady { .. })
    }
    pub(super) fn offer_status(&self) -> RekeyOfferStatus {
        if matches!(self.step, Step::ReceiptSigning { .. }) {
            RekeyOfferStatus::Absent
        } else {
            RekeyOfferStatus::Committed
        }
    }
    pub(super) fn response_status(&self) -> RekeyResponseStatus {
        if matches!(self.step, Step::ReceiptSigning { .. }) {
            RekeyResponseStatus::Committed
        } else {
            RekeyResponseStatus::Absent
        }
    }
    pub(super) fn inputs(&self) -> (&[u8], &[u8]) {
        (&self.offer, &self.response)
    }
    pub(super) fn encode(&self, bytes: &mut Zeroizing<Vec<u8>>) {
        bytes.extend_from_slice(&self.offer);
        bytes.extend_from_slice(&self.response);
        match &self.step {
            Step::FinalSigning {
                root,
                body,
                signing,
            } => {
                bytes.extend_from_slice(root.as_bytes());
                bytes.extend_from_slice(body);
                signing.encode(bytes);
            }
            Step::FinalReady { wire } => bytes.extend_from_slice(wire),
            Step::ReceiptSigning {
                final_wire,
                root,
                body,
                signing,
            } => {
                bytes.extend_from_slice(final_wire);
                bytes.extend_from_slice(root.as_bytes());
                bytes.extend_from_slice(body);
                signing.encode(bytes);
            }
        }
    }
    pub(super) fn decode(d: &mut Decoder<'_>, phase: u8) -> Result<Self, Error> {
        let offer = d.take(WIRE_LEN)?.to_vec();
        let response = d.take(response::RESPONSE_WIRE_LEN)?.to_vec();
        let step = match phase {
            7 => Step::FinalSigning {
                root: key(d.take(32)?)?,
                body: d.take(FINAL_BODY)?.to_vec(),
                signing: SigningReservation::decode(d.take(64)?)?,
            },
            8 => Step::FinalReady {
                wire: d.take(FINAL_WIRE)?.to_vec(),
            },
            9 => Step::ReceiptSigning {
                final_wire: d.take(FINAL_WIRE)?.to_vec(),
                root: key(d.take(32)?)?,
                body: d.take(RECEIPT_BODY)?.to_vec(),
                signing: SigningReservation::decode(d.take(64)?)?,
            },
            _ => return Err(Error::Encoding),
        };
        Ok(Self {
            offer,
            response,
            step,
        })
    }
    pub(super) fn validate(
        &self,
        control: &Control,
        session: &[u8; 32],
        role: u8,
        context: &[u8; 32],
        active_root: &ZeroizingBytes<32>,
    ) -> Result<(), Error> {
        let root = match &self.step {
            Step::FinalSigning { root, .. } | Step::ReceiptSigning { root, .. } => root,
            Step::FinalReady { .. } => active_root,
        };
        let (offer_body, _) = open_envelope(&self.offer)?;
        control.check_body(session, context, offer_body)?;
        let (response_body, _) = open_envelope(&self.response)?;
        response::check_body(
            &response::prefix(control, session, context, &self.offer)?,
            response_body,
            root,
        )?;
        let expected = proposer(control.target()?)?;
        match &self.step {
            Step::FinalSigning { body, .. } => {
                if role != expected {
                    return Err(Error::Scope);
                }
                verify_control_body(
                    control,
                    session,
                    context,
                    &self.offer,
                    &self.response,
                    None,
                    (body, root),
                )?;
            }
            Step::FinalReady { wire } => {
                if role != expected {
                    return Err(Error::Scope);
                }
                verify_control_body(
                    control,
                    session,
                    context,
                    &self.offer,
                    &self.response,
                    None,
                    (open_envelope(wire)?.0, root),
                )?;
            }
            Step::ReceiptSigning {
                final_wire, body, ..
            } => {
                if role == expected {
                    return Err(Error::Scope);
                }
                verify_control_body(
                    control,
                    session,
                    context,
                    &self.offer,
                    &self.response,
                    None,
                    (open_envelope(final_wire)?.0, root),
                )?;
                verify_control_body(
                    control,
                    session,
                    context,
                    &self.offer,
                    &self.response,
                    Some(final_wire),
                    (body, root),
                )?;
            }
        }
        Ok(())
    }
    fn outbox(&self, flight: RekeyFlight) -> Option<&[u8]> {
        match flight {
            RekeyFlight::Offer => Some(&self.offer),
            RekeyFlight::Response => Some(&self.response),
            RekeyFlight::Final => match &self.step {
                Step::FinalReady { wire } => Some(wire),
                Step::ReceiptSigning { final_wire, .. } => Some(final_wire),
                _ => None,
            },
            RekeyFlight::Receipt => None,
        }
    }
}

pub(super) struct Completed {
    pub(super) offer: Vec<u8>,
    pub(super) response: Vec<u8>,
    final_wire: Vec<u8>,
    receipt: Vec<u8>,
}
impl Completed {
    pub(super) fn encode(&self, bytes: &mut Zeroizing<Vec<u8>>) {
        for wire in [&self.offer, &self.response, &self.final_wire, &self.receipt] {
            bytes.extend_from_slice(wire);
        }
    }
    pub(super) fn decode(d: &mut Decoder<'_>) -> Result<Self, Error> {
        Ok(Self {
            offer: d.take(WIRE_LEN)?.to_vec(),
            response: d.take(response::RESPONSE_WIRE_LEN)?.to_vec(),
            final_wire: d.take(FINAL_WIRE)?.to_vec(),
            receipt: d.take(RECEIPT_WIRE)?.to_vec(),
        })
    }
    pub(super) fn digest(&self) -> [u8; 32] {
        hash(
            b"completed-epoch",
            &[
                self.offer.as_slice(),
                &self.response,
                &self.final_wire,
                &self.receipt,
            ]
            .concat(),
        )
    }
    pub(super) fn validate(
        &self,
        session: &[u8; 32],
        context: &[u8; 32],
        epoch: u64,
    ) -> Result<(), Error> {
        crate::codec::generation(epoch)?;
        let (offer, _) = open_envelope(&self.offer)?;
        let parent = offer
            .get(121..153)
            .ok_or(Error::Encoding)?
            .try_into()
            .map_err(|_| Error::Encoding)?;
        let prior = Control {
            epoch: epoch - 1,
            parent,
            plan: None,
            last: None,
        };
        if epoch == 1 && parent != genesis(session, context) {
            return Err(Error::Scope);
        }
        prior.check_body(session, context, offer)?;
        let (reply, _) = open_envelope(&self.response)?;
        if reply.len() != response::RESPONSE_BODY_LEN
            || !reply.starts_with(&response::prefix(&prior, session, context, &self.offer)?)
        {
            return Err(Error::Scope);
        }
        Ciphertext::from_bytes(
            reply
                .get(response::PREFIX_LEN..response::CORE_LEN)
                .ok_or(Error::Encoding)?,
        )?;
        structural_control(
            &prior,
            session,
            context,
            &self.offer,
            &self.response,
            None,
            open_envelope(&self.final_wire)?.0,
        )?;
        structural_control(
            &prior,
            session,
            context,
            &self.offer,
            &self.response,
            Some(&self.final_wire),
            open_envelope(&self.receipt)?.0,
        )?;
        Ok(())
    }
    pub(super) fn verify_public(&self, context: &BootstrapContext) -> Result<(), Error> {
        let (body, _) = open_envelope(&self.offer)?;
        let target = u64::from_be_bytes(
            body.get(112..120)
                .ok_or(Error::Encoding)?
                .try_into()
                .map_err(|_| Error::Encoding)?,
        );
        for flight in [
            RekeyFlight::Offer,
            RekeyFlight::Response,
            RekeyFlight::Final,
            RekeyFlight::Receipt,
        ] {
            verify_wire(context, target, flight, self.outbox(flight))?;
        }
        Ok(())
    }
    fn outbox(&self, flight: RekeyFlight) -> &[u8] {
        match flight {
            RekeyFlight::Offer => &self.offer,
            RekeyFlight::Response => &self.response,
            RekeyFlight::Final => &self.final_wire,
            RekeyFlight::Receipt => &self.receipt,
        }
    }
}

fn verify_wire(
    context: &BootstrapContext,
    target: u64,
    flight: RekeyFlight,
    wire: &[u8],
) -> Result<(), Error> {
    let (body, signature) = open_envelope(wire)?;
    device(context, flight.role(target)?)?
        .key
        .verify(flight.purpose(), body, signature)?;
    check_closing_budget(
        body,
        flight,
        context.policy().application_send_budget().messages(),
    )
}
fn check_closing_budget(body: &[u8], flight: RekeyFlight, limit: u16) -> Result<(), Error> {
    let closing_core = match flight {
        RekeyFlight::Final => Some(FINAL_CORE),
        RekeyFlight::Receipt => Some(RECEIPT_CORE),
        RekeyFlight::Offer | RekeyFlight::Response => None,
    };
    if let Some(core) = closing_core {
        let closing = u64::from_be_bytes(
            body.get(core - 8..core)
                .ok_or(Error::Encoding)?
                .try_into()
                .map_err(|_| Error::Encoding)?,
        );
        if closing > u64::from(limit) {
            return Err(Error::PolicyDenied);
        }
    }
    Ok(())
}
fn core_prefix(
    control: &Control,
    session: &[u8; 32],
    context: &[u8; 32],
    offer: &[u8],
    reply: &[u8],
    final_wire: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let mut out = control.prefix(session, context)?;
    out.get_mut(..8)
        .ok_or(Error::Encoding)?
        .copy_from_slice(if final_wire.is_some() {
            RECEIPT_TAG
        } else {
            FINAL_TAG
        });
    if final_wire.is_some() {
        *out.get_mut(120).ok_or(Error::Encoding)? = 3 - proposer(control.target()?)?;
    }
    out.extend_from_slice(&hash(b"offer-wire", offer));
    out.extend_from_slice(&hash(b"response-wire", reply));
    if let Some(wire) = final_wire {
        out.extend_from_slice(&hash(b"final-wire", wire));
    }
    Ok(out)
}
fn control_mac(
    root: &ZeroizingBytes<32>,
    receipt: bool,
    core: &[u8],
) -> Result<Hmac<Sha256>, Error> {
    let label = if receipt {
        b"receipt".as_slice()
    } else {
        b"final".as_slice()
    };
    let mut secret = ZeroizingBytes::<32>::zeroed();
    Hkdf::<Sha256>::new(None, root.as_bytes())
        .expand(
            &[DOMAIN, label, b"-confirmation"].concat(),
            secret.as_mut_bytes(),
        )
        .map_err(|_| Error::Provider)?;
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(secret.as_bytes())
        .map_err(|_| Error::Provider)?;
    mac.update(&hash(&[label, b"-core"].concat(), core));
    Ok(mac)
}
fn make_body(
    mut prefix: Vec<u8>,
    closing: u64,
    root: &ZeroizingBytes<32>,
    receipt: bool,
) -> Result<Vec<u8>, Error> {
    prefix.extend_from_slice(&closing.to_be_bytes());
    let tag = control_mac(root, receipt, &prefix)?.finalize().into_bytes();
    prefix.extend_from_slice(&tag);
    Ok(prefix)
}
fn structural_control(
    control: &Control,
    session: &[u8; 32],
    context: &[u8; 32],
    offer: &[u8],
    reply: &[u8],
    final_wire: Option<&[u8]>,
    body: &[u8],
) -> Result<u64, Error> {
    let prefix = core_prefix(control, session, context, offer, reply, final_wire)?;
    let core = if final_wire.is_some() {
        RECEIPT_CORE
    } else {
        FINAL_CORE
    };
    if body.len() != core + 32 || !body.starts_with(&prefix) {
        return Err(Error::Scope);
    }
    Ok(u64::from_be_bytes(
        body.get(core - 8..core)
            .ok_or(Error::Encoding)?
            .try_into()
            .map_err(|_| Error::Encoding)?,
    ))
}
fn verify_control_body(
    control: &Control,
    session: &[u8; 32],
    context: &[u8; 32],
    offer: &[u8],
    reply: &[u8],
    final_wire: Option<&[u8]>,
    authenticated: (&[u8], &ZeroizingBytes<32>),
) -> Result<u64, Error> {
    let (body, root) = authenticated;
    let closing = structural_control(control, session, context, offer, reply, final_wire, body)?;
    let core = body.len() - 32;
    control_mac(
        root,
        final_wire.is_some(),
        body.get(..core).ok_or(Error::Encoding)?,
    )?
    .verify_slice(body.get(core..).ok_or(Error::Encoding)?)
    .map_err(|_| Error::Authentication)?;
    Ok(closing)
}
fn signing_scope(journal: &[u8; 32], body: &[u8]) -> [u8; 32] {
    hash(b"cutover-signing", &[journal.as_slice(), body].concat())
}

impl Control {
    pub(in super::super) fn validate_cutovers(
        &self,
        state: &State,
        context: &[u8; 32],
    ) -> Result<(), Error> {
        if let Some(super::Plan::Completing(plan)) = &self.plan {
            let (body, final_wire) = match &plan.step {
                Step::FinalSigning { body, .. } => (body.as_slice(), None),
                Step::FinalReady { wire } => (open_envelope(wire)?.0, None),
                Step::ReceiptSigning {
                    body, final_wire, ..
                } => (body.as_slice(), Some(final_wire.as_slice())),
            };
            let closing = structural_control(
                self,
                &state.session,
                context,
                &plan.offer,
                &plan.response,
                final_wire,
                body,
            )?;
            let old = state.traffic(self.epoch)?;
            if old.sent != closing || old.pending.is_some() {
                return Err(Error::State);
            }
        }
        if let Some(last) = &self.last {
            let old = state.traffic(self.epoch - 1)?;
            let final_body = open_envelope(&last.final_wire)?.0;
            let receipt_body = open_envelope(&last.receipt)?.0;
            let final_count = u64::from_be_bytes(
                final_body
                    .get(FINAL_CORE - 8..FINAL_CORE)
                    .ok_or(Error::Encoding)?
                    .try_into()
                    .map_err(|_| Error::Encoding)?,
            );
            let receipt_count = u64::from_be_bytes(
                receipt_body
                    .get(RECEIPT_CORE - 8..RECEIPT_CORE)
                    .ok_or(Error::Encoding)?
                    .try_into()
                    .map_err(|_| Error::Encoding)?,
            );
            let (own, peer) = if state.role == proposer(self.epoch)? {
                (final_count, receipt_count)
            } else {
                (receipt_count, final_count)
            };
            if old.sent != own || old.receive_limit != Some(peer) {
                return Err(Error::State);
            }
        }
        Ok(())
    }
    pub(in super::super) fn validate_epochs(
        &self,
        send: u64,
        receive: u64,
        count: usize,
    ) -> Result<(), Error> {
        let expected = if matches!(
            &self.plan,
            Some(super::Plan::Completing(Plan {
                step: Step::FinalReady { .. },
                ..
            }))
        ) {
            (self.target()?, self.epoch)
        } else {
            (self.epoch, self.epoch)
        };
        let newest = send.max(receive);
        if (send, receive) != expected || count as u64 != newest - first_retained_epoch(newest) + 1
        {
            return Err(Error::State);
        }
        Ok(())
    }
    pub(in super::super) fn validate_budget(&self, limit: u16) -> Result<(), Error> {
        if let Some(last) = &self.last {
            for flight in [RekeyFlight::Final, RekeyFlight::Receipt] {
                check_closing_budget(open_envelope(last.outbox(flight))?.0, flight, limit)?;
            }
        }
        if let Some(super::Plan::Completing(plan)) = &self.plan {
            match &plan.step {
                Step::FinalSigning { body, .. } => {
                    check_closing_budget(body, RekeyFlight::Final, limit)?
                }
                Step::FinalReady { wire } => {
                    check_closing_budget(open_envelope(wire)?.0, RekeyFlight::Final, limit)?
                }
                Step::ReceiptSigning {
                    final_wire, body, ..
                } => {
                    check_closing_budget(open_envelope(final_wire)?.0, RekeyFlight::Final, limit)?;
                    check_closing_budget(body, RekeyFlight::Receipt, limit)?;
                }
            }
        }
        Ok(())
    }
}
impl State {
    pub(super) fn admit_history_retirement(&self) -> Result<(), DurableError> {
        let first = first_retained_epoch(self.control.target()?);
        if self
            .epochs
            .range(..first)
            .any(|(_, traffic)| !traffic.can_retire())
        {
            return Err(DurableError::Capacity);
        }
        Ok(())
    }
    fn admit_cutover(&self) -> Result<(), DurableError> {
        self.admit_history_retirement()?;
        if self.traffic(self.send_epoch)?.pending.is_some() {
            return Err(DurableError::Suspended);
        }
        Ok(())
    }
    fn add_epoch(
        &mut self,
        context: &[u8; 32],
        root: &ZeroizingBytes<32>,
        offer: &[u8],
        reply: &[u8],
    ) -> Result<(), Error> {
        let target = self.control.target()?;
        let first = first_retained_epoch(target);
        if self.epochs.contains_key(&target)
            || self
                .epochs
                .range(..first)
                .any(|(_, traffic)| !traffic.can_retire())
            || self.epochs.range(first..).count() >= MAX_TRAFFIC_EPOCHS
        {
            return Err(Error::Capacity);
        }
        let mut material = ZeroizingBytes::<128>::zeroed();
        let mut info = [DOMAIN, b"epoch-traffic/HKDF-SHA256/ChaCha20Poly1305/"].concat();
        info.extend_from_slice(context);
        info.extend_from_slice(&target.to_be_bytes());
        info.extend_from_slice(&hash(b"traffic-transcript", &[offer, reply].concat()));
        Hkdf::<Sha256>::new(Some(&self.session), root.as_bytes())
            .expand(&info, material.as_mut_bytes())
            .map_err(|_| Error::Provider)?;
        let traffic = Traffic::from_material(self.session, self.role, target, material.as_bytes())?;
        // Both first flights attest to settled history, including explicit local
        // accounting for unknown outcomes. The peer no longer needs the final ACK. Removal,
        // fresh owners and exact control output enter the same durable intent.
        self.epochs.retain(|epoch, _| *epoch >= first);
        self.epochs.insert(target, traffic);
        Ok(())
    }
    fn close_send(&mut self, closing: u64) -> Result<(), Error> {
        let old = self.traffic_mut(self.send_epoch)?;
        if old.sent != closing || old.pending.is_some() || old.send_closed {
            return Err(Error::State);
        }
        old.send_closed = true;
        old.send = ZeroizingBytes::zeroed();
        self.send_epoch = self.control.target()?;
        Ok(())
    }
    fn close_receive(&mut self, closing: u64) -> Result<(), Error> {
        let old = self.traffic_mut(self.receive_epoch)?;
        if old.receive_limit.is_some() {
            return Err(Error::State);
        }
        old.receive_limit = Some(closing);
        if old.received >= closing {
            old.receive = ZeroizingBytes::zeroed();
        }
        self.receive_epoch = self.control.target()?;
        Ok(())
    }
    fn complete(&mut self, completed: Completed) -> Result<(), Error> {
        self.control.epoch = self.control.target()?;
        self.control.parent = completed.digest();
        self.control.last = Some(completed);
        self.control.plan = None;
        Ok(())
    }
}

impl DeviceJournal {
    pub(super) fn check_completed(
        &mut self,
        context: &BootstrapContext,
        last: &Completed,
    ) -> Result<(), DurableError> {
        if let Err(error) = last.verify_public(context) {
            self.close();
            return Err(DurableError::InvalidCheckpoint(error));
        }
        Ok(())
    }
    fn check_cached_wire(
        &mut self,
        context: &BootstrapContext,
        epoch: u64,
        flight: RekeyFlight,
        wire: &[u8],
    ) -> Result<(), DurableError> {
        if let Err(error) = verify_wire(context, epoch, flight, wire) {
            self.close();
            return Err(DurableError::InvalidCheckpoint(error));
        }
        Ok(())
    }
    fn sign_cutover(
        &mut self,
        signing: &SigningReservation,
        signer: &DeviceSigningKey,
        scope: &[u8; 32],
        purpose: Purpose,
        body: &[u8],
    ) -> Result<Vec<u8>, DurableError> {
        match signing.sign(signer, scope, purpose, body) {
            Ok(signature) => Ok(signature),
            Err(error @ (Error::Scope | Error::Encoding)) => {
                self.close();
                Err(DurableError::InvalidCheckpoint(error))
            }
            Err(error) => Err(error.into()),
        }
    }
    /// Validate the signed response and real decapsulation confirmation, then
    /// commit the signed final and new sending epoch atomically. Dispatch this
    /// final before new-epoch application traffic; receive cutover awaits receipt.
    pub fn accept_rekey_response(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
        reply: &[u8],
        signer: &DeviceSigningKey,
        now: u64,
    ) -> Result<Vec<u8>, DurableError> {
        let mut image = self.image()?;
        let mut state = self.message_state(&image, context, &session, now)?;
        if let Some(last) = &state.control.last {
            if last.response == reply && state.role == proposer(state.control.epoch)? {
                self.check_completed(context, last)?;
                self.check_context_release(&image, context, now)?;
                return Ok(last.final_wire.clone());
            }
        }
        let target = state.control.target()?;
        if state.role != proposer(target)? {
            return Err(Error::State.into());
        }
        if let Some(super::Plan::Completing(plan)) = &state.control.plan {
            if plan.response != reply {
                return Err(DurableError::Conflict);
            }
            if let Step::FinalReady { wire } = &plan.step {
                self.check_cached_wire(context, target, RekeyFlight::Final, wire)?;
                self.check_context_release(&image, context, now)?;
                return Ok(wire.clone());
            }
        }
        if signer.public_key()? != device(context, state.role)?.key {
            return Err(Error::Scope.into());
        }
        if let Some(super::Plan::Ready {
            key: token,
            wire: offer,
        }) = &state.control.plan
        {
            state.admit_cutover()?;
            self.check_cached_wire(context, target, RekeyFlight::Offer, offer)?;
            verify_wire(context, target, RekeyFlight::Response, reply)?;
            let (body, _) = open_envelope(reply)?;
            let prefix = response::prefix(&state.control, &session, &context.digest(), offer)?;
            if body.len() != response::RESPONSE_BODY_LEN || !body.starts_with(&prefix) {
                return Err(Error::Scope.into());
            }
            let recovery = self.rekey_recovery_key()?;
            let scope = state
                .control
                .scope(&image.id, &session, &context.digest())?;
            let owner = match recovery.generate_key(
                &context.policy().runtime,
                &hash(b"key", &scope),
                token,
            ) {
                Ok(owner) => owner,
                Err(q_periapt_sdk::Error::InvalidPrivateKey) => {
                    self.close();
                    return Err(DurableError::InvalidCheckpoint(Error::Runtime(
                        q_periapt_sdk::Error::InvalidPrivateKey,
                    )));
                }
                Err(e) => return Err(Error::from(e).into()),
            };
            let (offer_body, _) = open_envelope(offer)?;
            if owner
                .public_key()
                .map_err(Error::from)?
                .to_bytes()
                .as_slice()
                != offer_body
                    .get(BODY_LEN - PUBLIC_KEY_LEN..)
                    .ok_or(Error::Encoding)?
            {
                self.close();
                return Err(DurableError::Corrupt);
            }
            let ciphertext = Ciphertext::from_bytes(
                body.get(response::PREFIX_LEN..response::CORE_LEN)
                    .ok_or(Error::Encoding)?,
            )
            .map_err(Error::from)?;
            let shared = owner
                .decapsulate(&ciphertext, &response::kem_context(offer))
                .map_err(Error::from)?
                .export_for_protocol()
                .map_err(Error::from)?;
            let root = response::derive_root(
                &state.rekey,
                &shared,
                body.get(..response::CORE_LEN).ok_or(Error::Encoding)?,
            )?;
            response::check_body(&prefix, body, &root)?;
            let closing = state.traffic(state.send_epoch)?.sent;
            let final_body = make_body(
                core_prefix(
                    &state.control,
                    &session,
                    &context.digest(),
                    offer,
                    reply,
                    None,
                )?,
                closing,
                &root,
                false,
            )?;
            let signing = SigningReservation::reserve(
                &device(context, state.role)?.key,
                &signing_scope(&image.id, &final_body),
                Purpose::RekeyFinal,
                &final_body,
            )?;
            state.control.plan = Some(super::Plan::Completing(Plan {
                offer: offer.clone(),
                response: reply.to_vec(),
                step: Step::FinalSigning {
                    root,
                    body: final_body,
                    signing,
                },
            }));
            self.store_message_state(&mut image, &state)?;
            #[cfg(all(test, unix))]
            super::super::tests::after_stage("rekey-final-reserved");
        }
        rosters::authorize_context(&image, context, now)?;
        let Some(super::Plan::Completing(plan)) = &state.control.plan else {
            return Err(DurableError::Suspended);
        };
        let Step::FinalSigning { body, signing, .. } = &plan.step else {
            return Err(Error::State.into());
        };
        let signature = self.sign_cutover(
            signing,
            signer,
            &signing_scope(&image.id, body),
            Purpose::RekeyFinal,
            body,
        )?;
        let wire = envelope(body, &signature)?;
        #[cfg(all(test, unix))]
        after_effect("rekey-final-computed", &wire);
        let Some(super::Plan::Completing(Plan {
            offer,
            response,
            step: Step::FinalSigning { root, body, .. },
        })) = state.control.plan.take()
        else {
            return Err(DurableError::Corrupt);
        };
        let closing = structural_control(
            &state.control,
            &session,
            &context.digest(),
            &offer,
            &response,
            None,
            &body,
        )?;
        state.add_epoch(&context.digest(), &root, &offer, &response)?;
        state.close_send(closing)?;
        state.rekey = root;
        state.control.plan = Some(super::Plan::Completing(Plan {
            offer,
            response,
            step: Step::FinalReady { wire: wire.clone() },
        }));
        self.store_message_state(&mut image, &state)?;
        #[cfg(all(test, unix))]
        super::super::tests::after_stage("rekey-final-committed");
        self.check_context_release(&image, context, now)?;
        Ok(wire)
    }

    /// Authenticate the final proposer proof, commit both new traffic directions
    /// and the signed completion receipt atomically, and return only that outbox.
    pub fn finish_rekey(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
        final_wire: &[u8],
        signer: &DeviceSigningKey,
        now: u64,
    ) -> Result<Vec<u8>, DurableError> {
        let mut image = self.image()?;
        let mut state = self.message_state(&image, context, &session, now)?;
        if let Some(last) = &state.control.last {
            if last.final_wire == final_wire && state.role == 3 - proposer(state.control.epoch)? {
                self.check_completed(context, last)?;
                self.check_context_release(&image, context, now)?;
                return Ok(last.receipt.clone());
            }
        }
        let target = state.control.target()?;
        if state.role == proposer(target)? {
            return Err(Error::State.into());
        }
        if signer.public_key()? != device(context, state.role)?.key {
            return Err(Error::Scope.into());
        }
        if let Some(super::Plan::Completing(plan)) = &state.control.plan {
            let Step::ReceiptSigning {
                final_wire: saved, ..
            } = &plan.step
            else {
                return Err(Error::State.into());
            };
            if saved != final_wire {
                return Err(DurableError::Conflict);
            }
        }
        if let Some(super::Plan::Response(plan)) = &state.control.plan {
            let response::Stage::Ready { wire: reply, root } = &plan.stage else {
                return Err(DurableError::Suspended);
            };
            state.admit_cutover()?;
            self.check_cached_wire(context, target, RekeyFlight::Offer, &plan.offer)?;
            self.check_cached_wire(context, target, RekeyFlight::Response, reply)?;
            verify_wire(context, target, RekeyFlight::Final, final_wire)?;
            verify_control_body(
                &state.control,
                &session,
                &context.digest(),
                &plan.offer,
                reply,
                None,
                (open_envelope(final_wire)?.0, root),
            )?;
            let body = make_body(
                core_prefix(
                    &state.control,
                    &session,
                    &context.digest(),
                    &plan.offer,
                    reply,
                    Some(final_wire),
                )?,
                state.traffic(state.send_epoch)?.sent,
                root,
                true,
            )?;
            let signing = SigningReservation::reserve(
                &device(context, state.role)?.key,
                &signing_scope(&image.id, &body),
                Purpose::RekeyReceipt,
                &body,
            )?;
            state.control.plan = Some(super::Plan::Completing(Plan {
                offer: plan.offer.clone(),
                response: reply.clone(),
                step: Step::ReceiptSigning {
                    final_wire: final_wire.to_vec(),
                    root: key(root.as_bytes())?,
                    body,
                    signing,
                },
            }));
            self.store_message_state(&mut image, &state)?;
            #[cfg(all(test, unix))]
            super::super::tests::after_stage("rekey-receipt-reserved");
        }
        rosters::authorize_context(&image, context, now)?;
        let Some(super::Plan::Completing(plan)) = &state.control.plan else {
            return Err(DurableError::Suspended);
        };
        let Step::ReceiptSigning { body, signing, .. } = &plan.step else {
            return Err(Error::State.into());
        };
        let signature = self.sign_cutover(
            signing,
            signer,
            &signing_scope(&image.id, body),
            Purpose::RekeyReceipt,
            body,
        )?;
        let wire = envelope(body, &signature)?;
        #[cfg(all(test, unix))]
        after_effect("rekey-receipt-computed", &wire);
        let Some(super::Plan::Completing(Plan {
            offer,
            response,
            step:
                Step::ReceiptSigning {
                    final_wire,
                    root,
                    body,
                    ..
                },
        })) = state.control.plan.take()
        else {
            return Err(DurableError::Corrupt);
        };
        let local_closing = structural_control(
            &state.control,
            &session,
            &context.digest(),
            &offer,
            &response,
            Some(&final_wire),
            &body,
        )?;
        let peer_closing = structural_control(
            &state.control,
            &session,
            &context.digest(),
            &offer,
            &response,
            None,
            open_envelope(&final_wire)?.0,
        )?;
        state.add_epoch(&context.digest(), &root, &offer, &response)?;
        state.close_send(local_closing)?;
        state.close_receive(peer_closing)?;
        state.rekey = root;
        state.complete(Completed {
            offer,
            response,
            final_wire,
            receipt: wire.clone(),
        })?;
        self.store_message_state(&mut image, &state)?;
        #[cfg(all(test, unix))]
        super::super::tests::after_stage("rekey-receipt-committed");
        self.check_context_release(&image, context, now)?;
        Ok(wire)
    }

    /// Authenticate the responder's completion receipt and atomically enable the
    /// new receiving epoch. Duplicate receipts cannot advance another epoch.
    pub fn accept_rekey_receipt(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
        receipt: &[u8],
        now: u64,
    ) -> Result<u64, DurableError> {
        let mut image = self.image()?;
        let mut state = self.message_state(&image, context, &session, now)?;
        if let Some(last) = &state.control.last {
            if last.receipt == receipt && state.role == proposer(state.control.epoch)? {
                self.check_completed(context, last)?;
                self.check_context_release(&image, context, now)?;
                return Ok(state.control.epoch);
            }
        }
        let target = state.control.target()?;
        if state.role != proposer(target)? {
            return Err(Error::State.into());
        }
        let Some(super::Plan::Completing(Plan {
            offer,
            response,
            step: Step::FinalReady { wire },
        })) = &state.control.plan
        else {
            return Err(DurableError::Suspended);
        };
        verify_wire(context, target, RekeyFlight::Receipt, receipt)?;
        let closing = verify_control_body(
            &state.control,
            &session,
            &context.digest(),
            offer,
            response,
            Some(wire),
            (open_envelope(receipt)?.0, &state.rekey),
        )?;
        let Some(super::Plan::Completing(Plan {
            offer,
            response,
            step: Step::FinalReady { wire },
        })) = state.control.plan.take()
        else {
            return Err(DurableError::Corrupt);
        };
        state.close_receive(closing)?;
        state.complete(Completed {
            offer,
            response,
            final_wire: wire,
            receipt: receipt.to_vec(),
        })?;
        self.store_message_state(&mut image, &state)?;
        #[cfg(all(test, unix))]
        super::super::tests::after_stage("rekey-receipt-accepted");
        self.check_context_release(&image, context, now)?;
        Ok(target)
    }

    /// Query authenticated local progress without granting output permission.
    pub fn rekey_progress(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
    ) -> Result<RekeyProgress, DurableError> {
        let state = self.message_state_for_status(context, session)?;
        Ok(RekeyProgress {
            confirmed_epoch: state.control.epoch,
            sending_epoch: state.send_epoch,
            receiving_epoch: state.receive_epoch,
            pending_epoch: if state.control.plan.is_some() {
                Some(state.control.target()?)
            } else {
                None
            },
        })
    }
    /// Release one exact committed control flight for the explicit target epoch,
    /// after current policy, roster and witness checks. Unsigned stages suspend.
    pub fn rekey_outbox(
        &mut self,
        context: &BootstrapContext,
        session: [u8; 32],
        epoch: u64,
        flight: RekeyFlight,
        now: u64,
    ) -> Result<Vec<u8>, DurableError> {
        let image = self.image()?;
        let state = self.message_state(&image, context, &session, now)?;
        let wire = if epoch == state.control.epoch {
            state
                .control
                .last
                .as_ref()
                .ok_or(DurableError::Absent)?
                .outbox(flight)
        } else if epoch == state.control.target()? {
            match &state.control.plan {
                Some(super::Plan::Ready { wire, .. }) if flight == RekeyFlight::Offer => wire,
                Some(super::Plan::Response(plan)) => match flight {
                    RekeyFlight::Offer => &plan.offer,
                    RekeyFlight::Response => {
                        if let response::Stage::Ready { wire, .. } = &plan.stage {
                            wire
                        } else {
                            return Err(DurableError::Suspended);
                        }
                    }
                    _ => return Err(DurableError::Suspended),
                },
                Some(super::Plan::Completing(plan)) => {
                    plan.outbox(flight).ok_or(DurableError::Suspended)?
                }
                _ => return Err(DurableError::Suspended),
            }
        } else {
            return Err(Error::Retired.into());
        };
        if let Err(error) = verify_wire(context, epoch, flight, wire) {
            self.close();
            return Err(DurableError::InvalidCheckpoint(error));
        }
        self.check_context_release(&image, context, now)?;
        Ok(wire.to_vec())
    }
}
