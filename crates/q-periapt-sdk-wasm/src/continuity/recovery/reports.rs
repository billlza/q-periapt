// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Complete public accounting snapshots. These JSON documents are not protocol inputs.
use super::*;

pub(in crate::continuity) fn hex(bytes: &[u8]) -> String {
    format!(
        "\"{}\"",
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}
// Decimal strings preserve every u64 through JSON.parse/stringify without rounding.
pub(in crate::continuity) fn integer(value: u64) -> String {
    format!("\"{value}\"")
}
fn optional(value: Option<u64>) -> String {
    value.map(integer).unwrap_or_else(|| "null".into())
}
pub(in crate::continuity) fn array_json(values: impl IntoIterator<Item = String>) -> String {
    format!("[{}]", values.into_iter().collect::<Vec<_>>().join(","))
}
// Keys are fixed ASCII schema literals. All values below come from typed numeric,
// fixed-byte or enum fields, so no external string enters this encoding.
pub(in crate::continuity) fn object(fields: &[(&'static str, String)]) -> String {
    format!(
        "{{{}}}",
        fields
            .iter()
            .map(|(name, value)| format!("\"{name}\":{value}"))
            .collect::<Vec<_>>()
            .join(",")
    )
}
pub(in crate::continuity) fn progress(value: &engine::RekeyProgress) -> String {
    let engine::RekeyProgress {
        confirmed_epoch,
        sending_epoch,
        receiving_epoch,
        pending_epoch,
    } = value;
    object(&[
        ("confirmed_epoch", integer(*confirmed_epoch)),
        ("sending_epoch", integer(*sending_epoch)),
        ("receiving_epoch", integer(*receiving_epoch)),
        ("pending_epoch", optional(*pending_epoch)),
    ])
}
pub(in crate::continuity) fn reserved(value: &engine::ReservedAbandonment) -> String {
    let engine::ReservedAbandonment {
        message,
        plaintext_bytes,
        associated_data_bytes,
    } = value;
    object(&[
        ("message", hex(message.as_bytes())),
        ("plaintext_bytes", plaintext_bytes.to_string()),
        ("associated_data_bytes", associated_data_bytes.to_string()),
    ])
}
pub(in crate::continuity) fn epoch(value: &engine::AbandonedEpoch) -> String {
    let engine::AbandonedEpoch {
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
    } = value;
    let (phase, report) = match resolution {
        engine::EpochResolutionStatus::Unrequested => ("\"unrequested\"", "null".into()),
        engine::EpochResolutionStatus::Pending(id) => ("\"pending\"", hex(id.as_bytes())),
        engine::EpochResolutionStatus::Acknowledged(id) => ("\"acknowledged\"", hex(id.as_bytes())),
    };
    object(&[
        ("epoch", integer(*epoch)),
        ("acknowledged_before", integer(*acknowledged_before)),
        ("sent", integer(*sent)),
        ("consumed_before", integer(*consumed_before)),
        ("received", integer(*received)),
        ("peer_sent", optional(*peer_sent)),
        (
            "resolution",
            object(&[("phase", phase.into()), ("report", report)]),
        ),
        (
            "unconfirmed",
            array_json(unconfirmed.iter().map(|message| {
                object(&[
                    ("message", hex(message.message_id().as_bytes())),
                    ("ciphertext_digest", hex(message.ciphertext_digest())),
                ])
            })),
        ),
        (
            "deliveries",
            array_json(deliveries.iter().map(|delivery| {
                let engine::AbandonedDelivery {
                    message,
                    index,
                    plaintext_bytes,
                } = delivery;
                object(&[
                    ("message", hex(message.as_bytes())),
                    ("index", integer(*index)),
                    ("plaintext_bytes", plaintext_bytes.to_string()),
                ])
            })),
        ),
        ("skipped", array_json(skipped.iter().copied().map(integer))),
    ])
}
fn member(value: &engine::AbandonedSession) -> String {
    let engine::AbandonedSession {
        device,
        generation,
        context,
        session,
        role,
        progress: current,
        reserved: pending,
        epochs,
    } = value;
    object(&[
        ("device", hex(device)),
        ("generation", integer(*generation)),
        ("context", hex(context)),
        ("session", hex(session)),
        ("role", role.to_string()),
        ("progress", progress(current)),
        ("reserved", reserved(pending)),
        ("epochs", array_json(epochs.iter().map(epoch))),
    ])
}

/// Full immutable loss snapshot for one reserved account transaction. Save the
/// entire JSON document with durable host deduplication before acknowledging its ID.
#[wasm_bindgen(js_name = QPeriaptContinuityAccountAbandonment)]
pub struct AccountReport {
    inner: engine::FanoutAbandonment,
}
impl AccountReport {
    pub(super) fn new(inner: engine::FanoutAbandonment) -> Self {
        Self { inner }
    }
}
#[wasm_bindgen(js_class = QPeriaptContinuityAccountAbandonment)]
impl AccountReport {
    pub fn operation_id(&self) -> Vec<u8> {
        self.inner.batch.as_bytes().to_vec()
    }
    pub fn report_id(&self) -> Vec<u8> {
        self.inner.report.as_bytes().to_vec()
    }
    pub fn member_count(&self) -> usize {
        self.inner.sessions.len()
    }
    /// Schema 1 uses hexadecimal byte IDs, decimal-string u64 values, bounded
    /// numeric lengths and null for genuinely absent optional metadata. No secret
    /// or plaintext is returned. JSON is for host accounting, never send authority.
    pub fn to_json(&self) -> String {
        let engine::FanoutAbandonment {
            batch,
            report,
            sessions,
        } = &self.inner;
        object(&[
            ("schema", "1".into()),
            ("kind", "\"account\"".into()),
            ("batch", hex(batch.as_bytes())),
            ("report", hex(report.as_bytes())),
            ("sessions", array_json(sessions.iter().map(member))),
        ])
    }
}
/// Full immutable accounting snapshot for one independently frozen session.
#[wasm_bindgen(js_name = QPeriaptContinuitySessionClosure)]
pub struct SessionReport {
    inner: engine::SessionClosure,
}
impl SessionReport {
    pub(super) fn new(inner: engine::SessionClosure) -> Self {
        Self { inner }
    }
}
#[wasm_bindgen(js_class = QPeriaptContinuitySessionClosure)]
impl SessionReport {
    pub fn session_id(&self) -> Vec<u8> {
        self.inner.session.to_vec()
    }
    pub fn report_id(&self) -> Vec<u8> {
        self.inner.report.as_bytes().to_vec()
    }
    /// Complete schema-1 loss metadata, using the same exact JSON representation
    /// as account abandonment. Persist every epoch, reservation and unknown outcome.
    pub fn to_json(&self) -> String {
        let engine::SessionClosure {
            session,
            context,
            report,
            role,
            peer_account,
            peer_device,
            peer_generation,
            progress: current,
            reserved: pending,
            epochs,
        } = &self.inner;
        object(&[
            ("schema", "1".into()),
            ("kind", "\"session\"".into()),
            ("session", hex(session)),
            ("context", hex(context)),
            ("report", hex(report.as_bytes())),
            ("role", role.to_string()),
            ("peer_account", hex(peer_account)),
            ("peer_device", hex(peer_device)),
            ("peer_generation", integer(*peer_generation)),
            ("progress", progress(current)),
            ("reserved", array_json(pending.iter().map(reserved))),
            ("epochs", array_json(epochs.iter().map(epoch))),
        ])
    }
}
