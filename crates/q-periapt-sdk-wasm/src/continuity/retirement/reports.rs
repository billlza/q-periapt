// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Complete typed historical metadata; no plaintext, secret or inferred delivery.
use super::super::recovery::reports::{
    array_json, epoch, hex, integer, object, progress, reserved,
};
use super::*;
use engine::retired_device as r;

mod bootstrap_metadata;
mod session_metadata;
use bootstrap_metadata::{bootstrap, cancellation};
use session_metadata::session;

fn optional(value: Option<String>) -> String {
    value.unwrap_or_else(|| "null".into())
}
fn label(value: &'static str) -> String {
    format!("\"{value}\"")
}
fn head(value: engine::AnchorHead) -> String {
    object(&[
        ("fence", integer(value.fence())),
        ("revision", integer(value.revision())),
        ("digest", hex(&value.digest())),
    ])
}
fn checkpoint(value: engine::RosterCheckpoint) -> String {
    object(&[
        ("version", integer(value.version())),
        ("digest", hex(&value.digest())),
    ])
}
fn fanout_status(value: engine::FanoutStatus) -> String {
    let (phase, id) = match value {
        engine::FanoutStatus::Absent => ("absent", None),
        engine::FanoutStatus::Reserved => ("reserved", None),
        engine::FanoutStatus::Committed => ("committed", None),
        engine::FanoutStatus::Abandoning(id) => ("abandoning", Some(id)),
        engine::FanoutStatus::Abandoned(id) => ("abandoned", Some(id)),
        engine::FanoutStatus::Retired => ("retired", None),
    };
    object(&[
        ("phase", label(phase)),
        ("report", optional(id.map(|v| hex(v.as_bytes())))),
    ])
}
fn member(value: &r::Member) -> String {
    let r::Member {
        device,
        generation,
        credential,
        context,
        session,
        role,
        message,
        state,
        ciphertext_digest,
    } = value;
    let state = match state {
        r::MemberState::Reserved => "reserved",
        r::MemberState::Retained(value) => match value {
            engine::FanoutMemberState::Committed => "committed",
            engine::FanoutMemberState::Acknowledged => "acknowledged",
            engine::FanoutMemberState::ResolutionPending => "resolution_pending",
            engine::FanoutMemberState::DeliveryUnknown => "delivery_unknown",
            engine::FanoutMemberState::HistoryRetired => "history_retired",
            engine::FanoutMemberState::ReservationAbandoned => "reservation_abandoned",
        },
    };
    object(&[
        ("device", hex(device)),
        ("generation", integer(*generation)),
        ("credential", hex(credential)),
        ("context", hex(context)),
        ("session", hex(session)),
        ("role", role.to_string()),
        ("message", hex(message.as_bytes())),
        ("state", label(state)),
        (
            "ciphertext_digest",
            optional(ciphertext_digest.as_ref().map(|v| hex(v))),
        ),
    ])
}
fn metadata(value: &r::RecordMetadata) -> String {
    match value {
        r::RecordMetadata::Bootstrap {
            entry,
            request,
            flights,
            cancellation: cancelled,
        } => {
            let r::BootstrapFlights {
                initial,
                reply,
                final_confirmation,
                session,
            } = flights;
            object(&[
                ("kind", label("bootstrap")),
                ("entry", bootstrap(entry)),
                (
                    "request",
                    optional(request.as_ref().map(|v| hex(v.as_bytes()))),
                ),
                (
                    "flights",
                    object(&[
                        ("initial", optional(initial.as_ref().map(|v| hex(v)))),
                        ("reply", optional(reply.as_ref().map(|v| hex(v)))),
                        (
                            "final_confirmation",
                            optional(final_confirmation.as_ref().map(|v| hex(v))),
                        ),
                        ("session", optional(session.as_ref().map(|v| hex(v)))),
                    ]),
                ),
                (
                    "cancellation",
                    optional(cancelled.as_deref().map(cancellation)),
                ),
            ])
        }
        r::RecordMetadata::Prekey {
            request,
            kind,
            validity,
            public_fingerprint,
            source,
        } => object(&[
            ("kind", label("prekey")),
            ("request", hex(request.as_bytes())),
            ("leaf_kind", (*kind as u8).to_string()),
            (
                "validity",
                object(&[
                    ("from", integer(validity.from())),
                    ("until", integer(validity.until())),
                ]),
            ),
            (
                "public_fingerprint",
                optional(public_fingerprint.as_ref().map(|v| hex(v))),
            ),
            (
                "source",
                optional(source.as_ref().map(|v| hex(v.as_bytes()))),
            ),
        ]),
        r::RecordMetadata::Session(value) => {
            object(&[("kind", label("session")), ("session", session(value))])
        }
        r::RecordMetadata::Roster {
            account,
            checkpoint: cp,
            public_history,
        } => object(&[
            ("kind", label("roster")),
            ("account", hex(account)),
            ("checkpoint", checkpoint(*cp)),
            ("public_history", hex(public_history)),
        ]),
        r::RecordMetadata::Fanout {
            batch,
            account,
            roster,
            status,
            members,
        } => object(&[
            ("kind", label("fanout")),
            ("batch", hex(batch.as_bytes())),
            ("account", hex(account)),
            ("roster", checkpoint(*roster)),
            ("status", fanout_status(*status)),
            ("members", array_json(members.iter().map(member))),
        ]),
        r::RecordMetadata::PrekeyPublications {
            next_epoch,
            public_history,
        } => object(&[
            ("kind", label("prekey_publications")),
            ("next_epoch", integer(*next_epoch)),
            ("public_history", hex(public_history)),
        ]),
    }
}
fn transaction(value: &r::Transaction) -> String {
    match value {
        r::Transaction::Ordinary => object(&[("kind", label("ordinary"))]),
        r::Transaction::Credential {
            operation,
            statement,
            policy,
        } => object(&[
            ("kind", label("credential")),
            ("operation", hex(operation)),
            ("statement", hex(statement)),
            (
                "policy",
                optional(policy.as_ref().map(|(adopt, statement)| {
                    object(&[("adopts", adopt.to_string()), ("statement", hex(statement))])
                })),
            ),
        ]),
        r::Transaction::CredentialUnderPolicy {
            operation,
            statement,
            policy,
        } => object(&[
            ("kind", label("credential_under_policy")),
            ("operation", hex(operation)),
            ("statement", hex(statement)),
            ("policy", hex(policy)),
        ]),
        r::Transaction::Policy {
            operation,
            statement,
        } => object(&[
            ("kind", label("policy")),
            ("operation", hex(operation)),
            ("statement", hex(statement)),
        ]),
        r::Transaction::Roster(wire) => object(&[("kind", label("roster")), ("scope", hex(wire))]),
    }
}
pub(super) fn describe(value: &r::Report) -> String {
    let intent = match value.intent() {
        r::Intent::None => object(&[("kind", label("none"))]),
        r::Intent::Cancellation(wire) => {
            object(&[("kind", label("cancellation")), ("wire", hex(wire))])
        }
        r::Intent::Write {
            expected,
            target,
            transaction: kind,
        } => object(&[
            ("kind", label("write")),
            ("expected", head(*expected)),
            ("target", head(*target)),
            ("transaction", transaction(kind)),
        ]),
    };
    object(&[
        ("schema", "1".into()),
        ("report_id", hex(value.proposal().report_id())),
        ("inventory", hex(&value.proposal().inventory().to_bytes())),
        ("intent", intent),
        (
            "views",
            array_json(value.views().iter().map(|view| {
                let r::View {
                    role,
                    head: position,
                    local_account,
                    next_fanout_ordinal,
                    records,
                } = view;
                let mut fields = vec![(
                    "role",
                    label(match role {
                        r::ViewRole::Authoritative => "authoritative",
                        r::ViewRole::SupersededSource => "superseded_source",
                        r::ViewRole::UncommittedTarget => "uncommitted_target",
                    }),
                )];
                fields.extend(image_fields(
                    *position,
                    local_account,
                    *next_fanout_ordinal,
                    records,
                ));
                object(&fields)
            })),
        ),
    ])
}

// Both flows use the same exhaustive record projection; a pending source/target
// view never acquires a retirement or commitment role merely by being displayed.
pub(in crate::continuity) fn describe_image(
    position: engine::AnchorHead,
    account: &[u8; 32],
    ordinal: u64,
    records: &[r::RecordMetadataEntry],
) -> String {
    object(&image_fields(position, account, ordinal, records))
}
fn image_fields(
    position: engine::AnchorHead,
    account: &[u8; 32],
    ordinal: u64,
    records: &[r::RecordMetadataEntry],
) -> Vec<(&'static str, String)> {
    vec![
        ("head", head(position)),
        ("local_account", hex(account)),
        ("next_fanout_ordinal", integer(ordinal)),
        ("records", array_json(records.iter().map(record))),
    ]
}
fn record(value: &r::RecordMetadataEntry) -> String {
    let r::RecordMetadataEntry {
        id,
        context,
        phase,
        authorities,
        one_time_claims,
        inventory_references,
        metadata: value,
    } = value;
    object(&[
        ("id", hex(id)),
        ("context", hex(context)),
        ("phase", (*phase as u8).to_string()),
        (
            "authorities",
            array_json(authorities.iter().map(|v| hex(v))),
        ),
        (
            "one_time_claims",
            array_json(one_time_claims.iter().map(|v| hex(v))),
        ),
        (
            "inventory_references",
            array_json(inventory_references.iter().map(|v| hex(v))),
        ),
        ("metadata", metadata(value)),
    ])
}
